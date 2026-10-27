"""GEN-03-04: Harness Validation — EXE-04(본 퍼징) 투입 전 게이트키퍼.

GEN-03-01~03을 통과한(=컴파일 성공한) 하네스가, ECU/네트워크 인터페이스
미가상화 등 "환경적 결함"으로 즉시 종료되는 오탐 하네스인지를 본 퍼징 캠페인
투입 전 짧게(수 초~수십 초) 걸러낸다. 검증은 아래 순서로 실행하고, 하나라도
실패하면 그 시점에서 중단하고 "검증 실패"로 분류한다:

  1. dry-run 스모크 테스트  — libFuzzer `-runs=N` 으로 즉시 crash/abort/
     segfault/timeout이 발생하는지 확인.
  2. 커버리지 임계치 검사   — 1번 실행 동안 수집된 edge coverage가 0이거나
     임계치 미만이면 "타겟 API 미도달"로 실패 처리.
  3. 입력 소비 검증        — 하네스가 퍼즈 입력을 실제로 쓰는지 확인.
     `LLVMFuzzerTestOneInput` 본문이 제 인자(`data`/`size`)를 한 번도
     참조하지 않으면 무엇을 넣든 같은 경로만 돌므로 퍼징이 성립하지 않는다.
  4. Mocking 호출 트레이싱  — 1번 실행 로그에서 GEN-03-03이 삽입한 CAN/UDS
     mock 함수 심볼이 실제로 호출되었는지 확인.
  5. (선택) 정적 리뷰       — `llm_review.py` 참고. `ValidationConfig.
     enable_static_review=True` 이고 `HarnessArtifact.source_path`가
     있을 때만 실행된다.

1·2·4번은 같은 dry-run 실행 로그 하나를 재사용한다(실행을 여러 번 하지 않음) —
"수 초~수십 초 내 완료"라는 성능 제약을 지키기 위함이다. 3번은 소스를 읽어
정적으로 판정하므로 추가 실행이 아예 없다.

3번을 왜 커버리지 검사와 따로 두나
-----------------------------------
둘은 서로 다른 실패를 잡는다. 커버리지가 0이면 "타겟에 못 닿았다"이고, 커버리지는
나오는데 입력을 안 쓰면 "닿긴 했는데 항상 같은 값으로 닿는다"이다. 후자는 커버리지
임계치를 통과하므로 2번으로는 절대 걸리지 않는데, 퍼징 캠페인을 몇 시간 돌려도
새 경로가 하나도 안 나온다. LLM이 만든 하네스에서 흔한 실패다 - 대상 API를 부르긴
하지만 인자를 하드코딩해 버린다.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import asdict, dataclass, field
from typing import Callable, Optional

from logosfuzz.generate.contracts import HarnessArtifact
from logosfuzz.generate.llm_review import MockStaticReviewer, StaticReviewer, StaticReviewResult

# 검증 결과 JSON에 저장할 dry-run 로그 최대 길이(전체 로그는 파싱에 사용하고,
# 직렬화 시점에만 뒤쪽 N자로 잘라 요약 파일이 과도하게 커지는 것을 막는다).
_MAX_LOG_CHARS = 20_000

STEP_SMOKE = "smoke_test"
STEP_COVERAGE = "coverage_threshold"
STEP_INPUT_CONSUMPTION = "input_consumption"
STEP_MOCK_TRACE = "mock_trace"
STEP_STATIC_REVIEW = "static_review"

_COV_RE = re.compile(r"\bcov:\s*(\d+)", re.IGNORECASE)
_NEW_UNITS_RE = re.compile(r"stat::new_units_added:\s*(\d+)")


# ---- 실행기 주입 (테스트 용이성 — docker_runner.py의 executor 패턴과 동일) ----

@dataclass
class RunResult:
    exit_code: int
    timed_out: bool
    log: str


Runner = Callable[[list, float], RunResult]


def _default_runner(argv: list, timeout: float) -> RunResult:
    """subprocess 기반 기본 실행기. stdout+stderr를 합쳐 반환한다."""
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return RunResult(
            exit_code=proc.returncode,
            timed_out=False,
            log=(proc.stdout or "") + (proc.stderr or ""),
        )
    except subprocess.TimeoutExpired as e:
        stdout = e.stdout if isinstance(e.stdout, str) else (e.stdout or b"").decode("utf-8", "replace")
        stderr = e.stderr if isinstance(e.stderr, str) else (e.stderr or b"").decode("utf-8", "replace")
        return RunResult(exit_code=-1, timed_out=True, log=stdout + stderr)


def parse_libfuzzer_coverage(log: str) -> int:
    """libFuzzer 출력에서 최대 edge coverage(`cov:`)를 뽑아낸다.

    커버리지는 실행이 진행될수록 단조 증가하므로, 등장한 값 중 최댓값을
    최종 커버리지로 취급한다.
    """
    matches = _COV_RE.findall(log)
    return max((int(m) for m in matches), default=0)


# ---- 1. dry-run 스모크 테스트 ----------------------------------------------

@dataclass
class SmokeTestConfig:
    runs: int = 100
    timeout_sec: float = 30.0
    extra_args: list = field(default_factory=list)


@dataclass
class SmokeTestResult:
    passed: bool
    exit_code: int
    timed_out: bool
    crashed: bool
    signal: Optional[int]
    coverage_edges: int
    log: str
    reason: str = ""

    def to_dict(self) -> dict:
        log = self.log
        if len(log) > _MAX_LOG_CHARS:
            log = f"...(생략, 총 {len(log)}자)...\n" + log[-_MAX_LOG_CHARS:]
        return {
            "passed": self.passed,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "crashed": self.crashed,
            "signal": self.signal,
            "coverage_edges": self.coverage_edges,
            "reason": self.reason,
            "log": log,
        }


def run_smoke_test(
    artifact: HarnessArtifact,
    config: SmokeTestConfig = SmokeTestConfig(),
    runner: Runner = _default_runner,
) -> SmokeTestResult:
    if not artifact.harness_path.exists():
        return SmokeTestResult(
            passed=False, exit_code=-1, timed_out=False, crashed=False, signal=None,
            coverage_edges=0, log="",
            reason=f"하네스 실행 파일 없음: {artifact.harness_path} (GEN-03-02 산출물을 확인하세요)",
        )

    argv = [str(artifact.harness_path), f"-runs={config.runs}", "-print_final_stats=1"]
    if artifact.corpus_dir:
        argv.append(str(artifact.corpus_dir))
    argv.extend(config.extra_args)

    result = runner(argv, config.timeout_sec)
    coverage = parse_libfuzzer_coverage(result.log)
    signal = -result.exit_code if result.exit_code < 0 else None
    crashed = (not result.timed_out) and result.exit_code != 0
    passed = not crashed and not result.timed_out

    reason = ""
    if result.timed_out:
        reason = f"dry-run이 {config.timeout_sec}초 내에 끝나지 않음(hang 의심)"
    elif crashed:
        sig_part = f", signal={signal}" if signal else ""
        reason = f"dry-run 중 비정상 종료(exit={result.exit_code}{sig_part}) — 즉시 crash/abort/segfault"

    return SmokeTestResult(
        passed=passed, exit_code=result.exit_code, timed_out=result.timed_out,
        crashed=crashed, signal=signal, coverage_edges=coverage, log=result.log, reason=reason,
    )


# ---- 2. 커버리지 임계치 검사 ------------------------------------------------

@dataclass
class CoverageCheckResult:
    passed: bool
    coverage_edges: int
    threshold: int
    reason: str = ""


def check_coverage(coverage_edges: int, threshold: int) -> CoverageCheckResult:
    passed = coverage_edges > 0 and coverage_edges >= threshold
    reason = "" if passed else (
        f"edge coverage {coverage_edges} < 임계치 {threshold} — 타겟 API 미도달 의심"
    )
    return CoverageCheckResult(passed, coverage_edges, threshold, reason)


# ---- 3. 입력 소비 검증 ------------------------------------------------------

ENTRY_POINT = "LLVMFuzzerTestOneInput"

# 인자를 '쓰지 않겠다'고 명시적으로 버리는 관용구. 이걸 참조로 세면 안 된다 -
# 오히려 안 쓴다는 증거다.
_DISCARD_RES = [
    re.compile(r"\(\s*void\s*\)\s*\(?\s*(?P<name>[A-Za-z_]\w*)\s*\)?\s*;"),
    re.compile(r"std\s*::\s*ignore\s*=\s*(?P<name>[A-Za-z_]\w*)"),
    re.compile(r"\b(?:UNUSED|LOGOSFUZZ_UNUSED|MAYBE_UNUSED)\s*\(\s*(?P<name>[A-Za-z_]\w*)\s*\)"),
]

_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.DOTALL)


def strip_comments_and_strings(source: str) -> str:
    """주석과 문자열 리터럴을 같은 길이의 공백으로 바꾼다.

    주석에 적힌 `data` 를 '입력을 쓴다'는 증거로 세면 안 된다. 길이를 보존해
    이후 오프셋 계산이 어긋나지 않게 한다.
    """
    def blank(match: re.Match) -> str:
        return "".join(" " if ch != "\n" else "\n" for ch in match.group(0))

    without_block = _BLOCK_COMMENT_RE.sub(blank, source)
    without_line = _LINE_COMMENT_RE.sub(blank, without_block)
    return _STRING_RE.sub(blank, without_line)


def _match_brace_block(text: str, open_index: int) -> Optional[str]:
    """`text[open_index]` 가 `{` 일 때 짝이 맞는 `}` 까지의 내용을 돌려준다."""
    depth = 0
    for i in range(open_index, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_index + 1:i]
    return None


def _split_top_level(params: str) -> list:
    """괄호/꺾쇠 안의 쉼표를 무시하고 인자 목록을 나눈다(`std::pair<a,b>` 대비)."""
    out, depth, current = [], 0, []
    for ch in params:
        if ch in "([<":
            depth += 1
        elif ch in ")]>":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(current))
            current = []
        else:
            current.append(ch)
    if current:
        out.append("".join(current))
    return [p.strip() for p in out if p.strip()]


_IDENT_RE = re.compile(r"[A-Za-z_]\w*")


def parse_entry_point(source: str):
    """`LLVMFuzzerTestOneInput` 의 인자 이름과 본문을 뽑는다.

    Returns:
        ``(param_names, body)``. 진입점을 못 찾거나 본문을 못 닫으면 ``None``.
    """
    clean = strip_comments_and_strings(source)
    for match in re.finditer(re.escape(ENTRY_POINT) + r"\s*\(", clean):
        open_paren = match.end() - 1
        close_paren = -1
        depth = 0
        for i in range(open_paren, len(clean)):
            if clean[i] == "(":
                depth += 1
            elif clean[i] == ")":
                depth -= 1
                if depth == 0:
                    close_paren = i
                    break
        if close_paren < 0:
            continue
        rest = clean[close_paren + 1:]
        brace_offset = rest.find("{")
        if brace_offset < 0:
            continue
        # 선언만 있고 정의가 없으면(`...);`) 건너뛴다.
        if ";" in rest[:brace_offset]:
            continue
        body = _match_brace_block(rest, brace_offset)
        if body is None:
            continue
        names = []
        for param in _split_top_level(clean[open_paren + 1:close_paren]):
            if param in ("void", ""):
                continue
            idents = _IDENT_RE.findall(param)
            if idents:
                names.append(idents[-1])
        return names, body
    return None


def parse_new_units_added(log: str) -> Optional[int]:
    """libFuzzer `-print_final_stats=1` 의 `stat::new_units_added`. 없으면 None."""
    match = _NEW_UNITS_RE.search(log)
    return int(match.group(1)) if match else None


@dataclass
class InputConsumptionResult:
    passed: bool
    checked: bool
    """소스를 실제로 분석했는지. False 면 근거 없이 통과시킨 것이다."""
    params: list = field(default_factory=list)
    used_params: list = field(default_factory=list)
    new_units_added: Optional[int] = None
    reason: str = ""
    warning: str = ""


def check_input_consumption(source: Optional[str], log: str = "") -> InputConsumptionResult:
    """하네스가 퍼즈 입력을 쓰는지 판정한다.

    **증명 가능한 경우에만 실패**시킨다. 진입점을 파싱하지 못했다면 그건 하네스가
    잘못됐다는 뜻이 아니라 이 검사기의 한계일 수 있으므로 통과시키고 그 사실을
    남긴다 - 게이트가 자기 파서의 빈틈 때문에 멀쩡한 하네스를 막으면 안 된다.

    Args:
        source: 하네스 소스. None 이면 검사하지 않고 통과.
        log: dry-run 로그. `stat::new_units_added` 를 보조 근거로 읽는다.
    """
    new_units = parse_new_units_added(log)

    if source is None:
        return InputConsumptionResult(
            True, False, new_units_added=new_units,
            reason="하네스 소스가 없어 입력 소비를 검사하지 않았다(통과 처리)",
        )

    parsed = parse_entry_point(source)
    if parsed is None:
        return InputConsumptionResult(
            True, False, new_units_added=new_units,
            reason=f"{ENTRY_POINT} 정의를 찾지 못해 입력 소비를 검사하지 않았다(통과 처리)",
        )

    params, body = parsed
    # 인자를 명시적으로 버리는 구문은 참조에서 제외한다.
    for discard in _DISCARD_RES:
        body = discard.sub(" ", body)

    used = [p for p in params if re.search(r"\b" + re.escape(p) + r"\b", body)]

    if not params:
        return InputConsumptionResult(
            True, False, params, used, new_units,
            reason=f"{ENTRY_POINT} 에 인자가 없어 입력 소비를 판정할 수 없다(통과 처리)",
        )

    if not used:
        return InputConsumptionResult(
            False, True, params, used, new_units,
            reason=(
                f"{ENTRY_POINT} 본문이 인자({', '.join(params)})를 한 번도 쓰지 않는다 "
                f"- 어떤 입력을 넣어도 같은 경로만 돌므로 퍼징이 성립하지 않는다. "
                f"대상 API 인자를 하드코딩했을 가능성이 크다."
            ),
        )

    warning = ""
    # 첫 인자(관례상 data 버퍼)를 안 쓰고 길이만 쓰면 입력의 '내용'은 무시하는 것이다.
    if params and params[0] not in used:
        warning = (
            f"길이 인자만 쓰고 버퍼({params[0]})는 쓰지 않는다 - 입력의 내용이 아니라 "
            f"크기에만 반응하므로 탐색 폭이 크게 좁다."
        )
    elif new_units == 0:
        warning = (
            "dry-run 동안 새로 추가된 코퍼스 단위가 0이다. 하네스가 입력을 쓰긴 하지만 "
            "돌연변이가 새 경로를 못 여는 상태일 수 있다(시드 코퍼스 점검 권장)."
        )

    return InputConsumptionResult(True, True, params, used, new_units, warning=warning)


# ---- 4. Mocking 호출 트레이싱 ----------------------------------------------

@dataclass
class MockTraceResult:
    passed: bool
    expected: list
    found: list
    missing: list
    reason: str = ""


def trace_mock_calls(log: str, expected_symbols: list) -> MockTraceResult:
    if not expected_symbols:
        return MockTraceResult(
            True, [], [], [],
            reason="검사할 mock 심볼 없음(GEN-03-03 미적용 그룹으로 간주, 통과 처리)",
        )
    found = [s for s in expected_symbols if re.search(re.escape(s) + r"\b", log)]
    missing = [s for s in expected_symbols if s not in found]
    passed = not missing
    reason = "" if passed else (
        f"실행 로그에서 호출 흔적을 찾지 못한 mock 심볼: {', '.join(missing)} "
        f"— ECU/네트워크 인터페이스 미가상화 의심"
    )
    return MockTraceResult(passed, list(expected_symbols), found, missing, reason)


# ---- 오케스트레이션 ---------------------------------------------------------

@dataclass
class ValidationConfig:
    runs: int = 100
    timeout_sec: float = 30.0
    coverage_threshold: int = 1
    enable_static_review: bool = False
    extra_args: list = field(default_factory=list)


@dataclass
class ValidationReport:
    group_id: str
    passed: bool
    steps_run: list
    failed_step: Optional[str]
    smoke: Optional[SmokeTestResult] = None
    coverage: Optional[CoverageCheckResult] = None
    input_consumption: Optional[InputConsumptionResult] = None
    mock_trace: Optional[MockTraceResult] = None
    static_review: Optional[StaticReviewResult] = None
    reason: str = ""

    @property
    def warnings(self) -> list:
        """실패는 아니지만 사람이 봐야 할 신호."""
        out = []
        if self.input_consumption and self.input_consumption.warning:
            out.append(f"{STEP_INPUT_CONSUMPTION}: {self.input_consumption.warning}")
        return out

    def to_dict(self) -> dict:
        return {
            "group_id": self.group_id,
            "passed": self.passed,
            "steps_run": self.steps_run,
            "failed_step": self.failed_step,
            "reason": self.reason,
            "warnings": self.warnings,
            "smoke": self.smoke.to_dict() if self.smoke else None,
            "coverage": asdict(self.coverage) if self.coverage else None,
            "input_consumption": (
                asdict(self.input_consumption) if self.input_consumption else None
            ),
            "mock_trace": asdict(self.mock_trace) if self.mock_trace else None,
            "static_review": self.static_review.to_dict() if self.static_review else None,
        }


def validate_harness(
    artifact: HarnessArtifact,
    config: ValidationConfig = ValidationConfig(),
    runner: Runner = _default_runner,
    static_reviewer: Optional[StaticReviewer] = None,
) -> ValidationReport:
    steps_run: list = []

    # 1. dry-run 스모크 테스트
    steps_run.append(STEP_SMOKE)
    smoke = run_smoke_test(
        artifact,
        SmokeTestConfig(config.runs, config.timeout_sec, config.extra_args),
        runner,
    )
    if not smoke.passed:
        return ValidationReport(artifact.group_id, False, list(steps_run), STEP_SMOKE,
                                 smoke=smoke, reason=smoke.reason)

    # 2. 커버리지 임계치 검사
    steps_run.append(STEP_COVERAGE)
    coverage = check_coverage(smoke.coverage_edges, config.coverage_threshold)
    if not coverage.passed:
        return ValidationReport(artifact.group_id, False, list(steps_run), STEP_COVERAGE,
                                 smoke=smoke, coverage=coverage, reason=coverage.reason)

    # 소스는 3번(입력 소비)과 5번(정적 리뷰)이 함께 쓰므로 한 번만 읽는다.
    source_code = None
    if artifact.source_path is not None:
        source_code = artifact.source_path.read_text(encoding="utf-8", errors="replace")

    # 3. 입력 소비 검증
    steps_run.append(STEP_INPUT_CONSUMPTION)
    consumption = check_input_consumption(source_code, smoke.log)
    if not consumption.passed:
        return ValidationReport(artifact.group_id, False, list(steps_run),
                                 STEP_INPUT_CONSUMPTION, smoke=smoke, coverage=coverage,
                                 input_consumption=consumption, reason=consumption.reason)

    # 4. Mocking 호출 트레이싱
    steps_run.append(STEP_MOCK_TRACE)
    mock_trace = trace_mock_calls(smoke.log, artifact.expected_mock_symbols)
    if not mock_trace.passed:
        return ValidationReport(artifact.group_id, False, list(steps_run), STEP_MOCK_TRACE,
                                 smoke=smoke, coverage=coverage,
                                 input_consumption=consumption, mock_trace=mock_trace,
                                 reason=mock_trace.reason)

    # 5. (선택) 정적 리뷰
    static_review = None
    if config.enable_static_review and source_code is not None:
        steps_run.append(STEP_STATIC_REVIEW)
        reviewer = static_reviewer or MockStaticReviewer()
        static_review = reviewer.review(source_code, artifact.api_signatures)
        if not static_review.passed:
            return ValidationReport(artifact.group_id, False, list(steps_run), STEP_STATIC_REVIEW,
                                     smoke=smoke, coverage=coverage,
                                     input_consumption=consumption, mock_trace=mock_trace,
                                     static_review=static_review, reason=static_review.reason)

    return ValidationReport(artifact.group_id, True, list(steps_run), None,
                             smoke=smoke, coverage=coverage,
                             input_consumption=consumption, mock_trace=mock_trace,
                             static_review=static_review, reason="")
