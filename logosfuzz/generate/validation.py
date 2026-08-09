"""GEN-03-04: Harness Validation — EXE-04(본 퍼징) 투입 전 게이트키퍼.

GEN-03-01~03을 통과한(=컴파일 성공한) 하네스가, ECU/네트워크 인터페이스
미가상화 등 "환경적 결함"으로 즉시 종료되는 오탐 하네스인지를 본 퍼징 캠페인
투입 전 짧게(수 초~수십 초) 걸러낸다. 검증은 아래 순서로 실행하고, 하나라도
실패하면 그 시점에서 중단하고 "검증 실패"로 분류한다:

  1. dry-run 스모크 테스트  — libFuzzer `-runs=N` 으로 즉시 crash/abort/
     segfault/timeout이 발생하는지 확인.
  2. 커버리지 임계치 검사   — 1번 실행 동안 수집된 edge coverage가 0이거나
     임계치 미만이면 "타겟 API 미도달"로 실패 처리.
  3. Mocking 호출 트레이싱  — 1번 실행 로그에서 GEN-03-03이 삽입한 CAN/UDS
     mock 함수 심볼이 실제로 호출되었는지 확인.
  4. (선택) 정적 리뷰       — `llm_review.py` 참고. `ValidationConfig.
     enable_static_review=True` 이고 `HarnessArtifact.source_path`가
     있을 때만 실행된다.

1~3번은 같은 dry-run 실행 로그 하나를 재사용한다(실행을 여러 번 하지 않음) —
"수 초~수십 초 내 완료"라는 성능 제약을 지키기 위함이다.
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
STEP_MOCK_TRACE = "mock_trace"
STEP_STATIC_REVIEW = "static_review"

_COV_RE = re.compile(r"\bcov:\s*(\d+)", re.IGNORECASE)


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


# ---- 3. Mocking 호출 트레이싱 ----------------------------------------------

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
    mock_trace: Optional[MockTraceResult] = None
    static_review: Optional[StaticReviewResult] = None
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "group_id": self.group_id,
            "passed": self.passed,
            "steps_run": self.steps_run,
            "failed_step": self.failed_step,
            "reason": self.reason,
            "smoke": self.smoke.to_dict() if self.smoke else None,
            "coverage": asdict(self.coverage) if self.coverage else None,
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

    # 3. Mocking 호출 트레이싱
    steps_run.append(STEP_MOCK_TRACE)
    mock_trace = trace_mock_calls(smoke.log, artifact.expected_mock_symbols)
    if not mock_trace.passed:
        return ValidationReport(artifact.group_id, False, list(steps_run), STEP_MOCK_TRACE,
                                 smoke=smoke, coverage=coverage, mock_trace=mock_trace,
                                 reason=mock_trace.reason)

    # 4. (선택) 정적 리뷰
    static_review = None
    if config.enable_static_review and artifact.source_path is not None:
        steps_run.append(STEP_STATIC_REVIEW)
        reviewer = static_reviewer or MockStaticReviewer()
        source_code = artifact.source_path.read_text(encoding="utf-8", errors="replace")
        static_review = reviewer.review(source_code, artifact.api_signatures)
        if not static_review.passed:
            return ValidationReport(artifact.group_id, False, list(steps_run), STEP_STATIC_REVIEW,
                                     smoke=smoke, coverage=coverage, mock_trace=mock_trace,
                                     static_review=static_review, reason=static_review.reason)

    return ValidationReport(artifact.group_id, True, list(steps_run), None,
                             smoke=smoke, coverage=coverage, mock_trace=mock_trace,
                             static_review=static_review, reason="")
