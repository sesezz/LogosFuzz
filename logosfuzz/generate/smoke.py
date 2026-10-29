"""하네스 시드 스모크 테스트와 런타임 자가치유 (GENERIC-B)
=====================================================

컴파일에 성공한 하네스를 퍼징 전에 **유효한 시드 파일 몇 개로 한 번씩만** 실행해 본다.
올바른 하네스는 유효한 입력 몇 개로 죽지 않으므로, 여기서 죽으면 하네스 결함일 가능성이 크다.

실측(libsndfile 6, 8, 12차): LLM 이 `sf_readf_float` 버퍼를 `frames` 개만 할당해 스테레오 시드에서 곧바로 힙 오버플로가 났고,
같은 하네스 결함이 퍼징 시간을 모두 소진시켰다. 컴파일 오류 자가치유(`selfheal`)는 이런 실행 시 결함을 보지 못한다.

흐름
----
1. 시드를 임시 폴더에 **복사**해서 ``-runs=0`` 으로 실행(libFuzzer 가 입력을 쓰는 폴더에 원본 시드가 섞이지 않게 함)
2. 크래시가 나면 ``analyze.contracts`` 판별 규칙으로 **하네스 결함 증거**가 있는지 본다
   (NULL 미검사, NUL 없는 문자열 전달, 하네스가 할당한 버퍼 초과 쓰기)
3. 증거가 있을 때만 크래시 로그와 소스를 LLM 에 주고 하네스를 고쳐 다시 빌드, 최대 ``rounds`` 회 반복
4. 증거가 없는 크래시(라이브러리 결함일 수 있음)는 건드리지 않고 퍼징으로 넘긴다 - 결함을 하네스 수정으로 덮지 않기 위함
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, List, Optional, Sequence

SMOKE_TIMEOUT_S = 60
OUTPUT_EXCERPT_LINES = 40
BUILD_ERROR_LINES = 25

STATUS_CLEAN = "clean"                    # 시드로 크래시 없음
STATUS_REPAIRED = "repaired"              # 하네스 결함을 고쳐 크래시가 사라짐
STATUS_UNRESOLVED = "unresolved"          # 라운드를 다 썼는데도 하네스 결함 크래시가 남음
STATUS_LIBRARY = "library-crash"          # 크래시가 났지만 하네스 결함 증거가 없음(수정하지 않음)
STATUS_REBUILD_FAILED = "rebuild-failed"  # 고친 소스가 빌드되지 않음(원래 하네스 유지)
STATUS_SKIPPED = "skipped"                # 시드 없음 등


@dataclass
class SmokeRun:
    """시드 1회 실행 결과."""

    ok: bool
    output: str = ""
    returncode: int = 0
    timed_out: bool = False
    records: List[Any] = field(default_factory=list)   # CrashRecord 목록


@dataclass
class SmokeOutcome:
    status: str
    source: str
    binary: Optional[Path]
    rounds: int = 0
    detail: str = ""

    @property
    def changed(self) -> bool:
        return self.status == STATUS_REPAIRED


def run_seed_smoke(binary: Path, seeds: Sequence[Path], *, timeout_s: int = SMOKE_TIMEOUT_S) -> SmokeRun:
    """하네스를 시드 파일들로 한 번씩 실행한다. 시드는 임시 폴더에 복사해서 쓴다."""
    from logosfuzz.analyze.models import CrashRecord
    from logosfuzz.execute.sanitizer import SanitizerMonitor
    from logosfuzz.execute.seeds import copy_seeds

    # 작업 디렉터리를 임시 폴더로 바꿔 실행하므로 상대경로 하네스는 찾지 못한다(실측: 13차에서 SMOKE 가 skipped).
    binary = Path(binary).resolve()
    seeds = [Path(seed).resolve() for seed in seeds]
    work = Path(tempfile.mkdtemp(prefix="logosfuzz-smoke-"))
    try:
        corpus = work / "corpus"
        copy_seeds(list(seeds), corpus)
        env = dict(os.environ)
        env.setdefault("ASAN_OPTIONS", "detect_leaks=0")
        env.setdefault("UBSAN_OPTIONS", "print_stacktrace=1:halt_on_error=0")
        try:
            proc = subprocess.run([str(binary), "-runs=0", str(corpus)], cwd=work, env=env,
                                  capture_output=True, text=True, errors="replace", timeout=timeout_s)
            output = (proc.stdout or "") + (proc.stderr or "")
            returncode, timed_out = proc.returncode, False
        except subprocess.TimeoutExpired as exc:
            text = lambda v: v if isinstance(v, str) else (v or b"").decode("utf-8", "replace")
            output, returncode, timed_out = text(exc.stdout) + text(exc.stderr), 124, True
        except OSError as exc:
            return SmokeRun(ok=False, output=f"실행할 수 없음: {exc}", returncode=127)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    monitor = SanitizerMonitor()
    for line in output.splitlines():
        monitor.feed(line)
    records = [CrashRecord.from_finding(f.to_dict()) for f in monitor.finish()]
    crashed = returncode != 0 or "ERROR: AddressSanitizer" in output
    return SmokeRun(ok=not crashed, output=output, returncode=returncode, timed_out=timed_out, records=records)


def harness_defect(records: Sequence[Any], profile, kb=None):
    """크래시 기록 중 하네스 결함 증거(``violation``)가 있는 첫 증거를 돌려준다. 없으면 None."""
    from logosfuzz.analyze.contracts import contract_for_profile

    contract = contract_for_profile(profile)
    for record in records:
        evidence = contract.analyze(record, kb=kb, profile=profile)
        if getattr(evidence, "violation", ""):
            return evidence
    return None


_REASONS = {
    "harness-buffer-suspect": (
        "The harness allocated an output buffer and the library API {api} wrote past its end. "
        "Size every output buffer from the values the library reports (for example the info struct filled by "
        "the open call: channels, frames) as the API documentation requires; a call that reads N frames "
        "writes N x channels items."),
    "harness-string": (
        "The harness passed fuzzer input directly as a `char *` string to the API {api}. The input has no NUL "
        "terminator. Build a NUL-terminated copy, or write the input to a temporary file and pass its path."),
    "harness-uninitialized-object": (
        "The harness created the object it passes to {api} with plain malloc/calloc instead of the library's "
        "own constructor, so its fields are uninitialised garbage. Obtain the object from the creator function "
        "declared in the headers (a *_create / *_init / *_open style function; it may not be in the API list "
        "above), check the result for NULL, and release it with the matching destroy function afterwards. Take any "
        "size/capacity argument of the creator from separate input bytes (for example data[0] % MAX + 1), never "
        "from the data length, and pass the remaining bytes as the data to process."),
    "harness": (
        "The harness did not check the result of an earlier call (a NULL or error return) before passing it "
        "to the API {api}. Check every open/create result and return 0 when it failed."),
}


def build_runtime_repair_prompt(source: str, evidence, output: str, build_error: str = "") -> str:
    reason = _REASONS.get(evidence.violation, "The harness misuses the API {api}.").format(api=evidence.api)
    excerpt = "\n".join(output.splitlines()[:OUTPUT_EXCERPT_LINES])
    compile_note = ""
    if build_error.strip():
        errors = "\n".join(build_error.strip().splitlines()[-BUILD_ERROR_LINES:])
        compile_note = (
            "YOUR PREVIOUS FIX DID NOT COMPILE. Compiler/linker output:\n"
            f"```\n{errors}\n```\n"
            "Correct the source below so it compiles, and keep the runtime fix.\n\n")
    return compile_note + (
        "The following libFuzzer harness crashed while running a VALID seed input, so the defect is in the "
        "harness, not in the library.\n\n"
        f"WHY: {reason}\n\n"
        f"SANITIZER OUTPUT (first {OUTPUT_EXCERPT_LINES} lines):\n```\n{excerpt}\n```\n\n"
        f"CURRENT HARNESS:\n```c\n{source}\n```\n\n"
        "Fix ONLY the harness defect. Keep LLVMFuzzerTestOneInput and keep calling the same library APIs. "
        "Do not remove API calls to hide the crash. Release every handle you open. Comments in English only. "
        "Return ONLY the full corrected source file inside one ```c code block."
    )


def smoke_repair(
    binary: Path,
    source: str,
    *,
    seeds: Sequence[Path],
    profile,
    kb=None,
    complete: Callable[[str, str], str],
    rebuild: Callable[[str], Optional[Path]],
    rounds: int = 3,
    sanitize: Callable[[str], str] = lambda text: text,
    run: Callable[..., SmokeRun] = run_seed_smoke,
    log: Callable[[str], None] = lambda message: None,
    build_error: Callable[[], str] = lambda: "",
) -> SmokeOutcome:
    """시드 스모크 테스트를 돌리고, 하네스 결함 증거가 있으면 LLM 으로 고쳐 다시 빌드한다.

    Args:
        complete: ``(prompt, system) -> LLM 응답``
        rebuild: 새 소스를 빌드하고 바이너리 경로를 돌려준다(실패하면 None)
        rounds: LLM 호출 상한. 수정본이 컴파일되지 않아 다시 부르는 것도 1회로 센다.
        build_error: 직전 ``rebuild`` 가 실패했을 때의 컴파일러 출력. 있으면 다음 LLM 호출에 함께 준다
            (실측: embedded-sample 에서 첫 수정본이 컴파일되지 않아 원래 하네스가 그대로 퍼징에 쓰였다)
    """
    from logosfuzz.generate.llm import domain_subject, extract_code

    if not seeds:
        return SmokeOutcome(STATUS_SKIPPED, source, binary, 0, "프로필에 시드가 없다")

    system = ("You are a C/C++ fuzzing-harness repair assistant for the LogosFuzz project, fixing runtime "
              f"defects in libFuzzer harnesses for {domain_subject(getattr(profile, 'domain', 'generic'))}.")
    used = 0
    while True:
        result = run(binary, seeds)
        if result.ok:
            return SmokeOutcome(STATUS_CLEAN if used == 0 else STATUS_REPAIRED, source, binary, used)
        if result.returncode == 127 and not result.records:
            return SmokeOutcome(STATUS_SKIPPED, source, binary, used, "하네스를 실행할 수 없어 건너뜀")
        evidence = harness_defect(result.records, profile, kb)
        if evidence is None:
            return SmokeOutcome(STATUS_LIBRARY, source, binary, used,
                                "시드에서 크래시가 났지만 하네스 결함 증거가 없어 수정하지 않는다")
        if used >= rounds:
            return SmokeOutcome(STATUS_UNRESOLVED, source, binary, used, evidence.violation)

        # 수정본이 컴파일되면 다시 시드로 돌려 보고, 컴파일되지 않으면 오류를 돌려주며 남은 횟수만큼 다시 고친다.
        attempt, error, built = source, "", None
        while used < rounds and built is None:
            used += 1
            log(f"    시드 스모크: 하네스 결함({evidence.violation}) - LLM 수정 {used}/{rounds}"
                f"{' (컴파일 오류 재전달)' if error else ''}")
            reply = complete(build_runtime_repair_prompt(attempt, evidence, result.output, error), system)
            fixed = sanitize(extract_code(reply))
            if not fixed.strip():
                return SmokeOutcome(STATUS_REBUILD_FAILED, source, binary, used, "LLM 이 빈 소스를 돌려줌")
            built = rebuild(fixed)
            attempt = fixed
            error = build_error() if built is None else ""
        if built is None:
            return SmokeOutcome(STATUS_REBUILD_FAILED, source, binary, used, "수정한 소스가 빌드되지 않음")
        source, binary = attempt, built
