"""재현 가능한 하네스 컴파일/실행 회귀 파이프라인.

매니페스트의 명령은 셸 문자열이 아닌 argv 배열로만 받는다. 각 케이스의 로그를
분리해 저장하며, ``--failed-only``로 이전 실패 케이스만 재실행할 수 있다.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

from logosfuzz.common.redact import redact_error
from logosfuzz.common.safe_path import resolve_within, safe_component
from logosfuzz.execute.sanitizer import SanitizerMonitor


@dataclass
class CommandResult:
    exit_code: int | None
    timed_out: bool
    stdout: str = ""
    stderr: str = ""
    duration_sec: float = 0.0
    error: str = ""


@dataclass
class RegressionResult:
    name: str
    target: str
    harness_name: str
    expected_status: str
    status: str
    matched_expected: bool
    exit_code: int | None
    signal: int | None
    timed_out: bool
    duration_sec: float
    compile_error_count: int
    sanitizer_error: bool
    sanitizer_findings: list[dict] = field(default_factory=list)
    stdout_log: str = ""
    stderr_log: str = ""
    failure_reason: str = ""


Executor = Callable[[list[str], Path, float, dict[str, str]], CommandResult]


def _execute(argv: list[str], cwd: Path, timeout: float,
             env: dict[str, str]) -> CommandResult:
    started = time.monotonic()
    # 일부 WSL 환경에서 ASAN이 크래시 심볼라이즈를 위해 띄우는 llvm-symbolizer가
    # 응답 없이 멈춰, 회귀 실행 전체가 타임아웃까지 걸리는 문제가 있었다.
    # 심볼라이즈 없이도 sanitizer/카테고리 판별에는 지장이 없으므로 기본으로 끈다
    # (케이스가 env에서 ASAN_OPTIONS를 직접 지정하면 그 값이 우선한다).
    merged_env = {**os.environ, **env}
    merged_env.setdefault("ASAN_OPTIONS", "symbolize=0")
    try:
        completed = subprocess.run(
            argv, cwd=cwd, env=merged_env, capture_output=True,
            text=True, timeout=timeout, errors="replace", stdin=subprocess.DEVNULL,
        )
        return CommandResult(completed.returncode, False, completed.stdout,
                             completed.stderr, time.monotonic() - started)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return CommandResult(None, True, stdout, stderr,
                             time.monotonic() - started, "command timed out")
    except OSError as exc:
        return CommandResult(None, False, duration_sec=time.monotonic() - started,
                             error=redact_error(exc))


def _signal_number(exit_code: int | None) -> int | None:
    if exit_code is None:
        return None
    if exit_code < 0:
        return -exit_code
    # Windows가 반환하는 대표적인 access violation 상태 코드.
    if exit_code in (0xC0000005, -1073741819):
        return getattr(signal, "SIGSEGV", 11)
    return None


def _classify(result: CommandResult, findings: list[dict]) -> str:
    if result.timed_out:
        return "timeout"
    if findings:
        return "sanitizer_error"
    if _signal_number(result.exit_code) is not None:
        return "crashed"
    if result.error or result.exit_code is None:
        return "execution_failed"
    if result.exit_code != 0:
        return "execution_failed"
    return "passed"


# ---------------------------------------------------------------------------
# GCC+ASan 재생 (크래시 회귀 검증)
# ---------------------------------------------------------------------------
# clang+libFuzzer 크래시를 GCC로 재생해 대상 코드 결함과 툴체인 의존 문제 구분
#
# 1. GCC 는 -fsanitize=fuzzer 미지원 → rules_fuzzing replay 엔진으로 빌드
# 2. GCC 툴체인: --config=bl-x86_64-linux
# 3. ASan: baselibs asan_ubsan_lsan config 그대로 사용
#
# abseil-cpp 의 -Werror=format-nonliteral 빌드 실패 회피용 외부 저장소 한정 -Wno-error
# (대상 코드 경고 정책은 유지)

GCC_REPLAY_PLATFORM_CONFIG = "bl-x86_64-linux"
GCC_REPLAY_SANITIZER_CONFIG = "asan_ubsan_lsan"
REPLAY_ENGINE_LABEL = "@rules_fuzzing//fuzzing/engines:replay"
GCC_REPLAY_EXTERNAL_NO_WERROR = ("external/abseil-cpp.*@-Wno-error",)


def gcc_replay_build_argv(target: str, *, bazel: str = "bazel") -> list[str]:
    """크래시 재생용 GCC+ASan 바이너리 빌드 커맨드 (실제 빌드 대상은 ``..._bin``)"""
    if not target.endswith("_bin"):
        target = f"{target}_bin"
    argv = [
        bazel, "build",
        f"--config={GCC_REPLAY_PLATFORM_CONFIG}",
        f"--config={GCC_REPLAY_SANITIZER_CONFIG}",
        # GCC libFuzzer 미지원으로 재생 엔진 교체 (미교체 시 링크 실패)
        f"--@rules_fuzzing//fuzzing:cc_engine={REPLAY_ENGINE_LABEL}",
    ]
    argv += [f"--per_file_copt={spec}" for spec in GCC_REPLAY_EXTERNAL_NO_WERROR]
    argv.append(target)
    return argv


def build_replay_manifest(
    crash_inputs: "list[Path] | list[str]",
    *,
    replay_binary: "Path | str",
    suite: str = "crash-replay",
    expected_status: str = "sanitizer_error",
    timeout_sec: float = 30.0,
    env: "dict[str, str] | None" = None,
) -> dict:
    """크래시 입력의 재생 회귀 매니페스트 변환

    ``expected_status`` 기본값 ``sanitizer_error``: 결함 재현 시 통과
    결함 수정 후에는 ``passed`` 로 변경해 회귀 케이스로 사용

    Returns:
        ``RegressionRunner.run_manifest`` 입력 매니페스트 dict
    """
    binary = str(replay_binary)
    cases = []
    for crash in crash_inputs:
        path = Path(crash)
        cases.append({
            "name": f"replay-{path.stem}",
            "target": binary,
            "harness_name": Path(binary).name,
            "run": [binary, str(path)],
            "expected_status": expected_status,
            "timeout_sec": timeout_sec,
            "env": dict(env or {}),
        })
    return {"suite": suite, "cases": cases}


def _validate_case(case: dict) -> None:
    required = ("name", "run", "expected_status")
    missing = [key for key in required if key not in case]
    if missing:
        raise ValueError(f"회귀 케이스 필드 누락: {', '.join(missing)}")
    for key in ("compile", "run"):
        if key in case and (not isinstance(case[key], list) or not case[key]):
            raise ValueError(f"{case['name']}.{key}는 비어 있지 않은 argv 배열이어야 합니다")


class RegressionRunner:
    def __init__(self, output_dir: Path, executor: Executor | None = None):
        self.output_dir = Path(output_dir)
        self.executor = executor or _execute

    def run_manifest(self, manifest_path: Path, *, failed_only: bool = False) -> dict:
        manifest_path = Path(manifest_path).resolve()
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        cases = manifest.get("cases", [])
        if not isinstance(cases, list):
            raise ValueError("manifest.cases는 배열이어야 합니다")
        previous_failed = self._previous_failed() if failed_only else None
        results = []
        for case in cases:
            _validate_case(case)
            if previous_failed is not None and case["name"] not in previous_failed:
                continue
            results.append(self._run_case(case, manifest_path.parent))
        summary = {
            "schema_version": "1.0",
            "suite": manifest.get("suite", manifest_path.stem),
            "total": len(results),
            "matched": sum(item.matched_expected for item in results),
            "failed": sum(not item.matched_expected for item in results),
            "groups": [asdict(item) for item in results],
        }
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "regression-summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return summary

    def _previous_failed(self) -> set[str]:
        path = self.output_dir / "regression-summary.json"
        try:
            previous = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return set()
        return {item["name"] for item in previous.get("groups", [])
                if not item.get("matched_expected", False)}

    def _run_case(self, case: dict, base_dir: Path) -> RegressionResult:
        cwd = (base_dir / case.get("cwd", ".")).resolve()
        timeout = float(case.get("timeout_sec", 5))
        env = {str(k): str(v) for k, v in case.get("env", {}).items()}
        # 케이스 이름은 manifest 입력이라 로그 디렉터리 이름으로 쓰기 전에 정화
        log_dir = resolve_within(self.output_dir, "logs", safe_component(case["name"]))
        log_dir.mkdir(parents=True, exist_ok=True)

        compile_result = None
        if case.get("compile"):
            compile_result = self.executor(case["compile"], cwd, timeout, env)
            self._write_logs(log_dir, "compile", compile_result)
            if compile_result.timed_out or compile_result.error or compile_result.exit_code != 0:
                reason = compile_result.error or (
                    "compile timed out" if compile_result.timed_out else "compiler returned non-zero"
                )
                return self._result(case, "compile_failed", compile_result, [], log_dir,
                                    compile_errors=1, reason=reason)

        run_result = self.executor(case["run"], cwd, timeout, env)
        self._write_logs(log_dir, "run", run_result)
        monitor = SanitizerMonitor()
        for line in (run_result.stdout + "\n" + run_result.stderr).splitlines():
            monitor.feed(line)
        findings = [finding.to_dict() for finding in monitor.finish()]
        status = _classify(run_result, findings)
        reason = run_result.error
        if not reason and status != "passed":
            reason = status.replace("_", " ")
        return self._result(case, status, run_result, findings, log_dir, reason=reason)

    def _result(self, case: dict, status: str, command: CommandResult,
                findings: list[dict], log_dir: Path, *, compile_errors: int = 0,
                reason: str = "") -> RegressionResult:
        log_prefix = "compile" if status == "compile_failed" else "run"
        return RegressionResult(
            name=case["name"], target=case.get("target", case["name"]),
            harness_name=case.get("harness_name", case["name"]),
            expected_status=case["expected_status"], status=status,
            matched_expected=status == case["expected_status"],
            exit_code=command.exit_code, signal=_signal_number(command.exit_code),
            timed_out=command.timed_out, duration_sec=round(command.duration_sec, 4),
            compile_error_count=compile_errors, sanitizer_error=bool(findings),
            sanitizer_findings=findings,
            stdout_log=str(log_dir / f"{log_prefix}.stdout.log"),
            stderr_log=str(log_dir / f"{log_prefix}.stderr.log"), failure_reason=reason,
        )

    @staticmethod
    def _write_logs(log_dir: Path, prefix: str, result: CommandResult) -> None:
        (log_dir / f"{prefix}.stdout.log").write_text(result.stdout, encoding="utf-8")
        stderr = result.stderr
        if result.error:
            stderr += ("\n" if stderr else "") + result.error
        (log_dir / f"{prefix}.stderr.log").write_text(stderr, encoding="utf-8")
