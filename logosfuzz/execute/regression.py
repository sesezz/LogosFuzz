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
                             error=str(exc))


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
#
# 퍼징은 clang + libFuzzer + ASan(--config=fuzz)으로 돈다. 거기서 나온 크래시를
# **다른 컴파일러로 다시 재생**해 보면, 그 크래시가 대상 코드의 진짜 결함인지
# 아니면 clang/libFuzzer 쪽 특성이나 하네스 문제인지가 갈린다. 재현되면 결함의
# 근거가 세지고, 재현되지 않으면 툴체인 의존성을 의심할 단서가 된다.
#
# 재생 경로를 어떻게 만드나 - 세 가지 사실을 조합한다.
#
# 1. GCC 에는 -fsanitize=fuzzer 가 없다. 그래서 퍼저 바이너리 자체는 GCC 로
#    못 만든다. 대신 rules_fuzzing 의 **기본 엔진이 replay** 다(GEN 파트 실측:
#    cc_engine 을 libfuzzer 로 바꾸지 않으면 "Launching ..._bin as a Replay
#    fuzz test" 가 뜨고 파일 재생만 한다). 재생 엔진으로 빌드하면 입력 파일을
#    인자로 받아 한 번씩 먹이는 바이너리가 나온다 - 퍼징 기능은 필요 없다.
# 2. GCC 툴체인은 --config=bl-x86_64-linux 가 공급한다(회귀 게이트용 config).
# 3. ASan 자체는 GCC 에도 있다. 다만 baselibs 의 asan_ubsan_lsan 은 test: 로만
#    정의돼 있어 bazel build 에서는 "config value is not defined" 가 된다.
#    그래서 그 config 가 펼치는 것과 같은 --features 를 직접 넘긴다.
#
# 주의 - 이 조합으로 실제 빌드해 본 적이 없다. 위 세 사실은 각각 확인된
# 것이지만 셋을 합친 커맨드는 미검증이다. baselibs 가 있는 환경에서
# gcc_replay_build_argv() 가 만드는 커맨드를 먼저 돌려봐야 한다.

GCC_REPLAY_PLATFORM_CONFIG = "bl-x86_64-linux"
GCC_REPLAY_SANITIZER_FEATURES = ("asan", "ubsan")
REPLAY_ENGINE_LABEL = "@rules_fuzzing//fuzzing/engines:replay"


def gcc_replay_build_argv(target: str, *, bazel: str = "bazel") -> list[str]:
    """크래시 재생용 GCC+ASan 바이너리를 빌드하는 커맨드.

    ``target`` 은 cc_fuzz_test 라벨(``//score/json/fuzz:json_parser_fuzz_test``)
    이며, 실제로 빌드되는 것은 그 바이너리 타깃(``..._bin``)이다.
    """
    if not target.endswith("_bin"):
        target = f"{target}_bin"
    argv = [bazel, "build", f"--config={GCC_REPLAY_PLATFORM_CONFIG}"]
    argv += [f"--features={feature}" for feature in GCC_REPLAY_SANITIZER_FEATURES]
    # 퍼징 엔진을 재생 엔진으로 바꾼다. GCC 에는 libFuzzer 가 없으므로 이
    # 교체가 없으면 링크에서 죽는다.
    argv.append(f"--@rules_fuzzing//fuzzing:cc_engine={REPLAY_ENGINE_LABEL}")
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
    """크래시 입력들을 재생 회귀 매니페스트로 변환한다.

    퍼징이 찾은 크래시 산출물(``out/crashes/<group>/...``)을 그대로 받아,
    :class:`RegressionRunner` 가 먹을 수 있는 매니페스트를 만든다. 각 케이스는
    재생 바이너리에 크래시 입력 하나를 물려 실행한다.

    ``expected_status`` 기본값이 ``sanitizer_error`` 인 이유 - 재생의 목적은
    "크래시가 다시 나는 것"을 확인하는 것이므로, **결함이 재현되는 쪽이 통과**다.
    결함이 수정된 뒤에는 이 값을 ``passed`` 로 바꿔 그 수정이 유지되는지를
    지키는 회귀 케이스로 쓴다.

    Returns:
        ``RegressionRunner.run_manifest`` 가 읽는 매니페스트 dict.
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
        if not path.exists():
            return set()
        previous = json.loads(path.read_text(encoding="utf-8"))
        return {item["name"] for item in previous.get("groups", [])
                if not item.get("matched_expected", False)}

    def _run_case(self, case: dict, base_dir: Path) -> RegressionResult:
        cwd = (base_dir / case.get("cwd", ".")).resolve()
        timeout = float(case.get("timeout_sec", 5))
        env = {str(k): str(v) for k, v in case.get("env", {}).items()}
        log_dir = self.output_dir / "logs" / case["name"]
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
