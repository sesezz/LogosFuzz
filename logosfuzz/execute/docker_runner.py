"""EXE-04-01: Docker 기반 격리 퍼징 실행

크래시로부터 호스트 보호를 위한 로직 그룹별 컨테이너 격리 실행

격리 정책:
  - --network none        : 외부 네트워크 차단
  - --cap-drop ALL        : 리눅스 capability 전체 제거
  - --security-opt no-new-privileges
  - --memory / --cpus / --pids-limit : 자원 상한
  - 하네스는 읽기 전용(:ro), 출력(/out)만 쓰기 가능으로 마운트

실제 프로세스 실행은 `executor` 콜러블로 주입.
기본 executor는 stdout/stderr를 각각 스레드로 읽어 큐에 모으고, 메인
스레드는 `queue.get(timeout=...)`으로 소비한다 - 자식이 침묵해도(예: ASAN이
크래시 시 심볼라이저를 내부에서 fork하며 응답 없이 대기) 데드라인이 정확히
발동한다(실측으로 확인된 회귀: 기존의 `for line in proc.stdout` 블로킹
방식은 출력이 없으면 하드 타임아웃까지 90초 넘게 멈췄다).
"""

from __future__ import annotations

import collections
import math
import os
import queue
import shlex
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from logosfuzz.common.logging import get_logger
from logosfuzz.common.security import minimal_env, safe_component, safe_join
from logosfuzz.config import FuzzConfig, LogicGroup
from logosfuzz.execute.errors import (
    DockerUnavailableError,
    HarnessNotFoundError,
    ImageBuildError,
)
from logosfuzz.execute.stats import LiveStats, StatsMonitor
from logosfuzz.execute.sanitizer import SanitizerFinding, SanitizerMonitor
from logosfuzz.execute.timeout_manager import DEFAULT_PER_INPUT_MS

# 컨테이너 내부 딕셔너리 마운트 위치
_CONTAINER_DICT = "/dict/fuzz.dict"


# executor(argv, timeout, on_line) -> ProcResult
OnLine = Callable[[str], None]
Executor = Callable[[list, float, OnLine], "ProcResult"]

# 큐 소비 폴링 주기(초). 이 값 이상 자식이 침묵해도 이 주기마다 데드라인을
# 재확인하므로, 무한정 블로킹되지 않는다.
_POLL_INTERVAL_SEC = 0.5

# 출력 상한(자원 관리, CWE-400) — 하네스는 비신뢰 코드라 출력을 무한히 쏟을 수 있음
#   - 큐: 가득 차면 읽기 스레드가 대기하고 그동안 자식은 파이프에서 막힘(배압)
#   - 줄: 개행 없는 거대한 한 줄이 메모리를 다 먹지 않도록 절단
#   - 보존: 스트림마다 앞쪽 _KEEP_HEAD_LINES 줄과 마지막 _KEEP_TAIL_LINES 줄만 유지
#     크래시 원인(ASAN 보고)은 끝에 오므로 꼬리 보존 필수. 모니터(on_line)는
#     버린 줄도 모두 수신 — 통계·새니타이저 판정은 상한과 무관
_QUEUE_MAXSIZE = 10000
_MAX_LINE_CHARS = 64 * 1024
_KEEP_HEAD_LINES = 2000
_KEEP_TAIL_LINES = 20000

# Docker CLI 가 데몬에 붙는 데 필요한 변수. 컨테이너 안으로는 전달되지 않는다.
_DOCKER_CLI_ENV = ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG",
                   "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY")

_log = get_logger("EXE-04-01")


class _BoundedLines:
    """앞 N줄 + 뒤 M줄만 보존하는 줄 버퍼."""

    def __init__(self, head: int = _KEEP_HEAD_LINES, tail: int = _KEEP_TAIL_LINES) -> None:
        self.head: list[str] = []
        self.tail: "collections.deque[str]" = collections.deque(maxlen=tail)
        self._head_max = head
        self.dropped = 0

    def append(self, line: str) -> None:
        if len(self.head) < self._head_max:
            self.head.append(line)
            return
        if len(self.tail) == self.tail.maxlen:
            self.dropped += 1
        self.tail.append(line)

    def text(self) -> str:
        lines = list(self.head)
        if self.dropped:
            lines.append(f"... (출력 상한 초과로 {self.dropped}줄 생략) ...")
        lines.extend(self.tail)
        return "\n".join(lines)


def _kill_tree(proc: "subprocess.Popen", sig: int) -> None:
    """자식과 그 자손(같은 프로세스 그룹)에 신호를 보낸다.

    부모만 죽이면 하네스가 fork 한 자손이나 docker CLI 아래 프로세스가 남을 수 있다.
    """
    killpg = getattr(os, "killpg", None)
    if killpg is not None:
        try:
            killpg(proc.pid, sig)
            return
        except (ProcessLookupError, PermissionError, OSError):
            pass
    try:
        proc.send_signal(sig)
    except (ProcessLookupError, OSError):
        pass


@dataclass
class ProcResult:
    exit_code: int
    timed_out: bool
    stdout: str = ""  # 표준 출력 전문(정상/컴파일 실패/타임아웃/크래시 모두 보존)
    stderr: str = ""  # 표준 오류 전문


@dataclass
class GroupResult:
    """단일 로직 그룹 퍼징 결과"""

    group: str
    exit_code: int
    timed_out: bool
    stats: LiveStats
    crashes: list  # 수집된 크래시 경로 (fuzz_session에서 기록)
    duration_sec: float
    sanitizer_findings: list[SanitizerFinding] = field(default_factory=list)
    coverage: object = None  # EXE-04-04 CoverageSummary (없으면 None)
    stdout_log: Optional[str] = None  # 표준 출력 로그 파일 경로(저장 실패 시 None)
    stderr_log: Optional[str] = None  # 표준 오류 로그 파일 경로
    timeout_sec: Optional[int] = None  # 그룹별 퍼징 시간 (run 의 SCH 배분)
    corpus_minimized: Optional[dict] = None  # -merge=1 결과 {"before": n, "after": m}
    # 증적(로그) 저장 실패 사유. 비어 있지 않으면 이 결과는 "증적 불완전"이다 -
    # 저장 실패를 정상 완료처럼 보고하지 않기 위해 남긴다.
    log_error: str = ""

    @property
    def evidence_complete(self) -> bool:
        return not self.log_error

    @property
    def failed_to_start(self) -> bool:
        """하네스 시작 실패 여부 (비정상 종료 + 실행 횟수 0)

        공유 라이브러리 누락 등으로 미실행된 경우를 크래시와 구분하기 위함
        크래시 산출물이나 새니타이저 결함이 있으면 시작 실패로 미판정
        """
        return (
            self.exit_code not in (0, None)
            and self.stats.execs == 0
            and not self.crashes
            and not self.sanitizer_findings
        )

    @property
    def crashed(self) -> bool:
        # libFuzzer는 크래시 시 non-zero 종료 및 크래시 산출물 생성
        if self.crashes:
            return True
        return (
            self.exit_code not in (0, None)
            and not self.timed_out
            and not self.failed_to_start
        )

    @property
    def status(self) -> str:
        """공유 결과 JSON 용 단일 실행 상태 (timeout·crashed·failed·passed)"""
        if self.timed_out:
            return "timeout"
        if self.crashed:
            return "crashed"
        if self.failed_to_start or self.exit_code not in (0, None):
            return "failed"
        return "passed"


def _default_executor(argv: list, timeout: float, on_line: OnLine) -> ProcResult:
    """subprocess 기반 기본 실행기.

    stdout/stderr를 각각 별도 스레드로 읽어 (스트림, 줄) 튜플을 큐에 넣고,
    메인 스레드는 `queue.get(timeout=_POLL_INTERVAL_SEC)`으로 소비한다.
    자식이 완전히 침묵해도(줄이 전혀 안 와도) 폴링 주기마다 데드라인을
    재확인하므로 하드 타임아웃이 정확한 시각에 발동한다 - 이전의
    `for line in proc.stdout:` 블로킹 순회는 다음 줄이 올 때까지 데드라인
    검사 자체가 실행되지 않아, 자식이 조용해지면 무한정 멈췄다(실측 확인:
    ASAN이 크래시 시 심볼라이저를 내부에서 fork하며 응답 없이 대기하는
    경우 90초 넘게 하드 타임아웃까지 멈춘 뒤에야 겨우 빠져나왔다).
    """
    # 부모 환경(API 키·클라우드 자격증명)은 하네스나 docker CLI 에 전달 금지
    # 새 세션으로 띄워 타임아웃 때 자손까지 프로세스 그룹 단위로 정리
    popen_kwargs = {"start_new_session": True} if os.name == "posix" else {}
    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        text=True,
        errors="replace",
        bufsize=1,
        env=minimal_env(allow=_DOCKER_CLI_ENV),
        **popen_kwargs,
    )

    lines: "queue.Queue[tuple[str, Optional[str]]]" = queue.Queue(maxsize=_QUEUE_MAXSIZE)

    def _pump(stream, tag: str) -> None:
        try:
            while True:
                line = stream.readline(_MAX_LINE_CHARS)
                if not line:
                    break
                lines.put((tag, line.rstrip("\n")))
        finally:
            lines.put((tag, None))  # EOF 신호

    if proc.stdout is None or proc.stderr is None:
        raise RuntimeError("자식 프로세스 stdout/stderr 파이프 없음")
    readers = [
        threading.Thread(target=_pump, args=(proc.stdout, "stdout"), daemon=True),
        threading.Thread(target=_pump, args=(proc.stderr, "stderr"), daemon=True),
    ]
    for reader in readers:
        reader.start()

    stdout_lines = _BoundedLines()
    stderr_lines = _BoundedLines()
    deadline = time.monotonic() + timeout
    timed_out = False
    open_streams = len(readers)

    def _drain_once(block: bool) -> bool:
        """큐에서 항목 하나를 꺼내 처리한다. 처리했으면 True."""
        nonlocal open_streams
        try:
            tag, line = lines.get(timeout=_POLL_INTERVAL_SEC) if block else lines.get_nowait()
        except queue.Empty:
            return False
        if line is None:
            open_streams -= 1
            return True
        (stdout_lines if tag == "stdout" else stderr_lines).append(line)
        on_line(line)
        return True

    while open_streams > 0 and time.monotonic() < deadline:
        _drain_once(block=True)
    if open_streams > 0:
        timed_out = True

    kill_sig = getattr(signal, "SIGKILL", signal.SIGTERM)
    if timed_out:
        _kill_tree(proc, signal.SIGTERM)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _kill_tree(proc, kill_sig)
            proc.wait()
    else:
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_tree(proc, kill_sig)
            proc.wait()

    # 큐가 가득 차 읽기 스레드가 막혀 있을 수 있으니, 스레드를 기다리기 전에 비운다.
    while _drain_once(block=False):
        pass

    # 프로세스가 끝난 뒤에도 큐에 남아있던 마지막 줄들을 마저 비운다(막
    # 종료된 시점까지 나온 출력을 최대한 보존 - 특히 크래시 직전 ASAN 로그).
    for reader in readers:
        reader.join(timeout=2)
    while _drain_once(block=False):
        pass

    return ProcResult(
        exit_code=proc.returncode if proc.returncode is not None else -1,
        timed_out=timed_out,
        stdout=stdout_lines.text(),
        stderr=stderr_lines.text(),
    )


class DockerIsolationRunner:
    def __init__(self, config: FuzzConfig, executor: Optional[Executor] = None,
                 docker_bin: str = "docker"):
        self.config = config
        self.executor = executor or _default_executor
        self.docker_bin = docker_bin

    # ---- 이미지 준비 ---------------------------------------------------
    def check_docker(self) -> None:
        if shutil.which(self.docker_bin) is None:
            raise DockerUnavailableError(
                f"'{self.docker_bin}' 실행 파일을 찾을 수 없습니다. Docker를 설치하세요."
            )

    def image_exists(self) -> bool:
        try:
            out = subprocess.run(
                [self.docker_bin, "images", "-q", self.config.image],
                capture_output=True, text=True, timeout=30,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return bool(out.stdout.strip())

    def ensure_image(self, build_context: Path = Path(".")) -> None:
        self.check_docker()
        if self.image_exists():
            return
        dockerfile = self.config.dockerfile
        if not Path(dockerfile).exists():
            raise ImageBuildError(f"Dockerfile 없음: {dockerfile}")
        rc = subprocess.run(
            [self.docker_bin, "build", "-t", self.config.image,
             "-f", str(dockerfile), str(build_context)],
        ).returncode
        if rc != 0:
            raise ImageBuildError(f"이미지 빌드 실패: {self.config.image}")

    # ---- 하네스 바이너리 위치 해석 -------------------------------------
    # 빌드 어댑터가 돌려준 실제 경로 그대로 사용 (경로 추측 없음)
    # 빌드 시스템과 무관하게 실행 파일 하나로 취급
    def harness_binary_path(self, group: LogicGroup) -> Path:
        """하네스 바이너리의 호스트 경로 (이름만 있으면 ``harness_dir`` 기준)"""
        p = Path(group.harness_path)
        if p.parent != Path("."):
            return p.resolve()
        return (self.config.harness_dir / p.name).resolve()

    def harness_mount_dir(self, group: LogicGroup) -> Path:
        """``/harness`` 읽기 전용 마운트 대상 호스트 디렉토리

        바이너리가 harness_dir 밖에 있으면 바이너리 소재 디렉토리 마운트
        """
        return self.harness_binary_path(group).parent

    # ---- libFuzzer 옵션 ------------------------------------------------
    def per_input_timeout_sec(self) -> int:
        """입력 1건 실행 제한(초, 올림, 최소 1초). 미지정 시 EXE-04-03 기본값"""
        ms = self.config.per_input_timeout_ms or DEFAULT_PER_INPUT_MS
        return max(1, math.ceil(ms / 1000))

    def resolve_dict(self, group: LogicGroup) -> Optional[Path]:
        """그룹 딕셔너리 경로 (명시 경로 → dict_dir/<name>.dict → <바이너리>.dict)"""
        candidates = []
        if group.dict_path is not None:
            candidates.append(Path(group.dict_path))
        if self.config.dict_dir is not None:
            candidates.append(Path(self.config.dict_dir) / f"{group.name}.dict")
        binary = self.harness_binary_path(group)
        candidates.append(binary.with_name(binary.name + ".dict"))
        for path in candidates:
            if path.is_file():
                return path.resolve()
        return None

    def libfuzzer_option_args(self, group: LogicGroup, *, in_docker: bool) -> list:
        """-timeout / -rss_limit_mb / -malloc_limit_mb / -max_len / -dict 인자 목록"""
        c = self.config
        args = [f"-timeout={self.per_input_timeout_sec()}"]
        if c.rss_limit_mb > 0:
            args.append(f"-rss_limit_mb={c.rss_limit_mb}")
        if c.malloc_limit_mb > 0:
            args.append(f"-malloc_limit_mb={c.malloc_limit_mb}")
        if c.max_len > 0:
            args.append(f"-max_len={c.max_len}")
        dict_path = self.resolve_dict(group)
        if dict_path is not None:
            args.append(f"-dict={_CONTAINER_DICT if in_docker else dict_path}")
        return args

    def _run_limit_args(self, timeout_sec: int, smoke_runs: Optional[int]) -> list:
        """본 퍼징은 -max_total_time(+ fork 모드 인자), 스모크 테스트는 -runs 로 실행 횟수 제한

        스모크 테스트는 단일 프로세스 고정 (-runs 와 -fork 동시 사용 시 -runs 미적용)
        """
        if smoke_runs is not None:
            return [f"-runs={smoke_runs}", f"-max_total_time={timeout_sec}"]
        args = [f"-max_total_time={timeout_sec}"]
        if self.config.fork_jobs > 0:
            args.append(f"-fork={self.config.fork_jobs}")
            if self.config.ignore_crashes:
                args.append("-ignore_crashes=1")
        return args

    def smoke_dir(self, group: LogicGroup) -> Path:
        """스모크 테스트 크래시 산출물 위치 (본 퍼징 crashes/ 와 분리)"""
        return self.config.output_dir / "smoke" / group.name

    # ---- 실행 커맨드 구성 ---------------------------------------------
    def _in_container_cmd(self, group: LogicGroup, smoke_runs: Optional[int] = None) -> str:
        """컨테이너 내부 libFuzzer 실행 셸 명령 문자열"""
        harness = f"/harness/{group.harness_path.name}"
        prefix = ("/out/crashes/" if smoke_runs is None
                  else f"/out/smoke/{group.name}/")
        parts = [
            shlex.quote(harness),
            *self._run_limit_args(self.config.timeout_sec, smoke_runs),
            f"-artifact_prefix={prefix}",
            "-print_final_stats=1",
            *self.libfuzzer_option_args(group, in_docker=True),
        ]
        if group.corpus_dir:
            parts.append("/corpus")
        return "chmod +x %s 2>/dev/null; %s" % (shlex.quote(harness), " ".join(parts))

    def _host_user(self) -> str | None:
        """호스트 uid:gid. Windows 등 uid 개념이 없는 플랫폼이면 None."""
        getuid = getattr(os, "getuid", None)
        getgid = getattr(os, "getgid", None)
        if getuid is None or getgid is None:
            return None
        return f"{getuid()}:{getgid()}"

    def build_run_argv(self, group: LogicGroup, smoke_runs: Optional[int] = None,
                       inner_cmd: Optional[str] = None, suffix: Optional[str] = None) -> list:
        """docker run 인자 목록. inner_cmd 지정 시 컨테이너 내부 명령 대체(크래시 재실행·코퍼스 최소화)"""
        c = self.config
        if suffix is None:
            suffix = "" if smoke_runs is None else "-smoke"
        argv = [
            self.docker_bin, "run", "--rm",
            "--name", f"logosfuzz-{group.name}{suffix}",
            "--network", c.network,
            "--memory", c.memory_limit,
            "--cpus", c.effective_cpus,
            "--pids-limit", str(c.pids_limit),
        ]
        if c.drop_all_caps:
            argv += ["--cap-drop", "ALL"]
        if c.no_new_privileges:
            argv += ["--security-opt", "no-new-privileges"]
        if c.run_as_host_user:
            user = self._host_user()
            if user:
                # 이미지 기본 사용자(uid 1000)로 두면 호스트 uid 가 다를 때
                # /out 바인드 마운트에 쓰기 권한이 없어 크래시 artifact 가
                # 조용히 사라진다(실측 확인).
                argv += ["--user", user]
        argv += [
            "-v", f"{self.harness_mount_dir(group)}:/harness:ro",
            "-v", f"{c.output_dir.resolve()}:/out",
        ]
        if group.corpus_dir:
            # 쓰기 가능 마운트 (최종 코퍼스를 커버리지 바이너리로 재생하기 위함)
            argv += ["-v", f"{group.corpus_dir.resolve()}:/corpus"]
        dict_path = self.resolve_dict(group)
        if dict_path is not None:
            argv += ["-v", f"{dict_path}:{_CONTAINER_DICT}:ro"]
        argv += [
            "-e", f"ASAN_OPTIONS={c.asan_options}",
            "-e", f"TSAN_OPTIONS={c.tsan_options}",
        ]
        # EXE-04-04: 커버리지 계측 시 profraw 출력 경로 환경변수 주입
        for k, v in self._coverage_env_pairs(group, in_docker=True).items():
            argv += ["-e", f"{k}={v}"]
        argv += [
            c.image,
            "bash", "-lc", inner_cmd or self._in_container_cmd(group, smoke_runs),
        ]
        return argv

    def _coverage_env_pairs(self, group: LogicGroup, *, in_docker: bool) -> dict:
        """EXE-04-04 커버리지 환경변수 (NONE이면 빈 dict)"""
        # config→execute 순환 의존 회피용 지연 임포트
        from logosfuzz.execute.coverage import profile_env

        return profile_env(group, self.config, in_docker=in_docker)

    def _local_argv(self, group: LogicGroup, smoke_runs: Optional[int] = None) -> list:
        """Docker 미사용 시 호스트 직접 실행 커맨드"""
        harness = str(self.harness_binary_path(group))
        prefix = self.config.crashes_dir if smoke_runs is None else self.smoke_dir(group)
        argv = [harness, *self._run_limit_args(self.config.timeout_sec, smoke_runs),
                f"-artifact_prefix={prefix}/",
                "-print_final_stats=1",
                *self.libfuzzer_option_args(group, in_docker=False)]
        if group.corpus_dir:
            argv.append(str(group.corpus_dir))
        # 호스트 실행에서는 env 프리픽스로 환경변수를 주입한다(기본 executor
        # 시그니처를 바꾸지 않기 위함). Docker 경로(build_run_argv)는
        # `-e ASAN_OPTIONS=...`로 넘기지만, 이 로컬 경로는 그동안 ASAN_OPTIONS/
        # TSAN_OPTIONS를 전혀 넘기지 않았다 - subprocess.Popen이 env= 없이
        # 호출되면 부모 셸 환경을 그대로 물려받으므로, 셸에 ASAN_OPTIONS가
        # 없으면 ASAN이 자체 기본값(symbolize=1 포함)을 쓴다. 그 결과
        # config.asan_options를 symbolize=0으로 바꿔도 --no-docker 실행에는
        # 전혀 반영되지 않았다(실측 확인: 설정을 바꿔도 여전히 하드 타임아웃까지
        # 멈춤). 커버리지 환경변수와 같은 프리픽스에 합쳐 넣는다.
        pairs = {
            "ASAN_OPTIONS": self.config.asan_options,
            "TSAN_OPTIONS": self.config.tsan_options,
            **self._coverage_env_pairs(group, in_docker=False),
        }
        argv = ["env", *[f"{k}={v}" for k, v in pairs.items()], *argv]
        return argv

    # ---- fork 모드 크래시 재실행 ---------------------------------------
    def replay_argv(self, group: LogicGroup, crash_file: Path) -> list:
        """크래시 입력 1건 단독 재실행 커맨드 (본 퍼징과 같은 격리·sanitizer 옵션)

        fork 모드의 부모 프로세스는 자식 sanitizer 보고 중 ERROR 한 줄만 출력하므로
        스택 복원용 전체 보고 확보 목적
        """
        opts = [f"-timeout={self.per_input_timeout_sec()}"]
        if self.config.rss_limit_mb > 0:
            opts.append(f"-rss_limit_mb={self.config.rss_limit_mb}")
        if self.config.malloc_limit_mb > 0:
            opts.append(f"-malloc_limit_mb={self.config.malloc_limit_mb}")
        if self.config.use_docker:
            rel = Path(crash_file).resolve().relative_to(self.config.output_dir.resolve())
            harness = f"/harness/{group.harness_path.name}"
            inner = "chmod +x %s 2>/dev/null; %s %s %s" % (
                shlex.quote(harness), shlex.quote(harness), " ".join(opts),
                shlex.quote(f"/out/{rel.as_posix()}"))
            return self.build_run_argv(group, inner_cmd=inner, suffix="-replay")
        pairs = {"ASAN_OPTIONS": self.config.asan_options,
                 "TSAN_OPTIONS": self.config.tsan_options}
        return ["env", *[f"{k}={v}" for k, v in pairs.items()],
                str(self.harness_binary_path(group)), *opts, str(crash_file)]

    def replay_crash(self, group: LogicGroup, crash_file: Path) -> list:
        """크래시 입력 1건 재실행 후 sanitizer 결함 목록 반환 (재현 실패 시 빈 목록)"""
        monitor = SanitizerMonitor()
        timeout = self.per_input_timeout_sec() + 30
        self.executor(self.replay_argv(group, crash_file), timeout, monitor.feed)
        return monitor.finish()

    # ---- 코퍼스 최소화 (-merge=1) --------------------------------------
    def merge_dir(self, group: LogicGroup) -> Path:
        """최소화 결과 임시 위치 (출력 디렉토리 하위, 컨테이너에서는 /out 하위)"""
        return self.config.output_dir / "corpus_merge" / group.name

    def merge_argv(self, group: LogicGroup) -> list:
        """코퍼스 최소화 커맨드. ``-merge=1 <새 디렉토리> <기존 코퍼스>``"""
        opts = [f"-timeout={self.per_input_timeout_sec()}"]
        if self.config.rss_limit_mb > 0:
            opts.append(f"-rss_limit_mb={self.config.rss_limit_mb}")
        if self.config.malloc_limit_mb > 0:
            opts.append(f"-malloc_limit_mb={self.config.malloc_limit_mb}")
        if self.config.use_docker:
            rel = self.merge_dir(group).resolve().relative_to(self.config.output_dir.resolve())
            harness = f"/harness/{group.harness_path.name}"
            inner = "chmod +x %s 2>/dev/null; %s -merge=1 %s %s /corpus" % (
                shlex.quote(harness), shlex.quote(harness), " ".join(opts),
                shlex.quote(f"/out/{rel.as_posix()}"))
            return self.build_run_argv(group, inner_cmd=inner, suffix="-merge")
        pairs = {"ASAN_OPTIONS": self.config.asan_options,
                 "TSAN_OPTIONS": self.config.tsan_options}
        return ["env", *[f"{k}={v}" for k, v in pairs.items()],
                str(self.harness_binary_path(group)), "-merge=1", *opts,
                str(self.merge_dir(group)), str(group.corpus_dir)]

    def minimize_corpus(self, group: LogicGroup) -> Optional[tuple]:
        """그룹 코퍼스 최소화 후 (이전 개수, 이후 개수) 반환

        최소화 실패(비정상 종료, 결과 0건) 시 기존 코퍼스 유지 후 None 반환
        """
        corpus = Path(group.corpus_dir) if group.corpus_dir else None
        if corpus is None or not corpus.is_dir():
            return None
        before = [f for f in corpus.iterdir() if f.is_file()]
        if not before:
            return None
        merged = self.merge_dir(group)
        shutil.rmtree(merged, ignore_errors=True)
        merged.mkdir(parents=True, exist_ok=True)
        hard_timeout = self.config.timeout_sec + 30
        result = self.executor(self.merge_argv(group), hard_timeout, lambda _line: None)
        self._write_run_logs(group, result, stem="merge")
        kept = [f for f in merged.iterdir() if f.is_file()]
        if result.exit_code != 0 or result.timed_out or not kept:
            shutil.rmtree(merged, ignore_errors=True)
            return None
        for f in before:
            f.unlink()
        for f in kept:
            shutil.move(str(f), corpus / f.name)
        shutil.rmtree(merged, ignore_errors=True)
        return len(before), len(kept)

    # ---- 스모크 테스트 (GEN-03-04 dry-run) -----------------------------
    def run_smoke(self, group: LogicGroup, runs: int, timeout_sec: int) -> ProcResult:
        """본 퍼징 전 짧은 dry-run (``-runs=N``). 본 퍼징과 같은 격리·옵션 사용

        크래시 산출물은 ``smoke/<group>/`` 에 남기고, 로그는
        ``logs/<group>/smoke.*.log`` 로 저장
        """
        harness_file = self.harness_binary_path(group)
        if not harness_file.exists():
            raise HarnessNotFoundError(f"하네스 없음: {harness_file}")
        self.config.ensure_dirs()
        self.smoke_dir(group).mkdir(parents=True, exist_ok=True)
        saved = self.config.timeout_sec
        self.config.timeout_sec = max(1, int(timeout_sec))
        try:
            argv = (self.build_run_argv(group, smoke_runs=runs) if self.config.use_docker
                    else self._local_argv(group, smoke_runs=runs))
        finally:
            self.config.timeout_sec = saved
        result = self.executor(argv, timeout_sec + 30, lambda _line: None)
        self._write_run_logs(group, result, stem="smoke")
        return result

    # ---- 그룹 1개 실행 ------------------------------------------------
    def run_group(self, group: LogicGroup, monitor: Optional[StatsMonitor] = None,
                  sanitizer_monitor: Optional[SanitizerMonitor] = None) -> GroupResult:
        # 그룹 이름은 컨테이너 이름·로그 디렉터리·커버리지 파일 이름으로 사용
        # '../x' 같은 값이 출력 디렉터리 밖에 쓰지 못하도록 실행 전에 거부
        safe_component(group.name, what="로직 그룹 이름")
        harness_file = self.harness_binary_path(group)
        if not harness_file.exists():
            raise HarnessNotFoundError(
                f"하네스 없음: {harness_file} (GEN 단계 산출물을 확인하세요)"
            )
        self.config.ensure_dirs()

        mon = monitor or StatsMonitor(LiveStats(group=group.name), live=False)
        stats = mon.stats
        argv = self.build_run_argv(group) if self.config.use_docker else self._local_argv(group)

        # 엔진 미종료 대비 하드 월클럭 상한 (+ grace)
        hard_timeout = self.config.timeout_sec + 30
        start = time.monotonic()
        sanitizer = sanitizer_monitor or SanitizerMonitor()

        def on_line(line: str) -> None:
            mon.feed(line)
            sanitizer.feed(line)

        result = self.executor(argv, hard_timeout, on_line)
        duration = time.monotonic() - start
        mon.finish()
        findings = sanitizer.finish()
        stdout_log, stderr_log, log_error = self._write_run_logs(group, result)

        return GroupResult(
            group=group.name,
            exit_code=result.exit_code,
            timed_out=result.timed_out,
            stats=stats,
            crashes=[],
            duration_sec=duration,
            sanitizer_findings=findings,
            stdout_log=stdout_log,
            stderr_log=stderr_log,
            log_error=log_error,
        )

    def _write_run_logs(self, group: LogicGroup, result: "ProcResult", stem: str = "run"
                        ) -> tuple[Optional[str], Optional[str], str]:
        """표준 출력/표준 오류 전문을 그룹별 로그 파일로 남긴다.

        정상 종료든 타임아웃이든 크래시든 상관없이 항상 저장한다 - 사후에
        "무엇이 출력됐는지" 볼 방법이 하나도 없으면 컴파일 실패나 실행 실패의
        원인을 알 수 없다. 로그 저장 자체가 실패해도(디스크 문제 등) 퍼징
        결과를 잃으면 안 되므로 세션은 계속하되, 경로를 None 으로 두고 사유를
        ``log_error`` 로 돌려줘 "증적 불완전"으로 표시한다(조용히 삼키지 않는다).
        """
        try:
            log_dir = safe_join(self.config.logs_dir, group.name, what="로직 그룹 이름")
            log_dir.mkdir(parents=True, exist_ok=True)
            stdout_path = log_dir / f"{stem}.stdout.log"
            stderr_path = log_dir / f"{stem}.stderr.log"
            stdout_path.write_text(result.stdout, encoding="utf-8")
            stderr_path.write_text(result.stderr, encoding="utf-8")
            return str(stdout_path), str(stderr_path), ""
        except (OSError, ValueError) as exc:
            _log.warning("실행 로그 저장 실패(group=%s): %s", group.name, exc)
            return None, None, f"실행 로그 저장 실패: {exc}"
