"""EXE-04-01: Docker 기반 격리 퍼징 실행.

퍼징 중 발생하는 크래시로부터 호스트를 보호하기 위해, 각 로직 그룹의
하네스를 격리된 Docker 컨테이너 안에서 실행한다.

격리 정책:
  - --network none        : 외부 네트워크 완전 차단(오탐/유출 방지)
  - --cap-drop ALL        : 리눅스 capability 전부 제거
  - --security-opt no-new-privileges
  - --memory / --cpus / --pids-limit : 자원 상한
  - 하네스는 읽기 전용(:ro)으로, 출력만 쓰기 가능(/out)으로 마운트

테스트 용이성을 위해 실제 프로세스 실행은 `executor` 콜러블로 주입한다.
기본 executor는 stdout/stderr를 각각 스레드로 읽어 큐에 모으고, 메인
스레드는 `queue.get(timeout=...)`으로 소비한다 - 자식이 침묵해도(예: ASAN이
크래시 시 심볼라이저를 내부에서 fork하며 응답 없이 대기) 데드라인이 정확히
발동한다(실측으로 확인된 회귀: 기존의 `for line in proc.stdout` 블로킹
방식은 출력이 없으면 하드 타임아웃까지 90초 넘게 멈췄다).
"""

from __future__ import annotations

import collections
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
from logosfuzz.config import Engine, FuzzConfig, LogicGroup
from logosfuzz.execute.errors import (
    DockerUnavailableError,
    HarnessNotFoundError,
    ImageBuildError,
)
from logosfuzz.execute.stats import LiveStats, StatsMonitor
from logosfuzz.execute.sanitizer import SanitizerFinding, SanitizerMonitor


# executor(argv, timeout, on_line) -> ProcResult
OnLine = Callable[[str], None]
Executor = Callable[[list, float, OnLine], "ProcResult"]

# 큐 소비 폴링 주기(초). 이 값 이상 자식이 침묵해도 이 주기마다 데드라인을
# 재확인하므로, 무한정 블로킹되지 않는다.
_POLL_INTERVAL_SEC = 0.5

# 출력 상한(자원 관리, CWE-400). 하네스는 비신뢰 코드라 출력을 무한히 쏟을 수 있다.
#   - 큐: 가득 차면 읽기 스레드가 기다리고, 그동안 자식은 파이프에서 막힌다(배압).
#   - 줄: 개행 없는 거대한 한 줄이 메모리를 다 먹지 않도록 자른다.
#   - 보존: 스트림마다 앞쪽 _KEEP_HEAD_LINES 줄과 마지막 _KEEP_TAIL_LINES 줄만 남긴다.
#     크래시 원인(ASAN 보고)은 끝에 오므로 꼬리를 반드시 남긴다. 모니터(on_line)는
#     버린 줄도 모두 본다 - 통계·새니타이저 판정은 상한과 무관하다.
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
    """단일 로직 그룹 퍼징 결과."""

    group: str
    exit_code: int
    timed_out: bool
    stats: LiveStats
    crashes: list  # 수집된 크래시 경로(fuzz_session이 채움)
    duration_sec: float
    sanitizer_findings: list[SanitizerFinding] = field(default_factory=list)
    coverage: object = None  # EXE-04-04 CoverageSummary(없으면 None); fuzz_session이 채움
    stdout_log: Optional[str] = None  # 표준 출력 로그 파일 경로(저장 실패 시 None)
    stderr_log: Optional[str] = None  # 표준 오류 로그 파일 경로
    # 증적(로그) 저장 실패 사유. 비어 있지 않으면 이 결과는 "증적 불완전"이다 -
    # 저장 실패를 정상 완료처럼 보고하지 않기 위해 남긴다.
    log_error: str = ""

    @property
    def evidence_complete(self) -> bool:
        return not self.log_error

    @property
    def failed_to_start(self) -> bool:
        """하네스가 입력을 한 번도 실행하지 못하고 죽었는가.

        컨테이너 안에서 공유 라이브러리를 못 찾거나(libatomic.so.1, GLIBC_2.38
        - 5주차 실측) 바이너리가 아예 실행되지 않으면 종료코드는 0 이 아닌데
        실행 횟수는 0 이다. 이걸 크래시로 세면 "크래시 0건, 완료" 또는 가짜
        크래시로 보고돼 퍼징이 실제로는 안 돌았다는 사실이 가려진다.

        첫 입력에서 바로 크래시한 경우와 구분하기 위해 크래시 산출물이나
        새니타이저 결함이 있으면 실행 실패로 보지 않는다.
        """
        return (
            self.exit_code not in (0, None)
            and self.stats.execs == 0
            and not self.crashes
            and not self.sanitizer_findings
        )

    @property
    def crashed(self) -> bool:
        # libFuzzer는 크래시 시 non-zero 종료, 크래시 산출물도 남긴다.
        if self.crashes:
            return True
        return (
            self.exit_code not in (0, None)
            and not self.timed_out
            and not self.failed_to_start
        )


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
    # 부모 환경(API 키·클라우드 자격증명)을 하네스나 docker CLI 에 물려주지 않는다.
    # 새 세션으로 띄워 타임아웃 때 자손까지 프로세스 그룹 단위로 정리한다.
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

    assert proc.stdout is not None and proc.stderr is not None
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
    #
    # GEN이 Bazel 어댑터로 넘어가면서 하네스 바이너리가 harness_dir 밖에
    # 생긴다. cc_fuzz_test 는 `<name>_bin`(계측된 퍼저 바이너리)을 워크스페이스
    # 의 bazel-bin 출력 트리에 떨구고, 그 경로는 빌드 설정(--platform_suffix)
    # 에 따라 달라진다. 그래서 EXE 계층은 경로를 **추측하지 않고** 빌드
    # 어댑터가 돌려준 실제 경로를 그대로 받는다(GEN 파트 결정사항 ④:
    # "EXE 계층은 bazel run 이 아니라 바이너리를 직접 실행한다").
    #
    # 덕분에 이 계층은 빌드 시스템을 모른다 - Bazel 산출물이든 CMake
    # 산출물이든 docker_runner 에겐 그냥 실행 파일 하나다.
    def harness_binary_path(self, group: LogicGroup) -> Path:
        """하네스 바이너리의 호스트 경로.

        ``harness_path`` 에 디렉토리가 붙어 있으면(절대경로 등) 그 경로를
        그대로 쓰고, 이름만 있으면 지금까지처럼 ``harness_dir`` 기준으로 푼다.
        """
        p = Path(group.harness_path)
        if p.parent != Path("."):
            return p.resolve()
        return (self.config.harness_dir / p.name).resolve()

    def harness_mount_dir(self, group: LogicGroup) -> Path:
        """``/harness`` 로 읽기 전용 마운트할 호스트 디렉토리.

        바이너리가 harness_dir 밖(bazel-bin 등)에 있으면 그 바이너리가 있는
        디렉토리를 대신 마운트한다. 컨테이너 안 경로는 두 경우 모두
        ``/harness/<파일명>`` 이라 내부 커맨드 구성은 달라지지 않는다.
        """
        return self.harness_binary_path(group).parent

    # ---- 실행 커맨드 구성 (EXE-04-01 핵심 로직) -----------------------
    def _in_container_cmd(self, group: LogicGroup) -> str:
        """엔진별로 컨테이너 내부에서 실행할 셸 명령 문자열."""
        harness = f"/harness/{group.harness_path.name}"
        corpus = "/corpus" if group.corpus_dir else ""
        t = self.config.timeout_sec
        if self.config.engine is Engine.LIBFUZZER:
            parts = [
                shlex.quote(harness),
                f"-max_total_time={t}",
                "-artifact_prefix=/out/crashes/",
                "-print_final_stats=1",
            ]
            if corpus:
                parts.append(shlex.quote(corpus))
            return "chmod +x %s 2>/dev/null; %s" % (shlex.quote(harness), " ".join(parts))
        # AFL++
        # 컨테이너 전용 /tmp(--rm 으로 매번 새로 생긴다)라 호스트 임시 디렉터리 경쟁과 무관하다.
        indir = shlex.quote(corpus) if corpus else "/tmp/seed"  # nosec B108
        seed_prep = "" if corpus else "mkdir -p /tmp/seed && printf a > /tmp/seed/seed;"
        return (
            f"{seed_prep} chmod +x {shlex.quote(harness)} 2>/dev/null; "
            f"afl-fuzz -i {indir} -o /out/afl -V {t} -- {shlex.quote(harness)} @@"
        )

    def _host_user(self) -> str | None:
        """호스트 uid:gid. Windows 등 uid 개념이 없는 플랫폼이면 None."""
        getuid = getattr(os, "getuid", None)
        getgid = getattr(os, "getgid", None)
        if getuid is None or getgid is None:
            return None
        return f"{getuid()}:{getgid()}"

    def build_run_argv(self, group: LogicGroup) -> list:
        c = self.config
        argv = [
            self.docker_bin, "run", "--rm",
            "--name", f"logosfuzz-{group.name}",
            "--network", c.network,
            "--memory", c.memory_limit,
            "--cpus", c.cpus,
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
            argv += ["-v", f"{group.corpus_dir.resolve()}:/corpus:ro"]
        argv += [
            "-e", f"ASAN_OPTIONS={c.asan_options}",
            "-e", f"TSAN_OPTIONS={c.tsan_options}",
        ]
        # EXE-04-04: 커버리지 계측 활성 시 profraw 출력 경로를 환경변수로 주입.
        for k, v in self._coverage_env_pairs(group, in_docker=True).items():
            argv += ["-e", f"{k}={v}"]
        argv += [
            c.image,
            "bash", "-lc", self._in_container_cmd(group),
        ]
        return argv

    def _coverage_env_pairs(self, group: LogicGroup, *, in_docker: bool) -> dict:
        """EXE-04-04 커버리지 환경변수(LLVM_PROFILE_FILE 등). NONE이면 빈 dict."""
        # 지연 임포트로 config→execute 순환 의존을 피한다.
        from logosfuzz.execute.coverage import profile_env

        return profile_env(group, self.config, in_docker=in_docker)

    def _local_argv(self, group: LogicGroup) -> list:
        """--docker 미사용 시(디버그) 호스트에서 직접 실행하는 커맨드."""
        harness = str(self.harness_binary_path(group))
        t = self.config.timeout_sec
        if self.config.engine is Engine.LIBFUZZER:
            argv = [harness, f"-max_total_time={t}",
                    f"-artifact_prefix={self.config.crashes_dir}/",
                    "-print_final_stats=1"]
            if group.corpus_dir:
                argv.append(str(group.corpus_dir))
        else:
            # 호스트에서는 예측 가능한 /tmp/seed 를 쓰지 않는다(다른 사용자가 미리 만들어 둔
            # 디렉터리·심볼릭 링크를 따라갈 수 있다). 출력 디렉터리 아래에 시드를 만든다.
            argv = ["afl-fuzz", "-i", str(group.corpus_dir or self._local_seed_dir()),
                    "-o", str(self.config.output_dir / "afl"), "-V", str(t),
                    "--", harness, "@@"]
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

    def _local_seed_dir(self) -> Path:
        seed_dir = self.config.output_dir / "afl-seed"
        seed_dir.mkdir(parents=True, exist_ok=True)
        seed = seed_dir / "seed"
        if not seed.exists():
            seed.write_bytes(b"a")
        return seed_dir

    # ---- 그룹 1개 실행 ------------------------------------------------
    def run_group(self, group: LogicGroup, monitor: Optional[StatsMonitor] = None,
                  sanitizer_monitor: Optional[SanitizerMonitor] = None) -> GroupResult:
        # 그룹 이름은 컨테이너 이름·로그 디렉터리·커버리지 파일 이름이 된다.
        # '../x' 같은 값이 출력 디렉터리 밖에 쓰지 못하게 실행 전에 거부한다.
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

        # 엔진이 스스로 종료하지 못할 경우를 대비한 하드 월클럭 상한(+ grace).
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

    def _write_run_logs(self, group: LogicGroup, result: "ProcResult"
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
            stdout_path = log_dir / "run.stdout.log"
            stderr_path = log_dir / "run.stderr.log"
            stdout_path.write_text(result.stdout, encoding="utf-8")
            stderr_path.write_text(result.stderr, encoding="utf-8")
            return str(stdout_path), str(stderr_path), ""
        except (OSError, ValueError) as exc:
            _log.warning("실행 로그 저장 실패(group=%s): %s", group.name, exc)
            return None, None, f"실행 로그 저장 실패: {exc}"
