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
기본 executor는 subprocess.Popen으로 stdout을 라인 단위 스트리밍한다.
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from logosfuzz.config import Engine, FuzzConfig, LogicGroup
from logosfuzz.execute.errors import (
    DockerUnavailableError,
    HarnessNotFoundError,
    ImageBuildError,
)
from logosfuzz.execute.stats import LiveStats, StatsMonitor


# executor(argv, timeout, on_line) -> ProcResult
OnLine = Callable[[str], None]
Executor = Callable[[list, float, OnLine], "ProcResult"]


@dataclass
class ProcResult:
    exit_code: int
    timed_out: bool


@dataclass
class GroupResult:
    """단일 로직 그룹 퍼징 결과."""

    group: str
    exit_code: int
    timed_out: bool
    stats: LiveStats
    crashes: list  # 수집된 크래시 경로(fuzz_session이 채움)
    duration_sec: float

    @property
    def crashed(self) -> bool:
        # libFuzzer는 크래시 시 non-zero 종료, 크래시 산출물도 남긴다.
        return bool(self.crashes) or (self.exit_code not in (0, None) and not self.timed_out)


def _default_executor(argv: list, timeout: float, on_line: OnLine) -> ProcResult:
    """subprocess 기반 기본 실행기: stdout 라인 스트리밍 + 하드 타임아웃."""
    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    deadline = time.monotonic() + timeout
    timed_out = False
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            on_line(line.rstrip("\n"))
            if time.monotonic() > deadline:
                timed_out = True
                proc.terminate()
                break
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        proc.wait()
    return ProcResult(exit_code=proc.returncode if proc.returncode is not None else -1,
                      timed_out=timed_out)


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
        indir = shlex.quote(corpus) if corpus else "/tmp/seed"
        seed_prep = "" if corpus else "mkdir -p /tmp/seed && printf a > /tmp/seed/seed;"
        return (
            f"{seed_prep} chmod +x {shlex.quote(harness)} 2>/dev/null; "
            f"afl-fuzz -i {indir} -o /out/afl -V {t} -- {shlex.quote(harness)} @@"
        )

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
        argv += [
            "-v", f"{c.harness_dir.resolve()}:/harness:ro",
            "-v", f"{c.output_dir.resolve()}:/out",
        ]
        if group.corpus_dir:
            argv += ["-v", f"{group.corpus_dir.resolve()}:/corpus:ro"]
        argv += [
            "-e", f"ASAN_OPTIONS={c.asan_options}",
            "-e", f"TSAN_OPTIONS={c.tsan_options}",
            c.image,
            "bash", "-lc", self._in_container_cmd(group),
        ]
        return argv

    def _local_argv(self, group: LogicGroup) -> list:
        """--docker 미사용 시(디버그) 호스트에서 직접 실행하는 커맨드."""
        harness = str((self.config.harness_dir / group.harness_path.name).resolve())
        t = self.config.timeout_sec
        if self.config.engine is Engine.LIBFUZZER:
            argv = [harness, f"-max_total_time={t}",
                    f"-artifact_prefix={self.config.crashes_dir}/",
                    "-print_final_stats=1"]
            if group.corpus_dir:
                argv.append(str(group.corpus_dir))
            return argv
        return ["afl-fuzz", "-i", str(group.corpus_dir or "/tmp/seed"),
                "-o", str(self.config.output_dir / "afl"), "-V", str(t),
                "--", harness, "@@"]

    # ---- 그룹 1개 실행 ------------------------------------------------
    def run_group(self, group: LogicGroup, monitor: Optional[StatsMonitor] = None) -> GroupResult:
        harness_file = self.config.harness_dir / group.harness_path.name
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
        result = self.executor(argv, hard_timeout, mon.feed)
        duration = time.monotonic() - start
        mon.finish()

        return GroupResult(
            group=group.name,
            exit_code=result.exit_code,
            timed_out=result.timed_out,
            stats=stats,
            crashes=[],
            duration_sec=duration,
        )
