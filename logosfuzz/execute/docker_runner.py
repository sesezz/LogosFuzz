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

import os
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

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
    sanitizer_findings: list[SanitizerFinding] = field(default_factory=list)
    coverage: object = None  # EXE-04-04 CoverageSummary(없으면 None); fuzz_session이 채움

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
            "-v", f"{c.harness_dir.resolve()}:/harness:ro",
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
        harness = str((self.config.harness_dir / group.harness_path.name).resolve())
        t = self.config.timeout_sec
        if self.config.engine is Engine.LIBFUZZER:
            argv = [harness, f"-max_total_time={t}",
                    f"-artifact_prefix={self.config.crashes_dir}/",
                    "-print_final_stats=1"]
            if group.corpus_dir:
                argv.append(str(group.corpus_dir))
        else:
            argv = ["afl-fuzz", "-i", str(group.corpus_dir or "/tmp/seed"),
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

    # ---- 그룹 1개 실행 ------------------------------------------------
    def run_group(self, group: LogicGroup, monitor: Optional[StatsMonitor] = None,
                  sanitizer_monitor: Optional[SanitizerMonitor] = None) -> GroupResult:
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
        sanitizer = sanitizer_monitor or SanitizerMonitor()

        def on_line(line: str) -> None:
            mon.feed(line)
            sanitizer.feed(line)

        result = self.executor(argv, hard_timeout, on_line)
        duration = time.monotonic() - start
        mon.finish()
        findings = sanitizer.finish()

        return GroupResult(
            group=group.name,
            exit_code=result.exit_code,
            timed_out=result.timed_out,
            stats=stats,
            crashes=[],
            duration_sec=duration,
            sanitizer_findings=findings,
        )
