"""
CMake 어댑터 (GENERIC-B)
========================

CMake 로 빌드하는 C/C++ 대상(libsndfile 등)에서 퍼저 바이너리를 만든다.

Bazel 과 다른 점
----------------
Bazel 은 하네스를 ``cc_fuzz_test`` 로 BUILD 에 선언하고 deps 로 링크한다. CMake 대상은
**라이브러리를 CMake 가 먼저 빌드하고(``prepare``), 하네스는 clang 으로 직접 링크한다**
(``build``). 그래서 BUILD 파일을 쓰지 않고, 빌드 실패는 하네스 소스의 컴파일·링크 오류뿐이다.
오류 원문은 ``BuildResult.log`` 에 그대로 남겨 자가치유 분류기(D)가 읽게 한다.

흐름::

    prepare()                        라이브러리를 계측해서 한 번 빌드(캐시됨)
      cmake -S <source_root> -B <build_dir> [-G Ninja] -DCMAKE_EXPORT_COMPILE_COMMANDS=ON <configure_args>
      cmake --build <build_dir> --parallel N
    emit_build_definition(spec, src) 하네스 소스를 작업 디렉터리에 쓴다
    build(spec)                      clang -fsanitize=address,undefined,fuzzer 하네스 + libraries ... -o <binary>

``prepare()`` 가 만드는 ``compile_commands.json`` 은 EXT(``extract/compile_db.py``)의 입력이기도 하다.
그래서 파이프라인에서는 ``prepare`` → EXT → GEN → ``build`` 순서가 되어야 한다.

계측은 어댑터가 넣는다: 프로필의 ``configure_args`` 에는 ``-fsanitize`` 가 없다. 계측 없는
라이브러리는 커버리지를 못 본다. ``coverage=True`` 는 같은 과정을 ``<build_dir>-cov`` 에서
``-fprofile-instr-generate -fcoverage-mapping`` 으로 한 번 더 한다(``execute/coverage.py`` 의
``instrumentation_flags()`` 재사용).

``TargetProfile`` 은 타입 힌트로만 import 한다(런타임 의존 없음). 이 어댑터는 프로필의
``build.*``, ``language``, ``name``, ``root``, ``abs()`` 만 읽는다.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import (
    TYPE_CHECKING, Callable, Dict, List, Mapping, Optional, Sequence,
)

from logosfuzz.common.security import minimal_env, safe_component, safe_join

from .base import BuildResult, HarnessSpecLike

if TYPE_CHECKING:  # pragma: no cover
    from logosfuzz.common.target_profile import TargetProfile

# 라이브러리 컴파일에는 fuzzer 런타임을 링크하지 않는다(fuzzer-no-link: 계측만).
_SANITIZE_COMPILE = "-fsanitize=address,undefined,fuzzer-no-link"
# 하네스를 링크할 때는 libFuzzer 엔트리(main)가 필요하다.
_SANITIZE_LINK = "-fsanitize=address,undefined,fuzzer"
_BASE_FLAGS = ("-g", "-O1", "-fno-omit-frame-pointer")

DEFAULT_BUILD_DIR = "build-fuzz"
COVERAGE_SUFFIX = "-cov"
# 외부 명령 1회의 기본 상한. CMake configure 는 대상 프로젝트가 정한 스크립트를 실행하므로
# 상한 없이 두면 멈춘 configure 하나가 파이프라인 전체를 붙잡는다(자원 관리, CWE-400).
DEFAULT_TIMEOUT_S = 3600.0
# 빌드 설정 지문. 소스·컴파일러·플래그가 바뀌었는데 예전 산출물을 캐시로 재사용하지 않게 한다.
FINGERPRINT_FILE = ".logosfuzz-build.json"


@dataclass
class RunResult:
    """외부 명령 1회의 결과."""

    returncode: int
    stdout: str = ""
    stderr: str = ""


# runner(argv, cwd, env, timeout_s) -> RunResult. 테스트에서 가짜를 주입한다.
Runner = Callable[
    [Sequence[str], Optional[Path], Optional[Mapping[str, str]], Optional[float]],
    RunResult,
]


def default_runner(
    argv: Sequence[str],
    cwd: Optional[Path],
    env: Optional[Mapping[str, str]],
    timeout_s: Optional[float],
) -> RunResult:
    """subprocess 로 실행한다. 도구가 없거나 시간이 넘어도 예외 대신 RunResult 로 돌려준다."""
    try:
        proc = subprocess.run(
            list(argv), cwd=cwd, env=dict(env) if env is not None else None,
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout_s,
        )
        return RunResult(proc.returncode, proc.stdout or "", proc.stderr or "")
    except subprocess.TimeoutExpired as exc:
        def _text(value) -> str:
            if value is None:
                return ""
            return value if isinstance(value, str) else value.decode("utf-8", "replace")
        return RunResult(124, _text(exc.stdout),
                         _text(exc.stderr) + f"\nERROR: 시간 초과({timeout_s}s): {argv[0]}")
    except OSError as exc:
        return RunResult(127, "", f"ERROR: 실행할 수 없음: {argv[0]} ({exc})")


def _coverage_flags() -> List[str]:
    """llvm-cov 소스 기반 커버리지 계측 플래그 (``execute/coverage.py`` 재사용)."""
    # 지연 import: execute 패키지는 이 모듈이 import 될 때마다 필요하지는 않다.
    from logosfuzz.config import CoverageMode
    from logosfuzz.execute.coverage import instrumentation_flags

    return list(instrumentation_flags(CoverageMode.LLVM_COV))


class CMakeAdapter:
    """CMake 대상용 빌드 어댑터. ``BuildAdapter`` 계약(emit/build/remove)을 따른다."""

    def __init__(
        self,
        profile: "TargetProfile",
        *,
        work_dir: Path | str | None = None,
        coverage: bool = False,
        runner: Optional[Runner] = None,
        jobs: Optional[int] = None,
        timeout_s: Optional[float] = None,
        cc: str = "clang",
        cxx: str = "clang++",
        which: Callable[[str], Optional[str]] = shutil.which,
    ) -> None:
        self.profile = profile
        self.coverage = coverage
        self.runner: Runner = runner or default_runner
        self.jobs = jobs or os.cpu_count() or 4
        self.timeout_s = DEFAULT_TIMEOUT_S if timeout_s is None else timeout_s
        self.cc = cc
        self.cxx = cxx
        self._which = which
        # 하네스 소스(harness/)와 바이너리(bin/)는 대상 소스 트리 밖에 둔다.
        self.work_dir = (
            Path(work_dir).expanduser() if work_dir is not None
            else Path.cwd() / "out" / "generic" / profile.name
        )
        self._prepared = False

    # ------------------------------------------------------------------ #
    # 경로·플래그
    # ------------------------------------------------------------------ #
    @property
    def source_dir(self) -> Path:
        return Path(self.profile.root)

    @property
    def build_dir_name(self) -> str:
        name = self.profile.build.build_dir or DEFAULT_BUILD_DIR
        return name + COVERAGE_SUFFIX if self.coverage else name

    @property
    def build_dir(self) -> Path:
        return self.profile.abs(self.build_dir_name)

    @property
    def compiler(self) -> str:
        return self.cxx if self.profile.language == "cpp" else self.cc

    def _rewrite_for_coverage(self, path: str) -> str:
        """커버리지 변형이면 ``<build_dir>/x`` 를 ``<build_dir>-cov/x`` 로 바꾼다."""
        if not self.coverage:
            return path
        base = (self.profile.build.build_dir or DEFAULT_BUILD_DIR).rstrip("/")
        posix = path.replace("\\", "/")
        if posix == base or posix.startswith(base + "/"):
            return base + COVERAGE_SUFFIX + posix[len(base):]
        return path

    @property
    def libraries(self) -> List[Path]:
        return [self.profile.abs(self._rewrite_for_coverage(lib))
                for lib in self.profile.build.libraries]

    @property
    def include_dirs(self) -> List[Path]:
        return [self.profile.abs(d) for d in self.profile.build.include_dirs]

    def compile_flags(self) -> List[str]:
        """라이브러리를 컴파일할 때의 CFLAGS/CXXFLAGS."""
        flags = [*_BASE_FLAGS, _SANITIZE_COMPILE]
        if self.coverage:
            flags += _coverage_flags()
        return flags

    def link_flags(self) -> List[str]:
        """하네스를 컴파일·링크할 때의 플래그(퍼저 엔트리 포함)."""
        flags = [*_BASE_FLAGS, _SANITIZE_LINK]
        if self.coverage:
            flags += _coverage_flags()
        return flags

    def _env(self) -> Dict[str, str]:
        """빌드 환경. 부모 환경을 통째로 복사하지 않는다.

        configure/build 는 대상 프로젝트의 CMake 스크립트를 실행한다. ``os.environ`` 을
        그대로 주면 ``OPENAI_API_KEY`` 나 클라우드 자격증명을 비신뢰 빌드 코드가 읽을 수
        있으므로, 허용 목록으로 새 환경을 만든다(``common.security.minimal_env``).
        """
        flags = " ".join(self.compile_flags())
        return minimal_env({"CC": self.cc, "CXX": self.cxx, "CFLAGS": flags, "CXXFLAGS": flags})

    def _bin_dir(self) -> Path:
        return self.work_dir / ("bin" + COVERAGE_SUFFIX if self.coverage else "bin")

    def _harness_path(self, spec: HarnessSpecLike) -> Path:
        srcs = list(spec.srcs)
        if len(srcs) != 1:
            raise ValueError(f"하네스 소스는 1개여야 한다(현재 {len(srcs)}개): {srcs}")
        # package·srcs 는 생성기가 정한 값이라 '../' 나 절대경로가 섞이면 작업 디렉터리
        # 밖을 덮어쓴다. 칸마다 검사하고 결과가 harness/ 안인지 확인한다.
        return safe_join(self.work_dir / "harness", spec.package, srcs[0], what="하네스 경로")

    def _binary_file(self, spec: HarnessSpecLike) -> Path:
        return self._bin_dir() / safe_component(spec.name, what="하네스 이름")

    def binary_path(self, spec: HarnessSpecLike) -> Optional[Path]:
        """빌드된 실행 파일의 실제 경로. 없으면 None."""
        path = self._binary_file(spec)
        return path if path.is_file() else None

    # ------------------------------------------------------------------ #
    # prepare: 라이브러리 계측 빌드 (캐시)
    # ------------------------------------------------------------------ #
    def _source_revision(self) -> str:
        """대상 소스의 git commit(있으면). 외부 명령 없이 .git 을 직접 읽는다."""
        git = self.source_dir / ".git"
        try:
            head = (git / "HEAD").read_text(encoding="utf-8").strip()
            if head.startswith("ref: "):
                ref = git / head[5:]
                return ref.read_text(encoding="utf-8").strip() if ref.is_file() else head
            return head
        except OSError:
            return ""

    def build_fingerprint(self) -> str:
        """캐시 키: 소스 commit·컴파일러·플래그·configure 인자·라이브러리 목록의 해시."""
        material = {
            "source": str(self.source_dir.resolve()),
            "revision": self._source_revision(),
            "cc": self.cc, "cxx": self.cxx,
            "compile_flags": self.compile_flags(),
            "configure_args": list(self.profile.build.configure_args),
            "libraries": [str(lib) for lib in self.libraries],
            "coverage": self.coverage,
        }
        blob = json.dumps(material, sort_keys=True, ensure_ascii=False).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()

    def _fingerprint_path(self) -> Path:
        return self.build_dir / FINGERPRINT_FILE

    def _is_built(self) -> bool:
        if not (self.build_dir / "CMakeCache.txt").is_file():
            return False
        if not all(lib.is_file() for lib in self.libraries):
            return False
        # 지문이 없거나(예전 캐시) 다르면 설정이 바뀐 것이므로 다시 빌드한다.
        try:
            saved = json.loads(self._fingerprint_path().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        return isinstance(saved, dict) and saved.get("fingerprint") == self.build_fingerprint()

    def _write_fingerprint(self) -> Optional[str]:
        """지문을 남긴다. 실패하면 오류 문구를 돌려준다(다음 실행이 캐시를 못 쓸 뿐)."""
        try:
            self._fingerprint_path().write_text(
                json.dumps({"fingerprint": self.build_fingerprint()}), encoding="utf-8")
            return None
        except OSError as exc:
            return f"WARNING: 빌드 지문을 저장하지 못했다({exc}) — 다음 실행은 캐시를 쓰지 않는다"

    def prepare(self, *, force: bool = False) -> BuildResult:
        """대상 라이브러리를 계측해서 한 번 빌드한다. 이미 되어 있으면 건너뛴다(캐시)."""
        target = f"cmake:{self.profile.name}" + (":cov" if self.coverage else "")
        started = time.monotonic()

        if not force and self._is_built():
            self._prepared = True
            return BuildResult(ok=True, target=target,
                               log=f"(캐시) {self.build_dir} 에 이미 빌드되어 있다",
                               duration_s=time.monotonic() - started)

        if not (self.source_dir / "CMakeLists.txt").is_file():
            return BuildResult(
                ok=False, target=target,
                log=f"ERROR: 소스 루트에 CMakeLists.txt 가 없다: {self.source_dir} "
                    f"(대상 소스를 source_root 위치에 받아 두었는가?)",
            )

        configure = [
            "cmake", "-S", str(self.source_dir), "-B", str(self.build_dir),
        ]
        # 이미 다른 생성기로 configure 된 캐시가 있으면 -G 를 주면 거부당한다.
        if not (self.build_dir / "CMakeCache.txt").is_file() and self._which("ninja"):
            configure += ["-G", "Ninja"]
        configure += ["-DCMAKE_EXPORT_COMPILE_COMMANDS=ON", *self.profile.build.configure_args]
        build = ["cmake", "--build", str(self.build_dir), "--parallel", str(self.jobs)]

        env = self._env()
        logs: List[str] = []
        for command in (configure, build):
            result = self.runner(command, None, env, self.timeout_s)
            logs.append(result.stdout + result.stderr)
            if result.returncode != 0:
                return BuildResult(ok=False, target=target, log="\n".join(logs),
                                   duration_s=time.monotonic() - started, command=tuple(command))

        missing = [str(lib) for lib in self.libraries if not lib.is_file()]
        if missing:
            logs.append("ERROR: 빌드는 끝났지만 라이브러리가 없다 — profile.build.libraries 경로를 "
                        "확인하라: " + ", ".join(missing))
            return BuildResult(ok=False, target=target, log="\n".join(logs),
                               duration_s=time.monotonic() - started, command=tuple(build))

        warning = self._write_fingerprint()
        if warning:
            logs.append(warning)
        self._prepared = True
        return BuildResult(ok=True, target=target, log="\n".join(logs),
                           duration_s=time.monotonic() - started, command=tuple(build))

    # ------------------------------------------------------------------ #
    # BuildAdapter 계약
    # ------------------------------------------------------------------ #
    def emit_build_definition(self, spec: HarnessSpecLike, harness_source: str) -> Path:
        """하네스 소스를 쓴다. CMake 는 BUILD 정의가 없으므로 소스 경로를 돌려준다."""
        path = self._harness_path(spec)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(harness_source, encoding="utf-8")
        return path

    def build(self, spec: HarnessSpecLike) -> BuildResult:
        """하네스를 라이브러리와 링크해 퍼저 바이너리를 만든다.

        실패하면 컴파일러·링커 원문을 ``log`` 에 그대로 남긴다(자가치유 분류기의 입력).
        """
        started = time.monotonic()
        source = self._harness_path(spec)
        if not source.is_file():
            return BuildResult(
                ok=False, target=spec.name,
                log=f"ERROR: 하네스 소스가 없다: {source} (emit_build_definition 을 먼저 호출하라)",
            )

        if not self._prepared:
            prepared = self.prepare()
            if not prepared.ok:
                return BuildResult(ok=False, target=spec.name, log=prepared.log,
                                   duration_s=time.monotonic() - started,
                                   command=prepared.command)

        binary = self._binary_file(spec)
        binary.parent.mkdir(parents=True, exist_ok=True)
        command = [
            self.compiler, *self.link_flags(),
            *[f"-I{d}" for d in self.include_dirs],
            str(source),
            *[str(lib) for lib in self.libraries],   # 소스 뒤에 두어야 정적 라이브러리가 풀린다
            *self.profile.build.link_flags,
            "-o", str(binary),
        ]
        result = self.runner(command, None, minimal_env(), self.timeout_s)
        log = result.stdout + result.stderr
        ok = result.returncode == 0 and binary.is_file()
        if result.returncode == 0 and not binary.is_file():
            log += f"\nERROR: 링크는 성공했지만 실행 파일이 없다: {binary}"
        return BuildResult(
            ok=ok, target=spec.name, log=log,
            binary=binary if ok else None,
            duration_s=time.monotonic() - started, command=tuple(command),
        )

    def remove(self, spec: HarnessSpecLike) -> None:
        """생성한 하네스 소스와 바이너리를 지운다(없어도 오류 없음)."""
        for path in (self._harness_path(spec), self._binary_file(spec)):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
