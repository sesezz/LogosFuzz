"""GEN-03-02 Bazel 빌드 백엔드.

자가치유 루프(`selfheal.py`)가 **실제 Bazel 빌드**로 하네스를 검증할 수 있게 하는
:class:`~logosfuzz.generate.compiler.Compiler` 구현이다.

왜 따로 두나
------------
`compiler.py` 의 :class:`SubprocessCompiler` 는 clang 을 직접 부른다. 대상이 S-CORE 로
바뀌면서 그 방식은 쓸 수 없게 됐다 - strict deps 와 visibility 를 강제하는 환경에서
`deps`·include 의 정답을 아는 것은 Bazel 뿐이고, 자가치유가 분류해야 할 에러
(`no such target`, `is not visible from`, ...)는 clang 이 아니라 Bazel 이 내는 문장이다.

즉 2주차 분류기와 3주차 프롬프트 주입은 **Bazel 로그를 전제**하는데, 그 로그를 만들어
줄 백엔드가 없으면 루프 전체가 실제로는 한 번도 검증되지 않는다. 이 모듈이 그 자리를
메운다.

동작
----
1. 하네스 소스를 워크스페이스의 정해진 경로에 쓴다.
2. `bazel build [--config=...] <target>` 을 돌린다.
3. stdout+stderr 를 합쳐 :class:`CompileResult` 로 돌려준다.

로그를 **자르지 않고** 그대로 싣는 것이 중요하다. 3주차 항목이 "로그 전문 투입"이고,
분류기는 로그 여기저기에 흩어진 블록을 읽어야 하기 때문이다.

사용 예::

    from logosfuzz.generate.bazel_compiler import BazelCompiler
    from logosfuzz.generate.selfheal import SelfHealLoop

    compiler = BazelCompiler(
        workspace="/path/to/workspace",
        target="//harness:json_fuzzer",
        source_path="harness/json_fuzzer.cc",
        config="asan_ubsan_lsan",
    )
    report = SelfHealLoop(compiler, llm, max_round=3).run(draft)
"""
from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Sequence

from .compiler import Compiler
from .models import CompileResult, HarnessDraft

__all__ = ["BazelCompiler", "BazelRunResult", "bazel_available"]


@dataclass
class BazelRunResult:
    returncode: int
    stdout: str
    stderr: str


# 실행기 주입(테스트 용이성 - validation.py 의 Runner 패턴과 같다).
Runner = Callable[[Sequence[str], str, float], BazelRunResult]


def _default_runner(argv: Sequence[str], cwd: str, timeout: float) -> BazelRunResult:
    try:
        proc = subprocess.run(
            list(argv), cwd=cwd, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout,
        )
        return BazelRunResult(proc.returncode, proc.stdout or "", proc.stderr or "")
    except subprocess.TimeoutExpired as exc:
        def _text(value) -> str:
            if value is None:
                return ""
            return value if isinstance(value, str) else value.decode("utf-8", "replace")
        return BazelRunResult(
            124, _text(exc.stdout),
            _text(exc.stderr) + f"\nERROR: bazel build 타임아웃({timeout}s)",
        )
    except OSError as exc:
        return BazelRunResult(
            127, "",
            f"ERROR: bazel 을 찾을 수 없거나 실행할 수 없음: {argv[0]} ({exc})",
        )


def bazel_available(executable: str = "bazel") -> bool:
    """PATH 에 bazel(bazelisk)이 있는지. 테스트 skip 조건에 쓴다."""
    return shutil.which(executable) is not None


class BazelCompiler(Compiler):
    """하네스 소스를 Bazel 워크스페이스에 써 넣고 `bazel build` 로 검증한다.

    Args:
        workspace: MODULE.bazel 이 있는 워크스페이스 루트.
        target: 빌드할 레이블(예: ``//harness:json_fuzzer``).
        source_path: 하네스 소스를 쓸 경로. 워크스페이스 기준 상대 경로다
            (예: ``harness/json_fuzzer.cc``). BUILD 의 ``srcs`` 와 일치해야 한다.
        config: `--config=` 로 넘길 설정 이름. None 이면 붙이지 않는다.
        extra_args: `bazel build` 에 덧붙일 인자.
        timeout_sec: 빌드 타임아웃.
        executable: bazel 실행 파일(기본 ``bazel`` = bazelisk).
        runner: 실행기 주입(테스트용).

    Note:
        ``target`` 은 :meth:`compile` 이 만든 로그를 분류할 때
        `bazel_errors.classify(requested_target=...)` 로 넘기면 판별이 정확해진다.
        :attr:`requested_target` 으로 노출한다.
    """

    def __init__(
        self,
        workspace: str | Path,
        target: str,
        source_path: str,
        *,
        config: Optional[str] = None,
        extra_args: Optional[List[str]] = None,
        timeout_sec: float = 900.0,
        executable: str = "bazel",
        runner: Runner = _default_runner,
    ) -> None:
        self.workspace = Path(workspace)
        self.target = target
        self.source_path = source_path
        self.config = config
        self.extra_args = list(extra_args or [])
        self.timeout_sec = timeout_sec
        self.executable = executable
        self.runner = runner

    # -- 조회 -------------------------------------------------------------- #
    @property
    def requested_target(self) -> str:
        return self.target

    def available(self) -> bool:
        return bazel_available(self.executable)

    def argv(self) -> List[str]:
        argv = [self.executable, "build"]
        if self.config:
            argv.append(f"--config={self.config}")
        argv += self.extra_args
        argv.append(self.target)
        return argv

    def artifact_path(self) -> Optional[str]:
        """`//pkg:name` -> `bazel-bin/pkg/name`. 관례적 위치이므로 보장은 아니다."""
        if not self.target.startswith("//"):
            return None
        label = self.target[2:]
        package, _, name = label.partition(":")
        if not name:
            name = package.rsplit("/", 1)[-1]
        path = self.workspace / "bazel-bin" / package / name
        return str(path) if path.exists() else None

    # -- 컴파일 ------------------------------------------------------------ #
    def compile(self, draft: HarnessDraft, source: Optional[str] = None) -> CompileResult:
        code = source if source is not None else draft.source

        if not (self.workspace / "MODULE.bazel").exists() and \
                not (self.workspace / "WORKSPACE").exists():
            return CompileResult(
                ok=False, returncode=1,
                stderr=f"ERROR: Bazel 워크스페이스가 아니다(MODULE.bazel 없음): {self.workspace}",
            )

        # bazel 존재 여부를 여기서 미리 막지 않는다. 그건 실행기가 판단할 일이고
        # (기본 실행기는 OSError 를 127 로 바꿔 분명한 메시지를 남긴다), 미리 막으면
        # 실행기를 주입한 테스트에서 실제 PATH 에 의존하게 된다.
        destination = self.workspace / self.source_path
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(code, encoding="utf-8")
        except OSError as exc:
            return CompileResult(
                ok=False, returncode=1,
                stderr=f"ERROR: 하네스 소스를 쓰지 못했다({destination}): {exc}",
            )

        start = time.monotonic()
        result = self.runner(self.argv(), str(self.workspace), self.timeout_sec)
        duration = time.monotonic() - start
        ok = result.returncode == 0
        return CompileResult(
            ok=ok,
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            artifact_path=self.artifact_path() if ok else None,
            duration_sec=duration,
        )
