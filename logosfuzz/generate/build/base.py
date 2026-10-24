"""
GEN 빌드 어댑터 공통 계약 (GENERIC-B)
=====================================

파이프라인의 공통 계약은 빌드 시스템이 아니라 **산출물**이다.

    어느 대상이든 최종 산출물 =
        clang + libFuzzer + sanitizer 로 빌드된,
        LLVMFuzzerTestOneInput 을 export 하는 실행 파일 1개

그 파일만 나오면 그 아래(EXE 실행 / ANA 트리아지 / 커버리지)는 Bazel 이든 CMake 든
동일하다. 어댑터는 빌드한 실행 파일의 **실제 경로**를 ``BuildResult.binary`` 로 돌려주고,
EXE(``docker_runner``, ``coverage``)는 그 경로를 ``LogicGroup.harness_path`` 로 받아 쓴다.
경로 형식은 정해져 있지 않다.

이 모듈은 원래 ``generate/bazel/adapter.py`` 에 있던 ``BuildResult`` / ``BuildAdapter`` 를
빌드 시스템 중립 위치로 옮긴 것이다. ``bazel/adapter.py`` 는 같은 이름을 **재수출**하므로
기존 ``from logosfuzz.generate.bazel.adapter import BuildResult`` 는 그대로 동작하고
같은 객체를 가리킨다(Bazel 동작은 바뀌지 않는다).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Protocol, Sequence, Tuple

# 실패 원인으로 읽을 줄. 빌드 시스템마다 형식이 다르다.
#   clang/gcc  : harness.c:12:5: error: ...  /  fatal error: ...  (색 제어문자가 섞여도 잡는다)
#   드라이버   : clang: error: linker command failed with exit code 1
#   링커       : undefined reference to / ld.lld: error: / multiple definition of / cannot find -l
_DIAGNOSTIC_RE = re.compile(
    r":\d+:\d+: (?:\x1b\[[0-9;]*m)*(?:fatal )?error"
    r"|(?:clang|gcc|cc)(?:\+\+)?: (?:fatal )?error"
    r"|undefined reference to"
    r"|undefined symbol"
    r"|ld(?:\.lld)?: error"
    r"|multiple definition of"
    r"|cannot find -l"
)

# 빌드 도구가 직접 찍는 오류 줄의 접두사(Bazel 의 ``ERROR``, CMake 의 ``CMake Error``).
_ERROR_LINE_PREFIXES = ("ERROR", "CMake Error")

# 빌드 명령 1회의 기본 제한 시간. 제한이 없으면 멈춘 빌드 도구 하나가 파이프라인 전체를
# 붙잡는다. 더 오래 걸리는 대상은 timeout_s 로 늘린다.
DEFAULT_BUILD_TIMEOUT_S = 3600.0


@dataclass
class BuildResult:
    """빌드 1회 시도의 결과."""

    ok: bool
    target: str
    log: str = ""
    binary: Optional[Path] = None
    duration_s: float = 0.0
    command: Sequence[str] = field(default_factory=tuple)

    @property
    def short_log(self) -> str:
        """실패 원인 요약: 빌드 도구의 오류 줄 + 컴파일러·링커 진단.

        Bazel 의 ``ERROR`` 줄은 "컴파일 실패" 까지만 말하고 뒤의 clang 인자를 생략한다
        ("... (remaining 47 arguments skipped)"). 진짜 원인(없는 멤버, 헤더 가시성, 미정의
        심볼 등)은 그 아래 진단에 있으므로 같이 싣지 않으면 요약 JSON 만 봐서는 왜 실패했는지
        알 수 없다. CMake 경로에서는 ``CMake Error`` 줄과 링커 오류(``undefined reference``
        등)를 같은 방식으로 싣는다. 경고는 싣지 않는다.
        """
        lines = self.log.splitlines()
        picked = [ln for ln in lines if ln.startswith(_ERROR_LINE_PREFIXES)][:5]
        picked += [ln for ln in lines
                   if _DIAGNOSTIC_RE.search(ln) and ln not in picked][:12]
        return "\n".join(picked) or self.log[-500:]


class HarnessSpecLike(Protocol):
    """어댑터가 하네스 하나에 대해 읽는 최소 속성.

    Bazel 의 ``FuzzTargetSpec`` 도 이 속성을 가지고 있어서 그대로 넘길 수 있다.
    """

    @property
    def name(self) -> str: ...

    @property
    def package(self) -> str: ...

    @property
    def srcs(self) -> Sequence[str]: ...


@dataclass(frozen=True)
class HarnessSpec:
    """빌드 시스템에 묶이지 않은 하네스 명세 (CMake / prebuilt 용).

    Attributes:
        name: 하네스(실행 파일) 이름. 바이너리 파일 이름이 된다.
        srcs: 하네스 소스 파일 이름. **1개**여야 한다.
        package: 작업 디렉터리 안에서 소스를 둘 하위 경로(비우면 바로 아래).
        deps: Bazel 라벨 같은 의존 목록. CMake 는 ``profile.build.libraries`` 를 쓰므로
            쓰지 않지만, 기존 코드가 ``spec.deps`` 를 읽어도 깨지지 않게 둔다.
    """

    name: str
    srcs: Tuple[str, ...]
    package: str = ""
    deps: Tuple[str, ...] = ()

    @property
    def label(self) -> str:
        """``BuildResult.target`` 과 로그에 쓰는 이름 (Bazel 의 ``label`` 대응)."""
        return self.name

    @property
    def bin_label(self) -> str:
        """실행 파일을 가리키는 이름 (Bazel 의 ``bin_label`` 대응)."""
        return self.name


class BuildAdapter(Protocol):
    """빌드 시스템 1종을 감싸는 어댑터."""

    def emit_build_definition(self, spec: HarnessSpecLike, harness_source: str) -> Path:
        """하네스 소스(와 빌드 정의)를 작업 위치에 쓴다. 쓴 파일 경로를 돌려준다.

        Bazel 은 BUILD 파일 경로, CMake / prebuilt 는 하네스 소스 경로(빌드 정의를
        따로 쓰지 않는다).
        """
        ...

    def build(self, spec: HarnessSpecLike) -> BuildResult:
        """퍼저 바이너리를 만든다. 성공하면 ``BuildResult.binary`` 에 실제 경로를 담는다."""
        ...

    def remove(self, spec: HarnessSpecLike) -> None:
        """생성한 것을 되돌린다."""
        ...
