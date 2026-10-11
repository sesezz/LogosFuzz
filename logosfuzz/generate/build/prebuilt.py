"""
Prebuilt 어댑터 (GENERIC-B)
===========================

이미 빌드된 라이브러리(``profile.build.libraries``)에 하네스만 링크한다. configure 도
라이브러리 빌드도 하지 않는다. 다음 경우에 쓴다.

* 라이브러리를 다른 곳에서 빌드해 둔 경우(공급받은 정적 라이브러리, CI 산출물)
* CMake 빌드가 어려운 대상에서 **공식 하네스를 보험으로** 링크해 EXE 이후 흐름만 먼저 확인할 때

링크 단계는 ``CMakeAdapter.build`` 와 같다(clang, ``-fsanitize=address,undefined,fuzzer``).
주의: 라이브러리가 계측 없이 빌드되어 있으면 하네스 코드만 계측되므로 커버리지는
하네스 파일에 한정된다. ``coverage=True`` 는 링크 플래그만 바꿀 뿐 라이브러리를 다시
빌드하지 않는다.
"""
from __future__ import annotations

import time

from .base import BuildResult
from .cmake import CMakeAdapter


class PrebuiltAdapter(CMakeAdapter):
    """라이브러리를 만들지 않고 링크만 하는 어댑터."""

    def prepare(self, *, force: bool = False) -> BuildResult:  # noqa: ARG002 - 호환용 인자
        """``libraries`` 와 ``include_dirs`` 가 실제로 있는지만 확인한다."""
        target = f"prebuilt:{self.profile.name}"
        started = time.monotonic()
        problems = []

        libraries = self.libraries
        if not libraries:
            problems.append("profile.build.libraries 가 비어 있다 — 링크할 라이브러리를 적어라")
        problems += [f"라이브러리가 없다: {lib}" for lib in libraries if not lib.is_file()]
        problems += [f"include 경로가 없다: {inc}" for inc in self.include_dirs if not inc.is_dir()]

        if problems:
            return BuildResult(
                ok=False, target=target,
                log="ERROR: prebuilt 대상이 준비되지 않았다\n" + "\n".join(f"ERROR: {p}" for p in problems),
                duration_s=time.monotonic() - started,
            )
        self._prepared = True
        return BuildResult(ok=True, target=target,
                           log=f"(prebuilt) 라이브러리 {len(libraries)}개 확인",
                           duration_s=time.monotonic() - started)
