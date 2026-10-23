"""
GEN 빌드 어댑터 패키지 (GENERIC-B)
==================================

``adapter_for(profile)`` 가 ``profile.build.system`` 으로 어댑터를 고른다.

    bazel    -> generate/bazel/adapter.py 의 BazelAdapter (기존 그대로)
    cmake    -> CMakeAdapter  (라이브러리를 계측 빌드하고 하네스를 직접 링크)
    prebuilt -> PrebuiltAdapter (빌드된 라이브러리에 하네스만 링크)

Bazel 경로는 이 패키지가 생기기 전과 동작이 같다. ``BuildResult`` / ``BuildAdapter`` 는
``base`` 로 옮겼고 ``bazel/adapter.py`` 가 재수출한다.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from .base import BuildAdapter, BuildResult, HarnessSpec, HarnessSpecLike
from .cmake import CMakeAdapter, RunResult, Runner, default_runner
from .prebuilt import PrebuiltAdapter

__all__ = [
    "BuildAdapter", "BuildResult", "HarnessSpec", "HarnessSpecLike",
    "CMakeAdapter", "PrebuiltAdapter", "RunResult", "Runner", "default_runner",
    "adapter_for",
]


def adapter_for(
    profile: Any,
    *,
    work_dir: Path | str | None = None,
    coverage: bool = False,
    runner: Optional[Runner] = None,
    jobs: Optional[int] = None,
    timeout_s: Optional[float] = None,
    bazel: str = "bazel",
    config: str = "fuzz",
) -> BuildAdapter:
    """프로필에 맞는 빌드 어댑터를 만든다.

    Args:
        profile: ``load_profile()`` 결과(``TargetProfile``).
        work_dir: CMake/prebuilt 의 하네스 소스(``harness/``)와 바이너리(``bin/``) 위치.
            기본은 ``<cwd>/out/generic/<profile.name>``. Bazel 은 쓰지 않는다.
        coverage: CMake 에서 ``<build_dir>-cov`` 커버리지 계측 변형을 만든다.
            Bazel 은 별도 config 로 처리하므로 무시한다.
        runner: 외부 명령 실행기 주입(테스트용). Bazel 은 쓰지 않는다.
        jobs, timeout_s: 병렬 빌드 수 / 명령 1회 제한 시간.
        bazel, config: Bazel 실행 파일 / ``--config`` (기본 ``fuzz``).

    Raises:
        ValueError: 알 수 없는 ``build.system``.
    """
    system = profile.build.system
    if system == "bazel":
        # 지연 import: bazel/adapter.py 가 이 패키지(base)를 import 하므로 순환을 피한다.
        from logosfuzz.generate.bazel.adapter import BazelAdapter

        workspace = profile.abs(profile.build.bazel.workspace)
        return BazelAdapter(workspace, config=config, bazel=bazel, timeout_s=timeout_s)
    if system == "cmake":
        return CMakeAdapter(profile, work_dir=work_dir, coverage=coverage, runner=runner,
                            jobs=jobs, timeout_s=timeout_s)
    if system == "prebuilt":
        return PrebuiltAdapter(profile, work_dir=work_dir, coverage=coverage, runner=runner,
                               jobs=jobs, timeout_s=timeout_s)
    raise ValueError(f"지원하지 않는 build.system: {system!r} (bazel / cmake / prebuilt)")
