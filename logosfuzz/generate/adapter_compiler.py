"""GENERIC-C 자가치유 컴파일 백엔드: ``adapter_for(profile)`` 의 빌드 어댑터 사용

자가치유 루프(``selfheal.py``)와 검증 피드백 루프(``feedback_loop.py``)는
:class:`~logosfuzz.generate.compiler.Compiler` 인터페이스만 의존. 기존 구현은

    SubprocessCompiler  clang -c 로 빠르게 컴파일만 확인
    BazelCompiler       bazel build (자동차/S-CORE)

두 가지. CMake/prebuilt 대상(libsndfile, 임베디드 샘플)은 **라이브러리와 링크까지
해야** 실패 원인(미정의 HAL 심볼 등)이 드러나므로, GENERIC-B 빌드 어댑터
(``generate/build`` 의 ``CMakeAdapter``/``PrebuiltAdapter``)를 감싸는 백엔드 추가
기존 두 백엔드는 그대로 유지

    profile ──adapter_for──▶ BuildAdapter ──AdapterCompiler──▶ SelfHealLoop
                                     ▲
                       스텁 C 파일을 link_flags 에 더해 재빌드(stubs.py)

빌드 성공 시 ``CompileResult.artifact_path`` 는 어댑터가 돌려준 실행 파일의 실제
경로(``BuildResult.binary``). EXE 는 이 경로를 ``LogicGroup.harness_path`` 로 사용

``adapter_for`` 는 지연 import. 빌드 어댑터 머지 전에도 이 모듈은 import 되고,
테스트는 ``adapter_factory`` 로 가짜 어댑터를 주입
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, List, Optional, Tuple

from .compiler import Compiler
from .models import CompileResult, HarnessDraft
from .stubs import StubPolicy, StubSet

# profile -> BuildAdapter. 기본은 logosfuzz.generate.build.adapter_for.
AdapterFactory = Callable[[Any], Any]

_CPP_LANGUAGES = ("cpp", "c++", "cxx")


@dataclass(frozen=True)
class HarnessBuildSpec:
    """어댑터에 넘기는 하네스 명세(``HarnessSpecLike`` 와 같은 속성)"""

    name: str
    srcs: Tuple[str, ...]
    package: str = ""
    deps: Tuple[str, ...] = ()

    @property
    def label(self) -> str:
        return self.name

    @property
    def bin_label(self) -> str:
        return self.name


def default_adapter_factory(work_dir: Optional[Path] = None, **kwargs) -> AdapterFactory:
    """``adapter_for(profile, work_dir=..., **kwargs)`` 를 호출하는 팩토리"""

    def factory(profile):
        try:
            from logosfuzz.generate.build import adapter_for
        except ImportError as exc:  # GENERIC-B 빌드 어댑터 머지 전
            raise RuntimeError(
                "logosfuzz.generate.build.adapter_for 가 없다 — GENERIC-B 빌드 어댑터가 "
                "머지된 뒤에 쓰거나 adapter_factory 를 주입하라"
            ) from exc
        return adapter_for(profile, work_dir=work_dir, **kwargs)

    return factory


def _with_extra_link_inputs(profile, extra: List[str]):
    """프로필의 ``build.link_flags`` 뒤에 파일을 더한 사본(프로필은 frozen)"""
    if not extra:
        return profile
    build = dataclasses.replace(profile.build,
                                link_flags=tuple(profile.build.link_flags) + tuple(extra))
    return dataclasses.replace(profile, build=build)


class AdapterCompiler(Compiler):
    """빌드 어댑터로 하네스를 **링크까지** 시도하는 컴파일 백엔드

    Args:
        profile: ``TargetProfile`` (cmake / prebuilt)
        adapter_factory: ``profile -> BuildAdapter``. 기본은 ``adapter_for``.
        work_dir: 스텁 파일 위치. 기본은 ``<cwd>/out/generic/<profile.name>``
        kb: 스텁 시그니처를 찾을 KnowledgeBase (선택)
    """

    def __init__(
        self,
        profile,
        *,
        adapter_factory: Optional[AdapterFactory] = None,
        work_dir: Path | str | None = None,
        kb=None,
    ) -> None:
        self.profile = profile
        self.work_dir = (Path(work_dir) if work_dir is not None
                         else Path.cwd() / "out" / "generic" / profile.name)
        self._factory = adapter_factory or default_adapter_factory(work_dir=self.work_dir)
        self.stubs = StubSet(kb=kb)
        self.stub_policy = StubPolicy.from_profile(profile)
        self.last_build = None
        self._adapter = None

    # ------------------------------------------------------------------ #
    @property
    def adapter(self):
        """현재 스텁 구성을 반영한 어댑터(필요 시 생성)"""
        if self._adapter is None:
            self._adapter = self._factory(self.effective_profile)
        return self._adapter

    @property
    def stub_path(self) -> Path:
        return self.work_dir / "stubs" / f"{self.profile.name}_stubs.c"

    @property
    def effective_profile(self):
        """스텁 파일을 링크 입력에 추가한 프로필"""
        extra = [str(self.stub_path)] if self.stubs.symbols else []
        return _with_extra_link_inputs(self.profile, extra)

    @property
    def stub_symbols(self) -> List[str]:
        return list(self.stubs.symbols)

    def apply_stubs(self, symbols) -> List[str]:
        """스텁 추가 후 파일 재작성. 다음 compile 부터 링크에 포함"""
        added = self.stubs.add(symbols)
        if added:
            self.stubs.write(self.stub_path)
            self._adapter = None  # link_flags 가 바뀌었으므로 어댑터 재생성
        return added

    # ------------------------------------------------------------------ #
    def spec_for(self, draft: HarnessDraft) -> HarnessBuildSpec:
        suffix = ".cc" if draft.language in _CPP_LANGUAGES else ".c"
        return HarnessBuildSpec(name=draft.logic_group, srcs=(f"{draft.logic_group}{suffix}",))

    def compile(self, draft: HarnessDraft, source: Optional[str] = None) -> CompileResult:
        code = source if source is not None else draft.source
        spec = self.spec_for(draft)
        adapter = self.adapter
        adapter.emit_build_definition(spec, code)
        result = adapter.build(spec)
        self.last_build = result
        return CompileResult(
            ok=bool(result.ok),
            returncode=0 if result.ok else 1,
            stderr=result.log or "",
            artifact_path=str(result.binary) if result.ok and result.binary else None,
            duration_sec=float(getattr(result, "duration_s", 0.0) or 0.0),
        )


def classifier_for(profile):
    """빌드 로그 분류기. Bazel 은 기존 분류기, 그 외는 컴파일러·링커 원문 분류기"""
    if profile is not None and profile.build.system == "bazel":
        from .bazel_errors import classify

        return classify
    from .errors import classify_toolchain_log

    return classify_toolchain_log


def compiler_for(profile, *, adapter_factory: Optional[AdapterFactory] = None,
                 work_dir: Path | str | None = None, kb=None) -> AdapterCompiler:
    """프로필에 맞는 자가치유 컴파일 백엔드

    Bazel 대상은 하네스마다 BUILD 타깃·소스 경로가 따로 있어서 프로필만으로 생성
    불가 — ``BazelCompiler(workspace, target, source_path)`` 직접 사용

    Raises:
        ValueError: ``build.system == "bazel"``.
    """
    if profile.build.system == "bazel":
        raise ValueError("Bazel 대상은 기존 BazelCompiler 경로를 쓴다(하네스 타깃이 필요하다)")
    return AdapterCompiler(profile, adapter_factory=adapter_factory, work_dir=work_dir, kb=kb)


def heal_loop_for(profile, llm, *, max_round: int = 3, kb=None,
                  adapter_factory: Optional[AdapterFactory] = None,
                  work_dir: Path | str | None = None, **loop_kwargs):
    """프로필 하나로 자가치유 루프 조립(컴파일 백엔드·분류기·스텁 정책)"""
    from .selfheal import SelfHealLoop

    compiler = compiler_for(profile, adapter_factory=adapter_factory, work_dir=work_dir, kb=kb)
    return SelfHealLoop(
        compiler,
        llm,
        max_round=max_round,
        classifier=classifier_for(profile),
        stub_policy=compiler.stub_policy,
        **loop_kwargs,
    )


__all__ = [
    "AdapterCompiler",
    "AdapterFactory",
    "HarnessBuildSpec",
    "classifier_for",
    "compiler_for",
    "default_adapter_factory",
    "heal_loop_for",
]
