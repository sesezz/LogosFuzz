"""황다연 고도화 4주차: 지식베이스와 GEN 파이프라인 연결

KB 의 API/제약조건/빌드 단위를 하네스 초안, BUILD 생성, 자가치유 힌트, 검증 계약으로 전달
(계획 단계는 subprocess 없음, 실제 빌드는 기존 생성기에 위임)

GENERIC-A: 비-Bazel(cmake/prebuilt) 빌드 단위도 수용, 이때 ``build_deps`` 는 링크할
라이브러리 경로이며 빌드는 ``generate.build.adapter_for(profile)`` 담당
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from logosfuzz.knowledge.kb_adapters import (
    as_include_path,
    build_unit_for_api,
    build_unit_metadata,
    harness_context,
)
from logosfuzz.knowledge.knowledge_base import KnowledgeBase

from .bazel.build_file import fuzz_package_for, parse_label
from .build_file_generator import BuildFileGenerator, GenerateReport
from .contracts import ApiSignature, HarnessArtifact
from .models import HarnessDraft


class KnowledgeBridgeError(ValueError):
    """KB 정보를 GEN 입력으로 변환할 수 없을 때 발생"""


class ApiNotFoundError(KnowledgeBridgeError):
    pass


class MissingBuildUnitError(KnowledgeBridgeError):
    pass


class UnsupportedApiError(KnowledgeBridgeError):
    pass


def _unique(values: Iterable[object]) -> List[str]:
    result: List[str] = []
    for value in values:
        text = str(value)
        if text and text not in result:
            result.append(text)
    return result


def _local_label(label: str) -> str:
    parsed = parse_label(label)
    return f"//{parsed.package}:{parsed.target}"


def _with_repository(label: str, repository: str) -> str:
    parsed = parse_label(label)
    if parsed.repo or not repository:
        return parsed.text
    return f"@{repository}//{parsed.package}:{parsed.target}"


def _visible_to_fuzz_package(label: str, visibility: Iterable[str],
                             target_label: str) -> bool:
    """Return true only when the known Bazel visibility admits the fuzz rule."""
    dependency = parse_label(label)
    consumer = parse_label(target_label)
    consumer_package = fuzz_package_for(target_label)
    if dependency.repo == consumer.repo and dependency.package == consumer_package:
        return True  # Bazel always allows access within the same package.
    for rule in visibility:
        if rule == "//visibility:public":
            return True
        if rule == "//visibility:private":
            continue
        if rule.startswith(":"):
            rule = f"//{dependency.package}{rule}"
        try:
            allowed = parse_label(rule)
        except ValueError:
            # A package_group needs Bazel to resolve it. Unknown visibility is
            # not evidence that this direct dependency is safe to add.
            continue
        allowed_repo = allowed.repo or dependency.repo
        if allowed_repo != consumer.repo:
            continue
        if allowed.target == "__pkg__" and consumer_package == allowed.package:
            return True
        if allowed.target == "__subpackages__" and (
            not allowed.package
            or consumer_package == allowed.package
            or consumer_package.startswith(f"{allowed.package}/")
        ):
            return True
    return False


def _is_bazel_unit(unit: dict) -> bool:
    """빌드 시스템 값이 없는 KB 단위는 Bazel 로 간주 (2주차 스키마)"""
    return str(unit.get("build_system") or "bazel") == "bazel"


class KnowledgeBaseDepsProvider:
    """KB의 Bazel 소유권/직접 의존성을 BUILD 생성기에 공급"""

    def __init__(self, kb: KnowledgeBase) -> None:
        # Bazel 단위만 대상 (cmake/prebuilt 단위의 build_target 은 라벨 아님)
        self._units = {
            parse_label(unit["build_target"]).text: unit
            for unit in build_unit_metadata(kb)
            if unit.get("build_target") and _is_bazel_unit(unit)
        }

    def deps_for(self, target_label: str) -> List[str]:
        requested = parse_label(target_label)
        unit = self._units.get(requested.text) or self._units.get(
            _local_label(target_label)
        )
        if unit is None:
            return [target_label]
        labels = [target_label]
        for dependency in unit.get("build_deps", []):
            label = _with_repository(dependency, requested.repo)
            parsed_dependency = parse_label(label)
            dependency_unit = self._units.get(parsed_dependency.text)
            if dependency_unit is None and parsed_dependency.repo == requested.repo:
                dependency_unit = self._units.get(_local_label(label))
            if dependency_unit and _visible_to_fuzz_package(
                label, dependency_unit.get("visibility", []), target_label
            ):
                labels.append(label)
        return _unique(labels)


@dataclass(frozen=True)
class HarnessBuildPlan:
    """KB 한 건에서 결정된 생성·빌드·검증 공통 입력"""

    api_id: int
    api_name: str
    signature: str
    return_type: str
    param_types: tuple[str, ...]
    source_file: str
    target_label: str
    build_rule_kind: str
    build_deps: tuple[str, ...]
    compile_flags: tuple[str, ...]
    include: str
    constraints: tuple[str, ...]
    error_contracts: tuple[str, ...]
    logic_group: str
    language: str
    prompt_context: str
    #: 빌드 단위의 빌드 시스템 ("bazel" / "cmake" / "prebuilt")
    #: bazel 이 아니면 ``target_label`` 은 프로필 이름, ``build_deps`` 는 라이브러리 경로
    build_system: str = "bazel"

    @property
    def is_bazel(self) -> bool:
        return self.build_system == "bazel"

    def repair_knowledge(self) -> Dict[str, str]:
        """SelfHealLoop.knowledge에 바로 전달 가능한 힌트"""
        if not self.is_bazel:
            return {
                "target_api": self.signature,
                "build_system": self.build_system,
                "build_target": self.target_label,
                "link_libraries": " ".join(self.build_deps),
                "include": self.include,
                "compile_flags": " ".join(self.compile_flags),
                "constraints": "\n".join(self.constraints),
                "error_contracts": "\n".join(self.error_contracts),
            }
        return {
            "target_api": self.signature,
            "bazel_target": self.target_label,
            "bazel_deps": " ".join(self.build_deps),
            "include": self.include,
            "compile_flags": " ".join(self.compile_flags),
            "constraints": "\n".join(self.constraints),
            "error_contracts": "\n".join(self.error_contracts),
        }

    def configure_self_heal(self, loop: object) -> object:
        """KB 힌트를 기존 자가치유 루프에 주입 후 같은 객체 반환"""
        current = getattr(loop, "knowledge", None) or {}
        merged = self.repair_knowledge()
        merged.update({str(key): str(value) for key, value in current.items()})
        setattr(loop, "knowledge", merged)
        return loop

    def to_draft(self, source: str, *, project: str = "") -> HarnessDraft:
        return HarnessDraft(
            logic_group=self.logic_group,
            source=source,
            project=project,
            target_apis=[self.api_name],
            language=self.language,
            context=(
                {
                    "bazel_target": self.target_label,
                    "kb_context": self.prompt_context,
                    "repair_knowledge": self.repair_knowledge(),
                }
                if self.is_bazel else
                {
                    "build_system": self.build_system,
                    "build_target": self.target_label,
                    "kb_context": self.prompt_context,
                    "repair_knowledge": self.repair_knowledge(),
                }
            ),
        )

    def api_signature(self) -> ApiSignature:
        return ApiSignature(
            name=self.api_name,
            param_types=list(self.param_types),
            return_type=self.return_type,
            source=self.source_file,
        )


@dataclass(frozen=True)
class KnowledgeBuildResult:
    plan: HarnessBuildPlan
    build_report: GenerateReport
    artifact: Optional[HarnessArtifact] = None

    @property
    def ok(self) -> bool:
        return self.build_report.ok and self.artifact is not None


def plan_harness(
    kb: KnowledgeBase,
    api: int | str,
    *,
    target_label: str = "",
    logic_group: str = "",
) -> HarnessBuildPlan:
    """API 정확 조회 후 GEN 전체가 공유하는 계획 생성"""
    document = kb.api(api)
    if document is None:
        raise ApiNotFoundError(f"지식베이스에서 API를 찾지 못했다: {api!r}")
    if document.get("is_static"):
        raise UnsupportedApiError(f"static API는 외부 하네스에서 호출할 수 없다: {api!r}")
    if document.get("is_test"):
        raise UnsupportedApiError(f"테스트/예제 API는 퍼징 대상에서 제외한다: {api!r}")

    unit = build_unit_for_api(kb, document["api_id"])
    if unit is None:
        raise MissingBuildUnitError(
            f"API에 빌드 단위가 연결되지 않았다: {document['function']}"
        )

    build_system = str(unit.get("build_system") or "bazel")
    requested = target_label or str(unit["build_target"])
    if build_system == "bazel":
        deps = KnowledgeBaseDepsProvider(kb).deps_for(requested)
    else:
        # cmake/prebuilt: 라이브러리 전체가 단위 1개, deps 는 링크할 라이브러리
        deps = _unique(unit.get("build_deps", []))
    flags = _unique(
        [*unit.get("compile_flags", []), *document.get("compile_flags", [])]
    )
    include = (
        as_include_path(document.get("header", ""))
        if document.get("header")
        else ""
    )
    descriptions = _unique(
        constraint.get("description", "")
        for constraint in document.get("constraints", [])
    )
    error_contracts = _unique(
        constraint.get("description", "")
        for constraint in document.get("constraints", [])
        if constraint.get("kind") == "error_contract"
    )
    params = tuple(str(param.get("type", "")) for param in document.get("params", []))
    file_name = str(document.get("file", ""))
    cpp_suffixes = {".cc", ".cpp", ".cxx", ".hpp", ".hh"}
    language = "cpp" if Path(file_name).suffix.lower() in cpp_suffixes else "c"

    return HarnessBuildPlan(
        api_id=int(document["api_id"]),
        api_name=str(document["function"]),
        signature=str(document.get("signature", "")),
        return_type=str(document.get("return_type", "void")),
        param_types=params,
        source_file=file_name,
        target_label=requested,
        build_rule_kind=str(unit.get("build_rule_kind", "")),
        build_deps=tuple(deps),
        compile_flags=tuple(flags),
        include=include,
        constraints=tuple(descriptions),
        error_contracts=tuple(error_contracts),
        logic_group=logic_group or f"kb-api-{document['api_id']}",
        language=language,
        prompt_context=harness_context(kb, document["api_id"]),
        build_system=build_system,
    )


def build_harness_from_kb(
    kb: KnowledgeBase,
    api: int | str,
    harness_source: str,
    generator: BuildFileGenerator,
    *,
    target_label: str = "",
    logic_group: str = "",
    corpus_dir: Path | None = None,
    gen_model: str = "",
) -> KnowledgeBuildResult:
    """KB 기반 BUILD 생성·빌드 및 성공 시 검증용 artifact 생성"""
    plan = plan_harness(kb, api, target_label=target_label, logic_group=logic_group)
    if not plan.is_bazel:
        raise KnowledgeBridgeError(
            f"{plan.build_system} 빌드 단위는 Bazel BUILD 생성기로 빌드할 수 없다. "
            "logosfuzz.generate.build.adapter_for(profile) 를 사용한다."
        )
    spec = generator.make_spec(plan.target_label).with_deps(plan.build_deps)
    report = generator.generate(plan.target_label, harness_source, spec=spec)
    artifact = None
    if report.ok and report.binary is not None:
        package_dir = getattr(generator.adapter, "package_dir", None)
        source_path = None
        if callable(package_dir):
            source_path = Path(package_dir(report.spec)) / report.spec.srcs[0]
        artifact = HarnessArtifact(
            group_id=plan.logic_group,
            harness_path=report.binary,
            source_path=source_path,
            corpus_dir=corpus_dir,
            api_signatures=[plan.api_signature()],
            gen_model=gen_model,
        )
    return KnowledgeBuildResult(plan=plan, build_report=report, artifact=artifact)
