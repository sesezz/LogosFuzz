"""황다연 고도화 4주차: 지식베이스와 GEN 파이프라인 연결.

3주차까지 추출한 API/제약조건/Bazel 빌드 단위를 하네스 초안,
BUILD 생성, 자가치유 힌트, 검증 계약으로 한 번에 전달한다.
계획 단계는 subprocess 없이 동작하고, 실제 빌드는 기존 생성기에 위임한다.
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

from .bazel.build_file import parse_label
from .build_file_generator import BuildFileGenerator, GenerateReport
from .contracts import ApiSignature, HarnessArtifact
from .models import HarnessDraft


class KnowledgeBridgeError(ValueError):
    """KB 정보를 GEN 입력으로 바꿀 수 없을 때 발생한다."""


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


class KnowledgeBaseDepsProvider:
    """KB의 Bazel 소유권/직접 의존성을 BUILD 생성기에 공급한다."""

    def __init__(self, kb: KnowledgeBase) -> None:
        self._units = {
            _local_label(unit["build_target"]): unit
            for unit in build_unit_metadata(kb)
            if unit.get("build_target")
        }

    def deps_for(self, target_label: str) -> List[str]:
        requested = parse_label(target_label)
        key = f"//{requested.package}:{requested.target}"
        unit = self._units.get(key)
        if unit is None:
            return [target_label]
        labels = [unit["build_target"], *unit.get("build_deps", [])]
        return _unique(_with_repository(label, requested.repo) for label in labels)


@dataclass(frozen=True)
class HarnessBuildPlan:
    """KB 한 건에서 결정된 생성·빌드·검증 공통 입력."""

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

    def repair_knowledge(self) -> Dict[str, str]:
        """SelfHealLoop.knowledge에 바로 전달할 수 있는 힌트."""
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
        """KB 힌트를 기존 자가치유 루프에 주입하고 같은 객체를 반환한다."""
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
            context={
                "bazel_target": self.target_label,
                "kb_context": self.prompt_context,
                "repair_knowledge": self.repair_knowledge(),
            },
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
    """API를 정확히 조회하여 GEN 전체가 공유하는 계획을 만든다."""
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
            f"API에 Bazel 빌드 단위가 연결되지 않았다: {document['function']}"
        )

    requested = target_label or str(unit["build_target"])
    deps = KnowledgeBaseDepsProvider(kb).deps_for(requested)
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
        prompt_context=harness_context(kb, str(document["function"])),
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
    """KB 기반 BUILD를 생성·빌드하고 성공 시 검증용 artifact까지 만든다."""
    plan = plan_harness(kb, api, target_label=target_label, logic_group=logic_group)
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
