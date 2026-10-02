from pathlib import Path

import pytest

from logosfuzz.generate.bazel.adapter import BuildResult
from logosfuzz.generate.build_file_generator import BuildFileGenerator
from logosfuzz.generate.kb_bridge import (
    ApiNotFoundError,
    KnowledgeBaseDepsProvider,
    MissingBuildUnitError,
    UnsupportedApiError,
    build_harness_from_kb,
    plan_harness,
)
from logosfuzz.knowledge.knowledge_base import KnowledgeBase


def _document(**updates):
    document = {
        "api_id": 7,
        "function": "parse_json",
        "signature": "score::Result<Value> parse_json(ByteSpan input)",
        "return_type": "score::Result<Value>",
        "params": [{"type": "ByteSpan", "name": "input"}],
        "file": "score/json/parser.cpp",
        "line": 42,
        "header": "score/json/parser.h",
        "doc": "Parse JSON without throwing.",
        "text": "function parse_json score Result ByteSpan parse error",
        "constraints": [
            {
                "kind": "bounds",
                "target": "input",
                "description": "input length is bounded",
                "confidence": 0.9,
                "expression": "input.size() <= max_size",
            },
            {
                "kind": "error_contract",
                "target": "return",
                "description": "score::Result may contain a parse error",
                "confidence": 0.95,
                "expression": "return error(ParseError)",
            },
        ],
        "calls_internal": [],
        "called_by": [],
        "call_seq_ids": [],
        "compile_flags": ["-DSCORE_JSON=1"],
        "build_system": "bazel",
        "build_target": "//score/json:json",
        "build_rule_kind": "cc_library",
        "build_deps": ["//score/base:base"],
        "is_static": False,
        "is_test": False,
    }
    document.update(updates)
    return document


def _kb(document=None, *, with_unit=True):
    document = document or _document()
    units = []
    if with_unit:
        units.append(
            {
                "target": "//score/json:json",
                "rule_kind": "cc_library",
                "deps": ["//score/base:base", "//score/base:base"],
                "sources": ["score/json/parser.cpp"],
                "headers": ["score/json/parser.h"],
                "include_dirs": ["."],
                "compile_flags": ["-Wall", "-DSCORE_JSON=1"],
                "build_file": "score/json/BUILD",
                "build_system": "bazel",
            }
        )
        units.append(
            {
                "target": "//score/base:base",
                "rule_kind": "cc_library",
                "visibility": ["//visibility:public"],
                "build_system": "bazel",
            }
        )
    return KnowledgeBase(documents=[document], build_units=units)


def test_kb_deps_provider_preserves_external_repository():
    deps = KnowledgeBaseDepsProvider(_kb()).deps_for(
        "@score_baselibs//score/json:json"
    )

    assert deps == [
        "@score_baselibs//score/json:json",
        "@score_baselibs//score/base:base",
    ]


def test_kb_deps_provider_skips_private_and_unknown_direct_deps():
    kb = _kb()
    kb.build_units[0]["deps"] = [
        "//score/json:json_builder",
        "//score/json:parser_interface",
        "//score/base:base",
        "//score/json:unresolved",
    ]
    kb.build_units.extend([
        {
            "target": "//score/json:json_builder",
            "rule_kind": "cc_library",
            "visibility": ["//visibility:private"],
        },
        {
            "target": "//score/json:parser_interface",
            "rule_kind": "cc_library",
            "visibility": ["//score/json:__subpackages__"],
        },
    ])

    assert KnowledgeBaseDepsProvider(kb).deps_for(
        "@score_baselibs//score/json:json"
    ) == [
        "@score_baselibs//score/json:json",
        "@score_baselibs//score/json:parser_interface",
        "@score_baselibs//score/base:base",
    ]


def test_plan_uses_api_id_for_context_when_names_collide():
    first = _document()
    second = _document(
        api_id=8,
        signature="score::Result<Other> parse_json(OtherSpan input)",
        file="score/json/other_parser.cpp",
        constraints=[{
            "kind": "bounds",
            "target": "input",
            "description": "second API only",
            "confidence": 0.9,
            "expression": "input.size() > 0",
        }],
    )
    kb = KnowledgeBase(
        documents=[first, second], build_units=_kb().build_units
    )

    plan = plan_harness(kb, 8)

    assert plan.api_id == 8
    assert "second API only" in plan.prompt_context
    assert "OtherSpan" in plan.prompt_context
    assert "api_id=7" not in plan.prompt_context


def test_plan_connects_kb_to_draft_repair_and_validation_contracts():
    plan = plan_harness(
        _kb(),
        "parse_json",
        target_label="@score_baselibs//score/json:json",
        logic_group="json-parse",
    )

    assert plan.language == "cpp"
    assert plan.include == "score/json/parser.h"
    assert plan.compile_flags == ("-Wall", "-DSCORE_JSON=1")
    assert plan.error_contracts == ("score::Result may contain a parse error",)
    assert plan.build_deps[0] == "@score_baselibs//score/json:json"

    draft = plan.to_draft("// generated harness", project="score")
    assert draft.context["bazel_target"] == plan.target_label
    assert "error_contracts" in draft.context["repair_knowledge"]
    assert plan.api_signature().param_types == ["ByteSpan"]

    class Loop:
        knowledge = {"team_rule": "keep explicit override"}

    loop = plan.configure_self_heal(Loop())
    assert loop.knowledge["team_rule"] == "keep explicit override"
    assert loop.knowledge["bazel_target"] == plan.target_label


@pytest.mark.parametrize(
    "document,error",
    [
        (_document(is_static=True), UnsupportedApiError),
        (_document(is_test=True), UnsupportedApiError),
    ],
)
def test_plan_rejects_unfuzzable_api(document, error):
    with pytest.raises(error):
        plan_harness(_kb(document), document["function"])


def test_plan_reports_missing_api_and_build_unit():
    with pytest.raises(ApiNotFoundError):
        plan_harness(_kb(), "does_not_exist")

    with pytest.raises(MissingBuildUnitError):
        plan_harness(
            _kb(_document(build_target="", build_deps=[]), with_unit=False),
            "parse_json",
        )


class _SuccessfulAdapter:
    def __init__(self, root: Path):
        self.root = root
        self.emitted = None

    def package_dir(self, spec):
        return self.root / spec.package

    def emit_build_definition(self, spec, harness_source):
        self.emitted = (spec, harness_source)
        return self.package_dir(spec) / "BUILD.bazel"

    def build(self, spec):
        return BuildResult(
            ok=True,
            target=spec.bin_label,
            binary=self.root / "bazel-bin" / spec.package / f"{spec.name}_bin",
        )

    def remove(self, spec):
        return None


def test_build_bridge_returns_validation_artifact(tmp_path):
    adapter = _SuccessfulAdapter(tmp_path)
    generator = BuildFileGenerator(adapter=adapter)

    result = build_harness_from_kb(
        _kb(),
        "parse_json",
        "extern \"C\" int LLVMFuzzerTestOneInput(const unsigned char*, unsigned long);",
        generator,
        target_label="@score_baselibs//score/json:json",
        logic_group="json-parse",
        gen_model="test-model",
    )

    assert result.ok
    assert result.artifact is not None
    assert result.artifact.group_id == "json-parse"
    assert result.artifact.gen_model == "test-model"
    assert result.artifact.api_signatures[0].name == "parse_json"
    assert adapter.emitted[0].deps == result.plan.build_deps
