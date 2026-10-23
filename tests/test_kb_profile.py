import json
import os

import pytest

from logosfuzz.common.target_profile import parse_profile
from logosfuzz.extract.bazel_query import parse_query_xml
from logosfuzz.generate.kb_bridge import (
    KnowledgeBridgeError,
    MissingBuildUnitError,
    build_harness_from_kb,
    plan_harness,
)
from logosfuzz.knowledge import knowledge_base as kb_module
from logosfuzz.knowledge.knowledge_base import KnowledgeBase


HEADER = """#ifndef DEMO_H
#define DEMO_H
typedef struct demo demo_t;
/** path 를 연다. path must not be NULL. 실패하면 NULL 을 돌려준다. */
demo_t *demo_open(const char *path);
/** 핸들을 닫는다. */
int demo_close(demo_t *handle);
int demo_helper(int value);
#endif
"""

SOURCE = """#include <stdlib.h>
#include "demo.h"
struct demo { int fd; };
static int internal_check(int value) { return value > 0; }
demo_t *demo_open(const char *path)
{
    if (path == NULL) {
        return NULL;
    }
    return calloc(1, sizeof(demo_t));
}
int demo_close(demo_t *handle)
{
    if (!handle) {
        return -1;
    }
    free(handle);
    return 0;
}
int demo_helper(int value) { return internal_check(value); }
"""

SCORE_LIKE = (
    "Result<int> demo_parse(int value) {"
    "  if (value <= 0) { return MakeUnexpected(Error::kInvalid); }"
    "  return value;"
    "}\n"
)


def _tree(root, with_db=True):
    (root / "include").mkdir()
    (root / "src").mkdir()
    (root / "build").mkdir()
    (root / "tests").mkdir()
    (root / "include" / "demo.h").write_text(HEADER, encoding="utf-8")
    (root / "src" / "demo.c").write_text(SOURCE, encoding="utf-8")
    (root / "tests" / "test_demo.c").write_text(
        "int test_demo_open(void) { return 0; }\n", encoding="utf-8"
    )
    if with_db:
        entries = [{
            "directory": str(root / "build"),
            "arguments": ["cc", "-DDEMO_FEATURE=1", "-I../include", "-std=gnu99",
                          "-c", "../src/demo.c"],
            "file": "../src/demo.c",
        }]
        (root / "build" / "compile_commands.json").write_text(
            json.dumps(entries), encoding="utf-8"
        )


def _profile(root, **overrides):
    data = {
        "name": "demo",
        "language": "c",
        "domain": "generic",
        "error_contract": "c_return_code",
        "build": {
            "system": "cmake",
            "source_root": str(root),
            "build_dir": "build",
            "libraries": ["build/libdemo.a"],
            "include_dirs": ["include"],
            "link_flags": ["-lm"],
            "compile_commands": "build/compile_commands.json",
        },
        "apis": ["demo_open", "demo_close", "demo_missing"],
    }
    for key, value in overrides.items():
        if key.startswith("build__"):
            data["build"][key[len("build__"):]] = value
        else:
            data[key] = value
    return parse_profile(data)


@pytest.fixture
def root(tmp_path):
    root = tmp_path.resolve()
    _tree(root)
    return root


@pytest.fixture
def kb(root):
    return KnowledgeBase.build(profile=_profile(root))


# ---------------------------------------------------------------------
# knowledge_base build --profile (비-Bazel)
# ---------------------------------------------------------------------

def test_profile_apis_limit_documents(kb):
    assert sorted(d["function"] for d in kb.documents) == ["demo_close", "demo_open"]
    assert kb.profile["apis_missing"] == ["demo_missing"]
    assert kb.profile["build_system"] == "cmake"
    assert kb.profile["domain"] == "generic"


def test_single_cmake_build_unit_is_referenced_by_every_api(kb, root):
    assert len(kb.build_units) == 1
    unit = kb.build_units[0]
    assert unit["build_system"] == "cmake"
    assert unit["build_target"] == "demo"
    assert unit["build_deps"] == [str((root / "build" / "libdemo.a").resolve())]
    assert unit["include_dirs"] == [str((root / "include").resolve())]
    assert unit["link_flags"] == ["-lm"]
    assert "-DDEMO_FEATURE=1" in unit["compile_flags"]
    assert not any(flag.startswith("-std=") for flag in unit["compile_flags"])
    for document in kb.documents:
        assert document["build_system"] == "cmake"
        assert document["build_target"] == "demo"
        assert document["build_deps"] == unit["build_deps"]


def test_stats_report_cmake_unit_and_profile(kb):
    stats = kb.stats()
    assert stats["build_units_by_system"] == {"cmake": 1}
    assert stats["apis"] == 2
    assert stats["apis_with_build_unit"] == 2
    assert stats["profile"]["apis_missing"] == ["demo_missing"]


def test_source_gets_its_own_compile_db_flags(kb, root):
    source = str(root / "src" / "demo.c")
    flags = kb.files[source]["flags"]
    assert "-DDEMO_FEATURE=1" in flags
    assert "-std=gnu99" in flags
    assert f"-I{os.path.normpath(str(root / 'include'))}" in flags
    header = str(root / "include" / "demo.h")
    assert "-std=gnu99" not in kb.files[header]["flags"]


def test_header_and_header_doc_are_attached(kb, root):
    document = kb.api("demo_open")
    assert document["header"] == str(root / "include" / "demo.h")
    assert "must not be NULL" in document["doc"]
    assert any(c["kind"] == "null_check" for c in document["constraints"])


def test_tests_tree_is_not_indexed(root):
    kb = KnowledgeBase.build(profile=_profile(root, apis=[]))
    names = {d["function"] for d in kb.documents}
    assert "test_demo_open" not in names


def test_without_apis_all_definitions_are_kept(root):
    kb = KnowledgeBase.build(profile=_profile(root, apis=[]))
    names = {d["function"] for d in kb.documents}
    assert {"demo_open", "demo_close", "demo_helper", "internal_check"} <= names
    assert kb.profile["apis_missing"] == []


def test_static_duplicate_loses_to_public_definition(root):
    (root / "src" / "dup.c").write_text(
        "static int demo_close(int x) { return x; }\n", encoding="utf-8"
    )
    kb = KnowledgeBase.build(
        paths=[str(root / "src"), str(root / "include")], profile=_profile(root)
    )
    closes = kb.apis("demo_close")
    assert len(closes) == 1
    assert not closes[0]["is_static"]


def test_missing_compile_db_falls_back_to_include_dirs(tmp_path):
    root = tmp_path.resolve()
    _tree(root, with_db=False)
    kb = KnowledgeBase.build(profile=_profile(root))

    # compile_db 부재 시 source_root 전체 탐색, tests/ 제외
    assert sorted(d["function"] for d in kb.documents) == ["demo_close", "demo_open"]
    include = f"-I{(root / 'include').resolve()}"
    assert kb.api("demo_open")["compile_flags"] == [include]
    assert kb.build_units[0]["build_file"] == ""


def test_prebuilt_profile_records_prebuilt_unit(root):
    kb = KnowledgeBase.build(profile=_profile(root, build__system="prebuilt"))
    assert kb.stats()["build_units_by_system"] == {"prebuilt": 1}
    assert kb.build_units[0]["build_rule_kind"] == "prebuilt_library"


def test_generic_profile_does_not_extract_score_result(root):
    (root / "src" / "parse.cc").write_text(SCORE_LIKE, encoding="utf-8")
    kb = KnowledgeBase.build(
        paths=[str(root / "src")], profile=_profile(root, apis=["demo_parse"])
    )
    kinds = {c["kind"] for c in kb.api("demo_parse")["constraints"]}
    assert "error_contract" not in kinds


def test_profile_kb_survives_save_and_load(kb, tmp_path):
    path = kb.save(str(tmp_path / "out" / "kb.json"))
    loaded = KnowledgeBase.load(path)
    assert loaded.profile == kb.profile
    assert loaded.build_units == kb.build_units
    assert loaded.stats()["build_units_by_system"] == {"cmake": 1}


def test_kb_without_profile_has_no_profile_key(tmp_path):
    (tmp_path / "a.c").write_text("int f(int x) { return x; }\n", encoding="utf-8")
    kb = KnowledgeBase.build(paths=[str(tmp_path)])
    assert kb.profile is None
    assert "profile" not in kb.stats()
    payload = json.loads(open(kb.save(str(tmp_path / "kb.json")), encoding="utf-8").read())
    assert "profile" not in payload


# ---------------------------------------------------------------------
# Bazel 프로필은 기존 bazel_query 경로
# ---------------------------------------------------------------------

def _bazel_profile(root, domain="automotive"):
    return parse_profile({
        "name": "score-json",
        "language": "cpp",
        "domain": domain,
        "error_contract": "score_result",
        "build": {
            "system": "bazel",
            "source_root": str(root),
            "bazel": {"workspace": ".", "target": "//score/json:json"},
        },
    })


def _bazel_tree(root):
    source = root / "score" / "json" / "json.cc"
    source.parent.mkdir(parents=True)
    source.write_text(SCORE_LIKE.replace("demo_parse", "ParseJson"), encoding="utf-8")
    xml = """<query version="2">
      <rule class="cc_library" location="score/json/BUILD.bazel:1:1"
            name="//score/json:json">
        <list name="srcs"><label value="//score/json:json.cc"/></list>
      </rule>
    </query>"""
    return parse_query_xml(xml, str(root), roots=["//score/json:json"])


def test_bazel_profile_uses_bazel_query_with_profile_location(tmp_path, monkeypatch):
    root = tmp_path.resolve()
    graph = _bazel_tree(root)
    calls = []

    def fake_query(workspace, targets, bazel=None):
        calls.append((workspace, list(targets)))
        return graph

    monkeypatch.setattr(kb_module, "query_bazel", fake_query)
    kb = KnowledgeBase.build(profile=_bazel_profile(root))

    assert calls == [(str(root), ["//score/json:json"])]
    assert kb.stats()["build_units_by_system"] == {"bazel": 1}
    document = kb.api("ParseJson")
    assert document["build_target"] == "//score/json:json"
    # 자동차 프로필은 score::Result 계약을 기존처럼 추출
    assert any(c["kind"] == "error_contract" for c in document["constraints"])


def test_bazel_profile_output_matches_profileless_bazel_kb(tmp_path):
    root = tmp_path.resolve()
    graph = _bazel_tree(root)
    legacy = KnowledgeBase.build(paths=[str(root)], bazel_graph=graph)
    profiled = KnowledgeBase.build(
        paths=[str(root)], bazel_graph=graph, profile=_bazel_profile(root)
    )
    assert profiled.documents == legacy.documents
    assert profiled.build_units == legacy.build_units


# ---------------------------------------------------------------------
# plan_harness 비-Bazel 수용
# ---------------------------------------------------------------------

def test_plan_harness_accepts_cmake_unit(kb, root):
    plan = plan_harness(kb, "demo_open")

    assert plan.build_system == "cmake"
    assert not plan.is_bazel
    assert plan.target_label == "demo"
    assert plan.build_rule_kind == "cmake_library"
    assert plan.build_deps == (str((root / "build" / "libdemo.a").resolve()),)
    assert "-DDEMO_FEATURE=1" in plan.compile_flags
    assert plan.include.endswith("include/demo.h")
    assert plan.language == "c"


def test_plan_repair_knowledge_and_draft_use_generic_keys(kb):
    plan = plan_harness(kb, "demo_open")
    knowledge = plan.repair_knowledge()

    assert knowledge["build_system"] == "cmake"
    assert knowledge["build_target"] == "demo"
    assert knowledge["link_libraries"].endswith("libdemo.a")
    assert "bazel_target" not in knowledge and "bazel_deps" not in knowledge
    draft = plan.to_draft("int LLVMFuzzerTestOneInput(const unsigned char*, unsigned long);")
    assert draft.context["build_target"] == "demo"
    assert draft.context["build_system"] == "cmake"
    assert "bazel_target" not in draft.context


def test_bazel_build_bridge_rejects_cmake_plan(kb):
    with pytest.raises(KnowledgeBridgeError, match="adapter_for"):
        build_harness_from_kb(kb, "demo_open", "int x;", generator=object())


def test_missing_build_unit_still_raises_without_any_unit(tmp_path):
    (tmp_path / "a.c").write_text("int f(int x) { return x; }\n", encoding="utf-8")
    kb = KnowledgeBase.build(paths=[str(tmp_path)])
    with pytest.raises(MissingBuildUnitError, match="빌드 단위"):
        plan_harness(kb, "f")


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

def test_cli_build_and_stats_with_profile(root, tmp_path, capsys):
    profile_path = tmp_path / "demo.json"
    profile_path.write_text(json.dumps(_profile(root).to_dict()), encoding="utf-8")
    out = tmp_path / "kb.json"

    kb_module.main(["build", "--profile", str(profile_path), "--output", str(out)])
    capsys.readouterr()
    kb_module.main(["stats", "--kb", str(out)])
    stats = json.loads(capsys.readouterr().out)

    assert stats["build_units_by_system"] == {"cmake": 1}
    assert stats["apis"] == 2
    assert stats["profile"]["name"] == "demo"


# ---------------------------------------------------------------------
# kb_eval --profile
# ---------------------------------------------------------------------

from logosfuzz.knowledge.kb_eval import GroundTruth, evaluate, restrict_to_apis


def _labels(tmp_path, entries):
    path = tmp_path / "labels.json"
    path.write_text(json.dumps({"apis": entries}), encoding="utf-8")
    return str(path)


def test_restrict_to_apis_keeps_only_profile_targets():
    truth = GroundTruth(source="clang", apis={"a": {}, "b": {}, "c": {}}, note="x")
    limited = restrict_to_apis(truth, ["a", "c", "z"])
    assert sorted(limited.apis) == ["a", "c"]
    assert "profile.apis" in limited.note
    assert restrict_to_apis(truth, []) is truth


def test_evaluate_with_profile_and_labels(root, tmp_path):
    labels = _labels(tmp_path, [
        {"name": "demo_open", "return_type": "demo_t*", "params": ["path"]},
        {"name": "demo_close", "return_type": "int", "params": ["handle"]},
        {"name": "demo_missing", "return_type": "int", "params": []},
        {"name": "not_a_target", "return_type": "int", "params": []},
    ])
    result = evaluate([], labels=labels, prefer="labels", profile=_profile(root))

    accuracy = result["extraction_accuracy"]
    assert result["target"] == ["demo"]
    assert result["ground_truth"]["apis"] == 3  # not_a_target 은 프로필 밖이라 제외
    assert accuracy["true_positive"] == 2
    assert accuracy["false_positive"] == 0
    assert accuracy["false_negative_names"] == ["demo_missing"]
    assert accuracy["param_count_accuracy"] == 1.0
    assert accuracy["return_type_accuracy"] == 1.0
