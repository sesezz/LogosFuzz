import json
import subprocess

import pytest

from logosfuzz.extract.bazel_query import (
    BazelQueryError,
    deps_of,
    normalize_label,
    parse_query_xml,
    query_bazel,
)


QUERY_XML = """<?xml version="1.1" encoding="UTF-8" standalone="no"?>
<query version="2">
  <rule class="cc_library" location="score/internal/BUILD.bazel:1:11"
        name="//score/internal:helper">
    <list name="srcs"><label value="//score/internal:helper.cc"/></list>
    <list name="hdrs"><label value="//score/internal:helper.h"/></list>
    <list name="defines"><string value="HELPER_ENABLED=1"/></list>
  </rule>
  <rule class="cc_library" location="score/json/BUILD.bazel:3:11"
        name="//score/json:json">
    <list name="srcs"><label value="//score/json:json.cc"/></list>
    <list name="hdrs"><label value="//score/json:json.h"/></list>
    <list name="deps"><label value="//score/internal:helper"/></list>
    <list name="copts"><string value="-DSCORE_JSON"/></list>
    <list name="includes"><string value="public"/></list>
  </rule>
  <rule class="py_library" location="tools/BUILD.bazel:1:11" name="//tools:util">
    <list name="srcs"><label value="//tools:util.py"/></list>
  </rule>
</query>
"""


def _workspace(tmp_path):
    for relative in (
        "score/internal/helper.cc",
        "score/internal/helper.h",
        "score/json/json.cc",
        "score/json/json.h",
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("// fixture\n", encoding="utf-8")
    return tmp_path


def test_query_xml_becomes_build_units_and_dependency_graph(tmp_path):
    workspace = _workspace(tmp_path)
    graph = parse_query_xml(QUERY_XML, str(workspace), roots=["//score/json:json"])

    assert set(graph.targets) == {"//score/internal:helper", "//score/json:json"}
    assert graph.targets["//score/json:json"].deps == ["//score/internal:helper"]
    assert graph.transitive_deps("//score/json:json") == ["//score/internal:helper"]
    assert all(unit["build_system"] == "bazel" for unit in graph.build_units())


def test_compile_context_combines_owner_and_transitive_dep_flags(tmp_path):
    workspace = _workspace(tmp_path)
    graph = parse_query_xml(QUERY_XML, str(workspace), roots=["//score/json:json"])

    context = graph.compile_context(str(workspace / "score/json/json.cc"))

    assert context["build_target"] == "//score/json:json"
    assert context["build_deps"] == ["//score/internal:helper"]
    assert "-DSCORE_JSON" in context["compile_flags"]
    assert "-DHELPER_ENABLED=1" in context["compile_flags"]
    assert any(flag.startswith("-I") for flag in context["compile_flags"])


def test_deps_provider_shape_includes_target_and_direct_deps(tmp_path):
    workspace = _workspace(tmp_path)
    graph = parse_query_xml(QUERY_XML, str(workspace), roots=["//score/json:json"])

    assert graph.deps_for("//score/json") == [
        "//score/json", "//score/internal:helper",
    ]
    assert normalize_label("@score_baselibs//score/json") == (
        "@score_baselibs//score/json:json"
    )


def test_query_bazel_uses_argument_list_and_parses_stdout(tmp_path):
    workspace = _workspace(tmp_path)
    observed = {}

    def fake_runner(command, **kwargs):
        observed["command"] = command
        observed["kwargs"] = kwargs
        return subprocess.CompletedProcess(command, 0, QUERY_XML, "")

    graph = query_bazel(
        str(workspace), ["//score/json:json"], bazel="bazelisk", runner=fake_runner
    )

    assert observed["command"] == [
        "bazelisk", "query", "--output=xml", "--noshow_progress",
        "deps(set(//score/json:json))",
    ]
    assert observed["kwargs"]["cwd"] == str(workspace.resolve())
    assert graph.roots == ["//score/json:json"]


def test_deps_of_is_directly_injectable_into_gen_provider(tmp_path):
    workspace = _workspace(tmp_path)

    def fake_runner(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, QUERY_XML, "")

    assert deps_of(
        "//score/json:json", workspace=str(workspace), bazel="bazel",
        runner=fake_runner,
    ) == ["//score/json:json", "//score/internal:helper"]


def test_query_rejects_non_label_before_running(tmp_path):
    with pytest.raises(ValueError, match="invalid Bazel target"):
        query_bazel(str(tmp_path), ["score/json"], runner=lambda *a, **k: None)


def test_query_error_keeps_bazel_diagnostic(tmp_path):
    def failed(command, **kwargs):
        return subprocess.CompletedProcess(command, 7, "", "no such target '//bad:target'")

    with pytest.raises(BazelQueryError, match="no such target"):
        query_bazel(
            str(tmp_path), ["//bad:target"], bazel="bazel", runner=failed
        )


def test_graph_json_roundtrip(tmp_path):
    workspace = _workspace(tmp_path)
    graph = parse_query_xml(QUERY_XML, str(workspace), roots=["//score/json:json"])

    payload = json.loads(json.dumps(graph.to_dict()))

    assert payload["build_system"] == "bazel"
    assert payload["targets"]["//score/json:json"]["rule_kind"] == "cc_library"
