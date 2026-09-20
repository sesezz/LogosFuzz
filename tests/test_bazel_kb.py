import json

from logosfuzz.extract.bazel_query import parse_query_xml
from logosfuzz.knowledge.knowledge_base import KnowledgeBase


def test_kb_records_bazel_build_unit_on_files_and_apis(tmp_path):
    source = tmp_path / "score" / "json" / "json.cc"
    header = tmp_path / "score" / "json" / "json.h"
    source.parent.mkdir(parents=True)
    header.write_text("int ParseJson(const char *text);\n", encoding="utf-8")
    source.write_text(
        '#include "score/json/json.h"\n'
        "int ParseJson(const char *text) { return text ? 0 : -1; }\n",
        encoding="utf-8",
    )
    xml = """<query version="2">
      <rule class="cc_library" location="score/json/BUILD.bazel:1:1"
            name="//score/json:json">
        <list name="srcs"><label value="//score/json:json.cc"/></list>
        <list name="hdrs"><label value="//score/json:json.h"/></list>
        <list name="deps"><label value="@json//:nlohmann_json"/></list>
        <list name="copts"><string value="-DSCORE_JSON=1"/></list>
      </rule>
    </query>"""
    graph = parse_query_xml(xml, str(tmp_path), roots=["//score/json:json"])

    kb = KnowledgeBase.build(paths=[str(tmp_path)], bazel_graph=graph)
    document = kb.api("ParseJson")
    file_info = kb.files[str(source)]

    assert document["build_system"] == "bazel"
    assert document["build_target"] == "//score/json:json"
    assert document["build_rule_kind"] == "cc_library"
    assert document["build_deps"] == ["@json//:nlohmann_json"]
    assert "-DSCORE_JSON=1" in document["compile_flags"]
    assert file_info["build_target"] == "//score/json:json"
    assert kb.build_units[0]["build_system"] == "bazel"
    assert kb.stats()["apis_with_build_unit"] == 1


def test_bazel_build_units_survive_save_and_load(tmp_path):
    source = tmp_path / "lib.cc"
    source.write_text("int Entry(int value) { return value; }\n", encoding="utf-8")
    xml = """<query version="2">
      <rule class="cc_library" location="BUILD.bazel:1:1" name="//:lib">
        <list name="srcs"><label value="//:lib.cc"/></list>
      </rule>
    </query>"""
    graph = parse_query_xml(xml, str(tmp_path), roots=["//:lib"])
    output = tmp_path / "kb.json"

    KnowledgeBase.build(paths=[str(tmp_path)], bazel_graph=graph).save(str(output))
    payload = json.loads(output.read_text(encoding="utf-8"))
    restored = KnowledgeBase.load(str(output))

    assert payload["version"] == 2
    assert payload["build_units"][0]["target"] == "//:lib"
    assert restored.build_units == payload["build_units"]


def test_version_one_kb_remains_loadable(tmp_path):
    source = tmp_path / "legacy.c"
    source.write_text("int Legacy(int value) { return value; }\n", encoding="utf-8")
    output = tmp_path / "legacy-kb.json"
    KnowledgeBase.build(paths=[str(tmp_path)]).save(str(output))
    payload = json.loads(output.read_text(encoding="utf-8"))
    payload["version"] = 1
    payload.pop("build_units", None)
    output.write_text(json.dumps(payload), encoding="utf-8")

    restored = KnowledgeBase.load(str(output))

    assert restored.build_units == []
    assert restored.api("Legacy") is not None
