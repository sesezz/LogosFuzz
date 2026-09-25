import subprocess
import json
import sys
import os

import pytest

from logosfuzz.extract.ast_analyzer import (
    HAVE_CLANG,
    analyze_file,
    analyze_paths,
    clang_args_for_path,
)
from logosfuzz.extract.bazel_query import parse_query_xml

ROOT = os.path.dirname(os.path.dirname(__file__))

def test_sample_analysis(tmp_path):
    exe = [sys.executable, '-m', 'logosfuzz.extract.ast_analyzer', os.path.join(ROOT, 'examples', 'sample.c')]
    out = subprocess.check_output(exe, universal_newlines=True)
    data = json.loads(out)
    assert isinstance(data, list)
    assert data[0]['file'].endswith('sample.c')


def test_language_defaults_follow_file_type():
    assert clang_args_for_path("unit.c")[:3] == ["-x", "c", "-std=c11"]
    assert clang_args_for_path("unit.cpp")[:3] == ["-x", "c++", "-std=c++17"]
    assert clang_args_for_path("score/json/json.h")[:3] == [
        "-x", "c++", "-std=c++17",
    ]


def test_explicit_language_and_standard_are_preserved():
    assert clang_args_for_path("unit.cpp", ["-x", "c++", "-std=c++20"]) == [
        "-x", "c++", "-std=c++20",
    ]


@pytest.mark.skipif(not HAVE_CLANG, reason="clang bindings are not installed")
def test_cpp_classes_namespaces_methods_and_templates(tmp_path):
    source = tmp_path / "parser.cpp"
    source.write_text(
        """
namespace score::json {
template <typename T> T Identity(T value) { return value; }
class Parser {
public:
    Parser(int mode) : mode_(mode) {}
    int Parse(const char *text) { return text ? mode_ : -1; }
    template <typename T> T Convert(T value) { return value; }
private:
    int mode_;
};
}
""",
        encoding="utf-8",
    )

    result = analyze_file(str(source))
    if result.get("clang_fallback"):
        pytest.skip("libclang binary is unavailable")
    by_qualified = {
        node.get("qualified_name"): node
        for node in result["nodes"]
        if node.get("qualified_name")
    }

    assert result["clang_args"][:3] == ["-x", "c++", "-std=c++17"]
    assert "score::json::Parser" in by_qualified
    assert by_qualified["score::json::Parser::Parser"]["callable_kind"] == "CONSTRUCTOR"
    assert by_qualified["score::json::Parser::Parse"]["callable_kind"] == "CXX_METHOD"
    assert by_qualified["score::json::Identity"]["is_template"] is True
    assert by_qualified["score::json::Identity"]["template_parameters"] == ["T"]
    assert by_qualified["score::json::Identity"]["is_definition"] is True
    assert by_qualified["score::json::Parser::Convert"]["is_method"] is True


@pytest.mark.skipif(not HAVE_CLANG, reason="clang bindings are not installed")
def test_bazel_compile_context_reaches_clang(tmp_path):
    source = tmp_path / "score" / "json" / "json.cc"
    source.parent.mkdir(parents=True)
    source.write_text(
        "int Enabled(void) { return SCORE_JSON_ENABLED; }\n", encoding="utf-8"
    )
    graph = parse_query_xml(
        """<query version="2">
          <rule class="cc_library" location="score/json/BUILD.bazel:1:1"
                name="//score/json:json">
            <list name="srcs"><label value="//score/json:json.cc"/></list>
            <list name="copts"><string value="-DSCORE_JSON_ENABLED=1"/></list>
          </rule>
        </query>""",
        str(tmp_path),
        roots=["//score/json:json"],
    )

    results = analyze_paths([], bazel_graph=graph)

    assert len(results) == 1
    assert results[0]["build_target"] == "//score/json:json"
    assert "-DSCORE_JSON_ENABLED=1" in results[0]["clang_args"]
    assert not [d for d in results[0]["diagnostics"] if d["severity"] >= 3]
