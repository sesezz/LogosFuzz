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


# ---------------------------------------------------------------------
# GENERIC-A: 대상 프로필의 compile_db 플래그
# ---------------------------------------------------------------------

from logosfuzz.common.target_profile import parse_profile
from logosfuzz.extract import ast_analyzer


def _cmake_profile(root, **build):
    data = {
        "name": "demo",
        "language": "c",
        "domain": "generic",
        "error_contract": "c_return_code",
        "build": {
            "system": "cmake",
            "source_root": str(root),
            "include_dirs": ["include"],
            "compile_commands": "build/compile_commands.json",
            **build,
        },
    }
    return parse_profile(data)


def _cmake_tree(root):
    (root / "include").mkdir()
    (root / "src").mkdir()
    (root / "build").mkdir()
    (root / "include" / "demo.h").write_text(
        "#ifndef DEMO_H\n#define DEMO_H\nint demo_open(const char *path);\n#endif\n",
        encoding="utf-8",
    )
    (root / "src" / "demo.c").write_text(
        '#include "demo.h"\n'
        "#ifdef DEMO_FEATURE\n"
        "int demo_open(const char *path) { return path ? 0 : -1; }\n"
        "#endif\n",
        encoding="utf-8",
    )
    entries = [{
        "directory": str(root / "build"),
        "arguments": ["arm-none-eabi-gcc", "-mcpu=cortex-m4", "-DDEMO_FEATURE",
                      "-I../include", "-std=gnu99", "-c", "../src/demo.c"],
        "file": "../src/demo.c",
    }]
    (root / "build" / "compile_commands.json").write_text(json.dumps(entries), encoding="utf-8")


def _capture_args(monkeypatch):
    calls = {}

    def fake_analyze_file(path, clang_args=None, language=None):
        calls[os.path.basename(path)] = (list(clang_args or []), language)
        return {"file": path}

    monkeypatch.setattr(ast_analyzer, "analyze_file", fake_analyze_file)
    return calls


def test_c_profile_parses_h_as_c():
    assert clang_args_for_path("demo.h", language="c")[:3] == ["-x", "c", "-std=c11"]
    assert clang_args_for_path("demo.hpp", language="c")[:3] == ["-x", "c++", "-std=c++17"]
    # 언어를 주지 않으면 기존(S-CORE) 규칙 그대로
    assert clang_args_for_path("demo.h")[:3] == ["-x", "c++", "-std=c++17"]


def test_profile_compile_db_flags_reach_clang(tmp_path, monkeypatch):
    root = tmp_path.resolve()
    _cmake_tree(root)
    calls = _capture_args(monkeypatch)

    ast_analyzer.analyze_paths([], profile=_cmake_profile(root))

    src_args, language = calls["demo.c"]
    assert language == "c"
    assert "-DDEMO_FEATURE" in src_args
    assert f"-I{os.path.normpath(str(root / 'include'))}" in src_args
    assert "-std=gnu99" in src_args
    # 항목 없는 헤더는 합집합 플래그를 쓰되 -std 는 언어 기본값에 맡긴다
    hdr_args, _ = calls["demo.h"]
    assert "-DDEMO_FEATURE" in hdr_args
    assert not any(a.startswith("-std=") for a in hdr_args)


def test_profile_strip_flags_applied(tmp_path, monkeypatch):
    root = tmp_path.resolve()
    _cmake_tree(root)
    calls = _capture_args(monkeypatch)
    data = _cmake_profile(root).to_dict()
    data["embedded"]["strip_flags"] = ["-mcpu=*"]
    data["build"]["source_root"] = str(root)

    ast_analyzer.analyze_paths([str(root / "src")], profile=parse_profile(data))

    assert "demo.c" in calls and "demo.h" not in calls  # 명시한 paths 만 분석
    assert not any(a.startswith("-mcpu") for a in calls["demo.c"][0])


def test_caller_args_come_first_and_are_not_duplicated(tmp_path, monkeypatch):
    root = tmp_path.resolve()
    _cmake_tree(root)
    calls = _capture_args(monkeypatch)

    ast_analyzer.analyze_paths([str(root / "src" / "demo.c")],
                               clang_args=["-DDEMO_FEATURE", "-Wall"],
                               profile=_cmake_profile(root))

    args, _ = calls["demo.c"]
    assert args[:2] == ["-DDEMO_FEATURE", "-Wall"]
    assert args.count("-DDEMO_FEATURE") == 1


def test_missing_compile_db_falls_back_to_include_dirs(tmp_path, monkeypatch):
    root = tmp_path.resolve()
    _cmake_tree(root)
    (root / "build" / "compile_commands.json").unlink()
    calls = _capture_args(monkeypatch)

    ast_analyzer.analyze_paths([str(root / "src" / "demo.c")], profile=_cmake_profile(root))

    assert calls["demo.c"][0] == [f"-I{root / 'include'}"]


def test_no_profile_keeps_previous_arguments(tmp_path, monkeypatch):
    source = tmp_path / "unit.c"
    source.write_text("int f(void) { return 0; }\n", encoding="utf-8")
    seen = []
    monkeypatch.setattr(
        ast_analyzer, "analyze_file",
        lambda path, clang_args=None, **kw: seen.append((list(clang_args), kw)) or {"file": path},
    )

    ast_analyzer.analyze_paths([str(source)], clang_args=["-DX"])

    # 프로필이 없으면 language 인자도 넘기지 않는다(기존 호출 형태 유지)
    assert seen == [(["-DX"], {})]


def test_bazel_profile_does_not_read_compile_db(tmp_path, monkeypatch):
    source = tmp_path / "json.cc"
    source.write_text("int f() { return 0; }\n", encoding="utf-8")
    calls = _capture_args(monkeypatch)
    profile = parse_profile({
        "name": "score-json", "language": "cpp", "domain": "automotive",
        "error_contract": "score_result",
        "build": {"system": "bazel", "source_root": str(tmp_path),
                  "compile_commands": "missing.json",
                  "bazel": {"workspace": ".", "target": "//score/json:json"}},
    })

    ast_analyzer.analyze_paths([str(source)], profile=profile)

    assert calls["json.cc"] == ([], "cpp")


@pytest.mark.skipif(not HAVE_CLANG, reason="clang bindings are not installed")
def test_profile_flags_expose_ifdef_function_with_clang(tmp_path):
    root = tmp_path.resolve()
    _cmake_tree(root)

    without = analyze_file(str(root / "src" / "demo.c"),
                           clang_args=[f"-I{root / 'include'}"], language="c")
    results = ast_analyzer.analyze_paths([str(root / "src" / "demo.c")],
                                         profile=_cmake_profile(root))

    def defined(result):
        return {n["spelling"] for n in result.get("nodes", [])
                if n.get("kind") == "FUNCTION_DECL" and n.get("is_definition")}

    assert "demo_open" not in defined(without)
    assert "demo_open" in defined(results[0])
    assert "-DDEMO_FEATURE" in results[0]["clang_args"]
