"""GEN-03-01 .cc + BUILD 쌍 생성 테스트 (3주차)."""
from __future__ import annotations

import json

import pytest

from logosfuzz.generate.bazel.deps_provider import (
    VERIFIED_SCORE_JSON_DEPS,
    StaticDepsProvider,
)
from logosfuzz.generate.gen_03_01_harness_generator import (
    MANIFEST_NAME,
    HarnessPair,
    demo_pair,
    generate_pairs,
    group_slug,
    include_path_for,
    load_pairs,
    make_pair_spec,
    pair_drivers,
    write_pairs,
)
from logosfuzz.generate.llm_harness_generator import (
    LANG_C,
    LANG_CPP,
    ApiContext,
    FuzzDriver,
    build_cpp_prompt,
    build_prompt,
    load_reference_harness,
    normalize_cpp_harness,
    strip_code_fences,
)
from logosfuzz.schedule.sch_02_03_resource_allocator import ScheduleResult

SCORE_JSON = "@score_baselibs//score/json"

CTX = ApiContext(
    api_id=1,
    func_signature="score::Result<Any> JsonParser::FromBuffer(std::string_view buffer) const",
    call_order=["FromBuffer"],
    constraints=["buffer may be any byte sequence"],
    source_type="//score/json:json",
)

MINIMAL_CC = (
    '#include "score/json/json_parser.h"\n'
    'extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) { return 0; }\n'
)


# --------------------------------------------------------------------------- #
# 이름·배치 규칙
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name, expected", [
    ("lg_json_parser", "lg_json_parser"),
    ("LG-Json Parser", "lg_json_parser"),
    ("//score/json:json", "score_json_json"),
    ("1st", "g_1st"),
    ("***", "group"),
])
def test_group_slug(name, expected):
    assert group_slug(name) == expected


def test_pair_spec_is_per_group_subpackage_of_build_unit():
    spec = make_pair_spec("lg_json", SCORE_JSON, StaticDepsProvider(VERIFIED_SCORE_JSON_DEPS))
    # 대상의 하위(의 하위) 패키지여야 __subpackages__ 가시성에 걸리지 않는다.
    assert spec.package == "score/json/fuzz/lg_json"
    assert spec.name == "lg_json_fuzz_test"
    assert spec.srcs == ("lg_json_fuzz.cc",)
    assert spec.deps == VERIFIED_SCORE_JSON_DEPS[SCORE_JSON]
    assert spec.tags == ("manual",)
    assert spec.bin_label == "//score/json/fuzz/lg_json:lg_json_fuzz_test_bin"


def test_pair_spec_rejects_bad_label():
    with pytest.raises(ValueError):
        make_pair_spec("g", "not-a-label")


def test_demo_pair_matches_week1_build_shape():
    pair = demo_pair()
    build = pair.build_file
    assert 'load("@rules_fuzzing//fuzzing:cc_defs.bzl", "cc_fuzz_test")' in build
    assert 'name = "lg_json_parser_fuzz_test"' in build
    assert 'srcs = ["lg_json_parser_fuzz.cc"]' in build
    assert '"@score_baselibs//score/json:parser_interface"' in build
    assert 'tags = ["manual"]' in build
    assert 'extern "C" int LLVMFuzzerTestOneInput' in pair.source
    # 참조 하네스는 주석에서 FuzzedDataProvider 를 언급만 한다 — include 를 끼우면 안 된다
    assert "FuzzedDataProvider.h" not in pair.source


# --------------------------------------------------------------------------- #
# 쓰기 / 읽기
# --------------------------------------------------------------------------- #
def test_write_and_load_pairs_roundtrip(tmp_path):
    pair = demo_pair()
    manifest = write_pairs([pair], tmp_path)

    assert manifest == tmp_path.resolve() / MANIFEST_NAME
    pkg = tmp_path / "score/json/fuzz/lg_json_parser"
    assert (pkg / "lg_json_parser_fuzz.cc").read_text(encoding="utf-8") == pair.source
    assert (pkg / "BUILD.bazel").read_text(encoding="utf-8") == pair.build_file

    data = json.loads(manifest.read_text(encoding="utf-8"))
    entry = data["pairs"][0]
    assert entry["build_target"] == SCORE_JSON
    assert entry["build_system"] == "bazel"
    assert entry["bin_target"] == pair.spec.bin_label

    loaded = load_pairs(manifest)
    assert len(loaded) == 1
    assert loaded[0].spec == pair.spec
    assert loaded[0].source == pair.source
    assert loaded[0].build_file == pair.build_file


def test_write_pairs_rejects_package_collision(tmp_path):
    a = demo_pair(group_name="LG json")
    b = demo_pair(group_name="lg_json")   # 같은 slug
    with pytest.raises(ValueError, match="패키지 충돌"):
        write_pairs([a, b], tmp_path)


def test_pair_drivers_skips_groups_without_build_unit():
    drivers = [
        FuzzDriver(group_name="has_target", code=MINIMAL_CC, language=LANG_CPP),
        FuzzDriver(group_name="no_target", code=MINIMAL_CC, language=LANG_CPP),
    ]
    pairs, skipped = pair_drivers(drivers, {"has_target": SCORE_JSON})
    assert [p.group_name for p in pairs] == ["has_target"]
    assert skipped == ["no_target"]

    pairs, skipped = pair_drivers(drivers, {}, default_target=SCORE_JSON)
    assert len(pairs) == 2 and skipped == []


# --------------------------------------------------------------------------- #
# C++ 정규화 / 프롬프트
# --------------------------------------------------------------------------- #
def test_strip_code_fences():
    assert strip_code_fences("```cpp\nint x;\n```\ntrailing") == "int x;"
    assert strip_code_fences("```cpp\nint x;") == "int x;"      # 닫는 펜스 없음
    assert strip_code_fences("int x;") == "int x;"


def test_normalize_adds_extern_c_and_fdp_include():
    code = (
        "```cpp\n"
        "#include <cstdint>\n"
        "int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {\n"
        "  FuzzedDataProvider fdp(data, size);\n"
        "  return 0;\n"
        "}\n"
        "```"
    )
    out = normalize_cpp_harness(code)
    assert 'extern "C" int LLVMFuzzerTestOneInput(' in out
    assert out.startswith("#include <fuzzer/FuzzedDataProvider.h>\n")
    assert "```" not in out


def test_normalize_keeps_correct_harness_unchanged():
    assert normalize_cpp_harness(MINIMAL_CC) == MINIMAL_CC


def test_cpp_prompt_contents():
    prompt = build_cpp_prompt(
        "lg_json", [CTX],
        includes=["score/json/json_parser.h"],
        build_target="//score/json:json",
        build_deps=["//score/json:json", "//score/json:parser_interface"],
        error_contracts=["FromBuffer: returns MakeUnexpected(kParsingError)"],
    )
    assert 'extern "C" int LLVMFuzzerTestOneInput' in prompt
    assert "FuzzedDataProvider" in prompt
    assert '#include "score/json/json_parser.h"' in prompt
    assert "//score/json:parser_interface" in prompt
    assert "ERROR CONTRACTS" in prompt and "kParsingError" in prompt
    # few-shot: 1주차 참조 하네스가 들어가고 라이선스 블록은 빠진다
    assert "parser.FromBuffer(" in prompt
    assert "SPDX-License-Identifier" not in prompt


def test_reference_harness_is_loaded_without_license():
    ref = load_reference_harness()
    assert "LLVMFuzzerTestOneInput" in ref
    assert "SPDX-License-Identifier" not in ref


def test_build_prompt_default_stays_legacy_c_and_cpp_is_explicit():
    # 기존 호출부(pipeline.py)는 인자 없이 부르므로 기본은 C 프롬프트여야 한다.
    default_prompt = build_prompt("g", [CTX])
    assert "Write a libFuzzer fuzz driver in C" in default_prompt
    assert "FuzzedDataProvider" not in default_prompt
    assert build_prompt("g", [CTX], language=LANG_C) == default_prompt

    cpp_prompt = build_prompt("g", [CTX], language=LANG_CPP)
    assert "FuzzedDataProvider" in cpp_prompt
    assert 'extern "C" int LLVMFuzzerTestOneInput' in cpp_prompt
    with pytest.raises(ValueError):
        build_prompt("g", [CTX], language="rust")


def test_include_path_for(tmp_path):
    header = tmp_path / "score" / "json" / "json_parser.h"
    assert include_path_for(str(header), tmp_path) == "score/json/json_parser.h"
    assert include_path_for("//score/json:json_parser.h", None) == "score/json/json_parser.h"
    assert include_path_for("/elsewhere/x.h", tmp_path) == "/elsewhere/x.h"
    assert include_path_for("", tmp_path) == ""


# --------------------------------------------------------------------------- #
# 생성 -> 쌍 (LLM 은 가짜 함수)
# --------------------------------------------------------------------------- #
def test_generate_pairs_with_fake_llm():
    prompts: list[str] = []

    def fake_llm(prompt: str) -> str:
        prompts.append(prompt)
        # extern "C" 를 빠뜨린 응답 — 정규화가 고쳐야 한다
        return "```cpp\nint LLVMFuzzerTestOneInput(const uint8_t* d, size_t n) { return 0; }\n```"

    schedule = [ScheduleResult("lg_json", 0.5, 0.0, 1.0, 0.5, 60)]
    pairs, skipped = generate_pairs(
        schedule,
        {"lg_json": [1]},
        {"lg_json": SCORE_JSON},
        deps_provider=StaticDepsProvider(VERIFIED_SCORE_JSON_DEPS),
        context_db={1: CTX},
        llm=fake_llm,
    )

    assert skipped == []
    assert len(pairs) == 1 and isinstance(pairs[0], HarnessPair)
    assert 'extern "C" int LLVMFuzzerTestOneInput' in pairs[0].source
    assert pairs[0].spec.deps == VERIFIED_SCORE_JSON_DEPS[SCORE_JSON]
    # 빌드 단위와 deps 가 프롬프트에 들어갔다
    assert SCORE_JSON in prompts[0]
    assert "@score_baselibs//score/json:parser_interface" in prompts[0]


# --------------------------------------------------------------------------- #
# 3주차 후속: normalize 의 진입점 extern "C" 검사
# --------------------------------------------------------------------------- #
def test_normalize_adds_extern_c_even_if_other_code_has_extern_c():
    """다른 곳의 extern "C" 는 진입점을 구해 주지 않는다 — 진입점 선언만 본다."""
    code = (
        '#include <cstdint>\n'
        'extern "C" int helper(int x) { return x; }\n'
        'int LLVMFuzzerTestOneInput(const uint8_t* d, size_t n) { return helper(0); }\n'
    )
    out = normalize_cpp_harness(code)
    assert 'extern "C" int LLVMFuzzerTestOneInput(' in out
    assert out.count('extern "C"') == 2          # helper + 진입점, 중복 추가 없음


def test_normalize_does_not_double_extern_c_across_lines():
    code = 'extern "C"\nint LLVMFuzzerTestOneInput(const uint8_t* d, size_t n) { return 0; }\n'
    assert normalize_cpp_harness(code) == code


def test_normalize_leaves_code_without_entry_point_alone():
    code = 'extern "C" int helper() { return 0; }\n'
    assert normalize_cpp_harness(code) == code


# --------------------------------------------------------------------------- #
# 3주차 후속: include 경로 / deps 공급자 / KB 연결
# --------------------------------------------------------------------------- #
def test_include_path_for_normalizes_windows_separators(tmp_path):
    assert include_path_for("score\\json\\json_parser.h", None) == "score/json/json_parser.h"
    assert include_path_for("//score\\json:json_parser.h", None) == "score/json/json_parser.h"


def test_static_provider_matches_same_target_across_repo_prefix():
    """KB 라벨(`//score/json:json`)이 검증 표 키(`@repo//score/json`)에 닿는다."""
    provider = StaticDepsProvider(VERIFIED_SCORE_JSON_DEPS)
    expected = VERIFIED_SCORE_JSON_DEPS[SCORE_JSON]
    assert tuple(provider.deps_for("//score/json:json")) == expected
    assert tuple(provider.deps_for(SCORE_JSON)) == expected
    # 다른 대상은 기존처럼 자기 자신만
    assert tuple(provider.deps_for("//score/other:other")) == ("//score/other:other",)
    # 라벨 형식이 아니어도 죽지 않는다
    assert tuple(provider.deps_for("not-a-label")) == ("not-a-label",)


class _FakeKbDepsProvider:
    def __init__(self, kb):
        self.kb = kb


def _install_fake_kb_bridge(monkeypatch, plan_for=None):
    """dev 병합 전에도 돌도록 가짜 ``kb_bridge`` 모듈을 끼운다."""
    import sys
    import types

    module = types.ModuleType("logosfuzz.generate.kb_bridge")

    class KnowledgeBridgeError(ValueError):
        pass

    module.KnowledgeBridgeError = KnowledgeBridgeError
    module.KnowledgeBaseDepsProvider = _FakeKbDepsProvider

    def plan_harness(kb, api_id, *, target_label="", logic_group=""):
        plan = (plan_for or {}).get(api_id)
        if plan is None:
            raise KnowledgeBridgeError(f"no plan for {api_id}")
        return plan

    module.plan_harness = plan_harness
    monkeypatch.setitem(sys.modules, "logosfuzz.generate.kb_bridge", module)
    return module


def _hide_kb_bridge(monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "logosfuzz.generate.kb_bridge", None)  # import -> ImportError


def test_make_deps_provider_kb_is_default_when_kb_given(monkeypatch):
    from logosfuzz.generate.gen_03_01_harness_generator import make_deps_provider

    _install_fake_kb_bridge(monkeypatch)
    kb = object()
    provider = make_deps_provider("auto", None, kb=kb)
    assert isinstance(provider, _FakeKbDepsProvider) and provider.kb is kb
    assert isinstance(make_deps_provider("kb", None, kb=kb), _FakeKbDepsProvider)
    # kb 가 없으면 auto 는 static
    assert isinstance(make_deps_provider("auto", None), StaticDepsProvider)
    # 명시한 static 은 KB 가 있어도 static
    assert isinstance(make_deps_provider("static", None, kb=kb), StaticDepsProvider)


def test_make_deps_provider_falls_back_to_static_without_kb_bridge(monkeypatch):
    from logosfuzz.generate.gen_03_01_harness_generator import make_deps_provider

    _hide_kb_bridge(monkeypatch)
    assert isinstance(make_deps_provider("auto", None, kb=object()), StaticDepsProvider)
    with pytest.raises(ValueError, match="kb_bridge"):
        make_deps_provider("kb", None, kb=object())


def test_make_deps_provider_kb_requires_kb():
    from logosfuzz.generate.gen_03_01_harness_generator import make_deps_provider

    with pytest.raises(ValueError, match="KB"):
        make_deps_provider("kb", None)


class _FakeKb:
    def __init__(self, documents):
        self._documents = {d["api_id"]: d for d in documents}

    def api(self, api_id):
        return self._documents.get(api_id)


def _group(group_id, api_ids, build_units):
    from types import SimpleNamespace
    return SimpleNamespace(group_id=group_id, api_ids=api_ids, build_units=build_units)


def _patch_kb_adapters(monkeypatch):
    from logosfuzz.knowledge import kb_adapters

    # build_unit_metadata 는 A 의 3주차 작업이라 dev 병합 전에는 속성 자체가 없다.
    # raising=False 로 없어도 주입하고, 있으면 원래 값을 테스트 뒤에 복원한다.
    monkeypatch.setattr(kb_adapters, "build_unit_metadata", lambda kb: [], raising=False)
    monkeypatch.setattr(kb_adapters, "harness_context",
                        lambda kb, target: f"KB-CTX:{target}", raising=False)


def test_group_meta_collects_plans_but_builds_context_by_api_id(monkeypatch):
    from types import SimpleNamespace

    from logosfuzz.generate.gen_03_01_harness_generator import group_meta_from_kb

    _patch_kb_adapters(monkeypatch)
    plan = SimpleNamespace(api_name="f1", prompt_context="PLAN-CTX")
    _install_fake_kb_bridge(monkeypatch, plan_for={1: plan})   # api 2 는 계획 실패

    kb = _FakeKb([
        {"api_id": 1, "function": "f1", "header": "score\\json\\a.h",
         "constraints": [{"kind": "error_contract", "description": "returns Error", "expression": "Result<T>"}]},
        {"api_id": 2, "function": "f2", "header": "score/json/b.h", "constraints": []},
    ])
    plans_out: dict = {}
    targets, meta = group_meta_from_kb(
        kb, [_group("lg_a", [1, 2], ["//score/json:json"])],
        deps_provider=StaticDepsProvider(VERIFIED_SCORE_JSON_DEPS), plans_out=plans_out,
    )

    assert targets == {"lg_a": "//score/json:json"}
    entry = meta["lg_a"]
    # 컨텍스트는 api_id 로 조회한다. 계획의 prompt_context 는 함수 **이름**으로 조회해서
    # 같은 이름의 다른 API(다른 빌드 단위의 FromBuffer)가 잡히므로 쓰지 않는다.
    assert entry["context_blocks"] == ["KB-CTX:1", "KB-CTX:2"]
    assert "PLAN-CTX" not in entry["context_blocks"]
    assert plans_out == {"lg_a": [plan]}
    assert entry["includes"] == ["score/json/a.h", "score/json/b.h"]
    # 에러 계약은 evidence 까지 붙인 기존 형식을 유지한다
    assert entry["error_contracts"] == ["f1: returns Error (evidence: Result<T>)"]
    # 라벨 표기가 달라도 검증 표의 deps 가 잡힌다
    assert entry["build_deps"] == list(VERIFIED_SCORE_JSON_DEPS[SCORE_JSON])


def test_group_meta_without_kb_bridge_uses_legacy_path(monkeypatch):
    from logosfuzz.generate.gen_03_01_harness_generator import group_meta_from_kb

    _patch_kb_adapters(monkeypatch)
    _hide_kb_bridge(monkeypatch)
    kb = _FakeKb([{"api_id": 1, "function": "f1", "header": "a.h", "constraints": []}])
    plans_out: dict = {}
    _, meta = group_meta_from_kb(kb, [_group("lg_a", [1], ["//x:y"])], plans_out=plans_out)

    assert meta["lg_a"]["context_blocks"] == ["KB-CTX:1"]
    assert plans_out == {"lg_a": []}


# --------------------------------------------------------------------------- #
# 선언 발췌(프롬프트에 실제 소스 제공) / 그룹 선택(--only, --list-groups)
# --------------------------------------------------------------------------- #
def test_declaration_excerpt_shows_lines_around_declaration(tmp_path):
    from logosfuzz.generate.gen_03_01_harness_generator import declaration_excerpt

    header = tmp_path / "x.h"
    header.write_text("\n".join(f"L{i}" for i in range(1, 31)) + "\n", encoding="utf-8")
    out = declaration_excerpt({"file": str(header), "line": 10}, tmp_path)

    assert out.startswith("// x.h:10\n")
    assert "L8" in out and "L10" in out and "L20" in out      # 앞 2줄 ~ 뒤 10줄
    assert "L7" not in out and "L21" not in out


def test_declaration_excerpt_is_truncated_and_tolerates_missing_info(tmp_path):
    from logosfuzz.generate.gen_03_01_harness_generator import declaration_excerpt

    header = tmp_path / "x.h"
    header.write_text("a" * 500 + "\n" + "b" * 500 + "\n", encoding="utf-8")
    out = declaration_excerpt({"file": str(header), "line": 1}, tmp_path, max_chars=30)
    assert out.endswith("// ... (truncated)")

    assert declaration_excerpt({"file": str(tmp_path / "missing.h"), "line": 3}) == ""
    assert declaration_excerpt({"file": str(header), "line": 0}) == ""
    assert declaration_excerpt({"line": 3}) == ""
    assert declaration_excerpt({"file": str(header), "line": 500}) == ""      # 줄 번호가 파일 끝을 넘음
    assert declaration_excerpt({"file": str(header), "line": "not-a-number"}) == ""


def test_group_meta_carries_declaration_excerpts_into_header_content(monkeypatch, tmp_path):
    from logosfuzz.generate.gen_03_01_harness_generator import group_meta_from_kb

    header = tmp_path / "score" / "json" / "a.h"
    header.parent.mkdir(parents=True)
    header.write_text(
        "// license\ntemplate <typename Fn>\nauto StringArray(const Fn& fn) noexcept -> JsonParser&;\n",
        encoding="utf-8")
    _patch_kb_adapters(monkeypatch)
    _hide_kb_bridge(monkeypatch)
    kb = _FakeKb([
        {"api_id": 1, "function": "StringArray", "file": str(header), "line": 3,
         "header": str(header), "constraints": []},
        {"api_id": 2, "function": "NoFile", "constraints": []},      # 위치 정보 없음 -> 건너뜀
    ])

    _, meta = group_meta_from_kb(kb, [_group("lg_a", [1, 2], ["//x:y"])], workspace_root=tmp_path)
    text = meta["lg_a"]["header_content"]
    assert text.startswith("// score/json/a.h:3")
    assert "-> JsonParser&" in text                                  # 반환 타입이 그대로 보인다

    _, bare = group_meta_from_kb(
        _FakeKb([{"api_id": 2, "function": "NoFile", "constraints": []}]),
        [_group("lg_b", [2], ["//x:y"])])
    assert "header_content" not in bare["lg_b"]


def test_header_content_reaches_the_prompt():
    prompts: list[str] = []

    def fake_llm(prompt: str) -> str:
        prompts.append(prompt)
        return MINIMAL_CC

    schedule = [ScheduleResult("lg_json", 0.5, 0.0, 1.0, 0.5, 60)]
    generate_pairs(
        schedule, {"lg_json": [1]}, {"lg_json": SCORE_JSON},
        deps_provider=StaticDepsProvider(VERIFIED_SCORE_JSON_DEPS),
        context_db={1: CTX},
        group_meta={"lg_json": {"header_content": "// a.h:3\nauto Parse() -> Widget&;"}},
        llm=fake_llm,
    )
    assert "auto Parse() -> Widget&;" in prompts[0]


def test_filter_groups_matches_group_name_or_build_unit():
    from logosfuzz.generate.gen_03_01_harness_generator import filter_groups

    groups = [
        _group("lg_json_public", [1], ["@score_baselibs//score/json"]),
        _group("lg_vajson_impl", [2], ["//score/json/internal/parser/vajson/vajson_impl:vajson_impl"]),
        _group("lg_nounit", [3], []),
    ]
    assert filter_groups(groups) == groups                               # 패턴 없음 = 전부
    assert [g.group_id for g in filter_groups(groups, ["score/json$"])] == ["lg_json_public"]
    assert [g.group_id for g in filter_groups(groups, ["vajson_impl:"])] == ["lg_vajson_impl"]
    assert [g.group_id for g in filter_groups(groups, ["^lg_nounit$"])] == ["lg_nounit"]
    # 여러 패턴은 OR
    assert len(filter_groups(groups, ["^lg_nounit$", "score/json$"])) == 2
    assert filter_groups(groups, ["does-not-exist"]) == []
    with pytest.raises(ValueError, match="--only"):
        filter_groups(groups, ["("])


def test_list_groups_summarises_groups_without_llm(monkeypatch):
    from logosfuzz.generate.gen_03_01_harness_generator import list_groups
    from logosfuzz.schedule import logic_groups

    groups = [_group("lg_a", [1, 2], ["//x:a"]), _group("lg_b", [3], ["//x:b"])]
    monkeypatch.setattr(logic_groups, "build_groups", lambda kb: groups)
    kb = _FakeKb([
        {"api_id": 1, "function": "f1"}, {"api_id": 2, "function": "f2"}, {"api_id": 3, "function": "g1"},
    ])

    rows = list_groups(kb)
    assert [r["group"] for r in rows] == ["lg_a", "lg_b"]
    assert rows[0] == {"group": "lg_a", "build_units": ["//x:a"], "apis": 2, "sample_apis": ["f1", "f2"]}
    assert [r["group"] for r in list_groups(kb, ["//x:b$"])] == ["lg_b"]


def test_cli_argument_rules():
    from logosfuzz.generate.gen_03_01_harness_generator import _parse_args

    assert _parse_args(["--demo", "--out", "o"]).out is not None
    assert _parse_args(["--kb", "kb.json", "--list-groups"]).list_groups is True
    assert _parse_args(["--kb", "kb.json", "--out", "o", "--only", "a", "--only", "b"]).only == ["a", "b"]
    with pytest.raises(SystemExit):
        _parse_args(["--demo"])                                      # --out 이 없다
    with pytest.raises(SystemExit):
        _parse_args(["--demo", "--list-groups"])                     # --list-groups 는 --kb 필요


def test_cpp_prompt_does_not_force_has_value_on_every_result():
    """모든 결과에 has_value() 를 강요하면 참조 반환 API 에도 그걸 호출해 컴파일이 깨진다."""
    prompt = build_cpp_prompt("g", [CTX])
    assert "auto&" in prompt and "NEVER `auto`" in prompt
    assert "Never invent members" in prompt
    assert "score::Result<T>" in prompt                     # Result 계열은 기존처럼 has_value()
    assert "CONSUME every result (e.g. check has_value() and read value())" not in prompt



# --------------------------------------------------------------------------- #
# include 헤더 선택: 테스트 보조 헤더 제외 + 같은 이름 공개 헤더로 대체
# (실사례: FromBuffer 의 KB 헤더가 parsers_test_suite.h 로 잡혀 빌드가 깨졌다)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("path,expected", [
    ("score/json/internal/parser/parsers_test_suite.h", True),
    ("score/json/internal/parser/number_parser_test_suite.h", True),
    ("score/json/json_parser_test.h", True),
    ("score/x/mock_reader.h", True),
    ("score/x/reader_mock.h", True),
    ("score/x/testing/helper.h", True),
    ("score/x/test/helper.h", True),
    ("score\\x\\tests\\helper.h", True),
    ("score/json/json_parser.h", False),
    ("score/json/internal/parser/vajson/vajson_parser.h", False),
    ("score/latest/contest.h", False),                      # 부분 문자열만으로는 테스트로 보지 않는다
])
def test_is_test_header(path, expected):
    from logosfuzz.generate.gen_03_01_harness_generator import is_test_header

    assert is_test_header(path) is expected


def _header_tree(tmp_path):
    package = tmp_path / "score" / "x"
    package.mkdir(parents=True)
    for name in ("vajson_parser.cpp", "vajson_parser.h", "parsers_test_suite.h", "real.h"):
        (package / name).write_text("// x\n", encoding="utf-8")
    return package


def test_header_for_document_keeps_a_valid_kb_header(tmp_path):
    from logosfuzz.generate.gen_03_01_harness_generator import header_for_document

    package = _header_tree(tmp_path)
    doc = {"file": str(package / "vajson_parser.cpp"), "header": str(package / "real.h")}
    assert header_for_document(doc, tmp_path) == "score/x/real.h"


def test_header_for_document_replaces_test_header_with_same_stem_header(tmp_path):
    from logosfuzz.generate.gen_03_01_harness_generator import header_for_document

    package = _header_tree(tmp_path)
    doc = {"file": str(package / "vajson_parser.cpp"),
           "header": str(package / "parsers_test_suite.h")}
    assert header_for_document(doc, tmp_path) == "score/x/vajson_parser.h"
    # 헤더 정보가 아예 없어도(GetData 사례) 같은 이름 헤더로 채운다
    assert header_for_document({"file": str(package / "vajson_parser.cpp")}, tmp_path) \
        == "score/x/vajson_parser.h"


def test_header_for_document_gives_up_instead_of_returning_a_test_header(tmp_path):
    from logosfuzz.generate.gen_03_01_harness_generator import header_for_document

    package = _header_tree(tmp_path)
    (package / "vajson_parser.h").unlink()                    # 대체할 공개 헤더가 없다
    doc = {"file": str(package / "vajson_parser.cpp"),
           "header": str(package / "parsers_test_suite.h")}
    assert header_for_document(doc, tmp_path) == ""
    assert header_for_document({}, tmp_path) == ""


def test_group_meta_never_includes_test_headers(monkeypatch, tmp_path):
    from logosfuzz.generate.gen_03_01_harness_generator import group_meta_from_kb

    package = _header_tree(tmp_path)
    _patch_kb_adapters(monkeypatch)
    _hide_kb_bridge(monkeypatch)
    source = str(package / "vajson_parser.cpp")
    kb = _FakeKb([
        {"api_id": 1, "function": "FromFile", "file": source, "line": 17,
         "header": str(package / "parsers_test_suite.h"), "constraints": []},
        {"api_id": 2, "function": "FromBuffer", "file": source, "line": 33,
         "header": str(package / "parsers_test_suite.h"), "constraints": []},
        {"api_id": 3, "function": "GetData", "file": source, "line": 51, "constraints": []},
    ])

    _, meta = group_meta_from_kb(kb, [_group("lg_v", [1, 2, 3], ["//score/x:y"])],
                                 workspace_root=tmp_path)
    assert meta["lg_v"]["includes"] == ["score/x/vajson_parser.h"]     # 중복 없이 공개 헤더 하나


def test_group_meta_unit_header_fallback_skips_test_headers(monkeypatch, tmp_path):
    """API 헤더가 하나도 없을 때 쓰는 빌드 단위 헤더 목록에서도 테스트 헤더는 뺀다."""
    from logosfuzz.generate.gen_03_01_harness_generator import group_meta_from_kb
    from logosfuzz.knowledge import kb_adapters

    _patch_kb_adapters(monkeypatch)
    _hide_kb_bridge(monkeypatch)
    monkeypatch.setattr(kb_adapters, "build_unit_metadata", lambda kb: [
        {"build_target": "//score/x:y",
         "headers": ["score/x/api.h", "score/x/api_test_suite.h"]}], raising=False)
    kb = _FakeKb([{"api_id": 1, "function": "f", "constraints": []}])

    _, meta = group_meta_from_kb(kb, [_group("lg_v", [1], ["//score/x:y"])])
    assert meta["lg_v"]["includes"] == ["score/x/api.h"]


# --------------------------------------------------------------------------- #
# 공개 헤더의 클래스 선언 발췌 (실사례: VajsonParser::FromBuffer 는 public static,
# 생성자는 private — LLM 이 JsonData 를 만들어 인스턴스를 생성하려다 컴파일이 깨졌다)
# --------------------------------------------------------------------------- #
VAJSON_LIKE_HEADER = """\
#include "x.h"
namespace score
{
namespace json
{
class Forward;
class VajsonParser final : private Base
{
  public:
    static auto FromFile(const std::string_view file_path) -> score::Result<Any>;
    static auto FromBuffer(const std::string_view buffer) -> score::Result<Any>;

  private:
    auto GetData() noexcept -> score::Result<Any>;
};
}
}
"""


def _excerpt(tmp_path, header_text, function):
    from logosfuzz.generate.gen_03_01_harness_generator import header_declaration_excerpt

    header = tmp_path / "x.h"
    header.write_text(header_text, encoding="utf-8")
    return header_declaration_excerpt({"function": function}, str(header), tmp_path)


def test_header_excerpt_shows_class_access_and_static(tmp_path):
    out = _excerpt(tmp_path, VAJSON_LIKE_HEADER, "FromBuffer")

    assert out.startswith("// x.h:11 (member of VajsonParser)\n")
    assert "class VajsonParser final : private Base" in out
    assert "  public:" in out
    assert "static auto FromBuffer(const std::string_view buffer) -> score::Result<Any>;" in out
    assert "FromFile" not in out and "private:" not in out       # 이 API 와 무관한 부분은 뺀다


def test_header_excerpt_marks_private_members(tmp_path):
    out = _excerpt(tmp_path, VAJSON_LIKE_HEADER, "GetData")
    assert "(member of VajsonParser)" in out and "  private:" in out


def test_header_excerpt_free_function_is_not_attributed_to_a_forward_declared_class(tmp_path):
    out = _excerpt(tmp_path, "namespace n {\nclass Fwd;\nvoid Free(int x);\n}\n", "Free")
    assert "member of" not in out and "class Fwd" not in out
    assert "void Free(int x);" in out


def test_header_excerpt_keeps_template_line_and_multiline_declaration(tmp_path):
    header = ("class A {\n public:\n  template <typename Fn>\n"
              "  static auto Run(const Fn& fn,\n                  int x) -> void;\n};\n")
    out = _excerpt(tmp_path, header, "Run")
    assert "template <typename Fn>" in out and "int x) -> void;" in out
    assert "(member of A)" in out


def test_header_excerpt_ignores_comments_and_tolerates_missing_things(tmp_path):
    out = _excerpt(tmp_path, "// FromBuffer(x) is documented here\nvoid FromBuffer(int);\n", "FromBuffer")
    assert out.startswith("// x.h:2")                             # 주석 줄은 건너뛴다

    assert _excerpt(tmp_path, "void Other();\n", "FromBuffer") == ""
    from logosfuzz.generate.gen_03_01_harness_generator import header_declaration_excerpt
    assert header_declaration_excerpt({"function": "f"}, str(tmp_path / "missing.h")) == ""
    assert header_declaration_excerpt({"function": ""}, str(tmp_path / "x.h")) == ""
    assert header_declaration_excerpt({"function": "f"}, "") == ""


def test_group_meta_prefers_header_class_excerpt_and_dedupes(monkeypatch, tmp_path):
    from logosfuzz.generate.gen_03_01_harness_generator import group_meta_from_kb

    package = tmp_path / "score" / "x"
    package.mkdir(parents=True)
    (package / "vajson_parser.h").write_text(VAJSON_LIKE_HEADER, encoding="utf-8")
    (package / "vajson_parser.cpp").write_text("// definitions\n" * 40, encoding="utf-8")
    (package / "parsers_test_suite.h").write_text("// test helper\n", encoding="utf-8")
    _patch_kb_adapters(monkeypatch)
    _hide_kb_bridge(monkeypatch)
    source = str(package / "vajson_parser.cpp")
    test_header = str(package / "parsers_test_suite.h")
    kb = _FakeKb([
        {"api_id": 1, "function": "FromFile", "file": source, "line": 17,
         "header": test_header, "constraints": []},
        {"api_id": 2, "function": "FromFile", "file": source, "line": 194,      # 같은 API 의 두 번째 정의
         "header": test_header, "constraints": []},
        {"api_id": 3, "function": "FromBuffer", "file": source, "line": 33,
         "header": test_header, "constraints": []},
    ])

    _, meta = group_meta_from_kb(kb, [_group("lg_v", [1, 2, 3], ["//score/x:y"])],
                                 workspace_root=tmp_path)
    text = meta["lg_v"]["header_content"]

    assert "(member of VajsonParser)" in text and "static auto FromBuffer" in text
    assert text.count("static auto FromFile") == 1                          # 중복 제거
    assert "parsers_test_suite" not in text and "definitions" not in text   # .cpp 정의는 폴백일 뿐
    assert meta["lg_v"]["includes"] == ["score/x/vajson_parser.h"]


def test_group_meta_falls_back_to_definition_excerpt_without_a_header(monkeypatch, tmp_path):
    from logosfuzz.generate.gen_03_01_harness_generator import group_meta_from_kb

    source = tmp_path / "impl.cpp"
    source.write_text("\n".join(f"line{i}" for i in range(1, 20)) + "\n", encoding="utf-8")
    _patch_kb_adapters(monkeypatch)
    _hide_kb_bridge(monkeypatch)
    kb = _FakeKb([{"api_id": 1, "function": "Only", "file": str(source), "line": 5, "constraints": []}])

    _, meta = group_meta_from_kb(kb, [_group("lg_v", [1], ["//x:y"])], workspace_root=tmp_path)
    assert meta["lg_v"]["header_content"].startswith("// impl.cpp:5")


def test_cpp_prompt_rules_for_static_members_and_file_apis():
    prompt = " ".join(build_cpp_prompt("g", [CTX]).split())                # 줄바꿈 무시
    assert "ClassName::Func(...)" in prompt and "NO instance" in prompt
    assert "do not construct a class whose public constructors are not shown" in prompt
    assert "do NOT call it" in prompt and "FromBuffer" in prompt           # FromFile 대신 buffer 변형


# --------------------------------------------------------------------------- #
# 하네스가 호출하면 안 되는 API 는 프롬프트 목록에서 미리 뺀다
# (실사례: 목록에 있던 FromFile·private GetData 를 LLM 이 그대로 호출해 컴파일이 깨졌다)
# --------------------------------------------------------------------------- #
def test_declaration_access_for_members(tmp_path):
    from logosfuzz.generate.gen_03_01_harness_generator import declaration_access

    header = tmp_path / "x.h"
    header.write_text(VAJSON_LIKE_HEADER, encoding="utf-8")
    assert declaration_access({"function": "FromBuffer"}, str(header)) == "public"
    assert declaration_access({"function": "GetData"}, str(header)) == "private"
    assert declaration_access({"function": "Nope"}, str(header)) == ""
    assert declaration_access({"function": "FromBuffer"}, "") == ""


def test_declaration_access_defaults_follow_struct_and_class(tmp_path):
    from logosfuzz.generate.gen_03_01_harness_generator import declaration_access

    header = tmp_path / "x.h"
    header.write_text(
        "struct S\n{\n    static void Open();\n};\nclass C\n{\n    void Hidden();\n};\n"
        "void Free(int);\n", encoding="utf-8")
    assert declaration_access({"function": "Open"}, str(header)) == "public"      # struct 기본
    assert declaration_access({"function": "Hidden"}, str(header)) == "private"   # class 기본
    assert declaration_access({"function": "Free"}, str(header)) == ""            # 자유 함수


@pytest.mark.parametrize("function,param,expected", [
    ("FromBuffer", "buffer", ""),
    ("FromFile", "file_path", "파일 경로를 받는 API"),
    ("Load", "filePath", "파일 경로를 받는 API"),
    ("Open", "dirname", "파일 경로를 받는 API"),
    ("Parse", "search_path", "파일 경로를 받는 API"),
    ("ReadFile", "data", "파일 경로를 받는 API"),                  # 함수 이름만으로도
    ("from_file", "data", "파일 경로를 받는 API"),
    ("GetProfile", "profile", ""),                                 # 부분 문자열 file 은 오탐 금지
])
def test_unfuzzable_reason_for_file_apis(function, param, expected):
    from logosfuzz.generate.gen_03_01_harness_generator import unfuzzable_reason

    doc = {"function": function, "params": [{"name": param, "type": "std::string_view"}]}
    assert unfuzzable_reason(doc) == expected


def _vajson_kb(tmp_path):
    header = tmp_path / "score" / "x" / "vajson_parser.h"
    header.parent.mkdir(parents=True)
    header.write_text(VAJSON_LIKE_HEADER, encoding="utf-8")
    source = str(header.with_suffix(".cpp"))

    def doc(api_id, function, params, line):
        return {"api_id": api_id, "function": function, "signature": f"Result {function}()",
                "params": params, "file": source, "line": line, "header": str(header),
                "constraints": []}

    file_param = [{"name": "file_path", "type": "const std::string_view"}]
    buffer_param = [{"name": "buffer", "type": "const std::string_view"}]
    return _FakeKb([
        doc(1, "FromFile", file_param, 17),
        doc(2, "FromBuffer", buffer_param, 33),
        doc(3, "GetData", [], 51),
        doc(4, "FromFile", file_param, 194),      # 같은 시그니처의 두 번째 정의
        doc(5, "FromBuffer", buffer_param, 200),
    ])


def test_fuzzable_api_ids_drops_file_private_and_duplicate_apis(tmp_path):
    from logosfuzz.generate.gen_03_01_harness_generator import fuzzable_api_ids

    kept, excluded = fuzzable_api_ids(_vajson_kb(tmp_path), _group("lg_v", [1, 2, 3, 4, 5], []))
    assert kept == [2]                                         # FromBuffer 첫 정의만
    assert excluded == [("FromFile", "파일 경로를 받는 API"), ("GetData", "private 멤버")]


def test_restrict_to_fuzzable_keeps_group_identity_and_drops_empty_groups(tmp_path, capsys):
    from logosfuzz.generate.gen_03_01_harness_generator import restrict_to_fuzzable
    from logosfuzz.schedule.logic_groups import GroupInfo

    kb = _vajson_kb(tmp_path)
    mixed = GroupInfo(group_id="lg_mixed", name="m", api_ids=[1, 2, 3], build_units=["//score/x:y"])
    only_file = GroupInfo(group_id="lg_file", name="f", api_ids=[1, 4], build_units=["//score/x:y"])

    groups = restrict_to_fuzzable(kb, [mixed, only_file])

    assert [g.group_id for g in groups] == ["lg_mixed"]        # 호출할 API 가 없는 그룹은 제외
    assert groups[0].api_ids == [2] and groups[0].build_units == ["//score/x:y"]
    assert mixed.api_ids == [1, 2, 3]                          # 원본은 건드리지 않는다
    out = capsys.readouterr().out
    assert "FromFile 제외" in out and "GetData 제외" in out and "lg_file" in out


def test_cpp_prompt_fdp_bytes_and_reference_are_style_only():
    prompt = " ".join(build_cpp_prompt("g", [CTX]).split())
    assert "ConsumeBytes<T> is only valid for a 1-byte T" in prompt
    assert "follow its STYLE only, not its API usage" in prompt
    assert "REFERENCE HARNESS (verified" in prompt


# --------------------------------------------------------------------------- #
# 호출 예시(Usage) / namespace 해석 / 컨텍스트 블록 정리 / 호출 순서 가지치기
# (실사례: 올바른 선언 발췌가 있었는데도 LLM 이 참조 하네스를 따라
#  `VajsonParser parser{}; parser.FromBuffer(..)` 로 인스턴스를 만들었다)
# --------------------------------------------------------------------------- #
def test_header_excerpt_gives_static_usage_with_qualified_class(tmp_path):
    out = _excerpt(tmp_path, VAJSON_LIKE_HEADER, "FromBuffer")
    assert ("// Usage: score::json::VajsonParser::FromBuffer(...) — static member: "
            "call it directly, NEVER create a VajsonParser instance") in out


def test_header_excerpt_has_no_usage_for_instance_or_private_members(tmp_path):
    header = ("namespace a\n{\nclass C\n{\n  public:\n    void Inst();\n"
              "  private:\n    static void Hidden();\n};\n}\n")
    assert "Usage" not in _excerpt(tmp_path, header, "Inst")          # static 이 아니다
    assert "Usage" not in _excerpt(tmp_path, header, "Hidden")        # private


@pytest.mark.parametrize("header,function,expected", [
    # 두 스타일: 여는 중괄호가 같은 줄 / 다음 줄
    ("namespace a { namespace b {\nclass K {\n public:\n  static int Go();\n};\n}}\n", "Go", "a::b::K::Go"),
    ("namespace a\n{\nnamespace b\n{\nclass K\n{\n public:\n  static int Go();\n};\n}\n}\n", "Go", "a::b::K::Go"),
    # 닫힌 namespace 는 이름에 들어가지 않는다
    ("namespace old { void X(); }\nnamespace cur {\nclass K\n{\n public:\n  static int Go();\n};\n}\n", "Go", "cur::K::Go"),
    # 이름 없는 namespace 와 주석 속 중괄호는 무시
    ("namespace {\n}\n// namespace fake {\nnamespace real\n{\nclass K\n{\n public:\n  static int Go();\n};\n}\n", "Go", "real::K::Go"),
    # namespace 가 없으면 클래스 이름만
    ("class K\n{\n public:\n  static int Go();\n};\n", "Go", "K::Go"),
    # alias 는 namespace 가 아니다
    ("namespace fs = std::filesystem;\nclass K\n{\n public:\n  static int Go();\n};\n", "Go", "K::Go"),
])
def test_header_excerpt_resolves_namespaces(tmp_path, header, function, expected):
    assert f"// Usage: {expected}(...)" in _excerpt(tmp_path, header, function)


def test_clean_context_block_replaces_test_include_and_drops_flags():
    from logosfuzz.generate.gen_03_01_harness_generator import clean_context_block

    block = ("## FromBuffer  (api_id=262)\n"
             "signature: Result FromBuffer(std::string_view)\n"
             'include: #include "parsers_test_suite.h"\n'
             "compile flags: -I/a -I/b -fno-builtin\n"
             "doc: parses a buffer")
    out = clean_context_block(block, "score/json/vajson_parser.h")
    assert 'include: #include "score/json/vajson_parser.h"' in out
    assert "parsers_test_suite" not in out and "compile flags" not in out
    assert "signature:" in out and "doc: parses a buffer" in out

    assert "include:" not in clean_context_block(block, "")               # 공개 헤더를 못 찾으면 줄을 뺀다


def test_group_meta_context_uses_resolved_public_header(monkeypatch, tmp_path):
    from logosfuzz.generate.gen_03_01_harness_generator import group_meta_from_kb
    from logosfuzz.knowledge import kb_adapters

    package = _header_tree(tmp_path)
    _patch_kb_adapters(monkeypatch)
    _hide_kb_bridge(monkeypatch)
    monkeypatch.setattr(kb_adapters, "harness_context", lambda kb, target: (
        f"## api {target}\ninclude: #include \"parsers_test_suite.h\"\ncompile flags: -I/x"), raising=False)
    kb = _FakeKb([{"api_id": 7, "function": "FromBuffer", "file": str(package / "vajson_parser.cpp"),
                   "header": str(package / "parsers_test_suite.h"), "constraints": []}])

    _, meta = group_meta_from_kb(kb, [_group("lg_v", [7], ["//score/x:y"])], workspace_root=tmp_path)
    block = meta["lg_v"]["context_blocks"][0]
    assert 'include: #include "score/x/vajson_parser.h"' in block
    assert "parsers_test_suite" not in block and "compile flags" not in block


def test_prune_call_order_keeps_only_group_members():
    from logosfuzz.generate.gen_03_01_harness_generator import prune_call_order

    kb = _FakeKb([
        {"api_id": 1, "function": "FromBuffer"},
        {"api_id": 2, "function": "Other"},
        {"api_id": 3, "function": "GetData"},                     # 그룹에서 제외된 API
    ])
    context_db = {
        1: ApiContext(1, "sig1", ["FromBuffer", "FromBuffer", "HandleEvent", "GetData", "Other"], [], "u"),
        2: ApiContext(2, "sig2", ["Other", "FromBuffer"], [], "u"),
    }
    prune_call_order(context_db, kb, [_group("lg", [1, 2], [])])      # 3 번은 group.api_ids 에 없다

    assert context_db[1].call_order == ["FromBuffer", "Other"]       # 내부 호출·제외 API·중복 제거
    assert context_db[2].call_order == ["Other", "FromBuffer"]


def test_using_namespace_directive_does_not_open_a_scope(tmp_path):
    """`using namespace std;` 의 std 가 바깥 클래스 본문의 `{` 에 붙어 이름에 끼어들면 안 된다."""
    header = ("using namespace std;\nclass Outer\n{\n  public:\n    class Inner\n    {\n"
              "      public:\n        static int Go();\n    };\n};\n")
    out = _excerpt(tmp_path, header, "Go")
    assert "std::" not in out
    assert "// Usage: Inner::Go(...)" in out          # 한계: 바깥 클래스 이름은 빠진다(문서화된 동작)


def test_fuzzable_api_ids_reports_same_name_exclusion_once():
    from logosfuzz.generate.gen_03_01_harness_generator import fuzzable_api_ids

    file_param = [{"name": "file_path", "type": "std::string_view"}]
    kb = _FakeKb([
        {"api_id": 1, "function": "FromFile", "signature": "A", "params": file_param},
        {"api_id": 2, "function": "FromFile", "signature": "B", "params": file_param},  # 시그니처만 다르다
    ])
    kept, excluded = fuzzable_api_ids(kb, _group("lg", [1, 2], []))
    assert kept == [] and excluded == [("FromFile", "파일 경로를 받는 API")]


def test_select_top_groups_follows_ranking_not_list_order():
    """--top 은 목록 앞에서 N개가 아니라 시너지 랭킹 상위 N개다 (예전에는 앞에서 잘랐다)."""
    from logosfuzz.generate.gen_03_01_harness_generator import select_top_groups

    groups = [_group("lg_first", [1], []), _group("lg_best", [2], []), _group("lg_mid", [3], [])]
    ranking = [("lg_best", 0.9), ("lg_mid", 0.5), ("lg_first", 0.1)]          # 점수 내림차순

    kept, top = select_top_groups(groups, ranking, 1)
    assert [g.group_id for g in kept] == ["lg_best"]                         # 목록 맨 앞이 아니다
    assert top == [("lg_best", 0.9)]

    kept, top = select_top_groups(groups, ranking, 2)
    assert [g.group_id for g in kept] == ["lg_best", "lg_mid"]               # 입력 목록 순서 유지
    assert [name for name, _ in top] == ["lg_best", "lg_mid"]                # 랭킹 순서를 유지

    # 0 이하이면 전부, 그룹 수보다 크면 전부
    assert len(select_top_groups(groups, ranking, 0)[0]) == 3
    assert len(select_top_groups(groups, ranking, 99)[0]) == 3
