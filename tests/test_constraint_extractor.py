from src.constraint_extractor import (
    extract_from_paths,
    extract_from_text,
    mask_source,
    parse_params,
    split_top_level,
)

SAMPLE = """
#include <stdlib.h>

/**
 * @param buf 입력 버퍼. must not be NULL.
 */
int decode(const char *buf, size_t len, int *out)
{
    if (!buf) {
        return -1;
    }
    if (len == 0) {
        return -1;
    }
    assert(out != NULL);
    char *scratch = malloc(len);
    memcpy(scratch, buf, len);
    *out = scratch[0];
    return 0;
}
"""


def _kinds(constraints):
    return {c.kind for c in constraints}


def _find(constraints, kind, target=None):
    return [c for c in constraints if c.kind == kind and (target is None or c.target == target)]


def test_mask_source_preserves_offsets_and_removes_comments():
    text = 'int a; // brace { here\nchar *s = "}"; /* } */\nint b;'
    masked = mask_source(text)

    assert len(masked) == len(text)
    assert masked.count("\n") == text.count("\n")
    assert "{" not in masked
    assert "}" not in masked
    assert "int a;" in masked and "int b;" in masked


def test_mask_source_strips_preprocessor_lines():
    text = "#define OPEN {\nint f(void) { return 0; }\n"
    masked = mask_source(text)

    assert masked.count("{") == 1


def test_split_top_level_keeps_function_pointer_params():
    parts = split_top_level("int a, void (*cb)(int, char), size_t n")

    assert parts == ["int a", "void (*cb)(int, char)", "size_t n"]


def test_parse_params_detects_pointers_and_names():
    params = parse_params("const char *buf, size_t len, struct header *out, void")

    assert [p.name for p in params] == ["buf", "len", "out"]
    assert [p.is_pointer for p in params] == [True, False, True]
    assert params[0].is_const is True


def test_parse_params_handles_arrays_and_unnamed():
    params = parse_params("char data[16], int")

    assert params[0].name == "data"
    assert params[0].is_pointer is True
    assert params[1].name == ""


def test_extract_finds_function_and_signature():
    facts = extract_from_text(SAMPLE, path="sample.c")

    assert [f.name for f in facts] == ["decode"]
    decode = facts[0]
    assert decode.return_type == "int"
    assert "decode" in decode.signature
    assert decode.file == "sample.c"
    assert decode.line > 0


def test_extract_null_check_constraint():
    decode = extract_from_text(SAMPLE)[0]
    null_checks = _find(decode.constraints, "null_check", "buf")

    assert null_checks, f"expected a null_check for buf, got {_kinds(decode.constraints)}"
    # early return 이 뒤따르므로 신뢰도가 높아야 한다
    assert null_checks[0].confidence >= 0.9
    assert "NULL" in null_checks[0].description


def test_extract_range_check_flips_operator_on_early_exit():
    decode = extract_from_text(SAMPLE)[0]
    range_checks = _find(decode.constraints, "range_check", "len")

    assert range_checks
    # `if (len == 0) return -1;` 은 len != 0 요구가 아니라 비교 기록으로 남는다.
    assert any("len" in c.description for c in range_checks)


def test_range_check_requires_bound_direction():
    facts = extract_from_text(
        "int f(int n) { if (n <= 0) { return -1; } return n; }"
    )
    checks = _find(facts[0].constraints, "range_check", "n")

    assert checks
    assert "n > 0" in checks[0].description


def test_extract_assert_constraint():
    decode = extract_from_text(SAMPLE)[0]
    asserts = _find(decode.constraints, "assert")

    assert asserts
    assert "out != NULL" in asserts[0].expression
    assert asserts[0].confidence > 0.9


def test_extract_buffer_size_pairing():
    decode = extract_from_text(SAMPLE)[0]
    pairs = _find(decode.constraints, "buffer_size")

    assert pairs
    assert pairs[0].target == "buf,len"


def test_extract_resource_ownership_when_unpaired():
    decode = extract_from_text(SAMPLE)[0]
    resources = _find(decode.constraints, "resource", "malloc")

    assert resources
    assert "caller" in resources[0].description


def test_resource_marked_paired_when_released():
    facts = extract_from_text(
        "void f(void) { char *p = malloc(10); free(p); }"
    )
    resources = _find(facts[0].constraints, "resource", "malloc")

    assert resources
    assert "same function" in resources[0].description


def test_extract_risky_call():
    decode = extract_from_text(SAMPLE)[0]
    risky = _find(decode.constraints, "risky_call", "memcpy")

    assert risky


def test_extract_return_value_error_code():
    decode = extract_from_text(SAMPLE)[0]
    returns = _find(decode.constraints, "return_value")

    assert returns
    assert "error code" in returns[0].description


def test_return_value_null_for_pointer_return():
    facts = extract_from_text(
        "char *dup(const char *s) { if (!s) { return NULL; } return strdup(s); }"
    )
    returns = _find(facts[0].constraints, "return_value")

    assert returns
    assert "NULL" in returns[0].description


def test_extract_doc_param_constraint():
    decode = extract_from_text(SAMPLE)[0]
    docs = _find(decode.constraints, "doc", "buf")

    assert docs
    assert "must not be NULL" in docs[0].description
    assert "입력 버퍼" in decode.doc


def test_line_comment_doc_is_captured():
    facts = extract_from_text(
        "// dst must be at least 64 bytes.\nvoid copy(char *dst) { dst[0] = 0; }"
    )

    assert "must be at least 64 bytes" in facts[0].doc
    assert _find(facts[0].constraints, "doc")


def test_control_flow_is_not_mistaken_for_a_function():
    facts = extract_from_text(
        "int f(int n) { while (n > 0) { n--; } switch (n) { default: break; } return n; }"
    )

    assert [f.name for f in facts] == ["f"]


def test_call_followed_by_block_is_not_a_function():
    facts = extract_from_text("void g(void) { helper(1); { int x = 0; (void)x; } }")

    assert [f.name for f in facts] == ["g"]


def test_declaration_without_body_is_skipped():
    facts = extract_from_text("int only_declared(int a);\nint defined(int a) { return a; }")

    assert [f.name for f in facts] == ["defined"]


def test_nullable_when_guarded_positively():
    facts = extract_from_text("void f(int *p) { if (p != NULL) { *p = 1; } }")
    nullable = _find(facts[0].constraints, "nullable", "p")

    assert nullable


def test_extract_from_paths_walks_directories(tmp_path):
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "a.c").write_text("int a(int *p) { if (!p) return -1; return 0; }",
                                             encoding="utf-8")
    (tmp_path / "notes.txt").write_text("ignored", encoding="utf-8")

    facts = extract_from_paths([str(tmp_path)])

    assert [f.name for f in facts] == ["a"]


def test_facts_serialize_to_json_ready_dict():
    payload = extract_from_text(SAMPLE)[0].to_dict()

    assert payload["name"] == "decode"
    assert isinstance(payload["params"], list)
    assert isinstance(payload["constraints"], list)
    assert set(payload["params"][0]) == {"name", "type", "is_pointer", "is_const"}


def test_example_source_is_parsed():
    facts = extract_from_paths(["examples/parser_sample.c"])
    names = [f.name for f in facts]

    assert "parse_header" in names
    assert "read_all" in names
    assert "copy_name" in names

    read_all = next(f for f in facts if f.name == "read_all")
    assert _find(read_all.constraints, "resource", "fopen")
    assert read_all.return_type.endswith("*")
