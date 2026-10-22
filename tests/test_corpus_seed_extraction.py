"""EXE-04-05: `*_test.cc` 시드 추출 기능 단위 테스트"""

from logosfuzz.execute.exe_04_05_corpus_manager import (
    SeedManager,
    _iter_cpp_string_literals,
)


_SAMPLE_TEST_CC = r'''
#include "score/json/json.h"
#include <gtest/gtest.h>

// 주석 안의 "이건 시드가 아니다"
/* 블록 주석의 "이것도 아니다" */

namespace {
constexpr char kSimple[] = "{\"key\": 1}";

TEST(JsonParser, ParsesNested) {
  const std::string nested = R"({"outer": {"inner": [1, 2, 3]}})";
  EXPECT_TRUE(Parse(nested));
}

TEST(JsonParser, SplitAcrossLines) {
  const char* multi = "{"
                      "  \"a\": true,"
                      "  \"b\": null"
                      "}";
  EXPECT_TRUE(Parse(multi));
}

TEST(JsonParser, RejectsGarbage) {
  char quote = '"';
  EXPECT_FALSE(Parse("not json at all"));
}
}
'''


def _literals(text):
    return list(_iter_cpp_string_literals(text))


# --- 스캐너 ----------------------------------------------------------------
def test_extracts_plain_literal_with_escapes():
    assert '{"key": 1}' in _literals(_SAMPLE_TEST_CC)


def test_extracts_raw_string_literal():
    """중첩 따옴표 입력(JSON 등)의 원시 문자열 추출"""
    assert '{"outer": {"inner": [1, 2, 3]}}' in _literals(_SAMPLE_TEST_CC)


def test_concatenates_adjacent_literals():
    """C++ 인접 리터럴의 한 문자열 연결"""
    assert '{  "a": true,  "b": null}' in _literals(_SAMPLE_TEST_CC)


def test_skips_include_paths():
    lits = _literals(_SAMPLE_TEST_CC)
    assert not any("score/json/json.h" in s for s in lits)


def test_skips_comments():
    lits = _literals(_SAMPLE_TEST_CC)
    assert not any("시드가 아니다" in s for s in lits)
    assert not any("이것도 아니다" in s for s in lits)


def test_char_literal_does_not_break_scanning():
    """'"' 같은 문자 리터럴의 문자열 시작 오인 방지"""
    assert "not json at all" in _literals(_SAMPLE_TEST_CC)


def test_unterminated_raw_string_does_not_hang():
    assert _literals('const char* s = R"tag(dangling') == []


# --- SeedManager 연동 ------------------------------------------------------
def _write_test_cc(tmp_path, name="json_test.cc", text=_SAMPLE_TEST_CC):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def test_extract_seeds_from_tests_creates_entries(tmp_path):
    src = _write_test_cc(tmp_path)
    seeds = SeedManager(base_dir=str(tmp_path / "corpus")).extract_seeds_from_tests(
        "grp_json", [src]
    )
    payloads = {s.data for s in seeds}
    assert b'{"key": 1}' in payloads
    assert b'{"outer": {"inner": [1, 2, 3]}}' in payloads
    assert all(s.group_name == "grp_json" for s in seeds)
    assert all(s.source == "initial" for s in seeds)


def test_extract_seeds_deduplicates_identical_payloads(tmp_path):
    text = 'auto a = "same"; auto b = "same";'
    src = _write_test_cc(tmp_path, text=text)
    seeds = SeedManager(base_dir=str(tmp_path / "corpus")).extract_seeds_from_tests(
        "grp", [src]
    )
    assert [s.data for s in seeds] == [b"same"]


def test_extract_seeds_respects_length_bounds(tmp_path):
    text = 'auto a = "x"; auto b = "okay"; auto c = "%s";' % ("y" * 50)
    src = _write_test_cc(tmp_path, text=text)
    seeds = SeedManager(base_dir=str(tmp_path / "corpus")).extract_seeds_from_tests(
        "grp", [src], min_len=2, max_len=10
    )
    assert [s.data for s in seeds] == [b"okay"]


def test_extract_seeds_respects_limit(tmp_path):
    text = ";".join(f'auto v{i} = "value{i}"' for i in range(50))
    src = _write_test_cc(tmp_path, text=text)
    seeds = SeedManager(base_dir=str(tmp_path / "corpus")).extract_seeds_from_tests(
        "grp", [src], limit=5
    )
    assert len(seeds) == 5


def test_unreadable_file_does_not_abort_extraction(tmp_path):
    """읽기 실패 파일이 있어도 나머지 추출 계속"""
    good = _write_test_cc(tmp_path)
    missing = tmp_path / "does_not_exist_test.cc"
    seeds = SeedManager(base_dir=str(tmp_path / "corpus")).extract_seeds_from_tests(
        "grp", [missing, good]
    )
    assert seeds


def test_extracted_seeds_round_trip_through_disk(tmp_path):
    src = _write_test_cc(tmp_path)
    mgr = SeedManager(base_dir=str(tmp_path / "corpus"))
    seeds = mgr.extract_seeds_from_tests("grp_json", [src])
    mgr.save_seeds(seeds)
    loaded = {s.data for s in mgr.load_seeds("grp_json")}
    assert b'{"key": 1}' in loaded


def test_identifier_r_followed_by_string_is_not_treated_as_raw_string():
    """`FOO(R, "v")` 처럼 R 뒤 일반 문자열의 원시 문자열 오인 방지"""
    text = 'CHECK(R, "value"); auto later = "second";'
    assert _literals(text) == ["value", "second"]
