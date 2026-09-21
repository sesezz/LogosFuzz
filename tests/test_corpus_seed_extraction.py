"""EXE-04-05: `*_test.cc` 에서 시드를 뽑는 기능의 단위 테스트.

형식 없는 합성 시드(빈 입력, 0xFF 반복)는 파서류 대상에서 입력 검증 첫 줄에
전부 튕긴다. 대상 저장소의 유닛 테스트에는 그 API 가 실제로 받아들이는 입력이
리터럴로 들어 있으므로, 그걸 시드로 쓰면 퍼저가 유효한 형식에서 출발한다.
"""

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
    """JSON 같은 중첩 따옴표 입력은 테스트에서 거의 항상 원시 문자열이다."""
    assert '{"outer": {"inner": [1, 2, 3]}}' in _literals(_SAMPLE_TEST_CC)


def test_concatenates_adjacent_literals():
    """C++ 에서 인접 리터럴은 한 문자열이다.

    이어 붙이지 않으면 여러 줄로 쪼개 쓴 JSON 이 쓸모없는 조각으로 나온다.
    """
    assert '{  "a": true,  "b": null}' in _literals(_SAMPLE_TEST_CC)


def test_skips_include_paths():
    lits = _literals(_SAMPLE_TEST_CC)
    assert not any("score/json/json.h" in s for s in lits)


def test_skips_comments():
    lits = _literals(_SAMPLE_TEST_CC)
    assert not any("시드가 아니다" in s for s in lits)
    assert not any("이것도 아니다" in s for s in lits)


def test_char_literal_does_not_break_scanning():
    """'"' 같은 문자 리터럴이 문자열 시작으로 오인되면 이후가 전부 깨진다."""
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
    """읽을 수 없는 파일 하나 때문에 나머지 추출이 멈추면 안 된다."""
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
    """`FOO(R, "v")` 처럼 R 뒤에 그냥 문자열이 오는 코드를 오인하면 안 된다.

    구분자 길이 제한이 없으면 저 멀리 있는 여는 괄호를 tag 끝으로 잡아
    파일 전체를 잘못 읽는다.
    """
    text = 'CHECK(R, "value"); auto later = "second";'
    assert _literals(text) == ["value", "second"]
