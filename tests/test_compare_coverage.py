"""유닛테스트 vs 퍼징 커버리지 비교 로직 단위 테스트 (lcov 파싱, 차집합 계산)"""

import importlib.util
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "compare_coverage.py"
_spec = importlib.util.spec_from_file_location("compare_coverage", _SCRIPT)
cc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cc)


def _lcov(tmp_path, name, records):
    """records: {소스경로: {행: 실행횟수}}"""
    lines = []
    for path, hits in records.items():
        lines.append(f"SF:{path}")
        for lineno, count in sorted(hits.items()):
            lines.append(f"DA:{lineno},{count}")
        lines.append("end_of_record")
    p = tmp_path / name
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


# --- lcov 파싱 -------------------------------------------------------------
def test_parses_lines_and_counts(tmp_path):
    p = _lcov(tmp_path, "a.lcov", {"score/json/json.cc": {10: 3, 11: 0}})
    assert cc.parse_lcov(p) == {"score/json/json.cc": {10: 3, 11: 0}}


def test_accumulates_counts_when_file_appears_twice(tmp_path):
    """타깃별 측정으로 같은 파일이 여러 레코드인 경우"""
    text = (
        "SF:x.cc\nDA:1,2\nend_of_record\n"
        "SF:x.cc\nDA:1,3\nend_of_record\n"
    )
    p = tmp_path / "b.lcov"
    p.write_text(text, encoding="utf-8")
    assert cc.parse_lcov(p)["x.cc"][1] == 5


def test_zero_hit_lines_are_known_but_not_covered(tmp_path):
    p = _lcov(tmp_path, "c.lcov", {"x.cc": {1: 0, 2: 1}})
    lcov = cc.parse_lcov(p)
    assert cc.covered_lines(lcov) == {"x.cc": {2}}
    assert cc.all_known_lines(lcov) == {"x.cc": {1, 2}}


# --- 경로 정규화 -----------------------------------------------------------
def test_normalizes_bazel_execroot_prefix():
    assert cc.normalize_path(
        "/home/u/.cache/bazel/_bazel_u/abc/execroot/_main/score/json/json.cc"
    ) == "score/json/json.cc"


def test_normalizes_proc_self_cwd_prefix():
    assert cc.normalize_path("/proc/self/cwd/score/json/json.cc") == "score/json/json.cc"


def test_differently_prefixed_paths_are_matched(tmp_path):
    """경로 정규화로 같은 파일 인식"""
    unit = _lcov(tmp_path, "u.lcov", {"/x/execroot/_main/score/json.cc": {1: 1}})
    fuzz = _lcov(tmp_path, "f.lcov", {"/proc/self/cwd/score/json.cc": {1: 1}})
    report = cc.compare(cc.parse_lcov(unit), cc.parse_lcov(fuzz))
    assert report["totals"]["both"] == 1
    assert report["totals"]["fuzz_only"] == 0


# --- 차집합 계산 -----------------------------------------------------------
def test_counts_four_buckets(tmp_path):
    unit = _lcov(tmp_path, "u.lcov", {"x.cc": {1: 1, 2: 1, 3: 0, 4: 0}})
    fuzz = _lcov(tmp_path, "f.lcov", {"x.cc": {1: 1, 2: 0, 3: 1, 4: 0}})
    t = cc.compare(cc.parse_lcov(unit), cc.parse_lcov(fuzz))["totals"]
    assert t["both"] == 1        # 1행
    assert t["unit_only"] == 1   # 2행
    assert t["fuzz_only"] == 1   # 3행
    assert t["neither"] == 1     # 4행
    assert t["known"] == 4


def test_fuzz_only_is_reported_even_when_total_is_lower(tmp_path):
    """총합이 낮아도 퍼징만 밟은 라인 집계"""
    unit = _lcov(tmp_path, "u.lcov", {"x.cc": {1: 1, 2: 1, 3: 1, 9: 0}})
    fuzz = _lcov(tmp_path, "f.lcov", {"x.cc": {1: 1, 2: 0, 3: 0, 9: 1}})
    t = cc.compare(cc.parse_lcov(unit), cc.parse_lcov(fuzz))["totals"]
    assert t["unit_covered"] == 3
    assert t["fuzz_covered"] == 2          # 총합은 퍼징이 낮음
    assert t["fuzz_only"] == 1             # 퍼징만 연 라인 존재
    assert t["fuzz_percent"] < t["unit_percent"]


def test_records_actual_fuzz_only_line_numbers(tmp_path):
    """퍼징만 연 라인의 행 번호 기록"""
    unit = _lcov(tmp_path, "u.lcov", {"x.cc": {1: 1, 42: 0, 77: 0}})
    fuzz = _lcov(tmp_path, "f.lcov", {"x.cc": {1: 1, 42: 1, 77: 1}})
    entry = cc.compare(cc.parse_lcov(unit), cc.parse_lcov(fuzz))["files"][0]
    assert entry["fuzz_only_lines"] == [42, 77]


def test_union_percent_counts_each_line_once(tmp_path):
    unit = _lcov(tmp_path, "u.lcov", {"x.cc": {1: 1, 2: 0}})
    fuzz = _lcov(tmp_path, "f.lcov", {"x.cc": {1: 1, 2: 1}})
    t = cc.compare(cc.parse_lcov(unit), cc.parse_lcov(fuzz))["totals"]
    assert t["union_percent"] == 100.0


def test_empty_inputs_do_not_divide_by_zero(tmp_path):
    empty = tmp_path / "e.lcov"
    empty.write_text("", encoding="utf-8")
    t = cc.compare(cc.parse_lcov(empty), cc.parse_lcov(empty))["totals"]
    assert t["known"] == 0
    assert t["unit_percent"] == 0.0


# --- 마크다운 출력 ---------------------------------------------------------
def test_markdown_highlights_fuzz_only(tmp_path):
    unit = _lcov(tmp_path, "u.lcov", {"x.cc": {1: 1, 2: 0}})
    fuzz = _lcov(tmp_path, "f.lcov", {"x.cc": {1: 0, 2: 1}})
    md = cc.to_markdown(cc.compare(cc.parse_lcov(unit), cc.parse_lcov(fuzz)))
    assert "퍼징만 커버" in md
    assert "`x.cc`" in md


# --- 비교 범위 --------------------------------------------------------------
def test_include_prefix_drops_modules_the_harness_cannot_reach():
    """baselibs 유닛 커버리지 scope 중 대상만 유지"""
    lcov = {
        "score/json/json_parser.cpp": {1: 1},
        "score/filesystem/path.cpp": {1: 0},
    }
    kept = cc.filter_lcov(lcov, include=["score/json/"])
    assert list(kept) == ["score/json/json_parser.cpp"]


def test_include_prefix_matches_after_normalization():
    """퍼징 lcov 의 /proc/self/cwd/ 접두사 정규화 후 비교"""
    lcov = {"/proc/self/cwd/score/json/any.cpp": {1: 1}}
    assert cc.filter_lcov(lcov, include=["score/json/"]) == lcov


def test_exclude_harness_drops_fuzz_harness_and_test_bodies():
    """하네스·테스트 본문 파일 비교 제외"""
    lcov = {
        "/proc/self/cwd/score/json/fuzz/json_parser_fuzz.cc": {1: 1},
        "score/json/json_test.cpp": {1: 1},
        "score/json/json_parser.cpp": {1: 1},
    }
    kept = cc.filter_lcov(lcov, exclude_harness=True)
    assert list(kept) == ["score/json/json_parser.cpp"]


def test_filter_is_noop_by_default():
    lcov = {"a/b_test.cpp": {1: 1}, "c.cpp": {2: 0}}
    assert cc.filter_lcov(lcov) == lcov
