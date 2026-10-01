"""유닛테스트 vs 퍼징 커버리지 비교 테스트 (4주차). 파일 입출력만 쓰고 bazel/llvm 은 불필요."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from logosfuzz.reporting.coverage_compare import (
    ALL_UNIT,
    UNASSIGNED_UNIT,
    CoverageCompareError,
    Metric,
    compare_coverage,
    in_scope,
    load_coverage,
    main,
    normalize_path,
    parse_coverage_json,
    parse_lcov,
    render_coverage_comparison_markdown,
    units_from_build_summary,
)

WORKSPACE = "/home/u/baselibs"

# 유닛테스트 lcov — json_parser.cc 는 줄 4개 중 10,11 만, 함수 2개 중 1개, 브랜치 2개 중 1개
UNIT_LCOV = """\
SF:score/json/json_parser.cc
FN:10,parse
FN:20,dump
FNDA:5,parse
FNDA:0,dump
DA:10,5
DA:11,5
DA:12,0
DA:20,0
BRDA:11,0,0,5
BRDA:11,0,1,-
end_of_record
SF:score/json/json_parser_test.cc
DA:1,1
end_of_record
SF:score/crypto/sha.cc
DA:1,1
DA:2,1
end_of_record
SF:external/gtest/gtest.cc
DA:1,1
end_of_record
"""

# 퍼징 lcov(절대 경로) — json_parser.cc 는 10,12 만 덮음. sha.cc 는 링크되지 않아 없음
FUZZ_LCOV = """\
SF:/home/u/baselibs/score/json/json_parser.cc
FN:10,parse
FNDA:100,parse
DA:10,100
DA:11,0
DA:12,7
DA:20,0
end_of_record
SF:/home/u/baselibs/score/json/fuzz/lg/lg_fuzz.cc
DA:1,9
end_of_record
"""

BUILD_SUMMARY = {"units": [
    {"group": "a", "build_target": "@score_baselibs//score/json"},
    {"group": "b", "build_target": "//score/crypto:sha"},
]}

JSON_UNIT = "@score_baselibs//score/json"
SHA_UNIT = "//score/crypto:sha"

LLVM_EXPORT = {"data": [{"files": [{
    "filename": "/home/u/baselibs/score/json/json_parser.cc",
    "summary": {
        "lines": {"count": 4, "covered": 2, "percent": 50},
        "functions": {"count": 1, "covered": 1, "percent": 100},
        "branches": {"count": 2, "covered": 1, "percent": 50},
        "regions": {"count": 9, "covered": 5, "percent": 55},
    },
}], "totals": {}}]}


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def _compare(tmp_path, fuzz_text=FUZZ_LCOV, **kw):
    unit = load_coverage([_write(tmp_path, "unit.lcov", UNIT_LCOV)], workspace=WORKSPACE)
    fuzz = load_coverage([_write(tmp_path, "fuzz.dat", fuzz_text)], workspace=WORKSPACE)
    return compare_coverage(unit, fuzz, units=units_from_build_summary(BUILD_SUMMARY), **kw)


def _unit(result, target):
    return next(u for u in result["units"] if u["build_target"] == target)


# --------------------------------------------------------------------------- #
# 파서
# --------------------------------------------------------------------------- #
def test_parse_lcov_metrics_from_details():
    files = parse_lcov(UNIT_LCOV)
    parser = files["score/json/json_parser.cc"]
    assert parser.lines == Metric(2, 4)
    assert parser.functions == Metric(1, 2)
    assert parser.branches == Metric(1, 2)          # '-' 는 실행 안 된 브랜치
    assert parser.line_hits == {10: 5, 11: 5, 12: 0, 20: 0}


def test_parse_lcov_function_record_with_end_line():
    """lcov 2.x 의 FN:<start>,<end>,<name> 도 읽는다."""
    text = "SF:a.cc\nFN:1,9,_Z1fv\nFNDA:3,_Z1fv\nFN:10,19,_Z1gv\nFNDA:0,_Z1gv\nend_of_record\n"
    assert parse_lcov(text)["a.cc"].functions == Metric(1, 2)


def test_parse_lcov_merges_repeated_records_for_same_file():
    text = ("SF:a.cc\nDA:1,1\nDA:2,0\nend_of_record\n"
            "SF:a.cc\nDA:1,2\nDA:2,4\nend_of_record\n")
    item = parse_lcov(text)["a.cc"]
    assert item.line_hits == {1: 3, 2: 4}
    assert item.lines == Metric(2, 2)


def test_parse_lcov_falls_back_to_summary_lines():
    text = "SF:a.cc\nLF:10\nLH:4\nFNF:2\nFNH:1\nBRF:6\nBRH:3\nend_of_record\n"
    item = parse_lcov(text)["a.cc"]
    assert (item.lines, item.functions, item.branches) == (Metric(4, 10), Metric(1, 2), Metric(3, 6))
    assert item.line_hits is None


def test_metric_percent_is_none_when_unknown():
    assert Metric(0, 0).percent is None
    assert Metric(1, 4).percent == 25.0
    assert Metric(1, 2) + Metric(2, 2) == Metric(3, 4)


def test_parse_coverage_json_llvm_cov_export_and_summary():
    export = parse_coverage_json(LLVM_EXPORT)
    item = export["/home/u/baselibs/score/json/json_parser.cc"]
    assert item.lines == Metric(2, 4) and item.functions == Metric(1, 1)
    assert item.branches == Metric(1, 2) and item.line_hits is None

    summary = parse_coverage_json({"files": [
        {"filename": "score/x.cc", "lines": {"covered": 3, "count": 6, "percent": 50}}]})
    assert summary["score/x.cc"].lines == Metric(3, 6)
    assert summary["score/x.cc"].functions == Metric(0, 0)      # 요약에는 없다 -> "모름"

    with pytest.raises(CoverageCompareError):
        parse_coverage_json({"unknown": 1})


# --------------------------------------------------------------------------- #
# 경로 정규화 / 범위 / 빌드 단위
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("raw,expected", [
    ("/home/u/baselibs/score/json/x.cc", "score/json/x.cc"),
    ("/cache/_bazel_u/abc/execroot/_main/score/json/x.cc", "score/json/x.cc"),
    ("./score/json/x.cc", "score/json/x.cc"),
    ("score\\json\\x.cc", "score/json/x.cc"),
    ("score/json/x.cc", "score/json/x.cc"),
])
def test_normalize_path(raw, expected):
    assert normalize_path(raw, WORKSPACE) == expected


def test_normalize_path_strip_prefix():
    assert normalize_path("/mnt/src/score/x.cc", None, ["/mnt/src/"]) == "score/x.cc"


def test_in_scope_defaults_and_include():
    assert in_scope("score/json/json_parser.cc")
    assert not in_scope("score/json/json_parser_test.cc")
    assert not in_scope("score/json/fuzz/lg/lg_fuzz.cc")
    assert not in_scope("fuzz/top_fuzz.cc")                  # 최상위 fuzz/ 도 제외
    assert not in_scope("external/gtest/gtest.cc")
    assert in_scope("score/json/a.cc", include=["score/json/"])
    assert not in_scope("score/crypto/a.cc", include=["score/json/"])


def test_units_from_build_summary():
    assert units_from_build_summary(BUILD_SUMMARY) == {
        JSON_UNIT: "score/json/", SHA_UNIT: "score/crypto/"}
    assert units_from_build_summary(None) == {}
    assert units_from_build_summary({"units": [{"build_target": "not-a-label"}]}) == {}


# --------------------------------------------------------------------------- #
# 비교
# --------------------------------------------------------------------------- #
def test_compare_per_build_unit_with_line_overlap(tmp_path):
    result = _compare(tmp_path)

    json_unit = _unit(result, JSON_UNIT)
    assert json_unit["files"] == 1 and json_unit["package"] == "score/json/"
    assert json_unit["unit_test"]["lines"] == {"covered": 2, "count": 4, "percent": 50.0}
    assert json_unit["fuzz"]["lines"] == {"covered": 2, "count": 4, "percent": 50.0}
    assert json_unit["unit_test"]["functions"]["covered"] == 1
    assert json_unit["fuzz"]["functions"]["count"] == 1
    assert json_unit["fuzz"]["branches"]["percent"] is None          # 퍼징 lcov 에 브랜치 없음
    assert json_unit["lines"] == {"both": 1, "test_only": 1, "fuzz_only": 1, "union": 3, "count": 4}
    assert json_unit["per_file"][0]["path"] == "score/json/json_parser.cc"

    # 퍼징 쪽에 없는 파일은 도달 못 함(0%), 분모는 유닛테스트 값
    sha_unit = _unit(result, SHA_UNIT)
    assert sha_unit["fuzz"]["lines"] == {"covered": 0, "count": 2, "percent": 0.0}
    assert sha_unit["lines"] == {"both": 0, "test_only": 2, "fuzz_only": 0, "union": 2, "count": 2}

    totals = result["totals"]
    assert totals["files"] == 2
    assert totals["unit_test"]["lines"]["covered"] == 4 and totals["unit_test"]["lines"]["count"] == 6
    assert totals["fuzz"]["lines"]["covered"] == 2
    assert totals["lines"] == {"both": 1, "test_only": 3, "fuzz_only": 1, "union": 5, "count": 6}
    assert not any("lcov 일 때만" in note for note in result["notes"])


def test_compare_excludes_tests_fuzz_harness_and_external(tmp_path):
    result = _compare(tmp_path)
    paths = {row["path"] for unit in result["units"] for row in unit["per_file"]}
    assert paths == {"score/json/json_parser.cc", "score/crypto/sha.cc"}


def test_compare_include_and_custom_exclude(tmp_path):
    only_json = _compare(tmp_path, include=["score/json/"])
    assert [u["build_target"] for u in only_json["units"]] == [JSON_UNIT]
    assert only_json["totals"]["files"] == 1

    everything = _compare(tmp_path, exclude=())
    paths = {row["path"] for unit in everything["units"] for row in unit["per_file"]}
    assert "score/json/json_parser_test.cc" in paths and "external/gtest/gtest.cc" in paths
    # 어느 단위에도 안 맞는 파일은 (unassigned)
    assert UNASSIGNED_UNIT in [u["build_target"] for u in everything["units"]]
    assert everything["units"][-1]["build_target"] == UNASSIGNED_UNIT


def test_compare_without_build_summary_is_one_all_unit(tmp_path):
    unit = load_coverage([_write(tmp_path, "u.lcov", UNIT_LCOV)], workspace=WORKSPACE)
    fuzz = load_coverage([_write(tmp_path, "f.lcov", FUZZ_LCOV)], workspace=WORKSPACE)
    result = compare_coverage(unit, fuzz)
    assert [u["build_target"] for u in result["units"]] == [ALL_UNIT]


def test_compare_with_llvm_json_has_no_line_level_overlap(tmp_path):
    export = json.dumps(LLVM_EXPORT)
    result = _compare(tmp_path, fuzz_text=export)

    json_unit = _unit(result, JSON_UNIT)
    assert json_unit["fuzz"]["branches"]["covered"] == 1            # JSON 에는 브랜치가 있다
    assert json_unit["lines"] is None and result["totals"]["lines"] is None
    assert "lcov 일 때만" in result["notes"][0]


def test_multiple_fuzz_inputs_are_merged_by_line_union(tmp_path):
    other = "SF:/home/u/baselibs/score/json/json_parser.cc\nDA:10,0\nDA:11,3\nDA:12,0\nDA:20,0\nend_of_record\n"
    unit = load_coverage([_write(tmp_path, "u.lcov", UNIT_LCOV)], workspace=WORKSPACE)
    fuzz = load_coverage(
        [_write(tmp_path, "f1.lcov", FUZZ_LCOV), _write(tmp_path, "f2.lcov", other)],
        workspace=WORKSPACE)
    item = fuzz["score/json/json_parser.cc"]
    assert item.line_hits == {10: 100, 11: 3, 12: 7, 20: 0}
    assert item.lines == Metric(3, 4)                                # 10, 11, 12
    result = compare_coverage(unit, fuzz, units=units_from_build_summary(BUILD_SUMMARY))
    assert _unit(result, JSON_UNIT)["lines"]["union"] == 3 + 0      # 테스트 {10,11} ∪ 퍼징 {10,11,12}


def test_load_coverage_errors(tmp_path):
    with pytest.raises(CoverageCompareError, match="읽을 수 없다"):
        load_coverage([tmp_path / "missing.lcov"])
    with pytest.raises(CoverageCompareError, match="하나도 없다"):
        load_coverage([_write(tmp_path, "empty.lcov", "no records here\n")])
    with pytest.raises(CoverageCompareError, match="JSON"):
        load_coverage([_write(tmp_path, "bad.json", "{not json")])
    with pytest.raises(CoverageCompareError):
        load_coverage([])


# --------------------------------------------------------------------------- #
# 출력 / CLI
# --------------------------------------------------------------------------- #
def test_markdown_table(tmp_path):
    text = render_coverage_comparison_markdown(_compare(tmp_path))
    assert f"| `{JSON_UNIT}` | 1 |" in text
    assert "75.0% (3/4)" in text                 # json 단위 합집합
    assert "**합계**" in text
    assert "해석 시 주의" in text
    assert text.count("\n|") >= 4                # 헤더 + 구분선 + 단위 2 + 합계


def test_cli_end_to_end(tmp_path, capsys):
    unit = _write(tmp_path, "unit.lcov", UNIT_LCOV)
    fuzz = _write(tmp_path, "fuzz.lcov", FUZZ_LCOV)
    build = _write(tmp_path, "build_summary.json", json.dumps(BUILD_SUMMARY))
    out, md = tmp_path / "out" / "cmp.json", tmp_path / "out" / "cmp.md"

    code = main(["--unit-test", str(unit), "--fuzz", str(fuzz), "--build", str(build),
                 "--workspace", WORKSPACE, "-o", str(out), "--markdown", str(md)])

    assert code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["schema_version"] == "1.0"
    assert data["inputs"]["unit_test"] == [str(unit)]
    assert data["totals"]["lines"]["union"] == 5
    assert "해석 시 주의" in md.read_text(encoding="utf-8")
    printed = capsys.readouterr().out
    assert "[COVERAGE]" in printed and "합집합 5/6" in printed


def test_cli_reports_missing_input_as_error(tmp_path, capsys):
    code = main(["--unit-test", str(tmp_path / "nope.lcov"), "--fuzz", str(tmp_path / "nope2"),
                 "-o", str(tmp_path / "o.json")])
    assert code == 1
    assert "COVERAGE 오류" in capsys.readouterr().err
    assert not (tmp_path / "o.json").exists()
