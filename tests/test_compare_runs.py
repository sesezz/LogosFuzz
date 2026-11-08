"""측정 런 비교 스크립트 단위 테스트 (timeline 파싱, 0/0 커버리지 처리)"""

import importlib.util
import json
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "compare_runs.py"
_spec = importlib.util.spec_from_file_location("compare_runs", _SCRIPT)
cr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cr)

TIMELINE = (
    "      0.0\tlabel=t rep=1 commit=abcdef12 budget=60 start=x\n"
    "     10.0\t[EXE] 시작\n"
    "     10.0\t[1/2] 로직 그룹 'lg_a' 격리 퍼징 시작\n"
    # 실제 로그와 같이 진행 로그 사이 '\r' 구분
    "     50.0\t\r[lg_a] exec/s=     100 cov=     5 crashes=  0 execs=200"
    "\r[lg_a] exec/s=     100 cov=     7 crashes=  0 execs=1000"
    "\r[lg_a] exec/s=       0 cov=     7 crashes=  0 execs=1000\n"
    "     50.0\t[2/2] 로직 그룹 'lg_b' 격리 퍼징 시작\n"
    "     51.0\t#7\tINITED cov: 11 ft: 12 corp: 1/1b exec/s: 7 rss: 1Mb\n"
    "     51.0\t\r[lg_b] exec/s=      20 cov=    12 crashes=  0 execs=40\r[lg_b] \n"
    "     52.0\t  lg_a: lines 0/0 (0.0%), branches 0/0 (0.0%)\n"
    "     52.0\t  lg_b: lines 10/100 (10.0%), branches 4/50 (8.0%)\n"
)


def _cov(lc, ln, bc, bn):
    return {"lines": {"covered": lc, "count": ln}, "branches": {"covered": bc, "count": bn}}


def _make_rep(root: Path, name: str, a_cov, b_cov):
    rep = root / name
    (rep / "out").mkdir(parents=True)
    (rep / "timeline.log").write_bytes(TIMELINE.encode("utf-8"))
    summary = {
        "stages": [{"stage": "EXE", "duration_s": 42.0}],
        "groups": [
            {"group": "lg_A", "slug": "lg_a", "outcome": "success", "execs": 1000,
             "crashes": 0, "coverage": a_cov},
            {"group": "lg_B", "slug": "lg_b", "outcome": "success", "execs": 40,
             "crashes": 1, "coverage": b_cov},
        ],
        "totals": {"groups": 2, "harness_built": 2, "crashes": 1},
    }
    fuzz = {"groups": [
        {"group": "lg_a", "crashed": False, "duration_sec": 40.0},
        {"group": "lg_b", "crashed": True, "duration_sec": 2.0},
    ]}
    (rep / "out" / "run_summary.json").write_text(json.dumps(summary), encoding="utf-8")
    (rep / "out" / "fuzz_summary.json").write_text(json.dumps(fuzz), encoding="utf-8")
    return rep


def test_parse_timeline_progress_and_groups():
    tl = cr.parse_timeline(TIMELINE)
    assert tl["header"]["commit"] == "abcdef12"
    assert tl["exe_start"] == 10.0
    assert tl["group_start"] == {"lg_a": 10.0, "lg_b": 50.0}
    covs = [(p["slug"], p["cov"]) for p in tl["points"]]
    # 한 줄 다중 진행 로그 + libFuzzer '#N ... cov:' 줄, 잘린 '[lg_b] ' 조각 무시
    assert covs == [("lg_a", 5), ("lg_a", 7), ("lg_a", 7), ("lg_b", 11), ("lg_b", 12)]
    assert tl["cov_lines"]["lg_a"]["lines"] == (0, 0)


def test_estimate_times_monotone_and_capped():
    tl = cr.parse_timeline(TIMELINE)
    pts = cr.estimate_times(tl["points"], tl["group_start"], {"lg_a": 40.0, "lg_b": 2.0})
    a = [p["group_elapsed_s"] for p in pts if p["slug"] == "lg_a"]
    assert a == [2.0, 10.0, 10.0]          # exec/s=0 → 직전 값 유지
    b = [p["group_elapsed_s"] for p in pts if p["slug"] == "lg_b"]
    assert b == [1.0, 2.0]                 # 그룹 소요 시간 상한
    assert pts[0]["run_elapsed_s"] == 12.0


def test_zero_denominator_reported_as_missing(tmp_path):
    before = tmp_path / "before"
    _make_rep(before, "rep1", _cov(0, 0, 0, 0), _cov(10, 100, 4, 50))
    _make_rep(before, "rep2", _cov(5, 100, 1, 50), _cov(20, 100, 8, 50))
    after = tmp_path / "after"
    _make_rep(after, "rep1", _cov(30, 100, 10, 50), _cov(40, 100, 20, 50))

    runs = cr.load_side(before)
    assert [r["name"] for r in runs] == ["rep1", "rep2"]
    r1 = runs[0]
    assert cr.pct(r1["groups"]["lg_a"]["lines"]) is None
    assert r1["immediate_crash"] == 1
    assert r1["ttfc_group_s"] == 2.0 and r1["ttfc_exe_s"] == 42.0
    assert r1["smoke"] is None
    assert len(r1["timeline"]) == 5          # 파일 경유 시 CR 보존 확인

    out = tmp_path / "cmp"
    assert cr.main(["--before", str(before), "--after", str(after), "-o", str(out)]) == 0
    md = (out / "comparison.md").read_text(encoding="utf-8")
    row = next(l for l in md.splitlines() if l.startswith("| 라인 커버리지 % — lg_a"))
    cells = [c.strip() for c in row.strip("|").split("|")]
    assert cells[1] == cr.NA                       # 전 rep1 0/0
    assert cells[3].startswith("5.000") and "(n=1)" in cells[3]
    assert cells[-1] == "6.00x"                    # 30 / 5
    assert (out / "coverage_timeline.csv").is_file()
    assert (out / "coverage_timeline.png").is_file() or (out / "coverage_timeline.svg").is_file()
