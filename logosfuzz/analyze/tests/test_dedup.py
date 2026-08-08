"""ANA-05-04 중복 제거 회귀 테스트."""

from __future__ import annotations

from pathlib import Path

from logosfuzz.analyze.dedup import CrashDeduplicator, deduplicate
from logosfuzz.analyze.loader import load_jsonl_findings
from logosfuzz.analyze.models import CrashRecord, Frame

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "sanitizer_dlt.jsonl"


def _rec(category, frames, group="g", crash_input=None):
    return CrashRecord(
        sanitizer="ASAN",
        category=category,
        traceback=[Frame(f, ln) for f, ln in frames],
        group=group,
        crash_input=crash_input,
    )


def test_identical_bug_merges_into_one_cluster():
    a = _rec("use-after-free", [("/x/dlt_common.c", 842), ("/x/harness/h.c", 41)])
    b = _rec("use-after-free", [("/x/dlt_common.c", 842), ("/x/harness/h.c", 41)])
    clusters, stats = deduplicate([a, b])
    assert len(clusters) == 1
    assert clusters[0].count == 2
    assert stats.total_records == 2
    assert stats.duplicates_removed == 1


def test_distinct_bugs_stay_separate():
    a = _rec("use-after-free", [("/x/a.c", 10)])
    b = _rec("heap-buffer-overflow", [("/x/b.c", 20)])
    clusters, _ = deduplicate([a, b])
    assert len(clusters) == 2


def test_clusters_sorted_by_count_desc():
    a = _rec("use-after-free", [("/x/a.c", 10)])
    b = _rec("use-after-free", [("/x/a.c", 10)])
    c = _rec("heap-buffer-overflow", [("/x/b.c", 20)])
    clusters, _ = deduplicate([a, b, c])
    assert clusters[0].bug_type == "use-after-free"
    assert clusters[0].count == 2
    assert clusters[1].count == 1


def test_crash_inputs_collected_and_deduped():
    a = _rec("use-after-free", [("/x/a.c", 10)], crash_input="crashes/id_1")
    b = _rec("use-after-free", [("/x/a.c", 10)], crash_input="crashes/id_2")
    dup = _rec("use-after-free", [("/x/a.c", 10)], crash_input="crashes/id_1")
    clusters, _ = deduplicate([a, b, dup])
    assert clusters[0].crash_inputs == ["crashes/id_1", "crashes/id_2"]


def test_sample_file_dedup_counts():
    records = load_jsonl_findings(SAMPLE)
    assert len(records) == 6
    clusters, stats = deduplicate(records)
    # 3x UAF(런타임 프레임/윈도우 경로 차이 무시) + double-free + buffer-overflow + mocking-fp
    assert stats.total_records == 6
    assert stats.unique_clusters == 4
    top = clusters[0]
    assert top.bug_type == "use-after-free"
    assert top.count == 3
    assert top.groups == ["sanitizer_dlt"]


def test_stats_ratio_zero_on_empty():
    dedup = CrashDeduplicator()
    assert dedup.stats().dedup_ratio == 0.0
    assert dedup.to_dict()["clusters"] == []


def test_to_dict_shape():
    records = load_jsonl_findings(SAMPLE)
    clusters, _ = deduplicate(records)
    d = clusters[0].to_dict()
    for key in ("cluster_id", "signature", "bug_type", "count",
                "crash_location", "traceback", "groups", "crash_inputs"):
        assert key in d
    assert d["cluster_id"].startswith("CL-")
