"""ANA CLI의 도달 가능성 증거 연결 회귀 테스트"""
from __future__ import annotations

import json

from logosfuzz.analyze.cli import main
from logosfuzz.analyze.models import CrashCluster, CrashRecord, Frame, Verdict
from logosfuzz.analyze.signature import has_application_frame
from logosfuzz.analyze.triage import rule_triage
from logosfuzz.cli import _build_parser


def _dedup_input(tmp_path):
    source_root = tmp_path / "target"
    source_root.mkdir()
    (source_root / "target.c").write_text(
        "#include <stddef.h>\n"
        "int target(int *value)\n"
        "{\n"
        "    return value[1];\n"
        "}\n",
        encoding="utf-8",
    )
    payload = {
        "stats": {"total_records": 1, "unique_clusters": 1},
        "clusters": [
            {
                "cluster_id": "cluster-1",
                "signature": "heap-buffer-overflow|target.c:4",
                "bug_type": "heap-buffer-overflow",
                "count": 1,
                "sanitizer": "ASAN",
                "error_reason": "heap-buffer-overflow",
                "traceback": [{"file": "/work/target.c", "line": 4}],
                "groups": ["target"],
                "crash_inputs": [],
            }
        ],
    }
    path = tmp_path / "dedup.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return source_root, path


def test_triage_cli_preserves_reachability_evidence(tmp_path):
    source_root, dedup = _dedup_input(tmp_path)
    output = tmp_path / "triage.json"

    assert main([
        "triage", str(dedup), "--source-root", str(source_root), "-o", str(output),
        "--review-store", str(tmp_path / "reviews.json"),
    ]) == 0

    result = json.loads(output.read_text(encoding="utf-8"))
    finding = result["results"][0]
    assert finding["reachability"]["function"] == "target"
    assert finding["reachability"]["definition"].endswith("target.c:2")
    assert "unreferenced-internal-function" in finding["signals"]


def test_triage_cli_without_source_root_keeps_legacy_shape(tmp_path):
    _, dedup = _dedup_input(tmp_path)
    output = tmp_path / "triage.json"

    assert main(["triage", str(dedup), "-o", str(output), "--no-approval-gate"]) == 0

    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["results"][0]["reachability"] is None
    assert "verified_crashes" not in result  # 게이트를 끄면 예전 출력 그대로


def test_generated_harness_frame_is_not_target_application_code():
    record = CrashRecord(
        sanitizer="ASAN",
        category="buffer-overflow",
        traceback=[Frame("/work/gen/score_generated.cpp", 64)],
    )

    assert has_application_frame(record) is False
    cluster = CrashCluster(
        cluster_id="generated-crash",
        signature="buffer-overflow@score_generated.cpp:64",
        bug_type="buffer-overflow",
        representative=record,
        members=[record],
    )
    assert rule_triage(cluster).verdict is Verdict.FALSE_POSITIVE


def test_top_level_analyze_cli_accepts_source_evidence_options():
    args = _build_parser().parse_args([
        "analyze", "input.json", "--source-root", "/work/source",
        "--harness-dir", "/work/harnesses",
    ])

    assert args.source_root == "/work/source"
    assert args.harness_dir == "/work/harnesses"


# ---------------------------------------------------------------------------
# 입력 경로 오류: 스택 트레이스 대신 한 줄로 알린다
# ---------------------------------------------------------------------------

def test_missing_input_path_is_reported_as_an_error(tmp_path, capsys):
    rc = main(["analyze", str(tmp_path / "없는디렉터리")])

    assert rc == 1
    err = capsys.readouterr().err
    assert "[ANA 오류]" in err and "입력 경로가 없습니다" in err


def test_broken_summary_json_is_reported_as_an_error(tmp_path, capsys):
    broken = tmp_path / "fuzz_summary.json"
    broken.write_text("{ not json", encoding="utf-8")

    rc = main(["analyze", str(broken)])

    assert rc == 1
    assert "JSON 이 아닙니다" in capsys.readouterr().err


def test_root_cli_reports_the_same_error(tmp_path, capsys):
    from logosfuzz.cli import main as root_main

    rc = root_main(["analyze", str(tmp_path / "없는디렉터리")])

    assert rc == 1
    assert "[ANA 오류]" in capsys.readouterr().err


def test_empty_input_warns_but_succeeds(tmp_path, capsys):
    """크래시 없는 캠페인은 정상이다 - 실패로 다루지 않고 경고만 남긴다."""
    empty = tmp_path / "sanitizer"
    empty.mkdir()

    rc = main(["analyze", str(empty)])

    assert rc == 0
    assert "[ANA 경고]" in capsys.readouterr().err
