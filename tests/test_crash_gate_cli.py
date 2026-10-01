"""4주차 D 완료 기준: 크래시 승인 게이트를 거친 **검증된 고유 크래시 목록** 산출.

실측 크래시 원문(EXE sanitizer 파서) → ``logosfuzz analyze``(dedup → triage →
CRASH_TRIAGE 게이트) → ``logosfuzz review`` 로 사람 결정 → 재실행 반영까지
사용자가 실제로 치는 명령 그대로 확인한다.
"""
from __future__ import annotations

import json
from pathlib import Path

from logosfuzz.cli import main
from logosfuzz.execute.sanitizer import SanitizerFinding, SanitizerMonitor, SourceLocation, write_findings

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "error_contract_logs"


def _findings():
    findings = []
    for name in ("harness_unchecked.txt", "library_unchecked.txt"):
        monitor = SanitizerMonitor()
        for line in (FIXTURES / name).read_text(encoding="utf-8").splitlines():
            monitor.feed(line)
        findings.extend(monitor.finish())
    # 신뢰도가 낮아 사람 검토로 가야 하는 대상 코드 데이터 레이스
    findings.append(SanitizerFinding(
        "TSAN", "race-condition", "data race",
        [SourceLocation("/src/score/concurrency/pool.cpp", 77)],
        ["WARNING: ThreadSanitizer: data race (pid=1)",
         "    #0 0x1 in score::concurrency::Pool::Push() /src/score/concurrency/pool.cpp:77"],
    ))
    return findings


def _analyze(tmp_path, store):
    out = tmp_path / "analysis.json"
    code = main(["analyze", str(tmp_path / "sanitizer.jsonl"), "-o", str(out),
                 "--review-store", str(store), "--project", "score"])
    assert code == 0
    return json.loads(out.read_text(encoding="utf-8"))


def test_verified_unique_crash_list_through_approval_gate(tmp_path, capsys):
    write_findings(tmp_path / "sanitizer.jsonl", _findings())
    store = tmp_path / "reviews.json"

    first = _analyze(tmp_path, store)
    by_type = {f["error_contract"]["violation"] or f["bug_type"]: f for f in first["findings"]}

    # 고유 크래시 3개(두 계약 위반이 abort 프레임으로 합쳐지지 않는다)
    assert first["dedup"]["stats"]["unique_clusters"] == 3
    # 에러계약 근거로 판정이 갈린다
    assert by_type["harness"]["triage_result"]["verdict"] == "false_positive"
    assert by_type["target"]["triage_result"]["verdict"] == "true_positive"
    # 게이트: 확실한 둘은 자동 결정, 데이터 레이스(conf 0.70)는 사람 대기
    assert by_type["target"]["approval"]["status"] == "approved"
    assert by_type["race-condition"]["approval"]["status"] == "pending"
    assert first["approval_summary"]["pending"] == 1
    assert [v["cluster_id"] for v in first["verified_crashes"]] == [by_type["target"]["cluster_id"]]
    assert first["verified_crashes"][0]["crash_function"] == "PayloadEnd"
    # summary 는 자동 판정 집계 그대로(ANA-05-02 / validation summary 계약)
    assert set(first["summary"]) == {"true_positive", "false_positive", "needs_review"}

    # 사람이 대기 항목을 확인하고 승인한다
    item_id = by_type["race-condition"]["approval"]["item_id"]
    assert main(["review", "--store", str(store), "--reviewer", "minju",
                 "approve", item_id, "-m", "락 없이 공유 큐 접근 확인"]) == 0

    second = _analyze(tmp_path, store)
    verified = {v["cluster_id"]: v for v in second["verified_crashes"]}
    assert set(verified) == {by_type["target"]["cluster_id"], by_type["race-condition"]["cluster_id"]}
    assert verified[by_type["race-condition"]["cluster_id"]]["by_human"] is True
    assert second["approval_summary"]["pending"] == 0

    # 재실행해도 리뷰 항목이 늘지 않는다(크래시당 1건)
    items = json.loads(store.read_text(encoding="utf-8"))
    assert len(items) == 3
    assert "검증된 고유 크래시 2개" in capsys.readouterr().out


def test_reviewer_can_flip_false_positive_with_edit(tmp_path):
    """하네스 프레임뿐인 오버플로(conf 0.65 오탐)를 사람이 정탐으로 뒤집는다."""
    store = tmp_path / "reviews.json"
    write_findings(tmp_path / "sanitizer.jsonl", [
        SanitizerFinding("ASAN", "heap-buffer-overflow", "heap-buffer-overflow",
                         [SourceLocation("/src/harness/json_fuzzer.cc", 12)],
                         ["==1==ERROR: AddressSanitizer: heap-buffer-overflow",
                          "    #0 0x1 in LLVMFuzzerTestOneInput /src/harness/json_fuzzer.cc:12"]),
    ])
    first = _analyze(tmp_path, store)
    finding = first["findings"][0]
    assert finding["triage_result"]["verdict"] == "false_positive"
    assert finding["approval"]["status"] == "pending"

    assert main(["review", "--store", str(store), "edit", finding["approval"]["item_id"],
                 "--set", "llm_verdict=true_positive", "-m", "하네스 경유지만 대상 결함"]) == 0
    second = _analyze(tmp_path, store)
    assert [v["cluster_id"] for v in second["verified_crashes"]] == [finding["cluster_id"]]
    assert second["approval_summary"]["edited"] == 1
