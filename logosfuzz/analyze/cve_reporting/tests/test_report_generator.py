"""
ANA-05-02 파이프라인 테스트

실행: 프로젝트 루트에서
    python -m pytest logosfuzz/analyze/cve_reporting/tests -v
"""

import json
from pathlib import Path

from logosfuzz.analyze.cve_reporting.asan_parser import parse_asan_log
from logosfuzz.analyze.cve_reporting.cwe_mapping import lookup_cwe, UNKNOWN_CWE
from logosfuzz.analyze.cve_reporting.cvss_estimator import estimate_cvss
from logosfuzz.analyze.cve_reporting.report_generator import build_cve_report
from logosfuzz.analyze.cve_reporting.render import render_json, render_markdown
from logosfuzz.analyze.cve_reporting.schema import Verdict

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


def _load_sample(name: str) -> dict:
    return json.loads((SAMPLES_DIR / name).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# asan_parser
# ---------------------------------------------------------------------------

def test_parse_heap_buffer_overflow():
    sample = _load_sample("sample_crash_1.json")
    parsed = parse_asan_log(sample["crash_report"]["asan_log"])

    assert parsed.sanitizer == "AddressSanitizer"
    assert parsed.error_type == "heap-buffer-overflow"
    assert parsed.access_type == "READ"
    assert parsed.access_size == 4
    assert parsed.crash_location is not None
    assert "dlt_common.c" in parsed.crash_location
    assert len(parsed.stack_trace) >= 2
    assert parsed.stack_trace[0]["function"] == "dlt_message_read"


def test_parse_use_after_free():
    sample = _load_sample("sample_crash_2.json")
    parsed = parse_asan_log(sample["crash_report"]["asan_log"])

    assert parsed.error_type == "heap-use-after-free"
    assert parsed.access_type == "WRITE"
    assert parsed.access_size == 8


def test_stack_trace_does_not_mix_with_allocation_block():
    """크래시 스택과 malloc 스택이 섞이지 않아야 한다 (frame 번호 중복 없음)."""
    sample = _load_sample("sample_crash_1.json")
    parsed = parse_asan_log(sample["crash_report"]["asan_log"])

    frame_numbers = [f["frame"] for f in parsed.stack_trace]
    # 크래시 발생 블록만 담겨야 하므로 #0 이 두 번 나오면 안 된다
    assert frame_numbers.count(0) == 1
    assert parsed.allocated_at_location is not None
    assert "dlt_common.c:820" in parsed.allocated_at_location


def test_use_after_free_freed_at_location_extracted():
    sample = _load_sample("sample_crash_2.json")
    parsed = parse_asan_log(sample["crash_report"]["asan_log"])

    assert parsed.freed_at_location is not None
    assert "channel.c:140" in parsed.freed_at_location
    assert parsed.allocated_at_location is not None
    assert "channel.c:88" in parsed.allocated_at_location


def test_parse_unknown_format_does_not_raise():
    parsed = parse_asan_log("some completely unrelated log text\nwith no sanitizer info")
    assert parsed.error_type == "unknown"
    assert parsed.stack_trace == []


# ---------------------------------------------------------------------------
# cwe_mapping
# ---------------------------------------------------------------------------

def test_cwe_lookup_known_type():
    info = lookup_cwe("heap-buffer-overflow")
    assert info.primary_id == "CWE-122"


def test_cwe_lookup_unknown_type_falls_back():
    info = lookup_cwe("some-new-sanitizer-error")
    assert info is UNKNOWN_CWE


# ---------------------------------------------------------------------------
# cvss_estimator
# ---------------------------------------------------------------------------

def test_cvss_estimate_heap_overflow_is_high_or_critical():
    est = estimate_cvss("heap-buffer-overflow")
    assert est.severity in ("High", "Critical")
    assert 0.0 <= est.base_score <= 10.0
    assert est.vector.startswith("CVSS:3.1/")


def test_cvss_estimate_memory_leak_is_lower_severity():
    overflow = estimate_cvss("heap-buffer-overflow")
    leak = estimate_cvss("memory-leak")
    assert leak.base_score < overflow.base_score


# ---------------------------------------------------------------------------
# end-to-end: build_cve_report + render
# ---------------------------------------------------------------------------

def test_build_cve_report_end_to_end_sample1():
    sample = _load_sample("sample_crash_1.json")
    report = build_cve_report(
        crash_report=sample["crash_report"],
        api_metadata=sample["api_metadata"],
        harness=sample["harness"],
        triage_result=sample["triage_result"],
        poc_input_path=sample.get("poc_input_path"),
        sequence=1,
    )

    assert report.crash_id == "CR-000123"
    assert report.cwe.id == "CWE-122"
    assert report.triage.verdict == Verdict.TRUE_POSITIVE
    assert report.affected_component.library_name == "dlt-daemon"
    assert "dlt_message_read" in report.title or "heap buffer overflow" in report.title

    # 렌더링이 예외 없이 동작하고 핵심 정보를 포함하는지 확인
    json_out = render_json(report)
    assert "CWE-122" in json_out
    assert report.report_id in json_out

    md_out = render_markdown(report)
    assert "## 재현 방법" in md_out
    assert "dlt_message_read" in md_out
    assert "⚠️" in md_out  # CVSS 추정치 경고 문구 포함 확인


def test_build_cve_report_end_to_end_sample2():
    sample = _load_sample("sample_crash_2.json")
    report = build_cve_report(
        crash_report=sample["crash_report"],
        api_metadata=sample["api_metadata"],
        harness=sample["harness"],
        triage_result=sample["triage_result"],
        poc_input_path=sample.get("poc_input_path"),
        sequence=2,
    )

    assert report.cwe.id == "CWE-416"  # Use After Free
    assert report.affected_component.library_name == "eclipse-score"
    assert report.report_id.endswith("000002")


def test_report_id_format():
    from logosfuzz.analyze.cve_reporting.schema import CVEReport

    rid = CVEReport.new_report_id(sequence=7, year=2026)
    assert rid == "LOGOSFUZZ-2026-000007"
