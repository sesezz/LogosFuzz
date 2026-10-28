"""하네스가 입력을 NUL 없는 문자열로 넘긴 크래시의 판별 (GENERIC-B, libsndfile 2차 실측 기반)."""
from __future__ import annotations

from pathlib import Path

import pytest

from logosfuzz.analyze.contracts import get_contract
from logosfuzz.analyze.dedup import deduplicate
from logosfuzz.analyze.models import CrashRecord, Verdict
from logosfuzz.analyze.triage import rule_triage
from logosfuzz.common.target_profile import load_profile
from logosfuzz.execute.sanitizer import SanitizerMonitor, classify_ubsan_error

REPO = Path(__file__).resolve().parents[1]

HARNESS_BAD = """\
#include "sndfile.h"
int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {
    SF_INFO sfinfo = {0};
    SNDFILE *f = sf_open((const char *)data, SFM_READ, &sfinfo);
    if (f) sf_close(f);
    return 0;
}
"""
HARNESS_OK = HARNESS_BAD.replace("(const char *)data", "path")


@pytest.fixture(scope="module")
def profile():
    return load_profile(REPO / "targets" / "libsndfile.json", base_dir=REPO)


def _record(tmp_path: Path, harness_source: str) -> CrashRecord:
    harness = tmp_path / "lg_sndfile.c"
    harness.write_text(harness_source, encoding="utf-8")
    log = f"""\
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000011 at pc 0x1 bp 0x2 sp 0x3
READ of size 2 at 0x502000000011 thread T0
    #0 0x595e624bc90e in strlen (/harness/lg_sndfile+0x33090e) (BuildId: db16)
    #1 0x595e626b7c28 in psf_log_printf {tmp_path}/src/common.c:174:14
    #2 0x595e6257e86c in sf_open {tmp_path}/src/sndfile.c:369:2
    #3 0x595e6257e53f in LLVMFuzzerTestOneInput {harness}:4:15
    #4 0x595e6248bda4 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/harness/lg_sndfile+0x2ffda4) (BuildId: db16)
SUMMARY: AddressSanitizer: heap-buffer-overflow (/harness/lg_sndfile+0x33090e) in strlen
"""
    monitor = SanitizerMonitor()
    for line in log.splitlines():
        monitor.feed(line)
    (finding,) = monitor.finish()
    return CrashRecord.from_finding(finding.to_dict())


def test_input_passed_as_c_string_is_a_harness_defect(tmp_path, profile):
    """실측: sf_open((const char *)data, ...) 가 strlen 으로 버퍼 끝을 넘어 읽음. 정탐으로 자동 승인되었던 크래시."""
    record = _record(tmp_path, HARNESS_BAD)
    evidence = get_contract("c_return_code").analyze(record, profile=profile)

    assert evidence.violation == "harness-string"
    assert evidence.api == "sf_open"
    assert evidence.crash_function == "strlen"
    assert "4행" in evidence.null_reason

    clusters, _ = deduplicate([record])
    result = rule_triage(clusters[0], profile=profile)
    assert result.verdict is Verdict.FALSE_POSITIVE
    assert "c-string-unterminated-by-harness" in result.signals
    assert "NUL 로 끝나지 않는 문자열" in result.rationale


def test_same_stack_with_a_proper_path_is_not_judged(tmp_path, profile):
    """소스 줄이 data 를 문자열로 넘기지 않으면(라이브러리 버그일 수 있음) 판정하지 않음."""
    record = _record(tmp_path, HARNESS_OK)
    evidence = get_contract("c_return_code").analyze(record, profile=profile)
    assert evidence.violation == ""

    clusters, _ = deduplicate([record])
    assert rule_triage(clusters[0], profile=profile).verdict is Verdict.TRUE_POSITIVE


def test_missing_harness_source_is_not_judged(tmp_path, profile):
    record = _record(tmp_path, HARNESS_BAD)
    (tmp_path / "lg_sndfile.c").unlink()
    assert get_contract("c_return_code").analyze(record, profile=profile).violation == ""


def test_ubsan_zero_offset_to_null_pointer_is_not_a_dereference():
    assert classify_ubsan_error("applying zero offset to null pointer") == "null-pointer-arithmetic"
    assert classify_ubsan_error("applying non-zero offset 8 to null pointer") == "null-pointer-arithmetic"
    assert classify_ubsan_error("member access within null pointer of type 'Header'") == "null-dereference"


# --------------------------------------------------------------------------- #
# 하네스가 할당한 버퍼를 API 가 넘어 쓴 경우 (libsndfile 6차 실측)
# --------------------------------------------------------------------------- #
def _fixture_record() -> CrashRecord:
    monitor = SanitizerMonitor()
    path = REPO / "tests" / "fixtures" / "c_return_code_logs" / "harness_undersized_buffer.txt"
    for line in path.read_text(encoding="utf-8").splitlines():
        monitor.feed(line)
    (finding,) = monitor.finish()
    return CrashRecord.from_finding(finding.to_dict())


def test_overflow_of_a_harness_allocated_buffer_is_not_auto_approved(profile):
    """sf_readf_float 가 frames x channels 개를 쓰는데 하네스가 frames 개만 할당. 정탐(0.95)으로 자동 승인되었던 크래시."""
    record = _fixture_record()
    evidence = get_contract("c_return_code").analyze(record, profile=profile)

    assert evidence.violation == "harness-buffer-suspect"
    assert evidence.api == "sf_readf_float"
    assert "lg_sndfile.c:59" in evidence.null_reason

    clusters, _ = deduplicate([record])
    result = rule_triage(clusters[0], profile=profile)
    assert result.verdict is Verdict.NEEDS_REVIEW                       # 정탐 자동 승인 제외
    assert "c-harness-buffer-overflow-suspect" in result.signals
    assert "frames x channels" in result.rationale


def test_buffer_rule_needs_the_api_in_the_profile(profile):
    """프로필 apis 에 없는 함수가 하네스 바로 위 프레임이면 판정하지 않음."""
    record = _fixture_record()
    record.raw_log = [line.replace("sf_readf_float", "not_an_api") for line in record.raw_log]
    assert get_contract("c_return_code").analyze(record, profile=profile).violation == ""


def test_buffer_suspect_stays_needs_review_even_when_reproduced_many_times(profile):
    """재현성 보너스(+0.10)로 점수가 올라가도 정탐으로 넘어가지 않음 (x6 클러스터가 정탐 0.70 이 된 실측)."""
    import copy

    records = [copy.deepcopy(_fixture_record()) for _ in range(6)]
    clusters, _ = deduplicate(records)
    assert clusters[0].count == 6

    result = rule_triage(clusters[0], profile=profile)

    assert result.verdict is Verdict.NEEDS_REVIEW
    assert "highly-reproducible" in result.signals
    assert "c-harness-buffer-overflow-suspect" in result.signals
