import json
from pathlib import Path

import pytest

from logosfuzz.execute.sanitizer import (
    SanitizerMonitor,
    classify_sanitizer_error,
    classify_ubsan_error,
    write_findings,
)

_FIXTURES = Path(__file__).parent / "fixtures" / "sanitizer_logs"


def _parse_fixture(name: str):
    monitor = SanitizerMonitor()
    for line in (_FIXTURES / name).read_text(encoding="utf-8").splitlines():
        monitor.feed(line)
    return monitor.finish()


def test_classifies_asan_and_tsan_defects():
    assert classify_sanitizer_error("ASAN", "heap-use-after-free") == "use-after-free"
    assert classify_sanitizer_error("ASAN", "attempting double-free") == "double-free"
    assert classify_sanitizer_error("TSAN", "lock-order-inversion") == "deadlock"
    assert classify_sanitizer_error("TSAN", "data race") == "race-condition"


def test_vehicle_specific_watchdog_classification_is_gone():
    """차량 RT 대상이 빠지면서 잡히지 않게 된 분류를 제거했다."""
    assert classify_sanitizer_error("TSAN", "watchdog timeout") == "unknown"


def test_monitor_parses_traceback_and_creates_signature(tmp_path):
    monitor = SanitizerMonitor()
    monitor.feed("==14==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1")
    monitor.feed("    #0 0x1 in parse_can /work/src/can/parser.c:42:7")
    monitor.feed("    #1 0x2 in fuzz_target /work/harness.cc:9:3")
    findings = monitor.finish()

    assert len(findings) == 1
    finding = findings[0]
    assert finding.sanitizer == "ASAN"
    assert finding.category == "buffer-overflow"
    assert finding.traceback[0].file == "/work/src/can/parser.c"
    assert finding.signature == "buffer-overflow_parser_c_42"

    output = tmp_path / "sanitizer" / "group-a.jsonl"
    write_findings(output, findings)
    saved = json.loads(output.read_text().strip())
    assert saved["signature"] == finding.signature
    assert saved["raw_log"][0].startswith("==14==ERROR")


def test_monitor_finishes_previous_event_when_next_event_starts():
    monitor = SanitizerMonitor()
    monitor.feed("WARNING: ThreadSanitizer: data race")
    monitor.feed("    #0 write /src/control.c:88:2")
    monitor.feed("ERROR: AddressSanitizer: attempting double-free")
    monitor.feed("    #0 free /src/memory.c:12:1")
    findings = monitor.finish()
    assert [finding.category for finding in findings] == ["race-condition", "double-free"]


def test_leak_sanitizer_is_labelled_lsan_not_asan():
    monitor = SanitizerMonitor()
    monitor.feed("ERROR: LeakSanitizer: detected memory leaks")
    findings = monitor.finish()
    assert [f.category for f in findings] == ["memory-leak"]
    assert findings[0].sanitizer == "LSAN"


# --- UBSan 파서 (EXE-04-02, 3주차) -----------------------------------------
#
# 입력은 GEN 파트가 실제 Bazel 빌드를 깨뜨려 수집한 출력 원문이다
# (tests/fixtures/sanitizer_logs, clang 18.1.3). 포맷을 추측하지 않는다.

@pytest.mark.parametrize("fixture,category,line_no", [
    ("ubsan_signed_overflow.txt", "integer-overflow", 38),
    ("ubsan_shift_exponent.txt", "shift-out-of-bounds", 47),
    ("ubsan_null_deref.txt", "null-dereference", 55),
    ("ubsan_divide_by_zero.txt", "divide-by-zero", 61),
    ("ubsan_array_bounds.txt", "array-out-of-bounds", 69),
    ("ubsan_misaligned_load.txt", "misaligned-access", 79),
    ("ubsan_float_cast_overflow.txt", "float-cast-overflow", 86),
    ("ubsan_invalid_bool.txt", "invalid-enum-load", 96),
])
def test_parses_each_ubsan_category_from_real_output(fixture, category, line_no):
    findings = _parse_fixture(fixture)
    ubsan = [f for f in findings if f.sanitizer == "UBSAN"]
    assert len(ubsan) == 1
    assert ubsan[0].category == category
    assert ubsan[0].traceback[0].line == line_no


def test_ubsan_is_detected_even_though_process_exits_zero():
    """복구 가능 UBSan 은 진단만 찍고 종료코드 0 으로 끝난다.

    종료코드만 보면 '정상 종료'라 결함을 통째로 놓친다. 출력 파싱으로
    잡히는지가 이 파서의 존재 이유다.
    """
    raw = (_FIXTURES / "ubsan_signed_overflow.txt").read_text(encoding="utf-8")
    assert "[exit code] 0" in raw          # 프로세스는 성공으로 끝났는데
    findings = _parse_fixture("ubsan_signed_overflow.txt")
    assert any(f.sanitizer == "UBSAN" for f in findings)   # 결함은 있다


def test_ubsan_block_does_not_swallow_trailing_libfuzzer_output():
    """SUMMARY 에서 블록을 끊지 않으면 libFuzzer 실행 요약까지 딸려 들어간다."""
    findings = _parse_fixture("ubsan_signed_overflow.txt")
    ubsan = [f for f in findings if f.sanitizer == "UBSAN"][0]
    assert ubsan.raw_log[-1].startswith("SUMMARY: UndefinedBehaviorSanitizer")
    assert not any("NOTE: fuzzing was not performed" in ln for ln in ubsan.raw_log)


def test_recoverable_ub_then_real_crash_are_separate_findings():
    """복구 가능 UB 로 계속 실행되다 ASan 이 실제 크래시를 잡는 경우."""
    findings = _parse_fixture("ubsan_array_bounds.txt")
    assert [(f.sanitizer, f.category) for f in findings] == [
        ("UBSAN", "array-out-of-bounds"),
        ("ASAN", "buffer-overflow"),
    ]


def test_segv_after_null_deref_is_classified():
    """null 역참조 UB 직후의 SEGV 가 unknown 으로 빠지지 않아야 한다."""
    findings = _parse_fixture("ubsan_null_deref.txt")
    assert [(f.sanitizer, f.category) for f in findings] == [
        ("UBSAN", "null-dereference"),
        ("ASAN", "segv"),
    ]


def test_clean_run_produces_no_findings():
    assert _parse_fixture("clean_no_diagnostic.txt") == []


def test_unknown_ub_kind_falls_back_to_undefined_behavior():
    """표본에 없는 UB 가 '결함 아님'으로 오인되지 않게 한다."""
    assert classify_ubsan_error("something nobody has seen yet") == "undefined-behavior"


def test_ubsan_signature_includes_category_and_location():
    findings = _parse_fixture("ubsan_divide_by_zero.txt")
    ubsan = [f for f in findings if f.sanitizer == "UBSAN"][0]
    assert ubsan.signature == "divide-by-zero_json_cc_61"
