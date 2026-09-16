import json

from logosfuzz.execute.sanitizer import SanitizerMonitor, classify_sanitizer_error, write_findings


def test_classifies_asan_and_tsan_vehicle_defects():
    assert classify_sanitizer_error("ASAN", "heap-use-after-free") == "use-after-free"
    assert classify_sanitizer_error("ASAN", "attempting double-free") == "double-free"
    assert classify_sanitizer_error("TSAN", "lock-order-inversion") == "deadlock"
    assert classify_sanitizer_error("TSAN", "data race") == "race-condition"
    assert classify_sanitizer_error("TSAN", "watchdog timeout") == "watchdog-timeout"


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


def test_monitor_handles_leak_and_watchdog_stream_lines():
    monitor = SanitizerMonitor()
    monitor.feed("ERROR: LeakSanitizer: detected memory leaks")
    monitor.feed("watchdog timeout in control loop")
    findings = monitor.finish()
    assert [finding.category for finding in findings] == ["memory-leak", "watchdog-timeout"]
