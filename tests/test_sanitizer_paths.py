# -*- coding: utf-8 -*-
"""공백이 들어간 소스 경로를 잃지 않는지 지킨다.

실측에서 나온 회귀다. 저장소가 ``C:/Users/minju/OneDrive/바탕 화면/LogosFuzz``
에 있는 채로 Docker 격리 캠페인을 돌리자 크래시 위치가
``화면/LogosFuzz/.../fuzz_target.c:16`` 으로 **공백 뒤부터 잘려** 기록됐다.
그러면 ANA 의 ``--source-root`` 조회가 파일을 못 찾고 리포트의
``crash_location`` 도 틀어진다.
"""

from logosfuzz.execute.sanitizer import SanitizerMonitor, source_locations

SPACED = "/mnt/c/Users/minju/OneDrive/바탕 화면/LogosFuzz/examples/stage1/fuzz_target.c"


def test_frame_keeps_a_path_with_spaces():
    locations = source_locations([
        f"    #1 0x57a665aa3726 in vulnerable {SPACED}:16:13",
        f"    #2 0x57a665aa33b4 in LLVMFuzzerTestOneInput {SPACED}:23:5",
    ])

    assert [(loc.file, loc.line) for loc in locations] == [(SPACED, 16), (SPACED, 23)]


def test_frame_without_a_column_keeps_the_path():
    """ASAN 의 "located in stack of thread" 블록은 열 번호가 없다."""
    locations = source_locations([f"    #0 0x1 in vulnerable {SPACED}:6"])

    assert locations == [locations[0].__class__(SPACED, 6)]


def test_windows_drive_path_with_spaces():
    win = "C:\\Users\\minju\\바탕 화면\\proj\\main.c"
    locations = source_locations([f"    #0 0x1 in main {win}:12:4"])

    assert (locations[0].file, locations[0].line) == (win, 12)


def test_relative_path_is_not_cut_at_the_first_slash():
    """상대 경로(공백 없음)는 기존 규칙이 읽는다. ``/json.cc`` 가 되면 안 된다."""
    locations = source_locations([
        "SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior score/json/json.cc:38:11",
    ])

    assert (locations[0].file, locations[0].line) == ("score/json/json.cc", 38)


def test_unsymbolized_frame_yields_no_location():
    """모듈+오프셋만 있는 줄에서 경로를 만들어내지 않는다."""
    assert source_locations([
        "    #3 0x3 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long)"
        " (/harness/rec_fuzz+0x4cca4) (BuildId: abc)",
    ]) == []


def test_ubsan_diagnostic_line_with_spaces():
    """UBSan 은 헤더 없이 경로로 시작한다 - 분류와 위치 모두 살아야 한다."""
    path = "/mnt/c/Users/minju/바탕 화면/score/json.cc"
    monitor = SanitizerMonitor()
    for line in [
        f"{path}:38:11: runtime error: signed integer overflow: 2147483647 + 1",
        f"    #0 0x1 in Dispatch {path}:38:11",
        f"SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior {path}:38:11",
    ]:
        monitor.feed(line)
    findings = monitor.finish()

    assert len(findings) == 1
    assert findings[0].sanitizer == "UBSAN"
    assert findings[0].category == "integer-overflow"
    assert (findings[0].traceback[0].file, findings[0].traceback[0].line) == (path, 38)
    assert findings[0].signature == "integer-overflow_json_cc_38"


def test_asan_block_with_spaces_end_to_end():
    monitor = SanitizerMonitor()
    for line in [
        "==8184==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7f78469da5a8",
        "WRITE of size 13 at 0x7f78469da5a8 thread T0",
        f"    #1 0x57a665aa3726 in vulnerable {SPACED}:16:13",
        "SUMMARY: AddressSanitizer: stack-buffer-overflow",
    ]:
        monitor.feed(line)
    finding = monitor.finish()[0]

    assert finding.traceback[0].file == SPACED
    assert finding.signature == "buffer-overflow_fuzz_target_c_16"
