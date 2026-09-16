"""ANA-05-01 도달 가능성 컨텍스트 회귀 테스트.

여기 있는 테스트는 전부 **실측에서 실제로 틀렸던 것**을 고정한다.
dlt-daemon 크래시 20건으로 재검증하는 과정에서 다음 네 가지가 순서대로
드러났고, 각각이 판정 결과를 뒤집었다.

1. 파라미터가 여러 줄인 시그니처를 못 잡아 정의를 놓치고, 그 바람에 정의 줄과
   헤더 프로토타입이 "호출부"로 잘못 집계됐다.
2. ASAN ``#0`` 프레임이 sanitizer 인터셉터(``malloc``)라 대상 함수 대신 libc
   함수를 분석했다.
3. "in-tree 호출부 0곳"을 오탐 근거로 삼아, 공개 API 의 실제 결함을 오탐으로
   뒤집었다.
4. 상태 기록 API 를 파일 순서로 잘라, 정작 문제의 값을 저장하는 함수가
   증거에서 빠졌다.
"""
from __future__ import annotations

from logosfuzz.analyze.models import CrashRecord, Frame
from logosfuzz.analyze.reachability import (
    analyze_reachability,
    crash_fields,
    crashing_function,
    derive_signals,
    enclosing_function,
    render_for_prompt,
    _signatures,
)

MULTILINE_SOURCE = """\
#include <stdio.h>

int helper(int a)
{
    return a + 1;
}

DltReturnValue dlt_filter_delete_v2(DltFilter *filter, const char *apid,
                                 const char *ctid, const int log_level,
                                 const int32_t payload_min, int verbose)
{
    int j;
    for (j = 0; j < filter->counter; j++)
        if (memcmp(filter->apid2[j], apid, filter->apid2len[j]) == 0)
            return DLT_RETURN_OK;
    return DLT_RETURN_ERROR;
}

DltReturnValue dlt_filter_add_v2(DltFilter *filter, const char *apid, int verbose)
{
    filter->apid2[filter->counter] = (char *)malloc(255);
    filter->apid2len[filter->counter] = (uint8_t)strlen(apid);
    return DLT_RETURN_OK;
}
"""

HEADER_SOURCE = """\
#ifndef DLT_COMMON_H
#define DLT_COMMON_H
DltReturnValue dlt_filter_delete_v2(DltFilter *filter, const char *apid,
                                 const char *ctid, const int log_level,
                                 const int32_t payload_min, int verbose);
#endif
"""


def _write_tree(tmp_path):
    src = tmp_path / "src" / "shared"
    src.mkdir(parents=True)
    (src / "dlt_common.c").write_text(MULTILINE_SOURCE, encoding="utf-8")
    include = tmp_path / "include" / "dlt"
    include.mkdir(parents=True)
    (include / "dlt_common.h").write_text(HEADER_SOURCE, encoding="utf-8")
    return tmp_path


def _record(line: int, log_lines: list[str] | None = None) -> CrashRecord:
    return CrashRecord(
        sanitizer="ASAN",
        category="heap-buffer-overflow",
        error_reason="heap-buffer-overflow",
        traceback=[Frame("/root/dlt-daemon/src/shared/dlt_common.c", line)],
        raw_log=log_lines or [],
    )


# --------------------------------------------------------------------------- #
# 1. 여러 줄 시그니처
# --------------------------------------------------------------------------- #
def test_multiline_signature_is_one_definition():
    lines = MULTILINE_SOURCE.splitlines()
    names = [s.name for s in _signatures(lines) if s.is_definition]
    assert "dlt_filter_delete_v2" in names
    assert "dlt_filter_add_v2" in names


def test_prototype_is_not_a_definition():
    lines = HEADER_SOURCE.splitlines()
    signatures = [s for s in _signatures(lines) if s.name == "dlt_filter_delete_v2"]
    assert len(signatures) == 1
    assert signatures[0].is_definition is False
    # 프로토타입이 세 줄에 걸쳐 있으므로 span 도 세 줄이어야 한다.
    assert signatures[0].end - signatures[0].start == 2


def test_enclosing_function_of_crash_line():
    lines = MULTILINE_SOURCE.splitlines()
    crash_line = next(i + 1 for i, l in enumerate(lines) if "memcmp" in l)
    assert enclosing_function(lines, crash_line) == "dlt_filter_delete_v2"


def test_signature_lines_are_not_counted_as_callers(tmp_path):
    """정의 줄·헤더 프로토타입이 호출부로 잡히면 안 된다."""
    root = _write_tree(tmp_path)
    crash_line = next(
        i + 1 for i, l in enumerate(MULTILINE_SOURCE.splitlines()) if "memcmp" in l
    )
    ctx = analyze_reachability(_record(crash_line), root)
    assert ctx.function == "dlt_filter_delete_v2"
    assert ctx.production_callers == []
    assert ctx.harness_callers == []


# --------------------------------------------------------------------------- #
# 2. ASAN 인터셉터 프레임
# --------------------------------------------------------------------------- #
def test_crashing_function_from_asan_frame():
    log = ["    #0 0x1 in dlt_filter_delete_v2 /x/dlt_common.c:905:18"]
    assert crashing_function(_record(905, log)) == "dlt_filter_delete_v2"


def test_interceptor_frame_does_not_hijack_target(tmp_path):
    """`#0` 이 sanitizer 인터셉터면 소스에서 역산한 이름을 써야 한다."""
    root = _write_tree(tmp_path)
    crash_line = next(
        i + 1 for i, l in enumerate(MULTILINE_SOURCE.splitlines()) if "memcmp" in l
    )
    log = [
        "    #0 0x1 in malloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:69",
        f"    #3 0x2 in dlt_filter_delete_v2 /root/dlt-daemon/src/shared/dlt_common.c:{crash_line}",
    ]
    ctx = analyze_reachability(_record(crash_line, log), root)
    assert ctx.function == "dlt_filter_delete_v2"
    assert ctx.definition_file.endswith("dlt_common.c")


# --------------------------------------------------------------------------- #
# 3. 공개 API 의 "호출부 0곳"은 오탐 근거가 아니다
# --------------------------------------------------------------------------- #
def test_public_api_without_in_tree_caller_is_not_penalized(tmp_path):
    """헤더에 선언된 API 는 의도된 호출자가 트리 밖이다 — 점수를 깎으면 안 된다."""
    root = _write_tree(tmp_path)
    crash_line = next(
        i + 1 for i, l in enumerate(MULTILINE_SOURCE.splitlines()) if "memcmp" in l
    )
    ctx = analyze_reachability(_record(crash_line), root)
    assert ctx.declared_in_header is True
    delta, signals = derive_signals(ctx)
    assert delta == 0.0
    assert "public-api-no-in-tree-caller" in signals


def test_harness_only_caller_is_penalized(tmp_path):
    """헤더에 없고 하네스만 부르는 함수는 오탐 쪽으로 민다."""
    root = tmp_path
    src = root / "src"
    src.mkdir()
    (src / "internal.c").write_text(
        "static int secret_helper(int *state)\n{\n    return state[0];\n}\n",
        encoding="utf-8",
    )
    fuzz = root / "fuzz"
    fuzz.mkdir()
    (fuzz / "harness.c").write_text(
        "int main(void)\n{\n    int s[1];\n    return secret_helper(s);\n}\n",
        encoding="utf-8",
    )
    ctx = analyze_reachability(_record(3), root, function="secret_helper")
    assert ctx.production_callers == []
    assert ctx.harness_callers
    delta, signals = derive_signals(ctx)
    assert delta < 0
    assert "harness-only-caller" in signals


# --------------------------------------------------------------------------- #
# 4. 상태 기록 API 선택
# --------------------------------------------------------------------------- #
def test_crash_fields_extracted_from_marked_line():
    source = [
        "   904      for (j = 0; j < filter->counter; j++)",
        "   905>         memcmp(filter->apid2[j], apid, filter->apid2len[j]);",
    ]
    assert crash_fields(source) == ["apid2", "apid2len"]


def test_state_writer_touching_crash_field_is_selected(tmp_path):
    """결함 라인이 읽은 필드를 쓰는 함수가 증거에 반드시 들어가야 한다."""
    root = _write_tree(tmp_path)
    crash_line = next(
        i + 1 for i, l in enumerate(MULTILINE_SOURCE.splitlines()) if "memcmp" in l
    )
    ctx = analyze_reachability(_record(crash_line), root)
    assert ctx.handle_types == ["DltFilter"]
    assert "dlt_filter_add_v2" in [name for name, _ in ctx.state_writers]

    rendered = render_for_prompt(ctx)
    assert "dlt_filter_add_v2" in rendered
    assert "apid2len" in rendered


def test_param_name_is_not_mistaken_for_state_type(tmp_path):
    """`const char *apid` 에서 `apid` 를 상태 타입으로 잡으면 안 된다."""
    root = _write_tree(tmp_path)
    crash_line = next(
        i + 1 for i, l in enumerate(MULTILINE_SOURCE.splitlines()) if "memcmp" in l
    )
    ctx = analyze_reachability(_record(crash_line), root)
    assert "apid" not in ctx.handle_types
    assert "ctid" not in ctx.handle_types
