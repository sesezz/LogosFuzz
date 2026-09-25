"""ANA-05-04 시그니처 로직 회귀 테스트."""

from __future__ import annotations

from logosfuzz.analyze.models import CrashRecord, Frame
from logosfuzz.analyze.signature import (
    application_frames,
    cluster_id_for,
    collapse_repeated_frames,
    has_application_frame,
    is_harness_frame,
    is_runtime_frame,
    signature_key,
)


def _rec(category, frames, base=""):
    return CrashRecord(
        sanitizer="ASAN",
        category=category,
        traceback=[Frame(f, ln) for f, ln in frames],
        base_signature=base,
    )


def test_runtime_frame_is_filtered_out():
    rt = Frame("/src/llvm/compiler-rt/lib/asan/asan_malloc_linux.cpp", 69)
    app = Frame("/src/dlt-daemon/src/shared/dlt_common.c", 842)
    assert is_runtime_frame(rt) is True
    assert is_runtime_frame(app) is False
    rec = _rec("use-after-free", [(rt.file, rt.line), (app.file, app.line)])
    # 런타임 프레임은 제외되고 앱 프레임만 남는다
    assert application_frames(rec) == [app]


def test_harness_frame_detection():
    harness = Frame("/src/harness/dlt_message_read_harness.c", 41)
    assert is_harness_frame(harness) is True
    # 하네스만 있으면 애플리케이션 프레임이 없다고 본다
    rec = _rec("mocking-fail-fp", [("/src/harness/mock_can_transport.c", 88)])
    assert has_application_frame(rec) is False


def test_has_application_frame_true_for_library_code():
    rec = _rec(
        "use-after-free",
        [("/src/dlt-daemon/src/shared/dlt_common.c", 842),
         ("/src/harness/dlt_message_read_harness.c", 41)],
    )
    assert has_application_frame(rec) is True


def test_multiframe_signature_uses_top_app_frames():
    rec = _rec(
        "use-after-free",
        [("/src/dlt-daemon/src/shared/dlt_common.c", 842),
         ("/src/harness/dlt_message_read_harness.c", 41)],
    )
    key = signature_key(rec, depth=2)
    assert key == "use-after-free@dlt_common.c:842|dlt_message_read_harness.c:41"


def test_signature_ignores_leading_runtime_frame():
    # 최상단이 sanitizer 런타임이어도, 실제 앱 프레임 기준으로 같은 시그니처여야 한다
    with_rt = _rec(
        "use-after-free",
        [("/src/llvm/compiler-rt/lib/asan/asan_interceptors.cpp", 322),
         ("/src/dlt-daemon/src/shared/dlt_common.c", 842),
         ("/src/harness/dlt_message_read_harness.c", 41)],
    )
    without_rt = _rec(
        "use-after-free",
        [("/src/dlt-daemon/src/shared/dlt_common.c", 842),
         ("/src/harness/dlt_message_read_harness.c", 41)],
    )
    assert signature_key(with_rt) == signature_key(without_rt)
    assert cluster_id_for(with_rt) == cluster_id_for(without_rt)


def test_windows_and_unix_paths_normalize_equal():
    unix = _rec("use-after-free", [("/src/dlt-daemon/src/shared/dlt_common.c", 842)])
    win = _rec("use-after-free", [("src\\dlt-daemon\\src\\shared\\dlt_common.c", 842)])
    assert signature_key(unix) == signature_key(win)


def test_same_location_different_bugtype_differ():
    uaf = _rec("use-after-free", [("/src/x/dlt_common.c", 842)])
    df = _rec("double-free", [("/src/x/dlt_common.c", 842)])
    assert signature_key(uaf) != signature_key(df)
    assert cluster_id_for(uaf) != cluster_id_for(df)


def test_fallback_to_base_signature_when_no_frames():
    rec = _rec("unknown", [], base="unknown_x_0")
    assert signature_key(rec) == "unknown@unknown_x_0"
    empty = _rec("unknown", [])
    assert signature_key(empty) == "unknown@unknown"


# --- UBSan 시그니처 (ANA-05-04, 4주차) --------------------------------------
#
# UBSan 진단은 헤더 줄과 스택 프레임 #0 이 같은 위치를 가리킨다. 경로 접두사만
# 달라서 전체 경로로는 다른 프레임처럼 보이지만 실제로는 한 지점이다.
# 합치지 않으면 시그니처 depth 한 칸을 중복이 먹는다.

_UBSAN_TRACEBACK = [
    # UBSan "runtime error:" 헤더 줄에서 뽑힌 위치
    ("score/json/json.cc", 38),
    # 스택 프레임 #0 - 같은 지점인데 경로 접두사가 붙어 있다
    ("/proc/self/cwd/score/json/json.cc", 38),
    ("/proc/self/cwd/harness/json_fuzzer.cc", 10),
]


def test_collapses_same_location_with_different_path_prefix():
    frames = [Frame(f, ln) for f, ln in _UBSAN_TRACEBACK]
    collapsed = collapse_repeated_frames(frames)
    assert [(f.basename, f.line) for f in collapsed] == [
        ("json.cc", 38),
        ("json_fuzzer.cc", 10),
    ]


def test_ubsan_signature_does_not_waste_depth_on_duplicate():
    rec = _rec("integer-overflow", _UBSAN_TRACEBACK)
    assert signature_key(rec) == "integer-overflow@json.cc:38|json_fuzzer.cc:10"


def test_collapses_recursion():
    """재귀 깊이는 입력에 따라 달라진다. 합치지 않으면 같은 버그가 흩어진다."""
    shallow = _rec("buffer-overflow", [("/src/parse.c", 10), ("/src/main.c", 3)])
    deep = _rec("buffer-overflow", [
        ("/src/parse.c", 10), ("/src/parse.c", 10), ("/src/parse.c", 10),
        ("/src/main.c", 3),
    ])
    assert signature_key(shallow) == signature_key(deep)


def test_does_not_collapse_non_adjacent_repeats():
    """떨어져 있는 같은 위치는 다른 호출 경로로 다시 도달한 것이라 의미가 있다."""
    rec = _rec("use-after-free", [
        ("/src/util.c", 7), ("/src/mid.c", 20), ("/src/util.c", 7),
    ])
    assert signature_key(rec) == "use-after-free@util.c:7|mid.c:20|util.c:7"


def test_asan_signature_is_unchanged_by_collapsing():
    """ASan 은 헤더 줄에 위치가 없어 중복이 애초에 없다. 회귀가 없어야 한다."""
    rec = _rec("buffer-overflow", [
        ("/proc/self/cwd/score/json/json.cc", 107),
        ("/proc/self/cwd/harness/json_fuzzer.cc", 10),
        ("/proc/self/cwd/score/json/json.cc", 102),
    ])
    assert signature_key(rec) == (
        "buffer-overflow@json.cc:107|json_fuzzer.cc:10|json.cc:102"
    )
