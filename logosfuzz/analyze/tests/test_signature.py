"""ANA-05-04 시그니처 로직 회귀 테스트."""

from __future__ import annotations

from logosfuzz.analyze.models import CrashRecord, Frame
from logosfuzz.analyze.signature import (
    application_frames,
    cluster_id_for,
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
