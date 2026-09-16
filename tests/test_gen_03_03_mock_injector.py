"""GEN-03-03 Mocking 코드 삽입 단위 테스트."""

from logosfuzz.generate.gen_03_03_mock_injector import (
    FunctionSignature,
    build_mock_plan,
    default_return,
    find_mock_candidates,
    insert_mocks,
    parse_signature,
)


# --- 시그니처 파서 ---------------------------------------------------------
def test_parse_signature_full():
    sig = parse_signature("uds_ctx_t *uds_session_lookup(uint8_t id, int flags)")
    assert sig.name == "uds_session_lookup"
    assert sig.return_type == "uds_ctx_t *"
    assert [p.type for p in sig.params] == ["uint8_t", "int"]
    assert sig.render_decl().startswith("uds_ctx_t * uds_session_lookup(")


def test_parse_signature_void_and_variadic():
    assert parse_signature("void f(void)").params == []
    v = parse_signature("int logf(const char *fmt, ...)")
    assert v.variadic is True


def test_parse_signature_fallback():
    sig = parse_signature("not a real signature formatted")
    assert isinstance(sig, FunctionSignature)
    assert sig.return_type == "int"


# --- 기본값 정책 -----------------------------------------------------------
def test_default_return_policy():
    assert default_return("void") is None
    assert default_return("int") == "0"
    assert default_return("uint32_t") == "0"
    assert default_return("double") == "0.0"
    assert default_return("bool") == "0"
    assert default_return("char *") == "NULL"
    assert default_return("uds_ctx_t *") == "NULL"
    assert default_return("my_struct_t") == "(my_struct_t){0}"


# --- 후보 탐지 -------------------------------------------------------------
def test_find_mock_candidates_excludes_defined_and_libc():
    defined = ["target_fn"]
    called = ["target_fn", "ext_dep", "malloc", "ext_dep", "hal_read"]
    cands = find_mock_candidates(defined, called)
    assert cands == ["ext_dep", "hal_read"]  # 정의됨/ libc 제외 + 중복 제거 + 순서 보존


# --- 계획/생성 -------------------------------------------------------------
def test_build_mock_plan_and_source():
    plan = build_mock_plan(
        "lg1",
        defined=["t"],
        called=["t", "hw_ts", "hal_read", "malloc"],
        signatures={
            "hw_ts": "uint32_t hw_ts(void)",
            "hal_read": "int hal_read(frame_t *out, int bus)",
        },
    )
    assert len(plan.stubs) == 2
    src = plan.mock_source()
    assert "uint32_t hw_ts(void) {" in src
    assert "return 0;" in src
    assert "int hal_read(frame_t * out, int bus) {" in src
    assert "malloc" in plan.skipped_libc
    # 마커는 buildable에서는 없음
    assert "LOGOSFUZZ-MOCK-HIT" not in src


def test_pointer_default_and_header():
    plan = build_mock_plan(
        "lg2", defined=[], called=["get_ctx"],
        signatures={"get_ctx": "ctx_t *get_ctx(int id)"},
    )
    assert "return NULL;" in plan.mock_source()
    header = plan.mock_header()
    assert "ctx_t * get_ctx(int id);" in header
    assert header.startswith("#ifndef LOGOSFUZZ_MOCKS_LG2_H")


def test_instrumented_strategy_emits_marker():
    plan = build_mock_plan("lg3", defined=[], called=["dep"],
                           strategy="instrumented")
    src = plan.mock_source()
    assert "LOGOSFUZZ_MOCK_MARK" in src
    assert plan.manifest()["mocked_symbols"][0]["emits_marker"] is True


# --- 매니페스트 ------------------------------------------------------------
def test_manifest_structure():
    plan = build_mock_plan("lgm", defined=[], called=["a", "malloc"],
                           signatures={"a": "int a(void)"})
    man = plan.manifest()
    assert man["harness"] == "lgm"
    assert man["mock_count"] == 1
    assert man["mocked_symbols"][0]["symbol"] == "a"
    assert man["mocked_symbols"][0]["default_return"] == "0"
    assert man["skipped_libc"] == ["malloc"]
    assert man["marker_hint"] == "LOGOSFUZZ-MOCK-HIT"


# --- 코드 삽입 -------------------------------------------------------------
def test_insert_mocks_append_and_idempotent():
    plan = build_mock_plan("lgi", defined=[], called=["dep"],
                           signatures={"dep": "int dep(void)"})
    harness = "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n){return 0;}\n"
    injected = insert_mocks(harness, plan)
    assert "mock injection begin" in injected
    assert "int dep(void) {" in injected
    # 원본 하네스 코드는 보존
    assert "LLVMFuzzerTestOneInput" in injected
    # 재삽입해도 중복되지 않음(idempotent)
    twice = insert_mocks(injected, plan)
    assert twice.count("mock injection begin") == 1


def test_insert_mocks_include_style():
    plan = build_mock_plan("lgh", defined=[], called=["dep"])
    out = insert_mocks("int main(){}", plan, style="include")
    assert '#include "mocks_lgh.h"' in out


# --- libc 허용목록 범위 ----------------------------------------------------
#
# 3단계 검증(linux-can/can-utils, `isotpsend.c`)에서 표준 POSIX/소켓 함수가
# 전부 "정의되지 않은 심볼"로 잡혀 stub 생성 대상이 됐다. 진짜 libc `socket()`과
# 시그니처가 다른 가짜 stub 이 함께 컴파일되면 링크가 깨지거나, 진짜 소켓 호출이
# stub 으로 조용히 대체되어 대상이 아무 통신도 안 하면서 정상으로 보인다.

SOCKETCAN_CALLS = [
    "socket", "bind", "setsockopt", "close", "write", "if_nametoindex",
    "getopt", "perror", "scanf", "sscanf", "strtoul", "usleep", "basename",
]


def test_posix_socket_calls_are_not_mock_candidates():
    assert find_mock_candidates([], SOCKETCAN_CALLS) == []


def test_c_constructs_are_never_mock_candidates():
    """`sizeof` 는 연산자지 함수가 아니다 - 실제로 후보에 올라왔었다."""
    assert find_mock_candidates([], ["sizeof", "va_start", "offsetof"]) == []


def test_protocol_apis_are_still_mock_candidates():
    """허용목록을 넓혔다고 진짜 모킹 대상까지 놓치면 안 된다."""
    candidates = find_mock_candidates([], ["isotp_send", "uds_read_did", "can_send"])
    assert candidates == ["isotp_send", "uds_read_did", "can_send"]


def test_locally_defined_socket_wrapper_is_not_mocked():
    """대상이 직접 정의한 함수는 이름이 겹쳐도 모킹하지 않는다."""
    assert find_mock_candidates(["can_socket_open"], ["can_socket_open", "socket"]) == []
