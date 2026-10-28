"""GENERIC-C 미정의 심볼 스텁 생성 테스트"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from logosfuzz.common.target_profile import load_profile
from logosfuzz.generate.stubs import (
    StubPolicy,
    StubSet,
    parse_undefined_symbols,
    plan_stubs,
    render_stub_source,
    signature_for,
)

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "tests" / "fixtures" / "linker_errors"
EMBEDDED = REPO / "examples" / "embedded"


class FakeKB:
    def __init__(self, docs):
        self.docs = docs

    def api(self, name):
        return self.docs.get(name)


def test_parse_undefined_symbols_both_linkers():
    gnu = parse_undefined_symbols((FIXTURES / "undefined_reference_gnu_ld.txt").read_text())
    lld = parse_undefined_symbols((FIXTURES / "undefined_symbol_lld.txt").read_text())
    assert gnu == lld == ["HAL_GetTick", "HAL_UART_Transmit"]


def test_policy_from_embedded_profile():
    profile = load_profile(REPO / "targets" / "embedded-sample.json", base_dir=REPO)
    policy = StubPolicy.from_profile(profile)
    assert policy.enabled and policy.allowlist == ("HAL_*",)
    assert policy.allows("HAL_GetTick")
    assert not policy.allows("vendor_crc32")
    assert not policy.allows("ns::HAL_x(int)")  # C 식별자만


def test_policy_disabled_for_generic_profile():
    profile = load_profile(REPO / "targets" / "libsndfile.json", base_dir=REPO)
    assert not StubPolicy.from_profile(profile).allows("HAL_GetTick")


def test_empty_allowlist_means_unrestricted():
    assert StubPolicy(enabled=True).allows("anything_goes")


def test_plan_splits_allowed_and_rejected():
    policy = StubPolicy(enabled=True, allowlist=("HAL_*", "BSP_*"))
    plan = plan_stubs(["HAL_GetTick", "crc32", "BSP_Init", "HAL_GetTick"], policy,
                      already=["BSP_Init"])
    assert plan.stub == ["HAL_GetTick"]
    assert plan.rejected == ["crc32"]
    assert not plan.only_rejected
    assert plan_stubs(["crc32"], policy).only_rejected


def test_fallback_stub_without_kb():
    source = render_stub_source(["HAL_GetTick"])
    assert "__attribute__((weak)) int HAL_GetTick() { return 0; }" in source
    assert "#include" not in source


def test_stub_uses_kb_signature_and_header():
    kb = FakeKB({
        "HAL_UART_Transmit": {
            "function": "HAL_UART_Transmit", "file": "/src/hal.h",
            "return_type": "HAL_StatusTypeDef",
            "params": [{"type": "UART_HandleTypeDef *", "name": "huart"},
                       {"type": "const uint8_t *", "name": "data"},
                       {"type": "uint16_t", "name": "size"},
                       {"type": "uint32_t", "name": "timeout"}],
        },
        "HAL_Delay": {"function": "HAL_Delay", "file": "hal.c", "return_type": "void",
                      "params": [{"type": "uint32_t", "name": "ms"}]},
    })
    sig = signature_for("HAL_UART_Transmit", kb)
    assert sig.from_kb and sig.header == "hal.h"
    source = render_stub_source(["HAL_UART_Transmit", "HAL_Delay", "HAL_GetTick"], kb)
    assert '#include "hal.h"' in source
    assert ("__attribute__((weak)) HAL_StatusTypeDef HAL_UART_Transmit(UART_HandleTypeDef * huart, "
            "const uint8_t * data, uint16_t size, uint32_t timeout)") in source
    assert "__builtin_memset(&ret, 0, sizeof(ret));" in source
    assert "__attribute__((weak)) void HAL_Delay(uint32_t ms)\n{\n}" in source
    assert "int HAL_GetTick() { return 0; }" in source  # KB 에 없으면 기본형


def test_stub_set_accumulates_and_writes(tmp_path):
    stubs = StubSet()
    assert stubs.write(tmp_path / "s.c") is None
    assert stubs.add(["HAL_GetTick"]) == ["HAL_GetTick"]
    assert stubs.add(["HAL_GetTick", "HAL_UART_Transmit"]) == ["HAL_UART_Transmit"]
    path = stubs.write(tmp_path / "stubs" / "s.c")
    assert path.read_text().count("__attribute__((weak))") == 2


def _clang_fuzzer_available(tmp_path: Path) -> bool:
    if not shutil.which("clang"):
        return False
    probe = tmp_path / "probe.c"
    probe.write_text("int LLVMFuzzerTestOneInput(const unsigned char*d, unsigned long n)"
                     "{return 0;}\n")
    proc = subprocess.run(["clang", "-fsanitize=address,fuzzer", str(probe), "-o",
                           str(tmp_path / "probe")], capture_output=True)
    return proc.returncode == 0


def test_real_link_failure_then_stub_links(tmp_path):
    """examples/embedded 를 HAL 없이 링크 → 로그에서 스텁 생성 → 다시 링크 성공"""
    if not _clang_fuzzer_available(tmp_path):
        pytest.skip("clang + libFuzzer 런타임이 없다")
    flags = ["-g", "-O1", "-fsanitize=address,undefined,fuzzer", f"-I{EMBEDDED}"]
    sources = [str(EMBEDDED / "harness" / "fuzz_proto.c"), str(EMBEDDED / "proto_parser.c")]
    out = tmp_path / "fuzz_proto"

    first = subprocess.run(["clang", *flags, *sources, "-o", str(out)],
                           capture_output=True, text=True)
    assert first.returncode != 0
    symbols = parse_undefined_symbols(first.stderr)
    assert sorted(symbols) == ["HAL_GetTick", "HAL_UART_Transmit"]

    plan = plan_stubs(symbols, StubPolicy(enabled=True, allowlist=("HAL_*",)))
    stubs = StubSet()
    stubs.add(plan.stub)
    stub_file = stubs.write(tmp_path / "stubs.c")

    second = subprocess.run(["clang", *flags, *sources, str(stub_file), "-o", str(out)],
                            capture_output=True, text=True)
    assert second.returncode == 0, second.stderr
    assert out.is_file()
