"""GEN-03 하네스 품질 게이트 회귀 테스트

실측에서 하네스를 무력화한 사례 고정
- `char **text` 자리의 `char *` 전달 (C 에서는 경고라 빌드 성공 후 SEGV)
- 헤더 include 후 대상 함수 재선언으로 `conflicting types` (자가 치유 라운드에서도 재발)
- 언어 미구분으로 C++ 대상의 C 컴파일
"""
from __future__ import annotations

from pathlib import Path

from logosfuzz.generate.compiler import (
    STRICT_C_WARNINGS,
    FakeCompiler,
    SubprocessCompiler,
)
from logosfuzz.generate.hygiene import (
    infer_language,
    sanitize_harness,
    strip_redundant_declarations,
)
from logosfuzz.generate.llm import ScriptedLLMClient
from logosfuzz.generate.models import HarnessDraft
from logosfuzz.generate.selfheal import SelfHealLoop

TARGETS = ["dlt_print_hex_string", "dlt_print_char_string"]


# --------------------------------------------------------------------------- #
# 1. 재선언 제거
# --------------------------------------------------------------------------- #
def test_prototype_of_target_api_is_removed():
    source = (
        '#include "dlt_common.h"\n'
        "void dlt_print_hex_string(char *text, int len, const uint8_t *p, int n);\n"
        "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { return 0; }\n"
    )
    out = strip_redundant_declarations(source, TARGETS)

    assert "void dlt_print_hex_string(char *text" not in out
    assert "LLVMFuzzerTestOneInput" in out


def test_extern_prototype_is_removed():
    source = "extern int dlt_print_char_string(char **t, int n, uint8_t *p, int s);\n"

    assert strip_redundant_declarations(source, TARGETS).strip() == ""


def test_definition_with_body_is_kept():
    """하네스가 만든 보조 함수 정의는 유지"""
    source = "int dlt_print_hex_string(char *t) { return 0; }\n"

    assert "return 0" in strip_redundant_declarations(source, TARGETS)


def test_call_site_is_not_removed():
    source = "    dlt_print_hex_string(text, sizeof(text), buf, (int)size);\n"

    assert "dlt_print_hex_string(text" in strip_redundant_declarations(source, TARGETS)


def test_unrelated_declaration_is_kept():
    source = "void some_helper(int a);\n"

    assert "some_helper" in strip_redundant_declarations(source, TARGETS)


def test_empty_target_list_is_a_noop():
    source = "void f(int a);\n"

    assert strip_redundant_declarations(source, []) == source


# --------------------------------------------------------------------------- #
# 2. 자가 치유 라운드 적용 여부
# --------------------------------------------------------------------------- #
def _draft(source: str) -> HarnessDraft:
    return HarnessDraft(
        logic_group="lg_print", source=source, target_apis=TARGETS, language="c"
    )


def test_sanitize_applies_to_repair_rounds():
    """수정본에 다시 들어간 재선언도 제거"""
    bad_decl = "void dlt_print_hex_string(char *t, int n, const uint8_t *p, int s);"
    # 수정 응답에 재선언 재포함 (후처리 없으면 그대로 컴파일)
    repaired = f"```c\n{bad_decl}\n// COMPILE_OK\nint LLVMFuzzerTestOneInput(void){{return 0;}}\n```"
    loop = SelfHealLoop(
        compiler=FakeCompiler(),
        llm=ScriptedLLMClient([repaired]),
        max_round=2,
        sanitize=sanitize_harness,
    )

    report = loop.run(_draft("int LLVMFuzzerTestOneInput(void){return 0;}"))

    assert report.success
    assert bad_decl not in report.final_source


def test_sanitize_applies_to_the_draft():
    bad_decl = "void dlt_print_char_string(char *t, int n, uint8_t *p, int s);"
    loop = SelfHealLoop(
        compiler=FakeCompiler(),
        llm=ScriptedLLMClient([]),
        max_round=0,
        sanitize=sanitize_harness,
    )

    report = loop.run(_draft(f"{bad_decl}\n// COMPILE_OK\n"))

    assert report.success
    assert bad_decl not in report.final_source


def test_loop_without_sanitize_keeps_old_behaviour():
    bad_decl = "void dlt_print_char_string(char *t);"
    loop = SelfHealLoop(compiler=FakeCompiler(), llm=ScriptedLLMClient([]), max_round=0)

    report = loop.run(_draft(f"{bad_decl}\n// COMPILE_OK\n"))

    assert bad_decl in report.final_source


def test_sanitize_failure_does_not_break_the_loop():
    def explode(source, draft):
        raise RuntimeError("후처리 실패")

    loop = SelfHealLoop(
        compiler=FakeCompiler(), llm=ScriptedLLMClient([]), max_round=0, sanitize=explode
    )

    assert loop.run(_draft("// COMPILE_OK\n")).success


# --------------------------------------------------------------------------- #
# 3. 실행 불가를 만드는 C 경고를 에러로
# --------------------------------------------------------------------------- #
def test_strict_warnings_are_applied_to_c(tmp_path):
    compiler = SubprocessCompiler(workdir=str(tmp_path))
    argv = compiler._build_argv(Path("h.c"), Path("h.o"), "c")

    for flag in STRICT_C_WARNINGS:
        assert flag in argv
    assert "-Werror=incompatible-pointer-types" in argv


def test_strict_warnings_are_skipped_for_cpp(tmp_path):
    """C++ 은 이미 에러이므로 미적용 (미지원 플래그 경고 방지)"""
    compiler = SubprocessCompiler(cc="clang++", workdir=str(tmp_path))
    argv = compiler._build_argv(Path("h.cpp"), Path("h.o"), "cpp")

    assert not any(f in argv for f in STRICT_C_WARNINGS)


def test_strict_warnings_can_be_disabled(tmp_path):
    compiler = SubprocessCompiler(strict_warnings=False, workdir=str(tmp_path))
    argv = compiler._build_argv(Path("h.c"), Path("h.o"), "c")

    assert not any(f in argv for f in STRICT_C_WARNINGS)


# --------------------------------------------------------------------------- #
# 4. 언어 판별
# --------------------------------------------------------------------------- #
def test_cpp_header_makes_the_group_cpp():
    assert infer_language(["dlt_common.c", "dlt_cpp_extension.hpp"]) == "cpp"


def test_pure_c_group_stays_c():
    assert infer_language(["dlt_common.c", "dlt_common.h"]) == "c"


def test_empty_group_defaults_to_c():
    assert infer_language([]) == "c"
