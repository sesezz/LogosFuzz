"""GEN-03 하네스 품질 게이트 회귀 테스트.

여기 있는 테스트는 전부 **실측에서 하네스를 못 쓰게 만들었던 것**을 고정한다.

- 2단계 검증에서 하네스 두 개가 첫 입력에 SEGV 로 죽었다. 원인은 `char **text`
  자리에 `char *` 를 넘긴 것인데, C 에서 이건 경고라 빌드가 "성공"했다.
- 4단계 검증에서 LLM 이 헤더를 include 하고도 대상 함수를 다시 선언해
  `conflicting types` 가 났다. 프롬프트로 금지해도 재발했고, **초안에만**
  후처리를 걸었더니 자가 치유 라운드에서 되살아났다.
- SCH 가 언어를 구분하지 않아 C++ 대상이 C 로 컴파일되면서 원인과 동떨어진
  에러가 떴다.
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
    """하네스가 만든 보조 함수 정의는 지우면 안 된다."""
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
# 2. 자가 치유 라운드에도 적용되는가 (초안에만 걸면 소용없다)
# --------------------------------------------------------------------------- #
def _draft(source: str) -> HarnessDraft:
    return HarnessDraft(
        logic_group="lg_print", source=source, target_apis=TARGETS, language="c"
    )


def test_sanitize_applies_to_repair_rounds():
    """LLM 이 수정본에 재선언을 다시 넣어도 걷어내야 한다."""
    bad_decl = "void dlt_print_hex_string(char *t, int n, const uint8_t *p, int s);"
    # 수정 응답에 재선언이 다시 들어있다. 후처리가 없으면 그대로 컴파일된다.
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
    """C++ 에서는 이미 에러라 붙이면 미지원 플래그 경고만 난다."""
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
