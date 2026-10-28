"""GENERIC-C 링커 오류 분류 테스트

정답지는 clang 18 / GNU ld 2.42 / lld 18 로 실제 링크를 깨뜨려 받은 로그
(``tests/fixtures/linker_errors``). ``undefined_*`` 두 개는 ``examples/embedded`` 를
HAL 정의 없이 링크한 결과
"""
from __future__ import annotations

from pathlib import Path

from logosfuzz.generate import bazel_errors
from logosfuzz.generate.errors import (
    BazelErrorKind,
    FixAction,
    classify_toolchain_log,
    undefined_symbols,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "linker_errors"


def _log(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_gnu_ld_undefined_reference():
    report = classify_toolchain_log(_log("undefined_reference_gnu_ld.txt"))
    assert undefined_symbols(report) == ["HAL_GetTick", "HAL_UART_Transmit"]
    primary = report.primary
    assert primary.kind is BazelErrorKind.UNDEFINED_SYMBOL
    assert primary.action is FixAction.RESOLVE_SYMBOL
    assert primary.line == 49 and primary.file.endswith("proto_parser.c")
    assert "proto_parse" in primary.detail["referenced_by"]
    # "clang: error: linker command failed" 는 결과일 뿐이라 진단으로 미집계
    assert len(report.diagnostics) == 2
    assert not report.needs_human


def test_lld_undefined_symbol():
    report = classify_toolchain_log(_log("undefined_symbol_lld.txt"))
    assert undefined_symbols(report) == ["HAL_GetTick", "HAL_UART_Transmit"]
    assert "proto_parser.c:49" in report.primary.detail["referenced_by"]


def test_multiple_definition():
    report = classify_toolchain_log(_log("multiple_definition.txt"))
    primary = report.primary
    assert primary.kind is BazelErrorKind.MULTIPLE_DEFINITION
    assert primary.action is FixAction.REMOVE_DUPLICATE_DEFINITION
    assert primary.detail == {"symbol": "HAL_GetTick"}
    assert bazel_errors.fix_target_artifact(primary.action) == "source"


def test_cannot_find_library_escalates():
    report = classify_toolchain_log(_log("cannot_find_lib.txt"))
    primary = report.primary
    assert primary.kind is BazelErrorKind.MISSING_LIBRARY
    assert primary.detail == {"library": "hal_vendor"}
    assert report.needs_human


def test_lld_duplicate_and_missing_library_wording():
    log = ("ld.lld: error: duplicate symbol: foo\n"
           ">>> defined at a.c:1\n"
           "ld.lld: error: unable to find library -lbar\n")
    kinds = {d.kind: d.detail for d in classify_toolchain_log(log).diagnostics}
    assert kinds[BazelErrorKind.MULTIPLE_DEFINITION] == {"symbol": "foo"}
    assert kinds[BazelErrorKind.MISSING_LIBRARY] == {"library": "bar"}


def test_missing_library_outranks_undefined_symbol():
    log = _log("undefined_reference_gnu_ld.txt") + "\n" + _log("cannot_find_lib.txt")
    assert classify_toolchain_log(log).primary.kind is BazelErrorKind.MISSING_LIBRARY


def test_compile_errors_are_retry_raw():
    log = ("h.c:3:10: fatal error: 'hal_extra.h' file not found\n"
           "h.c:9:5: error: use of undeclared identifier 'x'\n")
    report = classify_toolchain_log(log)
    kinds = [(d.kind, d.action) for d in report.diagnostics]
    assert kinds == [(BazelErrorKind.MISSING_DEP, FixAction.RETRY_RAW),
                     (BazelErrorKind.UNKNOWN, FixAction.RETRY_RAW)]
    assert report.diagnostics[0].detail == {"header": "hal_extra.h"}
    # CMake 경로에는 BUILD 가 없으므로 BUILD 수정 처방으로 차단하지 않음
    assert not bazel_errors.needs_build_file_edit(report)


def test_empty_log_is_ok():
    assert classify_toolchain_log("").ok


def test_bazel_classifier_handles_link_cases_in_error_blocks():
    log = ("ERROR: /ws/harness/BUILD:3:13: Linking harness/x_fuzzer failed: (Exit 1)\n"
           + _log("multiple_definition.txt")
           + "ERROR: /ws/harness/BUILD:9:13: Linking harness/y_fuzzer failed: (Exit 1)\n"
           + _log("cannot_find_lib.txt"))
    report = bazel_errors.classify(log)
    kinds = [d.kind for d in report.diagnostics]
    assert BazelErrorKind.MULTIPLE_DEFINITION in kinds
    assert BazelErrorKind.MISSING_LIBRARY in kinds
    hint = bazel_errors.prompt_hint(classify_toolchain_log(_log("multiple_definition.txt")))
    assert "두 번 정의" in hint
