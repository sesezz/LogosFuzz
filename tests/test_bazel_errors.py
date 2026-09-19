"""GEN-03-02 Bazel 에러 분류기 테스트 (D 파트 2주차).

분류기를 합성 로그가 아니라 **1주차에 실제로 빌드를 깨뜨려 모은 코퍼스**
(`tests/fixtures/bazel_errors/`)에 물려 검증한다. 합성 로그는 코퍼스가 담을 수
없는 경계 사례(자기 타깃 미정의가 *단독으로* 일어난 경우 등)에만 쓴다.

`docs/GEN-03-02-ERROR-CORPUS.md` 의 발견 A/B/C 는 각각 전용 테스트를 갖는다 —
분류기가 존재하는 이유가 그 셋이기 때문이다.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from logosfuzz.generate.bazel_errors import (
    classify,
    classify_block,
    load_statement_for,
    prompt_hint,
    split_blocks,
)
from logosfuzz.generate.errors import BazelErrorKind, BazelErrorReport, FixAction

CORPUS = Path(__file__).parent / "fixtures" / "bazel_errors"
HARNESS = "//harness:json_fuzzer"


def _log(case: str) -> str:
    return (CORPUS / f"{case}.txt").read_text(encoding="utf-8", errors="replace")


def _classify(case: str) -> BazelErrorReport:
    return classify(_log(case), requested_target=HARNESS)


# 코퍼스 케이스 -> (근본 원인 종류, 처방). 대응표는 문서 "1. Bazel 에러 대응표" 와 같다.
EXPECTED = [
    ("no_such_target", BazelErrorKind.NO_SUCH_TARGET, FixAction.FIX_DEP_LABEL),
    ("no_such_package", BazelErrorKind.NO_SUCH_PACKAGE, FixAction.FIX_DEP_LABEL),
    ("not_visible", BazelErrorKind.NOT_VISIBLE, FixAction.EXPAND_VISIBILITY),
    ("missing_dep", BazelErrorKind.MISSING_DEP, FixAction.ADD_DEPS),
    ("undeclared_inclusion", BazelErrorKind.MISSING_DEP, FixAction.ADD_DEPS),
    ("dep_cycle", BazelErrorKind.DEP_CYCLE, FixAction.ESCALATE),
    ("missing_srcs_file", BazelErrorKind.MISSING_SRCS_FILE, FixAction.ADD_SRCS_FILE),
    ("no_load_statement", BazelErrorKind.MISSING_LOAD, FixAction.ADD_LOAD),
    ("bad_syntax", BazelErrorKind.BUILD_SYNTAX_ERROR, FixAction.FIX_BUILD_SYNTAX),
    ("link_undefined", BazelErrorKind.UNDEFINED_SYMBOL, FixAction.RESOLVE_SYMBOL),
]


@pytest.mark.parametrize("case,kind,action", EXPECTED)
def test_corpus_case_is_classified(case: str, kind: BazelErrorKind,
                                   action: FixAction) -> None:
    report = _classify(case)
    assert report.primary is not None, f"{case}: 진단을 하나도 못 찾았다"
    assert report.primary.kind is kind
    assert report.primary.action is action


@pytest.mark.parametrize("case,kind,action", EXPECTED)
def test_each_case_yields_exactly_one_root_cause(case: str, kind: BazelErrorKind,
                                                 action: FixAction) -> None:
    """근본 원인은 케이스당 하나여야 한다.

    둘 이상이면 자가치유 프롬프트에 서로 다른 처방이 섞여 나가고, LLM 이 어느
    쪽을 고쳐야 할지 모른다. 실제로 Bazel 은 같은 결함을 두 번 보고하고(위치 없이
    한 번, `referenced by` 를 붙여 한 번) 뒤따르는 결과 줄도 ERROR 로 찍는다.
    """
    report = _classify(case)
    assert len(report.root_causes) == 1, (
        f"{case}: 근본 원인이 {len(report.root_causes)}개 "
        f"-> {[d.kind.value for d in report.root_causes]}"
    )
    assert report.actions == [action]


@pytest.mark.parametrize("case,_kind,_action", EXPECTED)
def test_no_case_falls_through_to_unknown(case: str, _kind, _action) -> None:
    """어떤 케이스도 UNKNOWN 을 근본 원인으로 내면 안 된다.

    UNKNOWN 은 처방이 RETRY_RAW(로그 보고 알아서 고쳐라)라, 이미 정확히 분류된
    결함이 있는데 같이 나가면 지시가 서로 모순된다.
    """
    report = _classify(case)
    assert BazelErrorKind.UNKNOWN not in [d.kind for d in report.root_causes]


def test_successful_build_yields_no_diagnostics() -> None:
    """대조군: 정상 빌드 로그에서는 아무것도 잡히면 안 된다(오탐 게이트)."""
    report = classify(_log("_baseline_ok"), requested_target=HARNESS)
    assert report.ok
    assert report.primary is None
    assert report.actions == []
    assert not report.needs_human


# --------------------------------------------------------------------------- #
# 발견 A — `no such target` 은 단독 분류 키로 쓸 수 없다
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("case", ["no_load_statement", "bad_syntax"])
def test_parse_failure_is_not_mistaken_for_a_deps_problem(case: str) -> None:
    """BUILD 파싱 실패가 deps 문제로 오분류되면 안 된다.

    두 케이스 모두 로그 끝에 deps 문제와 **똑같은** `no such target` 문장을 낸다.
    처방은 정반대(BUILD 수정 vs deps 수정)이므로 여기서 틀리면 자가치유가 엉뚱한
    수정을 반복하다 정체로 끝난다.
    """
    report = _classify(case)
    assert report.primary is not None
    assert report.primary.kind is not BazelErrorKind.NO_SUCH_TARGET
    assert report.actions not in ([FixAction.ADD_DEPS], [FixAction.FIX_DEP_LABEL])


@pytest.mark.parametrize("case", ["no_load_statement", "bad_syntax"])
def test_own_target_missing_is_demoted_to_symptom(case: str) -> None:
    """파싱 실패가 있으면 '자기 타깃이 없다'는 증상으로 내려가야 한다."""
    report = _classify(case)
    symptoms = report.of_kind(BazelErrorKind.TARGET_NOT_DEFINED)
    assert symptoms, f"{case}: target_not_defined 진단 자체가 없다"
    assert all(not d.root_cause for d in symptoms)
    assert symptoms[0].detail.get("label") == HARNESS


def test_own_target_missing_alone_is_a_root_cause() -> None:
    """반대 경우 — BUILD 는 파싱되는데 그 이름의 타깃만 없으면 그게 근본 원인이다.

    LLM 이 BUILD 의 `name` 을 다르게 써 넣으면 실제로 이 상태가 된다. 파싱 실패가
    없으므로 증상으로 내리면 안 되고, 처방은 '타깃을 정의하라' 다.
    """
    log = (
        "ERROR: Skipping '//harness:json_fuzzer': no such target "
        "'//harness:json_fuzzer': target 'json_fuzzer' not declared in package "
        "'harness' defined by /w/harness/BUILD.bazel\n"
        "ERROR: command succeeded, but there were errors parsing the target pattern\n"
        "ERROR: Build did NOT complete successfully\n"
    )
    report = classify(log, requested_target=HARNESS)
    assert report.primary is not None
    assert report.primary.kind is BazelErrorKind.TARGET_NOT_DEFINED
    assert report.primary.root_cause
    assert report.primary.action is FixAction.DEFINE_TARGET


def test_dependency_target_is_not_confused_with_own_target() -> None:
    """없는 타깃이 의존 대상이면 deps 문제로 남아야 한다."""
    report = _classify("no_such_target")
    assert report.primary is not None
    assert report.primary.kind is BazelErrorKind.NO_SUCH_TARGET
    assert report.primary.detail["label"] == "//score/json:jsonn"
    # Bazel 이 제안한 이름을 처방에 실어 보낸다.
    assert report.primary.detail.get("suggestion") == "json"
    assert report.primary.detail.get("referenced_by") == HARNESS


def test_requested_target_hint_identifies_own_target_without_skipping_line() -> None:
    """`Skipping` 줄이 없어도 requested_target 을 주면 자기 타깃으로 판별한다."""
    log = (
        "ERROR: /w/harness/BUILD.bazel:3:10: no such target '//harness:json_fuzzer': "
        "target 'json_fuzzer' not declared in package 'harness'\n"
    )
    assert classify(log, requested_target=HARNESS).primary.kind is (
        BazelErrorKind.TARGET_NOT_DEFINED
    )
    # 힌트가 없으면 의존 대상으로 본다(보수적 기본값).
    assert classify(log).primary.kind is BazelErrorKind.NO_SUCH_TARGET


# --------------------------------------------------------------------------- #
# 발견 B — deps 누락의 입구는 clang 의 `file not found` 다
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "case,header",
    [
        ("missing_dep", "score/json/json.h"),
        ("undeclared_inclusion", "score/internal/helper.h"),
    ],
)
def test_missing_dep_extracts_header_path(case: str, header: str) -> None:
    """deps 를 찾으려면 헤더 경로가 필요하다. A 파트 bazel_query 의 입력이 된다."""
    report = _classify(case)
    assert report.primary.kind is BazelErrorKind.MISSING_DEP
    assert report.primary.detail["header"] == header


def test_missing_dep_reports_the_clang_location_not_the_bazel_one() -> None:
    """위치는 include 가 있는 소스 줄이어야 고칠 지점을 가리킨다."""
    primary = _classify("missing_dep").primary
    assert primary.file.endswith("json_fuzzer.cc")
    assert primary.line > 0


def test_missing_dep_does_not_look_like_a_missing_target() -> None:
    """설계표의 `no such target -> deps 추가` 가 어긋나는 지점의 회귀 가드."""
    assert "no such target" not in _log("missing_dep")


# --------------------------------------------------------------------------- #
# 발견 C — visibility 문구는 ERROR: 줄에 없다(블록 단위 파싱)
# --------------------------------------------------------------------------- #
def test_visibility_error_extracts_both_labels_across_lines() -> None:
    report = _classify("not_visible")
    primary = report.primary
    assert primary.kind is BazelErrorKind.NOT_VISIBLE
    assert primary.detail["label"] == "//score/internal:helper"
    assert primary.detail["from"] == HARNESS


def test_visibility_phrase_really_spans_lines_in_the_corpus() -> None:
    """줄 단위 파싱으로는 못 잡는다는 전제 자체를 지킨다.

    이 전제가 깨지면(=Bazel 이 한 줄로 내보내기 시작하면) 블록 파싱은 여전히
    동작하지만, 문서의 발견 C 와 이 테스트의 의도는 다시 봐야 한다.
    """
    lines = _log("not_visible").splitlines()
    hits = [ln for ln in lines if "is not visible from" in ln]
    assert hits and not any(ln.startswith("ERROR:") for ln in hits)


def test_classify_block_handles_a_visibility_block_directly() -> None:
    block = (
        "ERROR: /w/harness/BUILD.bazel:3:10: in cc_binary rule //harness:json_fuzzer: "
        "Visibility error:\n"
        "target '//score/internal:helper' is not visible from\n"
        "target '//harness:json_fuzzer'\n"
    )
    diag = classify_block(block)
    assert diag.kind is BazelErrorKind.NOT_VISIBLE
    assert diag.action is FixAction.EXPAND_VISIBILITY


# --------------------------------------------------------------------------- #
# 그 밖의 계약
# --------------------------------------------------------------------------- #
def test_dep_cycle_escalates_instead_of_retrying() -> None:
    """순환 의존은 LLM 재시도로 못 고친다. 라운드를 낭비하지 말고 사람에게 올린다."""
    report = _classify("dep_cycle")
    assert report.primary.action is FixAction.ESCALATE
    assert report.needs_human


@pytest.mark.parametrize("case,_k,_a", EXPECTED)
def test_repairable_cases_do_not_ask_for_a_human(case: str, _k, _a) -> None:
    if case == "dep_cycle":
        pytest.skip("순환 의존은 의도적으로 에스컬레이션한다")
    assert not _classify(case).needs_human


def test_missing_load_suggests_the_exact_load_statement() -> None:
    """처방이 '뭔가 추가하라'가 아니라 붙여넣을 수 있는 한 줄이어야 쓸모가 있다."""
    primary = _classify("no_load_statement").primary
    assert primary.detail["rule"] == "cc_binary"
    assert primary.detail["load"] == 'load("@rules_cc//cc:defs.bzl", "cc_binary")'


@pytest.mark.parametrize(
    "rule,expected",
    [
        ("cc_binary", 'load("@rules_cc//cc:defs.bzl", "cc_binary")'),
        ("cc_library", 'load("@rules_cc//cc:defs.bzl", "cc_library")'),
        ("cc_fuzz_test", 'load("@rules_fuzzing//fuzzing:cc_defs.bzl", "cc_fuzz_test")'),
        ("py_binary", ""),
    ],
)
def test_load_statement_mapping(rule: str, expected: str) -> None:
    assert load_statement_for(rule) == expected


def test_undefined_symbol_is_captured_with_its_demangled_name() -> None:
    primary = _classify("link_undefined").primary
    assert "ParseStrict" in primary.detail["symbol"]


def test_missing_srcs_file_names_the_missing_label() -> None:
    primary = _classify("missing_srcs_file").primary
    assert primary.detail["label"] == "//harness:json_fuzzer_extra.cc"


# --------------------------------------------------------------------------- #
# 블록 분할 / 잡음 제거
# --------------------------------------------------------------------------- #
def test_split_blocks_keeps_continuation_lines_with_their_diagnostic() -> None:
    log = (
        "INFO: Analyzed target //harness:json_fuzzer.\n"
        "ERROR: /w/harness/BUILD.bazel:3:10: Visibility error:\n"
        "target '//a:b' is not visible from\n"
        "target '//harness:json_fuzzer'\n"
        "ERROR: Build did NOT complete successfully\n"
    )
    blocks = split_blocks(log)
    assert len(blocks) == 3
    assert "is not visible from" in blocks[1]


def test_split_blocks_on_empty_log() -> None:
    assert split_blocks("") == []
    assert split_blocks("아무 마커도 없는 줄\n") == []


def test_build_summary_lines_are_not_diagnostics() -> None:
    for line in (
        "ERROR: Build did NOT complete successfully\n",
        "ERROR: command succeeded, but there were loading phase errors\n",
    ):
        assert classify_block(line) is None


def test_consequence_lines_are_dropped_rather_than_marked_unknown() -> None:
    """앞선 에러의 결과 줄은 버린다.

    남겨 두면 UNKNOWN 근본 원인이 되어 처방에 RETRY_RAW 가 섞인다.
    """
    for line in (
        "ERROR: /w/harness/BUILD.bazel:3:10: Analysis of target "
        "'//harness:json_fuzzer' (config: abc123) failed\n",
        "ERROR: /w/harness/BUILD.bazel:3:10: Compiling x.cc failed: "
        "1 input file(s) do not exist\n",
    ):
        assert classify_block(line) is None


def test_unrecognised_error_still_produces_a_retryable_diagnostic() -> None:
    """모르는 에러라고 조용히 삼키면 자가치유가 실패 원인을 못 본다."""
    report = classify("ERROR: /w/BUILD.bazel:1:1: 처음 보는 실패 모양\n")
    assert report.primary.kind is BazelErrorKind.UNKNOWN
    assert report.primary.action is FixAction.RETRY_RAW


def test_duplicate_reports_of_one_defect_collapse() -> None:
    """Bazel 은 같은 deps 문제를 두 번 찍는다. 한 건으로 묶여야 한다."""
    report = _classify("no_such_target")
    labels = [d.detail.get("label") for d in report.diagnostics]
    assert labels.count("//score/json:jsonn") == 1


# --------------------------------------------------------------------------- #
# 프롬프트 힌트 (3주차 selfheal.py 가 쓴다)
# --------------------------------------------------------------------------- #
def test_prompt_hint_is_empty_for_a_successful_build() -> None:
    assert prompt_hint(classify(_log("_baseline_ok"))) == ""


@pytest.mark.parametrize("case,kind,action", EXPECTED)
def test_prompt_hint_states_kind_action_and_raw_text(case: str, kind, action) -> None:
    hint = prompt_hint(_classify(case))
    assert kind.value in hint
    assert action.value in hint
    assert "# 해당 에러 원문" in hint


def test_prompt_hint_warns_not_to_fix_the_symptom() -> None:
    """증상에 맞춰 고치지 말라는 경고가 프롬프트에 들어가야 발견 A 가 전달된다."""
    hint = prompt_hint(_classify("no_load_statement"))
    assert "증상" in hint
    assert BazelErrorKind.TARGET_NOT_DEFINED.value in hint
    assert "load()" in hint


def test_prompt_hint_truncates_long_blocks() -> None:
    hint = prompt_hint(_classify("missing_dep"), max_block_chars=50)
    assert len(hint) < 2000


@pytest.mark.parametrize("case,_k,_a", EXPECTED)
def test_runtime_text_is_printable_on_a_windows_console(case: str, _k, _a) -> None:
    """팀 다수가 Windows 라 기본 콘솔이 cp949 다.

    요약·지시 문자열에 cp949 로 못 쓰는 문자(em dash 등)가 들어가면 자가치유가
    진행 상황을 출력하다 UnicodeEncodeError 로 죽는다. 한글 자체는 문제없다.
    """
    report = _classify(case)
    prompt_hint(report).encode("cp949")
    for diag in report.diagnostics:
        diag.summary.encode("cp949")


# --------------------------------------------------------------------------- #
# 직렬화
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("case,kind,action", EXPECTED)
def test_report_to_dict_is_json_serialisable(case: str, kind, action) -> None:
    import json

    data = _classify(case).to_dict()
    json.dumps(data, ensure_ascii=False)
    assert data["primary"]["kind"] == kind.value
    assert data["actions"] == [action.value]
    assert data["ok"] is False
