"""GEN-03-02 자가치유 루프의 에러 분류기 주입 테스트 (D 파트 3주차).

3주차 항목은 "로그 전문 투입 → 분류기 결과 프롬프트 주입(루프 구조 유지)"이다.
여기서 검증하는 것은 셋이다.

1. 분류 결과가 실제로 프롬프트에 실려 나가는가
2. 로그를 요약하지 않고 전문으로 넣는가
3. 루프 구조가 그대로인가 — 즉 분류기를 붙였다고 기존 라운드/정체/소진 동작이
   달라지지 않는가 (기존 동작은 `logosfuzz/generate/tests/test_selfheal.py` 가
   계속 지킨다)

빌드 로그는 합성하지 않고 1주차 코퍼스(`tests/fixtures/bazel_errors/`)를 쓴다.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from logosfuzz.generate.compiler import Compiler, FakeCompiler
from logosfuzz.generate.errors import BazelErrorKind, FixAction
from logosfuzz.generate.llm import RepairPromptBuilder, ScriptedLLMClient, truncate_middle
from logosfuzz.generate.models import CompileResult, HarnessDraft, HealOutcome
from logosfuzz.generate.selfheal import SelfHealLoop

CORPUS = Path(__file__).parent / "fixtures" / "bazel_errors"
SOURCE = "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { return 0; }"


def _log(case: str) -> str:
    return (CORPUS / f"{case}.txt").read_text(encoding="utf-8", errors="replace")


class StuckCompiler(Compiler):
    """언제나 같은 빌드 로그로 실패하는 컴파일러."""

    def __init__(self, log: str) -> None:
        self.log = log
        self.calls = 0

    def compile(self, draft, source=None):
        self.calls += 1
        return CompileResult(ok=False, returncode=1, stderr=self.log)


def _loop(case: str, **kwargs):
    llm = ScriptedLLMClient([f"```c\n// 시도 {i}\n{SOURCE}\n```" for i in range(5)])
    loop = SelfHealLoop(StuckCompiler(_log(case)), llm, max_round=3, **kwargs)
    return loop, llm


# --------------------------------------------------------------------------- #
# 1. 분류 결과가 프롬프트에 실리는가
# --------------------------------------------------------------------------- #
def test_prompt_carries_the_classification() -> None:
    loop, llm = _loop("link_undefined")
    loop.run(HarnessDraft("g", SOURCE))

    assert llm.calls, "LLM 이 한 번도 호출되지 않았다"
    prompt = llm.calls[0]
    assert "# 빌드 에러 분류 결과" in prompt
    assert BazelErrorKind.UNDEFINED_SYMBOL.value in prompt
    assert FixAction.RESOLVE_SYMBOL.value in prompt


def test_prompt_carries_the_full_log_not_a_digest() -> None:
    """'로그 전문 투입' — 파싱된 진단 몇 줄이 아니라 원문이 들어가야 한다.

    요약해서 넣던 시절엔 Bazel 로그의 핵심이 통째로 잘려 나갔다. Bazel 은 진단을
    로그 전반에 흩어 놓고 clang/링커 출력은 블록 안쪽에 두기 때문이다.
    """
    loop, llm = _loop("link_undefined")
    loop.run(HarnessDraft("g", SOURCE))

    prompt = llm.calls[0]
    assert "# 빌드 로그 전문" in prompt
    # 원문에만 있고 요약에는 없는 줄들
    assert "ld.lld: error: undefined symbol" in prompt
    assert "Use --verbose_failures" in prompt


def test_classification_is_recorded_on_every_failed_round() -> None:
    """라운드 기록에 진단이 남아야 리포팅과 HITL 검토가 로그를 다시 안 읽는다."""
    loop, _ = _loop("link_undefined")
    report = loop.run(HarnessDraft("g", SOURCE))

    assert report.outcome is HealOutcome.EXHAUSTED
    assert all(r.diagnosis == "undefined_symbol/resolve_symbol" for r in report.rounds)
    assert report.to_dict()["rounds"][0]["diagnosis"] == "undefined_symbol/resolve_symbol"


# --------------------------------------------------------------------------- #
# 2. 고칠 수 없는 결함에서 라운드를 낭비하지 않는가
# --------------------------------------------------------------------------- #
def test_structural_defect_escalates_without_calling_the_llm() -> None:
    """순환 의존은 타깃을 쪼개야 풀린다. LLM 을 부를 이유가 없다."""
    loop, llm = _loop("dep_cycle")
    report = loop.run(HarnessDraft("g", SOURCE))

    assert report.outcome is HealOutcome.ESCALATED
    assert report.rounds_used == 0
    assert llm.calls == []


@pytest.mark.parametrize(
    "case", ["not_visible", "no_such_target", "missing_dep", "no_load_statement"]
)
def test_build_file_defects_escalate_when_the_loop_cannot_edit_build(case: str) -> None:
    """BUILD 를 고쳐야 풀리는 결함은 소스를 다시 써도 해결되지 않는다.

    분류가 정확할수록 루프가 더 확신에 차서 헛도는 구간이라, 분류기를 붙이는
    순간 같이 막아야 한다.
    """
    loop, llm = _loop(case)
    report = loop.run(HarnessDraft("g", SOURCE))

    assert report.outcome is HealOutcome.ESCALATED
    assert llm.calls == []


def test_build_file_defects_are_retried_once_the_loop_can_edit_build() -> None:
    """B 파트의 BUILD 생성기가 붙으면 같은 결함을 재시도 대상으로 돌린다."""
    loop, llm = _loop("not_visible", can_edit_build=True)
    report = loop.run(HarnessDraft("g", SOURCE))

    assert report.outcome is HealOutcome.EXHAUSTED
    assert report.rounds_used == 3
    assert len(llm.calls) == 3


def test_escalation_can_be_switched_off() -> None:
    loop, llm = _loop("dep_cycle", stop_on_escalate=False, can_edit_build=True)
    report = loop.run(HarnessDraft("g", SOURCE))

    assert report.outcome is not HealOutcome.ESCALATED
    assert llm.calls


# --------------------------------------------------------------------------- #
# 3. 루프 구조 유지 / 견고성
# --------------------------------------------------------------------------- #
def test_unclassifiable_log_still_runs_the_normal_loop() -> None:
    """분류가 안 되는 로그(예: 순수 clang 출력)에서도 예전처럼 돌아야 한다.

    분류는 거들 뿐이다. 못 알아보면 힌트 없이 로그만 들고 재시도한다.
    """
    llm = ScriptedLLMClient([f"```c\n// {i}\n```" for i in range(5)])
    loop = SelfHealLoop(FakeCompiler(), llm, max_round=2, stop_on_stagnation=False)
    report = loop.run(HarnessDraft("g", "잘못된 소스"))

    assert report.outcome is HealOutcome.EXHAUSTED
    assert report.rounds_used == 2
    assert "# 빌드 에러 분류 결과" not in llm.calls[0]


def test_classifier_failure_does_not_break_the_loop() -> None:
    """분류기가 예외를 던져도 자가치유 자체가 멈추면 안 된다."""

    def boom(_log):
        raise RuntimeError("분류기 폭발")

    llm = ScriptedLLMClient([f"```c\n// {i}\n```" for i in range(5)])
    loop = SelfHealLoop(StuckCompiler(_log("link_undefined")), llm,
                        max_round=2, stop_on_stagnation=False, classifier=boom)
    report = loop.run(HarnessDraft("g", SOURCE))

    assert report.outcome is HealOutcome.EXHAUSTED
    assert report.rounds_used == 2


def test_successful_draft_is_not_classified() -> None:
    """컴파일이 통과하면 분류할 것이 없다(쓸데없는 일을 하지 않는다)."""
    good = f"{SOURCE} // COMPILE_OK"
    loop = SelfHealLoop(FakeCompiler(), ScriptedLLMClient([]), max_round=3)
    report = loop.run(HarnessDraft("g", good))

    assert report.outcome is HealOutcome.SUCCESS
    assert report.rounds[0].classification is None
    assert report.rounds[0].diagnosis == ""


# --------------------------------------------------------------------------- #
# HITL 에스컬레이션에 진단이 실리는가
# --------------------------------------------------------------------------- #
def test_hitl_payload_carries_the_diagnosis() -> None:
    """검토자가 로그를 처음부터 읽지 않고 원인을 바로 보게 한다."""
    from logosfuzz.control.hitl import HITLManager, HITLPolicy
    from logosfuzz.control.hitl.store import InMemoryReviewStore

    hitl = HITLManager(store=InMemoryReviewStore(), policy=HITLPolicy.default())
    loop, _ = _loop("not_visible", hitl=hitl)
    report = loop.run(HarnessDraft("LG-1", SOURCE, project="p"))

    assert report.outcome is HealOutcome.ESCALATED
    pending = hitl.pending()
    assert len(pending) == 1
    payload = pending[0].payload
    assert payload["diagnosis"] == BazelErrorKind.NOT_VISIBLE.value
    assert payload["fix_action"] == FixAction.EXPAND_VISIBILITY.value
    assert payload["fix_target"] == "build"
    assert payload["diagnosis_detail"]["label"] == "//score/internal:helper"
    assert "stop_reason" in payload


# --------------------------------------------------------------------------- #
# 로그 잘라내기
# --------------------------------------------------------------------------- #
def test_truncate_middle_keeps_head_and_tail() -> None:
    """꼬리만 남기면 Bazel 의 핵심 ERROR 가 사라진다."""
    text = "ERROR: 원인이 여기 있다\n" + ("x" * 5000) + "\nINFO: 끝"
    cut = truncate_middle(text, 500)

    assert len(cut) <= 500 + len("\n... (중략) ...\n")
    assert "ERROR: 원인이 여기 있다" in cut
    assert "INFO: 끝" in cut
    assert "(중략)" in cut


def test_truncate_middle_leaves_short_text_alone() -> None:
    assert truncate_middle("짧다", 100) == "짧다"


def test_prompt_builder_accepts_an_empty_hint() -> None:
    builder = RepairPromptBuilder()
    prompt = builder.build(
        HarnessDraft("g", SOURCE), SOURCE,
        CompileResult(ok=False, returncode=1, stderr="boom"), round_idx=1, hint="",
    )
    assert "# 빌드 에러 분류 결과" not in prompt
    assert "boom" in prompt
