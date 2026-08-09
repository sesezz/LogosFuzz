"""ANA-05-03 통합 테스트: 오탐 확정 -> 원인분석 -> KB diff -> HITL 승인/거부 -> 재생성.

`crash_id <-> api_id <-> harness_id` 트레이서빌리티(감사 로그)까지 한 번에 검증한다.
"""
from __future__ import annotations

import unittest

from logosfuzz.analyze.audit import InMemoryAuditTrailStore
from logosfuzz.analyze.kb_feedback import InMemoryKBOverrideStore
from logosfuzz.analyze.models import FalsePositiveCrash, ProposalStatus, Verdict
from logosfuzz.analyze.pipeline import run_ana_05_03
from logosfuzz.control.hitl.gate import HITLManager
from logosfuzz.control.hitl.models import Decision, DecisionType
from logosfuzz.control.hitl.policy import HITLPolicy
from logosfuzz.control.hitl.store import InMemoryReviewStore
from logosfuzz.generate.compiler import FakeCompiler
from logosfuzz.generate.llm import ScriptedLLMClient
from src.knowledge_base import KnowledgeBase

ASAN_LOG = """\
==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdeadbeef
READ of size 4 at 0xdeadbeef thread T0
    #0 0x1111 in parse_header harness.c:42
"""

ROOT_CAUSE_SUMMARY = "하네스가 mock CAN 인터페이스를 초기화하지 않아 발생한 환경 오탐입니다."
OK_DRAFT = ("```c\nint LLVMFuzzerTestOneInput(const uint8_t*d,size_t n)"
            "{return 0;} // COMPILE_OK\n```")


def _kb() -> KnowledgeBase:
    return KnowledgeBase(documents=[{
        "api_id": 101, "function": "parse_header",
        "signature": "int parse_header(const char *buf, size_t len)",
        "file": "src/parse.c", "line": 42, "constraints": [], "text": "function parse_header",
    }])


def _crash() -> FalsePositiveCrash:
    return FalsePositiveCrash(
        crash_id="crash-1", api_id=101, harness_id="harness-1", run_id="run-1",
        asan_log=ASAN_LOG, verdict=Verdict.FALSE_POSITIVE, confidence=0.3,
    )


def _hitl(interactive: bool = False, prompt_fn=None) -> HITLManager:
    return HITLManager(
        store=InMemoryReviewStore(), policy=HITLPolicy.default(),
        interactive=interactive, reviewer="tester", prompt_fn=prompt_fn,
    )


class TestDeferredWhenNoHumanAvailable(unittest.TestCase):
    """비동기(interactive=False) 모드에서는 승인 없이 아무것도 반영되지 않는다."""

    def test_kb_and_regeneration_untouched_until_decided(self):
        kb = _kb()
        overrides = InMemoryKBOverrideStore()
        audit = InMemoryAuditTrailStore()
        hitl = _hitl(interactive=False)
        llm = ScriptedLLMClient([ROOT_CAUSE_SUMMARY])

        outcome = run_ana_05_03(
            _crash(), kb, llm, hitl, overrides, audit,
            compiler=FakeCompiler(), logic_group="lg_1", target_apis=["parse_header"],
        )

        self.assertEqual(outcome.decision_type, "defer")
        self.assertEqual(outcome.proposal.status, ProposalStatus.PENDING)
        self.assertIsNone(outcome.regeneration)
        self.assertEqual(overrides.current_text(101), "")  # 아직 KB 미반영
        self.assertEqual(len(hitl.pending()), 1)


class TestApprovedFlow(unittest.TestCase):
    """승인 -> KB 커밋 + 재색인 -> GEN-03-01(어댑터)/GEN-03-02 재생성까지 이어진다."""

    def test_full_approve_flow(self):
        kb = _kb()
        overrides = InMemoryKBOverrideStore()
        audit = InMemoryAuditTrailStore()
        approve = lambda item: Decision(type=DecisionType.APPROVE, reviewer="alice",
                                        comment="확인함")
        hitl = _hitl(interactive=True, prompt_fn=approve)
        llm = ScriptedLLMClient([ROOT_CAUSE_SUMMARY, OK_DRAFT])

        outcome = run_ana_05_03(
            _crash(), kb, llm, hitl, overrides, audit,
            compiler=FakeCompiler(), logic_group="lg_1", target_apis=["parse_header"],
        )

        self.assertEqual(outcome.decision_type, "approve")
        self.assertEqual(outcome.proposal.status, ProposalStatus.APPROVED)
        self.assertIn("환경 오탐", overrides.current_text(101))

        # KB가 실제로 재색인되어(오버라이드 포함) 반환됨
        self.assertIn("환경 오탐", outcome.kb.api(101)["text"])
        self.assertIn("updated_at", outcome.kb.api(101))

        # GEN-03-02 자가치유 루프까지 실행되어 컴파일 성공
        self.assertIsNotNone(outcome.regeneration)
        self.assertTrue(outcome.regeneration.compiled_ok)
        self.assertEqual(outcome.regeneration.outcome, "success")

        # crash_id <-> api_id <-> harness_id 트레이서빌리티
        trail = audit.for_crash("crash-1")
        kinds = {e["type"] for e in trail}
        self.assertEqual(kinds, {"proposal", "regeneration"})
        for entry in trail:
            self.assertEqual(entry["api_id"], 101)
            self.assertEqual(entry["harness_id"], "harness-1")

    def test_root_cause_prompt_reused_in_regeneration_prompt(self):
        """재생성 프롬프트에 오탐 근본원인 노트가 실제로 들어가는지(재발 방지 근거)."""
        kb = _kb()
        overrides = InMemoryKBOverrideStore()
        audit = InMemoryAuditTrailStore()
        approve = lambda item: Decision(type=DecisionType.APPROVE, reviewer="alice")
        hitl = _hitl(interactive=True, prompt_fn=approve)
        llm = ScriptedLLMClient([ROOT_CAUSE_SUMMARY, OK_DRAFT])

        run_ana_05_03(
            _crash(), kb, llm, hitl, overrides, audit,
            compiler=FakeCompiler(), logic_group="lg_1", target_apis=["parse_header"],
        )

        draft_prompt = llm.calls[1]  # 두 번째 호출 = 재생성 초안 요청
        self.assertIn("self-correction notes", draft_prompt)
        self.assertIn("환경 오탐", draft_prompt)


class TestRejectedFlow(unittest.TestCase):
    """거부 -> 아무것도 반영되지 않는다(승인 전 상태이므로 롤백=무동작)."""

    def test_kb_and_overrides_untouched_after_reject(self):
        kb = _kb()
        overrides = InMemoryKBOverrideStore()
        audit = InMemoryAuditTrailStore()
        reject = lambda item: Decision(type=DecisionType.REJECT, reviewer="alice",
                                       comment="실제로는 정탐입니다")
        hitl = _hitl(interactive=True, prompt_fn=reject)
        llm = ScriptedLLMClient([ROOT_CAUSE_SUMMARY])

        outcome = run_ana_05_03(
            _crash(), kb, llm, hitl, overrides, audit,
            compiler=FakeCompiler(), logic_group="lg_1", target_apis=["parse_header"],
        )

        self.assertEqual(outcome.decision_type, "reject")
        self.assertEqual(outcome.proposal.status, ProposalStatus.REJECTED)
        self.assertEqual(outcome.proposal.rejection_reason, "실제로는 정탐입니다")
        self.assertIsNone(outcome.regeneration)
        self.assertEqual(overrides.current_text(101), "")
        self.assertIs(outcome.kb, kb)  # 원본 KB 그대로(재색인 안 함)


if __name__ == "__main__":
    unittest.main()
