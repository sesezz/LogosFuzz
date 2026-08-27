"""ANA-05-03 STEP 3(HITL 승인/거부 처리) 단위 테스트."""
from __future__ import annotations

import unittest

from logosfuzz.analyze.commit import apply_kb_update, discard_kb_update
from logosfuzz.analyze.kb_feedback import InMemoryKBOverrideStore
from logosfuzz.analyze.models import KBUpdateProposal, ProposalStatus


def _proposal() -> KBUpdateProposal:
    return KBUpdateProposal.new(
        crash_id="crash-1", api_id=101, harness_id="harness-1",
        before_text="", after_text="- [crash-1] 오탐 원인",
    )


class TestApplyKBUpdate(unittest.TestCase):
    def test_writes_override_and_marks_approved(self):
        store = InMemoryKBOverrideStore()
        proposal = apply_kb_update(_proposal(), store, decided_by="alice")

        self.assertEqual(proposal.status, ProposalStatus.APPROVED)
        self.assertEqual(proposal.decided_by, "alice")
        self.assertIsNotNone(proposal.decided_at)
        self.assertEqual(store.current_text(101), "- [crash-1] 오탐 원인")


class TestDiscardKBUpdate(unittest.TestCase):
    def test_leaves_override_store_untouched(self):
        store = InMemoryKBOverrideStore()
        proposal = discard_kb_update(_proposal(), reason="사람이 오탐 아니라고 판단", decided_by="bob")

        self.assertEqual(proposal.status, ProposalStatus.REJECTED)
        self.assertEqual(proposal.rejection_reason, "사람이 오탐 아니라고 판단")
        self.assertEqual(proposal.decided_by, "bob")
        self.assertEqual(store.current_text(101), "")  # 아무것도 반영되지 않음(롤백 불필요)


if __name__ == "__main__":
    unittest.main()
