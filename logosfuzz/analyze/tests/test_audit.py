"""ANA-05-03 STEP 5(감사 로그: crash_id <-> api_id <-> harness_id) 테스트."""
from __future__ import annotations

import unittest

from logosfuzz.analyze.audit import InMemoryAuditTrailStore
from logosfuzz.analyze.models import KBUpdateProposal, ProposalStatus, RegenerationRecord


def _proposal(crash_id="crash-1", api_id=101, harness_id="harness-1") -> KBUpdateProposal:
    return KBUpdateProposal.new(
        crash_id=crash_id, api_id=api_id, harness_id=harness_id,
        before_text="", after_text="- note",
    )


class TestAuditTrailStore(unittest.TestCase):
    def test_records_are_queryable_by_crash_api_and_harness(self):
        store = InMemoryAuditTrailStore()
        proposal = _proposal()
        store.record_proposal(proposal)
        regen = RegenerationRecord.new(proposal, "lg_1", "success", 0, True)
        store.record_regeneration(regen)

        by_crash = store.for_crash("crash-1")
        by_api = store.for_api(101)
        by_harness = store.for_harness("harness-1")

        self.assertEqual(len(by_crash), 2)  # proposal + regeneration
        self.assertEqual(len(by_api), 2)
        self.assertEqual(len(by_harness), 2)
        types = {e["type"] for e in by_crash}
        self.assertEqual(types, {"proposal", "regeneration"})

    def test_unrelated_crash_not_returned(self):
        store = InMemoryAuditTrailStore()
        store.record_proposal(_proposal(crash_id="crash-1"))
        store.record_proposal(_proposal(crash_id="crash-2"))

        self.assertEqual(len(store.for_crash("crash-1")), 1)
        self.assertEqual(len(store.for_crash("crash-2")), 1)

    def test_re_recording_same_proposal_appends_history_not_overwrites(self):
        store = InMemoryAuditTrailStore()
        proposal = _proposal()
        store.record_proposal(proposal)  # 생성 시점
        proposal.status = ProposalStatus.APPROVED
        store.record_proposal(proposal)  # 승인 시점

        entries = store.for_crash("crash-1")
        self.assertEqual(len(entries), 2)


if __name__ == "__main__":
    unittest.main()
