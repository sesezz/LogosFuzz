"""CTR-06-02 HITL 골격 단위 테스트."""
from __future__ import annotations

import unittest

from logosfuzz.control.hitl import (
    Checkpoint,
    DecisionType,
    HITLManager,
    HITLPolicy,
    ReviewStatus,
)
from logosfuzz.control.hitl.store import InMemoryReviewStore


def _mgr(policy=None, interactive=False, prompt_fn=None):
    m = HITLManager(
        store=InMemoryReviewStore(),
        policy=policy or HITLPolicy.default(),
        interactive=interactive,
        reviewer="tester",
    )
    m.prompt_fn = prompt_fn
    return m


class TestPolicyRouting(unittest.TestCase):
    def test_auto_checkpoint_returns_approve_immediately(self):
        m = _mgr()
        d = m.request(Checkpoint.SCHEDULE_REVIEW, target="LG-1")
        self.assertEqual(d.type, DecisionType.APPROVE)
        self.assertEqual(m.stats()["pending"], 0)

    def test_manual_checkpoint_queues_when_async(self):
        m = _mgr()
        d = m.request(Checkpoint.CVE_DISCLOSURE, target="CVE-1")
        self.assertEqual(d.type, DecisionType.DEFER)
        self.assertEqual(len(m.pending()), 1)

    def test_conditional_compile_ok_auto_but_fail_queues(self):
        m = _mgr()
        d_ok = m.request(Checkpoint.HARNESS_REVIEW, target="LG-ok",
                         payload={"compile_ok": True})
        self.assertEqual(d_ok.type, DecisionType.APPROVE)

        d_fail = m.request(Checkpoint.HARNESS_REVIEW, target="LG-fail",
                           payload={"compile_ok": False})
        self.assertEqual(d_fail.type, DecisionType.DEFER)
        self.assertEqual(len(m.pending()), 1)

    def test_conditional_low_confidence_crash_queues(self):
        m = _mgr()
        hi = m.request(Checkpoint.CRASH_TRIAGE, target="c1", payload={"confidence": 0.99})
        lo = m.request(Checkpoint.CRASH_TRIAGE, target="c2", payload={"confidence": 0.4})
        self.assertEqual(hi.type, DecisionType.APPROVE)
        self.assertEqual(lo.type, DecisionType.DEFER)


class TestDecisionLifecycle(unittest.TestCase):
    def test_decide_moves_pending_to_terminal(self):
        m = _mgr()
        m.request(Checkpoint.CVE_DISCLOSURE, target="CVE-1")
        item = m.pending()[0]
        m.decide(item.id, DecisionType.APPROVE, comment="ok")
        self.assertEqual(m.get(item.id).status, ReviewStatus.APPROVED)
        self.assertEqual(len(m.pending()), 0)

    def test_decide_twice_raises(self):
        m = _mgr()
        m.request(Checkpoint.CVE_DISCLOSURE, target="CVE-1")
        item = m.pending()[0]
        m.decide(item.id, DecisionType.APPROVE)
        with self.assertRaises(ValueError):
            m.decide(item.id, DecisionType.REJECT)

    def test_edit_uses_edited_payload(self):
        m = _mgr()
        m.request(Checkpoint.CRASH_TRIAGE, target="c2", payload={"confidence": 0.4,
                                                                 "llm_verdict": "false_positive"})
        item = m.pending()[0]
        m.decide(item.id, DecisionType.EDIT,
                 edited_payload={"llm_verdict": "true_positive"})
        got = m.get(item.id)
        self.assertEqual(got.status, ReviewStatus.EDITED)
        self.assertEqual(got.effective_payload["llm_verdict"], "true_positive")

    def test_unknown_id_raises(self):
        m = _mgr()
        with self.assertRaises(KeyError):
            m.decide("nope", DecisionType.APPROVE)


class TestInteractiveMode(unittest.TestCase):
    def test_interactive_prompt_is_invoked(self):
        from logosfuzz.control.hitl.models import Decision

        calls = {"n": 0}

        def fake_prompt(item):
            calls["n"] += 1
            return Decision(type=DecisionType.APPROVE, reviewer="human")

        m = _mgr(interactive=True, prompt_fn=fake_prompt)
        d = m.request(Checkpoint.CVE_DISCLOSURE, target="CVE-1")
        self.assertEqual(calls["n"], 1)
        self.assertEqual(d.type, DecisionType.APPROVE)
        self.assertEqual(m.stats()["approved"], 1)


class TestFullyManualAuto(unittest.TestCase):
    def test_fully_auto_never_queues(self):
        m = _mgr(policy=HITLPolicy.fully_auto())
        m.request(Checkpoint.CVE_DISCLOSURE, target="CVE-1")
        self.assertEqual(len(m.pending()), 0)

    def test_fully_manual_always_queues(self):
        m = _mgr(policy=HITLPolicy.fully_manual())
        m.request(Checkpoint.SCHEDULE_REVIEW, target="LG-1")
        self.assertEqual(len(m.pending()), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
