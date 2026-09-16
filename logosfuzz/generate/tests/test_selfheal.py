"""GEN-03-02 자가 치유 루프 단위 테스트."""
from __future__ import annotations

import unittest

from logosfuzz.control.hitl import Checkpoint, HITLManager, HITLPolicy
from logosfuzz.control.hitl.store import InMemoryReviewStore
from logosfuzz.generate import (
    FakeCompiler,
    HarnessDraft,
    HealOutcome,
    ScriptedLLMClient,
    SelfHealLoop,
    parse_diagnostics,
    summarize,
)

GOOD = "int LLVMFuzzerTestOneInput(const uint8_t*d,size_t n){return 0;} // COMPILE_OK"
BAD = "int LLVMFuzzerTestOneInput(const uint8_t*d,size_t n){return 0;"


def _fix_response(src: str = GOOD) -> str:
    return f"수정.\n```c\n{src}\n```"


class TestDiagnosticsParser(unittest.TestCase):
    def test_parse_clang_style(self):
        log = "harness.c:42:5: error: expected ';' before '}' token\n" \
              "harness.c:10:1: warning: unused variable 'x'"
        diags = parse_diagnostics(log)
        self.assertEqual(len(diags), 2)
        errs = [d for d in diags if d.severity == "error"]
        self.assertEqual(errs[0].line, 42)
        self.assertIn("expected", errs[0].message)

    def test_fatal_error_normalized(self):
        diags = parse_diagnostics("x.c:1:1: fatal error: no.h: No such file")
        self.assertEqual(diags[0].severity, "error")


class TestSelfHealHappyPath(unittest.TestCase):
    def test_draft_compiles_immediately(self):
        loop = SelfHealLoop(FakeCompiler(), ScriptedLLMClient([]), max_round=3)
        rep = loop.run(HarnessDraft("g", GOOD))
        self.assertIs(rep.outcome, HealOutcome.SUCCESS)
        self.assertEqual(rep.rounds_used, 0)
        self.assertEqual(len(rep.rounds), 1)

    def test_heals_in_one_round(self):
        loop = SelfHealLoop(FakeCompiler(), ScriptedLLMClient([_fix_response()]),
                            max_round=3)
        rep = loop.run(HarnessDraft("g", BAD))
        self.assertIs(rep.outcome, HealOutcome.SUCCESS)
        self.assertEqual(rep.rounds_used, 1)
        self.assertIn("COMPILE_OK", rep.final_source)


class TestSelfHealFailure(unittest.TestCase):
    def test_exhausts_max_round(self):
        # LLM은 매번 코드를 바꾸지만 절대 고치지 못함(마커 없음, 매번 다른 내용)
        responses = [f"```c\n{BAD}\n// try {i}\n```" for i in range(5)]
        loop = SelfHealLoop(FakeCompiler(), ScriptedLLMClient(responses),
                            max_round=3, stop_on_stagnation=False)
        rep = loop.run(HarnessDraft("g", BAD))
        self.assertIs(rep.outcome, HealOutcome.EXHAUSTED)
        self.assertEqual(rep.rounds_used, 3)

    def test_stagnation_stops_early(self):
        # 매번 동일한(고쳐지지 않는) 코드 → 동일 에러 반복 → 조기 중단
        same = f"```c\n{BAD}\n// same\n```"
        llm = ScriptedLLMClient([same, same, same, same])
        loop = SelfHealLoop(FakeCompiler(), llm, max_round=5, stop_on_stagnation=True)
        rep = loop.run(HarnessDraft("g", BAD))
        self.assertIs(rep.outcome, HealOutcome.STAGNATED)
        # 첫 수정 후 동일 에러 감지로 5라운드 다 돌지 않음
        self.assertLess(rep.rounds_used, 5)

    def test_llm_no_change_is_stagnation(self):
        # LLM이 원본과 동일한 소스를 반환 → 변화 없음 → 정체
        llm = ScriptedLLMClient([f"```c\n{BAD}\n```"])
        loop = SelfHealLoop(FakeCompiler(), llm, max_round=3)
        rep = loop.run(HarnessDraft("g", BAD))
        self.assertIs(rep.outcome, HealOutcome.STAGNATED)


class TestHITLEscalation(unittest.TestCase):
    def _hitl(self):
        return HITLManager(store=InMemoryReviewStore(), policy=HITLPolicy.default())

    def test_failure_escalates_to_hitl(self):
        hitl = self._hitl()
        responses = [f"```c\n{BAD}\n// v{i}\n```" for i in range(5)]
        loop = SelfHealLoop(FakeCompiler(), ScriptedLLMClient(responses),
                            max_round=2, stop_on_stagnation=False, hitl=hitl)
        rep = loop.run(HarnessDraft("LG-x", BAD, project="p"))
        self.assertFalse(rep.success)
        self.assertIsNotNone(rep.hitl_item_id)
        pend = hitl.pending()
        self.assertEqual(len(pend), 1)
        self.assertIs(pend[0].checkpoint, Checkpoint.HARNESS_REVIEW)
        self.assertFalse(pend[0].payload["compile_ok"])

    def test_success_does_not_escalate(self):
        hitl = self._hitl()
        loop = SelfHealLoop(FakeCompiler(), ScriptedLLMClient([_fix_response()]),
                            max_round=3, hitl=hitl)
        rep = loop.run(HarnessDraft("LG-y", BAD, project="p"))
        self.assertTrue(rep.success)
        self.assertEqual(len(hitl.pending()), 0)


class TestSummarize(unittest.TestCase):
    def test_summary_counts(self):
        loop_ok = SelfHealLoop(FakeCompiler(), ScriptedLLMClient([_fix_response()]),
                               max_round=2)
        loop_bad = SelfHealLoop(FakeCompiler(),
                                ScriptedLLMClient([f"```c\n{BAD}\n// x\n```"] * 3),
                                max_round=1, stop_on_stagnation=False)
        r1 = loop_ok.run(HarnessDraft("a", BAD))
        r2 = loop_bad.run(HarnessDraft("b", BAD))
        s = summarize([r1, r2])
        self.assertEqual(s["total"], 2)
        self.assertEqual(s["success"], 1)
        self.assertEqual(s["failed"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
