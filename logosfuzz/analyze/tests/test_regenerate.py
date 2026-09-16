"""ANA-05-03 STEP 4(재생성 트리거: GEN-03-01 어댑터 -> GEN-03-02 자가치유) 테스트."""
from __future__ import annotations

import unittest

from logosfuzz.analyze.kb_feedback import InMemoryKBOverrideStore
from logosfuzz.analyze.models import KBUpdateProposal
from logosfuzz.analyze.regenerate import draft_via_llm, trigger_regeneration
from logosfuzz.generate.compiler import FakeCompiler
from logosfuzz.generate.llm import ScriptedLLMClient
from logosfuzz.knowledge.knowledge_base import KnowledgeBase

OK_SOURCE = ("```c\nint LLVMFuzzerTestOneInput(const uint8_t*d,size_t n)"
             "{return 0;} // COMPILE_OK\n```")
BAD_SOURCE = "```c\nint LLVMFuzzerTestOneInput(const uint8_t*d,size_t n){return 0;}\n```"


def _kb() -> KnowledgeBase:
    return KnowledgeBase(documents=[{
        "api_id": 101, "function": "parse_header",
        "signature": "int parse_header(const char *buf, size_t len)",
        "file": "src/parse.c", "line": 42, "constraints": [], "text": "function parse_header",
    }])


def _proposal() -> KBUpdateProposal:
    return KBUpdateProposal.new(
        crash_id="crash-1", api_id=101, harness_id="harness-1",
        before_text="", after_text="- [crash-1] buf 미초기화로 인한 환경 오탐",
    )


class TestDraftViaLLM(unittest.TestCase):
    def test_prompt_includes_kb_context_and_override_note(self):
        kb = _kb()
        overrides = InMemoryKBOverrideStore()
        overrides.upsert(101, "- [crash-1] buf 미초기화로 인한 환경 오탐", "kbprop-1")
        llm = ScriptedLLMClient([OK_SOURCE])

        draft = draft_via_llm(kb, overrides, llm, "lg_1", ["parse_header"])

        self.assertIn("COMPILE_OK", draft.source)
        self.assertIn("parse_header", llm.calls[0])
        self.assertIn("buf 미초기화로 인한 환경 오탐", llm.calls[0])
        self.assertIn("self-correction notes", llm.calls[0])

    def test_falls_back_to_stub_when_llm_returns_empty(self):
        # extract_code()는 코드펜스가 없으면 응답 전체를 소스로 간주한다(GEN-03-02와
        # 동일 컨벤션) - 폴백은 응답 자체가 비어 있을 때만 쓰인다.
        kb = _kb()
        overrides = InMemoryKBOverrideStore()
        llm = ScriptedLLMClient([""])
        draft = draft_via_llm(kb, overrides, llm, "lg_1", ["parse_header"])
        self.assertIn("LLVMFuzzerTestOneInput", draft.source)


class TestTriggerRegeneration(unittest.TestCase):
    def test_success_records_compiled_ok(self):
        kb = _kb()
        overrides = InMemoryKBOverrideStore()
        record, report = trigger_regeneration(
            _proposal(), kb, overrides, FakeCompiler(), ScriptedLLMClient([OK_SOURCE]),
            logic_group="lg_1", target_apis=["parse_header"], max_round=2,
        )
        self.assertTrue(record.compiled_ok)
        self.assertEqual(record.outcome, "success")
        self.assertEqual(record.crash_id, "crash-1")
        self.assertEqual(record.api_id, 101)
        self.assertEqual(record.harness_id, "harness-1")
        self.assertTrue(report.success)

    def test_never_fixed_records_failure_without_infinite_retry(self):
        kb = _kb()
        overrides = InMemoryKBOverrideStore()
        record, report = trigger_regeneration(
            _proposal(), kb, overrides, FakeCompiler(), ScriptedLLMClient([BAD_SOURCE]),
            logic_group="lg_1", target_apis=["parse_header"], max_round=2,
        )
        self.assertFalse(record.compiled_ok)
        self.assertIn(record.outcome, ("stagnated", "exhausted"))
        self.assertLessEqual(report.rounds_used, 2)  # --max-round 상한 준수


if __name__ == "__main__":
    unittest.main()
