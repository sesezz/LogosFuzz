"""ANA-05-03 STEP 1(오탐 원인 분석) 단위 테스트."""
from __future__ import annotations

import unittest

from ana_05_02_cve_reporting.schema import Verdict

from logosfuzz.analyze.models import CrashRecord
from logosfuzz.analyze.rootcause import analyze_false_positive
from logosfuzz.generate.llm import FnLLMClient, ScriptedLLMClient
from src.knowledge_base import KnowledgeBase

ASAN_LOG = """\
==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdeadbeef
READ of size 4 at 0xdeadbeef thread T0
    #0 0x1111 in parse_header harness.c:42
    #1 0x2222 in LLVMFuzzerTestOneInput harness.c:10
"""


def _kb_with_api(api_id: int = 101) -> KnowledgeBase:
    document = {
        "api_id": api_id,
        "function": "parse_header",
        "signature": "int parse_header(const char *buf, size_t len)",
        "file": "src/parse.c",
        "line": 42,
        "constraints": [
            {"kind": "doc", "target": "buf", "description": "buf must not be NULL",
             "confidence": 0.9, "expression": "", "occurrences": 1},
        ],
    }
    return KnowledgeBase(documents=[document])


def _crash(api_id: int = 101, verdict: Verdict = Verdict.FALSE_POSITIVE) -> CrashRecord:
    return CrashRecord(
        crash_id="crash-1",
        api_id=api_id,
        harness_id="harness-1",
        run_id="run-1",
        asan_log=ASAN_LOG,
        verdict=verdict,
        confidence=0.42,
    )


class TestCrashRecord(unittest.TestCase):
    def test_rejects_non_false_positive_verdict(self):
        with self.assertRaises(ValueError):
            _crash(verdict=Verdict.TRUE_POSITIVE)


class TestAnalyzeFalsePositive(unittest.TestCase):
    def test_returns_llm_summary_with_traceability_ids(self):
        crash = _crash()
        kb = _kb_with_api()
        llm = ScriptedLLMClient(["parse_header을 호출한 하네스가 buf를 초기화하지 않아 "
                                  "발생한 환경 오탐입니다."])

        analysis = analyze_false_positive(crash, kb, llm)

        self.assertEqual(analysis.crash_id, "crash-1")
        self.assertEqual(analysis.api_id, 101)
        self.assertIn("오탐", analysis.summary)
        self.assertEqual(analysis.rationale.strip(),
                          "==1234==ERROR: AddressSanitizer: heap-buffer-overflow "
                          "on address 0xdeadbeef")

    def test_prompt_includes_stack_trace_and_kb_context(self):
        crash = _crash()
        kb = _kb_with_api()
        seen = {}

        def fake_llm(prompt: str, system: str) -> str:
            seen["prompt"] = prompt
            seen["system"] = system
            return "요약."

        analyze_false_positive(crash, kb, FnLLMClient(fake_llm))

        self.assertIn("parse_header", seen["prompt"])
        self.assertIn("harness.c:42", seen["prompt"])
        self.assertIn("buf must not be NULL", seen["prompt"])
        self.assertIn("false positive", seen["system"])

    def test_missing_kb_entry_does_not_crash(self):
        crash = _crash(api_id=999)
        kb = _kb_with_api(api_id=101)  # 다른 api_id만 보유
        analysis = analyze_false_positive(crash, kb, ScriptedLLMClient(["요약."]))
        self.assertEqual(analysis.api_id, 999)


if __name__ == "__main__":
    unittest.main()
