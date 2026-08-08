"""ANA-05-03 STEP 2(KB 변경 제안/diff + 오버라이드 저장소) 단위 테스트."""
from __future__ import annotations

import unittest

from logosfuzz.analyze.kb_feedback import (
    InMemoryKBOverrideStore,
    propose_kb_update,
    rebuild_with_overrides,
)
from logosfuzz.analyze.models import RootCauseAnalysis
from src.knowledge_base import KnowledgeBase


def _kb() -> KnowledgeBase:
    return KnowledgeBase(documents=[{
        "api_id": 101, "function": "parse_header", "signature": "int parse_header(...)",
        "file": "src/parse.c", "line": 42, "constraints": [], "text": "function parse_header",
    }])


def _analysis(crash_id: str = "crash-1", api_id: int = 101,
              summary: str = "buf 미초기화로 인한 환경 오탐") -> RootCauseAnalysis:
    return RootCauseAnalysis(crash_id=crash_id, api_id=api_id, summary=summary)


class TestKBOverrideStore(unittest.TestCase):
    def test_empty_store_has_no_current_text(self):
        store = InMemoryKBOverrideStore()
        self.assertEqual(store.current_text(101), "")
        self.assertIsNone(store.get(101))

    def test_upsert_sets_updated_at_and_is_retrievable(self):
        store = InMemoryKBOverrideStore()
        record = store.upsert(101, "note-1", "kbprop-1")
        self.assertEqual(record["text"], "note-1")
        self.assertIn("updated_at", record)
        self.assertEqual(store.current_text(101), "note-1")

    def test_upsert_overwrites_previous_value(self):
        store = InMemoryKBOverrideStore()
        store.upsert(101, "note-1", "kbprop-1")
        store.upsert(101, "note-1\nnote-2", "kbprop-2")
        self.assertEqual(store.current_text(101), "note-1\nnote-2")


class TestProposeKBUpdate(unittest.TestCase):
    def test_first_proposal_has_empty_before_text(self):
        store = InMemoryKBOverrideStore()
        proposal = propose_kb_update(_analysis(), harness_id="harness-1", overrides=store)

        self.assertEqual(proposal.before_text, "")
        self.assertIn("crash-1", proposal.after_text)
        self.assertIn("buf 미초기화", proposal.after_text)
        self.assertEqual(proposal.api_id, 101)
        self.assertEqual(proposal.harness_id, "harness-1")

    def test_second_proposal_appends_to_prior_approved_text(self):
        store = InMemoryKBOverrideStore()
        store.upsert(101, "- [crash-1] 이전 오탐 원인", "kbprop-1")

        proposal = propose_kb_update(
            _analysis(crash_id="crash-2", summary="새 오탐 원인"),
            harness_id="harness-1", overrides=store,
        )

        self.assertIn("이전 오탐 원인", proposal.before_text)
        self.assertIn("이전 오탐 원인", proposal.after_text)
        self.assertIn("새 오탐 원인", proposal.after_text)

    def test_embed_false_skips_embedding(self):
        store = InMemoryKBOverrideStore()
        proposal = propose_kb_update(_analysis(), harness_id="h1", overrides=store, embed=False)
        self.assertIsNone(proposal.embedding)


class TestRebuildWithOverrides(unittest.TestCase):
    def test_untouched_documents_pass_through(self):
        kb = _kb()
        store = InMemoryKBOverrideStore()
        rebuilt = rebuild_with_overrides(kb, store)
        self.assertEqual(rebuilt.api(101)["text"], "function parse_header")
        self.assertNotIn("updated_at", rebuilt.api(101))

    def test_override_merges_into_document_text_and_sets_updated_at(self):
        kb = _kb()
        store = InMemoryKBOverrideStore()
        store.upsert(101, "- [crash-1] 오탐 원인 요약", "kbprop-1")

        rebuilt = rebuild_with_overrides(kb, store)
        document = rebuilt.api(101)

        self.assertIn("오탐 원인 요약", document["text"])
        self.assertIn("updated_at", document)
        self.assertEqual(document["self_correction_notes"], "- [crash-1] 오탐 원인 요약")
        # 원본 kb는 그대로 유지되어야 REJECT 시 그냥 버리기만 하면 된다
        self.assertNotIn("updated_at", kb.api(101))


if __name__ == "__main__":
    unittest.main()
