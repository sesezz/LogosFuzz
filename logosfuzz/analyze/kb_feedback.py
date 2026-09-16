"""
ANA-05-03 STEP 2: KB 변경 제안(diff) 생성 및 오버라이드 저장소
================================================================

`API_METADATA.updated_at`을 갱신하는 실제 반영은 승인 이후(`commit.py`)에만
일어난다. 이 모듈은 "무엇을 얼마나 바꿀 제안인지" diff를 만들고 pending
상태로 넘기는 역할까지만 한다 - HITL 승인 게이트(CTR-06-02)가 막고 있는
동안에는 `KnowledgeBase`도 `KBOverrideStore`도 건드리지 않는다.

`logosfuzz/knowledge/knowledge_base.py`(EXT-01)의 document 스키마에는 `updated_at` 필드가
없고 그 파일은 변경하지 않기로 했으므로(설계 승인 사항), api_id별 오버라이드
텍스트와 갱신 시각을 별도 JSON 사이드 스토어에 보관한다.

임베딩은 `logosfuzz/knowledge/rag_index.py`의 `DenseIndex`와 동일하게 `sentence-transformers`가
설치되어 있을 때만 계산한다(선택적 의존성 - 없으면 embedding=None으로 스텁).

"Vector DB에 upsert"의 알려진 제약: `BM25Index`/`DenseIndex`는 append-only라
문서 하나만 in-place로 갱신할 방법이 이 저장소에 없다. `rebuild_with_overrides()`는
그 대신 오버라이드가 반영된 문서 전체로 새 `KnowledgeBase`(=새 인덱스)를 매번
다시 만든다 - 문서 수가 작을 때는 충분하지만, 대규모 환경에서는 증분 upsert가
가능한 실제 벡터 DB(Chroma/FAISS 등)로 교체가 필요하다(후속 TODO).
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import List, Optional

from logosfuzz.knowledge.knowledge_base import KnowledgeBase

from .models import KBUpdateProposal, RootCauseAnalysis, now_iso

_MODEL = None  # sentence-transformers 지연 로드 싱글턴(여러 호출 간 재사용)


def embed_text(text: str) -> Optional[List[float]]:
    """가능하면 텍스트 임베딩을 반환하고, 아니면 None(BM25-only 폴백)."""
    global _MODEL
    try:
        from sentence_transformers import SentenceTransformer
    except Exception:
        return None
    if _MODEL is None:
        _MODEL = SentenceTransformer("all-MiniLM-L6-v2")
    vector = _MODEL.encode([text], normalize_embeddings=True)[0]
    return [float(x) for x in vector]


class KBOverrideStore:
    """api_id -> 승인된 역피드백 오버라이드 텍스트/갱신시각.

    `logosfuzz/knowledge/knowledge_base.py`(EXT-01)의 KB JSON 파일과는 별개의 사이드 스토어다.
    ERD의 `API_METADATA.updated_at`에 해당하는 값은 여기서만 갱신된다.
    `logosfuzz.control.hitl.store.JsonReviewStore`와 동일하게 스레드 락 +
    원자적 쓰기(tmp -> replace) 패턴을 따른다.
    """

    DEFAULT_PATH = Path(".logosfuzz") / "analyze" / "kb_overrides.json"

    def __init__(self, path: Optional[Path | str] = None) -> None:
        self.path = Path(path) if path else self.DEFAULT_PATH
        self._lock = threading.RLock()
        self._data: dict = {}
        self._loaded = False

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        if self.path.exists():
            self._data = json.loads(self.path.read_text(encoding="utf-8") or "{}")
        self._loaded = True

    def _flush(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(self._data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    def get(self, api_id: int) -> Optional[dict]:
        with self._lock:
            self._ensure_loaded()
            return self._data.get(str(api_id))

    def current_text(self, api_id: int) -> str:
        record = self.get(api_id)
        return record["text"] if record else ""

    def upsert(self, api_id: int, text: str, proposal_id: str,
               embedding: Optional[List[float]] = None) -> dict:
        """승인된 텍스트를 반영하고 `updated_at`을 갱신한다(ERD 필수 필드)."""
        with self._lock:
            self._ensure_loaded()
            record = {
                "api_id": api_id,
                "text": text,
                "embedding": embedding,
                "updated_at": now_iso(),
                "source_proposal_id": proposal_id,
            }
            self._data[str(api_id)] = record
            self._flush()
            return record


class InMemoryKBOverrideStore(KBOverrideStore):
    """테스트/데모용 - 디스크에 쓰지 않는다."""

    def __init__(self) -> None:
        super().__init__(path=None)
        self._loaded = True

    def _flush(self) -> None:  # no-op
        pass


def propose_kb_update(
    analysis: RootCauseAnalysis,
    harness_id: str,
    overrides: KBOverrideStore,
    embed: bool = True,
) -> KBUpdateProposal:
    """근본 원인 분석 결과를 KB 변경 제안(diff)으로 만든다.

    같은 api_id에 이전에 승인된 오버라이드가 있으면 유지하고 새 원인 설명을
    `crash_id`가 붙은 항목으로 덧붙인다 - 한 API가 여러 번 오탐을 겪을 때
    이전 근거를 덮어쓰지 않아야 감사(audit)로 전부 역추적할 수 있다.
    """
    before_text = overrides.current_text(analysis.api_id)
    note = f"- [{analysis.crash_id}] {analysis.summary}"
    after_text = f"{before_text}\n{note}".strip() if before_text else note

    embedding = embed_text(after_text) if embed else None

    return KBUpdateProposal.new(
        crash_id=analysis.crash_id,
        api_id=analysis.api_id,
        harness_id=harness_id,
        before_text=before_text,
        after_text=after_text,
        embedding=embedding,
    )


def rebuild_with_overrides(kb: KnowledgeBase, overrides: KBOverrideStore) -> KnowledgeBase:
    """오버라이드가 반영된 문서들로 KB 검색 인덱스를 새로 만든다.

    `kb.documents`를 직접 변형하지 않는다(원본 KB는 그대로 두고 새 인스턴스를
    반환) - 승인 전 상태를 계속 참조할 수 있어야 HITL REJECT 시 그냥
    버리기만 하면 되는 구조가 유지된다.
    """
    documents: List[dict] = []
    for document in kb.documents:
        record = overrides.get(document["api_id"])
        if record is None:
            documents.append(document)
            continue
        updated = dict(document)
        updated["updated_at"] = record["updated_at"]
        updated["self_correction_notes"] = record["text"]
        updated["text"] = f"{document.get('text', '')}\nself_correction {record['text']}"
        documents.append(updated)
    return KnowledgeBase(
        documents=documents, files=kb.files,
        use_dense=getattr(kb, "_dense_enabled", False),
    )
