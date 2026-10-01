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

역피드백 단위 = Bazel 타깃 (4주차)
---------------------------------
3주차부터 Logic Group 경계가 Bazel 타깃이다(`logic_groups.py`). 하네스도 타깃
하나를 대상으로 생성되고, 같은 타깃의 API들은 같은 하네스·같은 상태 객체를
공유한다. 그래서 오탐 원인("이 타깃의 Reader는 Init 없이 쓰면 안 된다",
"이 타깃의 Result는 has_value를 확인해야 한다")은 크래시가 난 API 하나가
아니라 **그 타깃의 다음 하네스 전체**가 알아야 하는 사실이다. API 단위로만
남기면 같은 타깃의 다른 API를 겨냥한 재생성 하네스가 같은 실수를 반복한다.

그래서 제안·오버라이드·재생성을 모두 타깃 단위로 맞춘다.

- 제안의 before/after는 타깃 노트다. 같은 타깃에서 나온 오탐은 API가 달라도
  한 노트에 누적된다(각 줄에 crash_id와 API 이름을 남겨 역추적한다).
- `rebuild_with_overrides()`는 타깃 노트를 그 타깃 소속 **모든** API 문서에
  싣는다.
- 빌드 정보가 없는 구 KB는 타깃을 알 수 없으므로 예전처럼 API 단위로 남긴다.
  두 형식이 한 스토어에 공존한다.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import List, Optional

from logosfuzz.knowledge.knowledge_base import KnowledgeBase

from .models import KBUpdateProposal, RootCauseAnalysis, now_iso

STORE_VERSION = 2

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
    """승인된 역피드백 오버라이드 텍스트/갱신시각 - Bazel 타깃 단위 + API 단위.

    `logosfuzz/knowledge/knowledge_base.py`(EXT-01)의 KB JSON 파일과는 별개의 사이드 스토어다.
    ERD의 `API_METADATA.updated_at`에 해당하는 값은 여기서만 갱신된다.
    `logosfuzz.control.hitl.store.JsonReviewStore`와 동일하게 스레드 락 +
    원자적 쓰기(tmp -> replace) 패턴을 따른다.

    저장 형식(v2)::

        {"version": 2,
         "targets": {"//score/json:json": {"build_target", "text", "api_ids", ...}},
         "apis":    {"101": {"api_id", "text", ...}}}

    3주차까지의 v1 형식(``{"101": {...}}`` 평면 dict)은 읽을 때 ``apis``로 옮긴다.
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
        raw: dict = {}
        if self.path.exists():
            raw = json.loads(self.path.read_text(encoding="utf-8") or "{}")
        self._data = self._migrate(raw)
        self._loaded = True

    @staticmethod
    def _migrate(raw: dict) -> dict:
        if raw.get("version") == STORE_VERSION:
            return {"version": STORE_VERSION, "targets": dict(raw.get("targets") or {}),
                    "apis": dict(raw.get("apis") or {})}
        # v1: api_id 문자열 키의 평면 dict
        return {"version": STORE_VERSION, "targets": {}, "apis": dict(raw)}

    @property
    def _apis(self) -> dict:
        self._ensure_loaded()
        return self._data.setdefault("apis", {})

    @property
    def _targets(self) -> dict:
        self._ensure_loaded()
        return self._data.setdefault("targets", {})

    def _flush(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(self._data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    def get(self, api_id: int) -> Optional[dict]:
        with self._lock:
            return self._apis.get(str(api_id))

    def current_text(self, api_id: int) -> str:
        record = self.get(api_id)
        return record["text"] if record else ""

    def upsert(self, api_id: int, text: str, proposal_id: str,
               embedding: Optional[List[float]] = None) -> dict:
        """승인된 텍스트를 반영하고 `updated_at`을 갱신한다(ERD 필수 필드)."""
        with self._lock:
            record = {
                "api_id": api_id,
                "text": text,
                "embedding": embedding,
                "updated_at": now_iso(),
                "source_proposal_id": proposal_id,
            }
            self._apis[str(api_id)] = record
            self._flush()
            return record

    # -- Bazel 타깃 단위 ------------------------------------------------------
    def get_target(self, build_target: str) -> Optional[dict]:
        with self._lock:
            return self._targets.get(build_target)

    def current_target_text(self, build_target: str) -> str:
        record = self.get_target(build_target)
        return record["text"] if record else ""

    def targets(self) -> List[str]:
        with self._lock:
            return sorted(self._targets)

    def upsert_target(self, build_target: str, text: str, proposal_id: str,
                      api_ids: Optional[List[int]] = None,
                      embedding: Optional[List[float]] = None) -> dict:
        """타깃 노트를 반영한다. ``api_ids``는 지금까지 이 노트에 기여한 API 누적."""
        with self._lock:
            previous = self._targets.get(build_target) or {}
            merged = list(previous.get("api_ids") or [])
            for api_id in api_ids or []:
                if api_id not in merged:
                    merged.append(api_id)
            record = {
                "build_target": build_target,
                "text": text,
                "api_ids": merged,
                "embedding": embedding,
                "updated_at": now_iso(),
                "source_proposal_id": proposal_id,
            }
            self._targets[build_target] = record
            self._flush()
            return record

    def records_for(self, document: dict) -> List[dict]:
        """KB 문서 하나에 적용되는 오버라이드(타깃 노트 먼저, 그다음 API 노트)."""
        records: List[dict] = []
        target = str(document.get("build_target") or "")
        if target:
            record = self.get_target(target)
            if record:
                records.append(record)
        record = self.get(document["api_id"])
        if record:
            records.append(record)
        return records

    def notes_for(self, document: dict) -> str:
        """문서에 실릴 self-correction 노트 전문(타깃 + API)."""
        return "\n".join(r["text"] for r in self.records_for(document) if r.get("text"))


class InMemoryKBOverrideStore(KBOverrideStore):
    """테스트/데모용 - 디스크에 쓰지 않는다."""

    def __init__(self) -> None:
        super().__init__(path=None)
        self._loaded = True

    def _flush(self) -> None:  # no-op
        pass


def resolve_build_target(kb: Optional[KnowledgeBase], api_id: int, hint: str = "") -> str:
    """역피드백 범위가 될 Bazel 타깃. 모르면 ""(API 단위로 폴백).

    우선순위: 호출자가 아는 값(``hint``) > KB 문서의 ``build_target``.
    """
    if hint:
        return hint
    if kb is None:
        return ""
    document = kb.api(api_id)
    return str(document.get("build_target") or "") if document else ""


def apis_in_target(kb: Optional[KnowledgeBase], build_target: str) -> List[dict]:
    """타깃 소속 API 문서(api_id 순). 타깃 노트가 실릴 대상이다."""
    if kb is None or not build_target:
        return []
    return sorted(
        (d for d in kb.documents if str(d.get("build_target") or "") == build_target),
        key=lambda d: d["api_id"],
    )


def propose_kb_update(
    analysis: RootCauseAnalysis,
    harness_id: str,
    overrides: KBOverrideStore,
    embed: bool = True,
    *,
    kb: Optional[KnowledgeBase] = None,
    build_target: str = "",
) -> KBUpdateProposal:
    """근본 원인 분석 결과를 KB 변경 제안(diff)으로 만든다.

    Bazel 타깃을 알 수 있으면(``build_target`` 또는 ``kb``) 그 타깃의 노트에,
    모르면 예전처럼 API의 노트에 덧붙인다. 어느 쪽이든 이전에 승인된 노트는
    유지하고 새 원인 설명을 `crash_id`가 붙은 항목으로 덧붙인다 - 이전 근거를
    덮어쓰지 않아야 감사(audit)로 전부 역추적할 수 있다. 타깃 노트에는 API
    이름도 남긴다 - 한 노트에 여러 API의 오탐이 섞이기 때문이다.
    """
    target = resolve_build_target(kb, analysis.api_id, build_target)
    if target:
        before_text = overrides.current_target_text(target)
        document = kb.api(analysis.api_id) if kb is not None else None
        api_label = document["function"] if document else f"api_id={analysis.api_id}"
        note = f"- [{analysis.crash_id}] ({api_label}) {analysis.summary}"
        affected = [d["api_id"] for d in apis_in_target(kb, target)] or [analysis.api_id]
    else:
        before_text = overrides.current_text(analysis.api_id)
        note = f"- [{analysis.crash_id}] {analysis.summary}"
        affected = [analysis.api_id]
    after_text = f"{before_text}\n{note}".strip() if before_text else note

    embedding = embed_text(after_text) if embed else None

    return KBUpdateProposal.new(
        crash_id=analysis.crash_id,
        api_id=analysis.api_id,
        harness_id=harness_id,
        before_text=before_text,
        after_text=after_text,
        embedding=embedding,
        build_target=target,
        affected_api_ids=affected,
    )


def rebuild_with_overrides(kb: KnowledgeBase, overrides: KBOverrideStore) -> KnowledgeBase:
    """오버라이드가 반영된 문서들로 KB 검색 인덱스를 새로 만든다.

    `kb.documents`를 직접 변형하지 않는다(원본 KB는 그대로 두고 새 인스턴스를
    반환) - 승인 전 상태를 계속 참조할 수 있어야 HITL REJECT 시 그냥
    버리기만 하면 되는 구조가 유지된다.
    """
    documents: List[dict] = []
    for document in kb.documents:
        records = overrides.records_for(document)
        if not records:
            documents.append(document)
            continue
        notes = overrides.notes_for(document)
        updated = dict(document)
        updated["updated_at"] = max(r["updated_at"] for r in records)
        updated["self_correction_notes"] = notes
        updated["self_correction_scope"] = [
            r.get("build_target") or f"api:{r.get('api_id')}" for r in records
        ]
        updated["text"] = f"{document.get('text', '')}\nself_correction {notes}"
        documents.append(updated)
    # build_units를 넘기지 않으면 재색인된 KB에서 build_unit_for_api()가 깨진다.
    return KnowledgeBase(
        documents=documents, files=kb.files,
        use_dense=getattr(kb, "_dense_enabled", False),
        build_units=kb.build_units,
    )
