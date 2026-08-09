"""
ANA-05-03 STEP 5: 감사 로그 (crash_id <-> api_id <-> harness_id 추적성)
=========================================================================

"어떤 오탐이 어떤 KB 변경과 어떤 재생성을 유발했는가"를 역추적할 수 있도록
제안(`KBUpdateProposal`)과 재생성 시도(`RegenerationRecord`)를 하나의
append-only JSON 파일에 기록한다.
`logosfuzz.control.hitl.store.JsonReviewStore`와 동일한 패턴(스레드 락 +
원자적 쓰기)을 따른다.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import List, Optional

from .models import KBUpdateProposal, RegenerationRecord


class AuditTrailStore:
    DEFAULT_PATH = Path(".logosfuzz") / "analyze" / "audit_trail.json"

    def __init__(self, path: Optional[Path | str] = None) -> None:
        self.path = Path(path) if path else self.DEFAULT_PATH
        self._lock = threading.RLock()
        self._entries: List[dict] = []
        self._loaded = False

    # -- 내부 I/O ------------------------------------------------------------
    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        if self.path.exists():
            self._entries = json.loads(self.path.read_text(encoding="utf-8") or "[]")
        self._loaded = True

    def _flush(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(self._entries, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    # -- 기록 ------------------------------------------------------------- #
    def record_proposal(self, proposal: KBUpdateProposal) -> None:
        """제안 생성/승인/거부 시점마다 호출 - 최신 상태를 새 항목으로 남긴다."""
        with self._lock:
            self._ensure_loaded()
            self._entries.append({"type": "proposal", **proposal.to_dict()})
            self._flush()

    def record_regeneration(self, record: RegenerationRecord) -> None:
        with self._lock:
            self._ensure_loaded()
            self._entries.append({"type": "regeneration", **record.to_dict()})
            self._flush()

    # -- 조회(역추적) ------------------------------------------------------- #
    def for_crash(self, crash_id: str) -> List[dict]:
        with self._lock:
            self._ensure_loaded()
            return [e for e in self._entries if e.get("crash_id") == crash_id]

    def for_api(self, api_id: int) -> List[dict]:
        with self._lock:
            self._ensure_loaded()
            return [e for e in self._entries if e.get("api_id") == api_id]

    def for_harness(self, harness_id: str) -> List[dict]:
        with self._lock:
            self._ensure_loaded()
            return [e for e in self._entries if e.get("harness_id") == harness_id]

    def all(self) -> List[dict]:
        with self._lock:
            self._ensure_loaded()
            return list(self._entries)


class InMemoryAuditTrailStore(AuditTrailStore):
    """테스트/데모용 - 디스크에 쓰지 않는다."""

    def __init__(self) -> None:
        super().__init__(path=None)
        self._loaded = True

    def _flush(self) -> None:  # no-op
        pass
