"""
CTR-06-02 HITL 인터페이스 - 리뷰 항목 저장소
============================================

리뷰 항목(ReviewItem)의 영속화를 담당한다.

- ReviewStore: 추상 인터페이스. 향후 SQLite/Vector DB 백엔드로 교체 가능하도록 분리.
- JsonReviewStore: 스켈레톤 기본 구현. 프로젝트별 JSON 파일(append-friendly)에 저장.

기본 저장 경로: <workdir>/.logosfuzz/hitl/reviews.json
"""
from __future__ import annotations

import json
import threading
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Optional

from .models import Checkpoint, ReviewItem, ReviewStatus


class ReviewStore(ABC):
    """리뷰 항목 저장소 인터페이스."""

    @abstractmethod
    def add(self, item: ReviewItem) -> ReviewItem: ...

    @abstractmethod
    def get(self, item_id: str) -> Optional[ReviewItem]: ...

    @abstractmethod
    def update(self, item: ReviewItem) -> ReviewItem: ...

    @abstractmethod
    def list(
        self,
        *,
        status: Optional[ReviewStatus] = None,
        checkpoint: Optional[Checkpoint] = None,
        project: Optional[str] = None,
    ) -> List[ReviewItem]: ...

    def pending(self, **kw) -> List[ReviewItem]:
        return self.list(status=ReviewStatus.PENDING, **kw)


class JsonReviewStore(ReviewStore):
    """
    JSON 파일 기반 저장소(스켈레톤 기본값).

    스레드 락으로 단일 프로세스 내 동시 접근을 보호한다.
    (다중 프로세스/분산 환경에서는 DB 백엔드로 교체할 것 - TODO.)
    """

    DEFAULT_PATH = Path(".logosfuzz") / "hitl" / "reviews.json"

    def __init__(self, path: Optional[Path | str] = None) -> None:
        self.path = Path(path) if path else self.DEFAULT_PATH
        self._lock = threading.RLock()
        self._items: Dict[str, ReviewItem] = {}
        self._loaded = False

    # -- 내부 I/O ----------------------------------------------------------- #
    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        if self.path.exists():
            raw = json.loads(self.path.read_text(encoding="utf-8") or "[]")
            for d in raw:
                item = ReviewItem.from_dict(d)
                self._items[item.id] = item
        self._loaded = True

    def _flush(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = [it.to_dict() for it in self._items.values()]
        # 원자적 쓰기: 임시 파일에 쓴 뒤 교체
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    # -- 인터페이스 구현 --------------------------------------------------- #
    def add(self, item: ReviewItem) -> ReviewItem:
        with self._lock:
            self._ensure_loaded()
            self._items[item.id] = item
            self._flush()
            return item

    def get(self, item_id: str) -> Optional[ReviewItem]:
        with self._lock:
            self._ensure_loaded()
            # 접두사 매칭도 허용(짧은 id를 CLI에서 편하게 쓰도록)
            if item_id in self._items:
                return self._items[item_id]
            matches = [it for k, it in self._items.items() if k.startswith(item_id)]
            return matches[0] if len(matches) == 1 else None

    def update(self, item: ReviewItem) -> ReviewItem:
        with self._lock:
            self._ensure_loaded()
            self._items[item.id] = item
            self._flush()
            return item

    def list(
        self,
        *,
        status: Optional[ReviewStatus] = None,
        checkpoint: Optional[Checkpoint] = None,
        project: Optional[str] = None,
    ) -> List[ReviewItem]:
        with self._lock:
            self._ensure_loaded()
            out = list(self._items.values())
        if status is not None:
            out = [it for it in out if it.status is status]
        if checkpoint is not None:
            out = [it for it in out if it.checkpoint is checkpoint]
        if project:
            out = [it for it in out if it.project == project]
        return sorted(out, key=lambda it: it.created_at)


class InMemoryReviewStore(JsonReviewStore):
    """테스트/데모용 - 디스크에 쓰지 않는 인메모리 저장소."""

    def __init__(self) -> None:
        super().__init__(path=None)
        self._loaded = True  # 파일 로드 건너뜀

    def _flush(self) -> None:  # no-op
        pass
