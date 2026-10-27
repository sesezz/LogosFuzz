"""
CTR-06-02 HITL 인터페이스 - 리뷰 항목 저장소
============================================

리뷰 항목(ReviewItem)의 영속화를 담당한다.

- ReviewStore: 추상 인터페이스. 향후 SQLite/Vector DB 백엔드로 교체 가능하도록 분리.
- JsonReviewStore: 스켈레톤 기본 구현. 프로젝트별 JSON 파일(append-friendly)에 저장.

기본 저장 경로: <workdir>/.logosfuzz/hitl/reviews.json
"""
from __future__ import annotations

import contextlib
import json
import os
import tempfile
import threading
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Iterator, List, Optional

try:  # POSIX 전용. Windows 에서는 스레드 락만 쓴다(단일 사용자 CLI 가정).
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

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

    스레드 락으로 단일 프로세스 내 동시 접근을, POSIX 에서는 ``<path>.lock`` 파일
    락(fcntl.flock)으로 같은 호스트의 다중 프로세스 접근을 보호한다. 쓰기는
    "락 → 디스크 최신본 다시 읽기 → 병합 → 고유 임시 파일 → 교체" 순서라 두 프로세스가
    동시에 승인해도 한쪽 항목이 사라지지 않는다. 파일 권한은 소유자만(0600).
    (여러 호스트가 공유하는 서비스라면 트랜잭션 DB 로 교체할 것.)
    """

    DEFAULT_PATH = Path(".logosfuzz") / "hitl" / "reviews.json"

    def __init__(self, path: Optional[Path | str] = None) -> None:
        self.path = Path(path) if path else self.DEFAULT_PATH
        self._lock = threading.RLock()
        self._items: Dict[str, ReviewItem] = {}
        self._loaded = False
        self._persistent = True

    # -- 내부 I/O ----------------------------------------------------------- #
    def _ensure_loaded(self) -> None:
        # 디스크 저장소는 매번 최신본을 읽는다. 다른 프로세스(다른 CLI 창)가 승인·거부한
        # 상태를 오래된 메모리 사본으로 판단하지 않기 위해서다.
        if self._loaded and not self._persistent:
            return
        self._items = self._read_disk()
        self._loaded = True

    @contextlib.contextmanager
    def _process_lock(self) -> Iterator[None]:
        """같은 호스트의 다른 프로세스와 쓰기를 직렬화한다."""
        if fcntl is None:
            yield
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.path.with_name(self.path.name + ".lock")
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _read_disk(self) -> Dict[str, ReviewItem]:
        if not self.path.exists():
            return {}
        raw = json.loads(self.path.read_text(encoding="utf-8") or "[]")
        items = (ReviewItem.from_dict(d) for d in raw)
        return {it.id: it for it in items}

    def _write_disk(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = [it.to_dict() for it in self._items.values()]
        # 원자적 쓰기: 같은 디렉터리의 고유 임시 파일(0600)에 쓴 뒤 교체.
        # 고정 이름(.tmp)을 쓰면 두 프로세스가 같은 임시 파일을 덮어쓴다.
        fd, tmp_name = tempfile.mkstemp(prefix=self.path.name + ".", suffix=".tmp",
                                        dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(data, ensure_ascii=False, indent=2))
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_name, self.path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp_name)
            raise

    def _flush(self) -> None:
        self._write_disk()

    def _save(self, item: ReviewItem) -> None:
        """항목 1개를 저장한다. 다른 프로세스가 그사이 쓴 항목을 잃지 않게 병합한다.

        저장에 실패하면 예외를 그대로 올린다 - 승인 기록이 디스크에 남지 않았는데
        승인된 것처럼 진행하면 안 된다.
        """
        if not self._persistent:
            self._items[item.id] = item
            self._flush()
            return
        with self._process_lock():
            # 디스크가 기준이다: 다른 프로세스가 추가·수정한 항목을 먼저 반영한다.
            merged = self._read_disk()
            merged[item.id] = item
            self._items = merged
            self._flush()

    # -- 인터페이스 구현 --------------------------------------------------- #
    def add(self, item: ReviewItem) -> ReviewItem:
        with self._lock:
            self._ensure_loaded()
            self._save(item)
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
            self._save(item)
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
        self._persistent = False

    def _flush(self) -> None:  # no-op
        pass
