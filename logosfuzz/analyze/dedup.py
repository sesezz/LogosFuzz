"""ANA-05-04: Crash Deduplication.

EXE-04-02가 남긴 크래시 결함 스트림을 다중 프레임 시그니처 기준으로 묶어
**고유 크래시 목록**을 만든다. 같은 버그를 가리키는 수백 개의 크래시 입력을
하나의 대표로 접어(fold) 이후 단계(ANA-05-01 정/오탐 판별, ANA-05-02 CVE
리포트)가 **버그 1개당 한 번만** 처리하도록 한다.

핵심 알고리즘
-------------
1. 각 결함 레코드에서 다중 프레임 시그니처를 계산한다(``signature.py``).
2. 시그니처가 같은 레코드를 한 클러스터로 병합한다.
3. 처음 관측된 레코드를 대표로 삼고, 등장 순서를 보존한다(재현성).

무의존/결정성: 표준 라이브러리만 사용하며, 동일 입력이면 항상 동일한 클러스터
집합과 순서를 낸다(정렬 키가 명확하므로 회귀 테스트가 안정적).
"""

from __future__ import annotations

from dataclasses import dataclass

from logosfuzz.analyze.models import CrashCluster, CrashRecord
from logosfuzz.analyze.signature import signature_digest, signature_key


@dataclass
class DedupStats:
    """중복 제거 요약 통계."""

    total_records: int
    unique_clusters: int

    @property
    def duplicates_removed(self) -> int:
        return self.total_records - self.unique_clusters

    @property
    def dedup_ratio(self) -> float:
        """중복 제거율(0.0~1.0). 입력이 없으면 0.0."""
        if self.total_records == 0:
            return 0.0
        return self.duplicates_removed / self.total_records

    def to_dict(self) -> dict:
        return {
            "total_records": self.total_records,
            "unique_clusters": self.unique_clusters,
            "duplicates_removed": self.duplicates_removed,
            "dedup_ratio": round(self.dedup_ratio, 4),
        }


class CrashDeduplicator:
    """시그니처 기반 크래시 중복 제거기.

    Args:
        depth: 시그니처에 사용할 상위 애플리케이션 프레임 수(기본 3).
    """

    def __init__(self, depth: int = 3) -> None:
        self.depth = depth
        # 삽입 순서 보존(파이썬 dict는 3.7+에서 삽입 순서 유지)
        self._clusters: dict[str, CrashCluster] = {}
        self._count = 0

    def add(self, record: CrashRecord) -> CrashCluster:
        """레코드 1건을 흡수하고, 소속 클러스터를 반환한다."""
        key = signature_key(record, self.depth)
        cid = "CL-" + signature_digest(key)
        cluster = self._clusters.get(cid)
        if cluster is None:
            cluster = CrashCluster(
                cluster_id=cid,
                signature=key,
                bug_type=record.category,
                representative=record,
                members=[],
                first_seen_index=self._count,
            )
            self._clusters[cid] = cluster
        cluster.members.append(record)
        self._count += 1
        return cluster

    def extend(self, records: list[CrashRecord]) -> None:
        for r in records:
            self.add(r)

    def clusters(self) -> list[CrashCluster]:
        """클러스터 목록.

        정렬 규칙(내림차순 우선순위):
          1) count 큰 것 우선 — 자주 재현되는 버그가 대개 더 중요/실재적.
          2) 처음 등장 순서(first_seen_index) — 동률일 때 결정성 보장.
        """
        return sorted(
            self._clusters.values(),
            key=lambda c: (-c.count, c.first_seen_index),
        )

    def stats(self) -> DedupStats:
        return DedupStats(total_records=self._count, unique_clusters=len(self._clusters))

    def to_dict(self) -> dict:
        return {
            "stats": self.stats().to_dict(),
            "depth": self.depth,
            "clusters": [c.to_dict() for c in self.clusters()],
        }


def deduplicate(records: list[CrashRecord], depth: int = 3) -> tuple[list[CrashCluster], DedupStats]:
    """편의 함수: 레코드 목록 → (클러스터 목록, 통계)."""
    dedup = CrashDeduplicator(depth=depth)
    dedup.extend(records)
    return dedup.clusters(), dedup.stats()
