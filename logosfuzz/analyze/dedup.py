"""ANA-05-04: Crash Deduplication

EXE-04-02 크래시 결함 스트림의 다중 프레임 시그니처 기준 고유 크래시 목록 생성

1. 결함 레코드별 다중 프레임 시그니처 계산 (``signature.py``)
2. 같은 시그니처 레코드를 한 클러스터로 병합
3. 처음 관측된 레코드를 대표로 지정, 등장 순서 보존

동일 입력에 대해 항상 동일한 클러스터 집합과 순서 보장
"""

from __future__ import annotations

from dataclasses import dataclass

from logosfuzz.analyze.models import CrashCluster, CrashRecord
from logosfuzz.analyze.signature import signature_digest, signature_key


@dataclass
class DedupStats:
    """중복 제거 요약 통계"""

    total_records: int
    unique_clusters: int

    @property
    def duplicates_removed(self) -> int:
        return self.total_records - self.unique_clusters

    @property
    def dedup_ratio(self) -> float:
        """중복 제거율 (0.0~1.0, 입력 없으면 0.0)"""
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
    """시그니처 기반 크래시 중복 제거기

    Args:
        depth: 시그니처에 사용할 상위 애플리케이션 프레임 수 (기본 3)
    """

    def __init__(self, depth: int = 3) -> None:
        self.depth = depth
        # 삽입 순서 보존
        self._clusters: dict[str, CrashCluster] = {}
        self._count = 0

    def add(self, record: CrashRecord) -> CrashCluster:
        """레코드 1건 흡수 및 소속 클러스터 반환"""
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
        """클러스터 목록

        정렬 규칙:
          1) count 내림차순
          2) 동률 시 처음 등장 순서(first_seen_index)
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
    """레코드 목록 → (클러스터 목록, 통계) 변환"""
    dedup = CrashDeduplicator(depth=depth)
    dedup.extend(records)
    return dedup.clusters(), dedup.stats()
