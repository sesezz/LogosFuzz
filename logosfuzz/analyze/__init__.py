"""ANA 파트: 크래시 분석 단계.

하위 기능:
  - ANA-05-04 Crash Deduplication  (dedup.py, signature.py) — 5주차
  - ANA-05-01 LLM 기반 정/오탐 판별 (triage.py)             — 6주차
  - (연계) ANA-05-02 CVE 리포트     — 별도 패키지 ``ana_05_02_cve_reporting``

파이프라인: EXE-04-02(Sanitizer 모니터링) → ANA-05-04(중복 제거)
            → ANA-05-01(정/오탐) → ANA-05-02(CVE 리포트)
"""

from logosfuzz.analyze.models import (
    CrashCluster,
    CrashRecord,
    Frame,
    TriageResult,
    Verdict,
)
from logosfuzz.analyze.signature import (
    application_frames,
    cluster_id_for,
    has_application_frame,
    signature_key,
)
from logosfuzz.analyze.dedup import CrashDeduplicator, DedupStats, deduplicate
from logosfuzz.analyze.loader import load_records
from logosfuzz.analyze.triage import (
    LLMTriager,
    RuleBasedTriager,
    rule_triage,
    summarize,
    triage_clusters,
)

__all__ = [
    "CrashCluster",
    "CrashRecord",
    "Frame",
    "TriageResult",
    "Verdict",
    "application_frames",
    "cluster_id_for",
    "has_application_frame",
    "signature_key",
    "CrashDeduplicator",
    "DedupStats",
    "deduplicate",
    "load_records",
    "LLMTriager",
    "RuleBasedTriager",
    "rule_triage",
    "summarize",
    "triage_clusters",
]
