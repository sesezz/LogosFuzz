"""ANA (Analyze) 계층 - 크래시 분석 및 지식 베이스 역피드백.

- ANA-05-01 LLM 기반 정탐/오탐 자동 판별 (이 저장소에 미구현 - `models.CrashRecord`가
  그 출력 계약의 최소 스텁 역할을 한다)
- ANA-05-03 지식 베이스 역피드백 및 하네스 재생성 (이 패키지)

공개 API
--------
    from logosfuzz.analyze import (
        CrashRecord, KBOverrideStore, AuditTrailStore, run_ana_05_03,
    )
    from logosfuzz.control.hitl import HITLManager

    outcome = run_ana_05_03(
        crash_record, kb, llm, HITLManager.create(),
        KBOverrideStore(), AuditTrailStore(),
    )
"""
from .audit import AuditTrailStore, InMemoryAuditTrailStore
from .commit import apply_kb_update, discard_kb_update
from .kb_feedback import (
    InMemoryKBOverrideStore,
    KBOverrideStore,
    embed_text,
    propose_kb_update,
    rebuild_with_overrides,
)
from .models import (
    CrashRecord,
    KBUpdateProposal,
    ProposalStatus,
    RegenerationRecord,
    RootCauseAnalysis,
)
from .pipeline import FeedbackOutcome, run_ana_05_03
from .regenerate import draft_via_llm, trigger_regeneration
from .rootcause import analyze_false_positive

__all__ = [
    "CrashRecord",
    "RootCauseAnalysis",
    "KBUpdateProposal",
    "ProposalStatus",
    "RegenerationRecord",
    "FeedbackOutcome",
    "analyze_false_positive",
    "KBOverrideStore",
    "InMemoryKBOverrideStore",
    "embed_text",
    "propose_kb_update",
    "rebuild_with_overrides",
    "apply_kb_update",
    "discard_kb_update",
    "draft_via_llm",
    "trigger_regeneration",
    "AuditTrailStore",
    "InMemoryAuditTrailStore",
    "run_ana_05_03",
]

__version__ = "0.2.0"  # ANA-05-03 전체 구현 (2/2: KB 역피드백 + 재생성 오케스트레이션)
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
