"""ANA 파트: 크래시 분석, 중복 제거, 정/오탐 판별, 지식 베이스 역피드백.

하위 기능:
  - ANA-05-04 Crash Deduplication (dedup.py, signature.py, loader.py)
  - ANA-05-01 LLM 기반 정/오탐 판별 (triage.py)
  - ANA-05-03 지식 베이스 역피드백 및 하네스 재생성 (rootcause.py, kb_feedback.py,
    commit.py, regenerate.py, audit.py, pipeline.py). ANA-05-01의 출력
    (`TriageResult`)이 아직 api_id/harness_id/run_id 매핑까지 제공하지 않아,
    `models.FalsePositiveCrash`가 그 매핑까지 포함한 최소 입력 계약의 스텁
    역할을 한다(`models.CrashRecord`와는 다른 타입 - 그쪽은 ANA-05-04가 쓰는
    "원시 크래시 레코드").
  - (연계) ANA-05-02 CVE 리포트 - 별도 패키지 ``ana_05_02_cve_reporting``

파이프라인: EXE-04-02(Sanitizer 모니터링) → ANA-05-04(중복 제거)
            → ANA-05-01(정/오탐) → ANA-05-03(역피드백/재생성) → ANA-05-02(CVE 리포트)

공개 API
--------
    from logosfuzz.analyze import (
        FalsePositiveCrash, KBOverrideStore, AuditTrailStore, run_ana_05_03,
    )
    from logosfuzz.control.hitl import HITLManager

    outcome = run_ana_05_03(
        crash_record, kb, llm, HITLManager.create(),
        KBOverrideStore(), AuditTrailStore(),
    )
"""
from .audit import AuditTrailStore, InMemoryAuditTrailStore
from .commit import apply_kb_update, discard_kb_update
from .dedup import CrashDeduplicator, DedupStats, deduplicate
from .kb_feedback import (
    InMemoryKBOverrideStore,
    KBOverrideStore,
    embed_text,
    propose_kb_update,
    rebuild_with_overrides,
)
from .loader import load_records
from .models import (
    CrashCluster,
    CrashRecord,
    FalsePositiveCrash,
    Frame,
    KBUpdateProposal,
    ProposalStatus,
    RegenerationRecord,
    RootCauseAnalysis,
    TriageResult,
    Verdict,
)
from .pipeline import FeedbackOutcome, run_ana_05_03
from .regenerate import draft_via_llm, trigger_regeneration
from .rootcause import analyze_false_positive
from .signature import (
    application_frames,
    cluster_id_for,
    has_application_frame,
    signature_key,
)
from .triage import LLMTriager, RuleBasedTriager, rule_triage, summarize, triage_clusters

__all__ = [
    # ANA-05-04 (dedup)
    "CrashCluster",
    "CrashRecord",
    "Frame",
    "application_frames",
    "cluster_id_for",
    "has_application_frame",
    "signature_key",
    "CrashDeduplicator",
    "DedupStats",
    "deduplicate",
    "load_records",
    # ANA-05-01 (triage)
    "TriageResult",
    "Verdict",
    "LLMTriager",
    "RuleBasedTriager",
    "rule_triage",
    "summarize",
    "triage_clusters",
    # ANA-05-03 (KB 역피드백 + 재생성)
    "FalsePositiveCrash",
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
