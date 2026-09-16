"""
ANA-05-03 오케스트레이터
=========================

ANA-05-01이 오탐(FALSE_POSITIVE)으로 확정한 크래시(`FalsePositiveCrash`)를 받아:

  1. 근본 원인 분석 (`rootcause.analyze_false_positive`)
  2. KB 변경 제안(diff) 생성 (`kb_feedback.propose_kb_update`) - 아직 KB 미반영
  3. HITL 승인 게이트에 큐잉 (`Checkpoint.KB_FEEDBACK`)
       - 정책상 자동 결정이거나 interactive 모드면 즉시 Decision을 받는다
       - 아니면 PENDING으로 저장되고 사람이 나중에 `logosfuzz review`로 결정
  4. 결정 처리:
       - APPROVE/EDIT -> KB 오버라이드 커밋 + 인덱스 재구성 + 재생성 트리거
       - REJECT        -> 폐기(승인 전에는 아무것도 반영되지 않았으므로 "롤백"은
                          곧 무동작이다)
       - SKIP/DEFER    -> 이번 호출에서는 더 진행하지 않는다(PENDING 유지)
  5. 각 단계 산출물을 `AuditTrailStore`에 기록(crash_id/api_id/harness_id 추적성)

트리거 정책은 reactive(즉시)다: ANA-05-01이 오탐 판정을 내리는 즉시 이
파이프라인을 호출한다고 전제한다. 크래시 발생 빈도 자체가 이미 "이벤트당
1회 LLM 호출"의 자연스러운 상한이고, 실제 KB/재생성 반영은 어차피 HITL
승인 없이는 일어나지 않으므로 배치로 모아 처리해도 얻는 이득이 크지
않다는 것이 설계 검토 시 결론이었다.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from logosfuzz.control.hitl.gate import HITLManager
from logosfuzz.control.hitl.models import Checkpoint, DecisionType
from logosfuzz.generate.compiler import Compiler
from logosfuzz.generate.llm import LLMClient
from logosfuzz.knowledge.knowledge_base import KnowledgeBase

from . import commit, regenerate
from .audit import AuditTrailStore
from .kb_feedback import KBOverrideStore, propose_kb_update, rebuild_with_overrides
from .models import FalsePositiveCrash, KBUpdateProposal, RegenerationRecord, RootCauseAnalysis
from .rootcause import analyze_false_positive


@dataclass
class FeedbackOutcome:
    crash_id: str
    api_id: int
    analysis: RootCauseAnalysis
    proposal: KBUpdateProposal
    decision_type: str  # DecisionType.value
    kb: KnowledgeBase  # 반영 시 재구성된 KB, 아니면 원본 그대로
    regeneration: Optional[RegenerationRecord] = None


def _latest_item_id(hitl: HITLManager, project: str, target: str) -> Optional[str]:
    """방금 request()가 큐에 쌓은(또는 즉시 처리한) 항목의 id를 찾는다.

    `logosfuzz.generate.selfheal.SelfHealLoop._escalate`와 동일한 패턴.
    """
    items = [
        it for it in hitl.store.list(checkpoint=Checkpoint.KB_FEEDBACK, project=project)
        if it.target == target
    ]
    return items[-1].id if items else None


def run_ana_05_03(
    crash: FalsePositiveCrash,
    kb: KnowledgeBase,
    llm: LLMClient,
    hitl: HITLManager,
    overrides: KBOverrideStore,
    audit: AuditTrailStore,
    *,
    compiler: Optional[Compiler] = None,
    logic_group: str = "",
    target_apis: Optional[List[str]] = None,
    max_round: int = 3,
    project: str = "",
) -> FeedbackOutcome:
    """ANA-05-03 5단계 오케스트레이션. `crash.verdict`는 항상 FALSE_POSITIVE다
    (`FalsePositiveCrash.__post_init__`이 강제)."""
    analysis = analyze_false_positive(crash, kb, llm)

    proposal = propose_kb_update(analysis, crash.harness_id, overrides)
    audit.record_proposal(proposal)

    decision = hitl.request(
        Checkpoint.KB_FEEDBACK,
        target=str(crash.api_id),
        project=project,
        summary=f"[api_id={crash.api_id}] 오탐 역피드백 제안 (crash={crash.crash_id})",
        payload={
            "crash_id": crash.crash_id,
            "api_id": crash.api_id,
            "harness_id": crash.harness_id,
            "before_text": proposal.before_text,
            "after_text": proposal.after_text,
            "root_cause_summary": analysis.summary,
        },
    )
    proposal.hitl_item_id = _latest_item_id(hitl, project, str(crash.api_id))

    result_kb = kb
    regeneration: Optional[RegenerationRecord] = None

    if decision.type in (DecisionType.APPROVE, DecisionType.EDIT):
        commit.apply_kb_update(proposal, overrides, decided_by=decision.reviewer)
        audit.record_proposal(proposal)
        result_kb = rebuild_with_overrides(kb, overrides)

        if compiler is not None:
            record, _report = regenerate.trigger_regeneration(
                proposal, result_kb, overrides, compiler, llm,
                logic_group=logic_group or crash.harness_id,
                target_apis=target_apis or [],
                max_round=max_round, project=project, hitl=hitl,
            )
            audit.record_regeneration(record)
            regeneration = record
    elif decision.type == DecisionType.REJECT:
        commit.discard_kb_update(proposal, decision.comment or "HITL reject",
                                 decided_by=decision.reviewer)
        audit.record_proposal(proposal)
    # SKIP/DEFER: 상태 변경 없이 PENDING 유지 - 호출자가 나중에 다시 조회해서
    # decide() 이후 재진입해야 한다(무한 대기 방지는 HITL 자체 책임 범위).

    return FeedbackOutcome(
        crash_id=crash.crash_id, api_id=crash.api_id, analysis=analysis,
        proposal=proposal, decision_type=decision.type.value, kb=result_kb,
        regeneration=regeneration,
    )
