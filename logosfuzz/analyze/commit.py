"""
ANA-05-03 STEP 3: HITL 승인/거부 처리
=====================================

`KBUpdateProposal`에 대해 사람이 이미 내린 결정(APPROVE/REJECT)을 받아 처리:

  - APPROVE/EDIT -> `KBOverrideStore`에 실제로 반영(commit)
  - REJECT       -> 아무것도 반영하지 않고 폐기 사유만 기록

HITL 게이트 호출(`hitl.request(...)`)은 `pipeline.py` 담당
이 모듈은 "이미 결정된 Decision의 KB 반영/폐기"만 담당 -
HITL 없이도(테스트에서 Decision 직접 생성) 단위 테스트 가능

"롤백": 승인 전에는 `propose_kb_update()`가 `KBOverrideStore`를
건드리지 않으므로(HITL 게이트가 반영 차단), 거부는 되돌릴 것이 없는
무동작(no-op)
"""
from __future__ import annotations

from .kb_feedback import KBOverrideStore
from .models import KBUpdateProposal, ProposalStatus, now_iso


def apply_kb_update(
    proposal: KBUpdateProposal,
    overrides: KBOverrideStore,
    *,
    decided_by: str = "operator",
) -> KBUpdateProposal:
    """승인된 제안의 오버라이드 스토어 upsert 및 제안 상태 갱신

    Bazel 타깃 제안이면 타깃 노트, 아니면(구 KB) API 노트로 반영
    """
    if proposal.build_target:
        overrides.upsert_target(
            proposal.build_target, proposal.after_text, proposal.proposal_id,
            api_ids=[proposal.api_id], embedding=proposal.embedding,
        )
    else:
        overrides.upsert(
            proposal.api_id, proposal.after_text, proposal.proposal_id,
            embedding=proposal.embedding,
        )
    proposal.status = ProposalStatus.APPROVED
    proposal.decided_at = now_iso()
    proposal.decided_by = decided_by
    return proposal


def discard_kb_update(
    proposal: KBUpdateProposal,
    reason: str,
    *,
    decided_by: str = "operator",
) -> KBUpdateProposal:
    """거부된 제안 폐기. KB/오버라이드 스토어는 변경 없음"""
    proposal.status = ProposalStatus.REJECTED
    proposal.decided_at = now_iso()
    proposal.decided_by = decided_by
    proposal.rejection_reason = reason
    return proposal
