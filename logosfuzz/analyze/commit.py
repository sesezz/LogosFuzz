"""
ANA-05-03 STEP 3: HITL 승인/거부 처리
=====================================

`KBUpdateProposal`에 대해 사람이 이미 내린 결정(APPROVE/REJECT)을 받아서:

  - APPROVE/EDIT -> `KBOverrideStore`에 실제로 반영(commit)
  - REJECT       -> 아무것도 반영하지 않고 폐기 사유만 기록

HITL 게이트 호출 자체(`hitl.request(...)`)는 `pipeline.py`가 담당한다. 이
모듈은 "이미 결정된 Decision을 받아 KB에 어떻게 반영/폐기할지"만 책임진다 -
그래야 HITL 없이도(테스트에서 Decision을 직접 만들어) 단위 테스트할 수 있다.

"롤백"에 대하여: 승인 전에는 `propose_kb_update()`가 `KBOverrideStore`를
전혀 건드리지 않으므로(HITL 게이트가 실제로 반영을 막고 있음), 거부는
"아직 아무것도 쓰지 않았으므로 되돌릴 것도 없는" 무동작(no-op)이다.
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
    """승인된 제안을 오버라이드 스토어에 upsert하고 제안 상태를 갱신한다."""
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
    """거부된 제안을 폐기한다. KB/오버라이드 스토어는 건드리지 않는다."""
    proposal.status = ProposalStatus.REJECTED
    proposal.decided_at = now_iso()
    proposal.decided_by = decided_by
    proposal.rejection_reason = reason
    return proposal
