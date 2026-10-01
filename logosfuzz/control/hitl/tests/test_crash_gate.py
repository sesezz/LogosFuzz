"""CTR-06-02 CRASH_TRIAGE 크래시 승인 게이트(4주차 활성화) 단위 테스트."""
from __future__ import annotations

from logosfuzz.control.hitl import hooks
from logosfuzz.control.hitl.gate import CrashApprovalGate, HITLManager
from logosfuzz.control.hitl.models import Checkpoint, DecisionType
from logosfuzz.control.hitl.policy import HITLPolicy
from logosfuzz.control.hitl.store import InMemoryReviewStore, JsonReviewStore


def _gate(store=None, project="p"):
    hitl = HITLManager(store=store or InMemoryReviewStore(), policy=HITLPolicy.default())
    return CrashApprovalGate(hitl, project=project), hitl


def _items(hitl):
    return hitl.store.list(checkpoint=Checkpoint.CRASH_TRIAGE)


def test_confident_true_positive_is_auto_verified():
    gate, _ = _gate()
    approval = gate.review("CL-1", "true_positive", 0.92)

    assert approval.status == "approved"
    assert approval.final_verdict == "true_positive"
    assert approval.verified and not approval.by_human
    assert approval.reviewer.startswith("auto:")


def test_needs_review_goes_to_human_even_with_high_confidence():
    """규칙 판별기는 needs_review 에 최대 0.9 신뢰도를 준다 - 자동 승인되면 안 된다."""
    gate, hitl = _gate()
    approval = gate.review("CL-1", "needs_review", 0.9)

    assert approval.status == "pending"
    assert approval.final_verdict is None and not approval.verified
    assert len(hitl.pending()) == 1


def test_low_confidence_verdict_waits_for_human():
    gate, _ = _gate()
    approval = gate.review("CL-1", "true_positive", 0.7)
    assert approval.status == "pending" and not approval.verified


def test_rerun_does_not_duplicate_pending_items():
    gate, hitl = _gate()
    first = gate.review("CL-1", "true_positive", 0.7)
    second = gate.review("CL-1", "true_positive", 0.7)

    assert second.reused and second.item_id == first.item_id
    assert len(_items(hitl)) == 1


def test_human_approval_is_reused_on_next_run():
    gate, hitl = _gate()
    pending = gate.review("CL-1", "true_positive", 0.7)
    hitl.decide(pending.item_id, DecisionType.APPROVE, reviewer="minju")

    again = gate.review("CL-1", "true_positive", 0.7)
    assert again.verified and again.by_human and again.reused
    assert again.reviewer == "minju"


def test_human_edit_flips_false_positive_to_verified():
    gate, hitl = _gate()
    pending = gate.review("CL-1", "false_positive", 0.6)
    item = hitl.get(pending.item_id)
    hitl.decide(item.id, DecisionType.EDIT, reviewer="minju",
                edited_payload={**item.payload, "llm_verdict": "true_positive"})

    again = gate.review("CL-1", "false_positive", 0.6)
    assert again.auto_verdict == "false_positive"
    assert again.final_verdict == "true_positive" and again.verified


def test_human_decision_survives_changed_auto_verdict():
    """사람의 판단이 자동 판정보다 우선한다 - 판별기가 바뀌어도 덮어쓰지 않는다."""
    gate, hitl = _gate()
    pending = gate.review("CL-1", "true_positive", 0.7)
    hitl.decide(pending.item_id, DecisionType.REJECT, reviewer="minju")

    again = gate.review("CL-1", "true_positive", 0.95)
    assert again.final_verdict == "false_positive" and not again.verified
    assert len(_items(hitl)) == 1


def test_auto_decision_is_rerequested_when_auto_verdict_changes():
    gate, hitl = _gate()
    gate.review("CL-1", "false_positive", 0.95)
    again = gate.review("CL-1", "true_positive", 0.95)

    assert not again.reused and again.verified
    assert len(_items(hitl)) == 2


def test_gate_state_persists_in_json_store(tmp_path):
    path = tmp_path / "reviews.json"
    gate, hitl = _gate(JsonReviewStore(path))
    pending = gate.review("CL-1", "true_positive", 0.7)
    hitl.decide(pending.item_id, DecisionType.APPROVE, reviewer="minju")

    # 다른 프로세스(다음 analyze 실행)가 같은 저장소를 연다
    fresh, _ = _gate(JsonReviewStore(path))
    assert fresh.review("CL-1", "true_positive", 0.7).verified


def test_hook_delegates_to_gate():
    hitl = HITLManager(store=InMemoryReviewStore(), policy=HITLPolicy.default())
    assert hooks.review_crash_triage(hitl, project="p", crash_signature="s1",
                                     verdict="true_positive", confidence=0.95) == "true_positive"
    assert hooks.review_crash_triage(hitl, project="p", crash_signature="s2",
                                     verdict="false_positive", confidence=0.5) is None
