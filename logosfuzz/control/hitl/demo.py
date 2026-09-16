"""
CTR-06-02 HITL 골격 - 데모 시나리오
===================================

인메모리 저장소로 파이프라인 훅 → 리뷰 큐 → 사람 결정 흐름을 시연한다.
실행: python -m logosfuzz.control.hitl.demo
"""
from __future__ import annotations

from . import hooks
from .gate import HITLManager
from .models import Checkpoint, DecisionType
from .policy import HITLPolicy
from .store import InMemoryReviewStore


def run() -> None:
    hitl = HITLManager(
        store=InMemoryReviewStore(),
        policy=HITLPolicy.default(),   # 조건부 정책
        interactive=False,             # 비동기(큐) 모드
        reviewer="demo-operator",
    )
    project = "dlt-daemon"

    print("### 1) GEN: 컴파일 성공 하네스 → 정책상 자동 통과")
    ok = hooks.review_generated_harness(
        hitl, project=project, logic_group="LG-can-parse",
        harness_code="int LLVMFuzzer... {}", compile_ok=True,
    )
    print(f"   다음 단계(fuzz) 진행 가능? {ok}")

    print("\n### 2) GEN: 컴파일 실패 하네스 → 사람 검토 큐로")
    ok = hooks.review_generated_harness(
        hitl, project=project, logic_group="LG-uds-session",
        harness_code="int LLVMFuzzer... {", compile_ok=False,
        compile_log="error: expected '}' at end of input",
    )
    print(f"   즉시 진행 가능? {ok} (False = 검토 대기)")

    print("\n### 3) ANA: 신뢰도 높은 크래시 판정 → 자동 통과")
    verdict = hooks.review_crash_triage(
        hitl, project=project, crash_signature="heap-bof@dlt_message.c:210",
        verdict="true_positive", confidence=0.95, sanitizer="ASAN",
    )
    print(f"   확정 판정: {verdict}")

    print("\n### 4) ANA: 신뢰도 낮은 크래시 판정 → 사람 검토 큐로")
    verdict = hooks.review_crash_triage(
        hitl, project=project, crash_signature="wild-ptr@dlt_user.c:88",
        verdict="false_positive", confidence=0.55, sanitizer="ASAN",
    )
    print(f"   즉시 확정? {verdict} (None = 검토 대기)")

    print("\n### 5) ANA-05-02: CVE 공개 승인 → 항상 사람 필수")
    approved = hooks.approve_cve_disclosure(
        hitl, project=project, cve_draft_id="CVE-DRAFT-001",
        title="DLT 메시지 파싱 힙 오버플로우", severity="HIGH",
    )
    print(f"   즉시 공개 승인? {approved} (False = 검토 대기)")

    print("\n### 대기 중인 리뷰 항목:")
    for it in hitl.pending():
        print(f"   - {it.id}  {it.checkpoint.value:<16} {it.summary}")

    print("\n### 사람이 검토 결정을 내림(CLI: logosfuzz review ...)")
    for it in list(hitl.pending()):
        if it.checkpoint is Checkpoint.CVE_DISCLOSURE:
            hitl.decide(it.id, DecisionType.APPROVE, comment="CVD 절차 검토 완료")
        elif it.checkpoint is Checkpoint.CRASH_TRIAGE:
            hitl.decide(it.id, DecisionType.EDIT, comment="실제로는 정탐",
                        edited_payload={**it.payload, "llm_verdict": "true_positive"})
        else:
            hitl.decide(it.id, DecisionType.REJECT, comment="재생성 필요")

    print("\n### 최종 집계:")
    for k, v in hitl.stats().items():
        print(f"   {k:<9}: {v}")


if __name__ == "__main__":
    run()
