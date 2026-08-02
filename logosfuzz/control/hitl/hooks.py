"""
CTR-06-02 HITL 인터페이스 - 파이프라인 연동 훅(예시)
====================================================

각 파이프라인 단계(GEN/ANA 등)가 HITL 게이트를 어떻게 호출하는지 보여주는
얇은 어댑터 계층이다. 실제 단계 구현에서 아래 함수를 호출하면 된다.

여기서는 "골격"이므로 단계 내부 로직(재생성/리포트 작성 등)은 TODO 스텁으로 둔다.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from .gate import HITLManager
from .models import Checkpoint, DecisionType


def review_generated_harness(
    hitl: HITLManager,
    *,
    project: str,
    logic_group: str,
    harness_code: str,
    compile_ok: bool,
    compile_log: str = "",
) -> bool:
    """
    GEN-03 이후 호출. 생성된 하네스에 대해 HARNESS_REVIEW 체크포인트를 태운다.

    반환값: 이 하네스를 다음 단계(fuzz)로 넘겨도 되는가?
    """
    decision = hitl.request(
        Checkpoint.HARNESS_REVIEW,
        target=logic_group,
        project=project,
        summary=f"[{logic_group}] 하네스 {'컴파일 성공' if compile_ok else '컴파일 실패'}",
        payload={
            "logic_group": logic_group,
            "compile_ok": compile_ok,
            "compile_log": compile_log,
            "harness_code": harness_code,
        },
    )
    if decision.type in (DecisionType.APPROVE, DecisionType.EDIT):
        return True
    if decision.type == DecisionType.REJECT:
        # TODO(GEN-03-02): 반려 시 self-heal 루프로 되돌려 하네스 재생성
        return False
    # SKIP / DEFER
    return False


def review_crash_triage(
    hitl: HITLManager,
    *,
    project: str,
    crash_signature: str,
    verdict: str,          # LLM 1차 판정: "true_positive" | "false_positive"
    confidence: float,
    stacktrace: str = "",
    sanitizer: str = "",
) -> Optional[str]:
    """
    ANA-05-01 이후 호출. 정탐/오탐 판정을 CRASH_TRIAGE 체크포인트로 확인한다.

    반환값: 최종 확정된 verdict 문자열, 보류/건너뜀이면 None.
    """
    decision = hitl.request(
        Checkpoint.CRASH_TRIAGE,
        target=crash_signature,
        project=project,
        summary=f"{crash_signature} → LLM판정={verdict} (conf={confidence:.2f})",
        payload={
            "crash_signature": crash_signature,
            "llm_verdict": verdict,
            "confidence": confidence,
            "sanitizer": sanitizer,
            "stacktrace": stacktrace,
        },
    )
    if decision.type == DecisionType.APPROVE:
        return verdict
    if decision.type == DecisionType.EDIT and decision.edited_payload:
        # 사람이 판정을 뒤집은 경우
        return decision.edited_payload.get("llm_verdict", verdict)
    if decision.type == DecisionType.REJECT:
        # TODO(ANA-05-03): 오탐 확정 → 지식베이스 역피드백 트리거
        return "false_positive"
    return None


def approve_cve_disclosure(
    hitl: HITLManager,
    *,
    project: str,
    cve_draft_id: str,
    title: str,
    severity: str,
) -> bool:
    """
    ANA-05-02 취약점 공개 전 최종 승인(항상 사람 필수 - 정책 기본값 MANUAL).
    """
    decision = hitl.request(
        Checkpoint.CVE_DISCLOSURE,
        target=cve_draft_id,
        project=project,
        summary=f"CVE 공개 승인: [{severity}] {title}",
        payload={"cve_draft_id": cve_draft_id, "title": title, "severity": severity},
    )
    return decision.type in (DecisionType.APPROVE, DecisionType.EDIT)
