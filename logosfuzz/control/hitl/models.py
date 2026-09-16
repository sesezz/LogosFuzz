"""
CTR-06-02 Human-in-the-loop (HITL) 인터페이스 - 데이터 모델
===========================================================

LogosFuzz 파이프라인(EXT -> SCH -> GEN -> EXE -> ANA)의 자동화 과정 중
사람의 판단이 필요한 "개입 지점(Checkpoint)"을 표현하기 위한 핵심 타입들을 정의한다.

설계서(26년_SW개발_HW제작설계서) 기능 분류와의 대응:
    EXT(Extract) / SCH(Schedule) / GEN(Generate) / EXE(Execute) / ANA(Analysis) / CTR(Control)

이 모듈은 순수 데이터 정의만 담당하며 외부 의존성이 없다(표준 라이브러리만 사용).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional


# --------------------------------------------------------------------------- #
# 유틸
# --------------------------------------------------------------------------- #
def now_iso() -> str:
    """UTC ISO-8601 타임스탬프."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_id() -> str:
    """짧은 리뷰 항목 식별자."""
    return uuid.uuid4().hex[:12]


# --------------------------------------------------------------------------- #
# 열거형
# --------------------------------------------------------------------------- #
class Stage(str, Enum):
    """파이프라인 단계 (설계서 기능 분류 코드와 1:1)."""
    EXTRACT = "EXT"
    SCHEDULE = "SCH"
    GENERATE = "GEN"
    EXECUTE = "EXE"
    ANALYZE = "ANA"
    CONTROL = "CTR"


class Checkpoint(str, Enum):
    """
    HITL 개입 지점.

    각 체크포인트는 특정 Stage의 산출물에 대해 사람 검토를 요청하는 지점이다.
    새 개입 지점이 필요하면 여기에 추가하고 policy.DEFAULT_POLICY에 모드를 등록하면 된다.
    """
    COMPAT_CHECK = "compat_check"        # CTR-06-01 사전 호환성 체크리스트 확인
    SCHEDULE_REVIEW = "schedule_review"  # SCH  로직 그룹/퍼징 우선순위 사람 조정
    HARNESS_REVIEW = "harness_review"    # GEN  생성된 하네스 검토/수정
    CRASH_TRIAGE = "crash_triage"        # ANA  정탐/오탐 판정 확인
    CVE_DISCLOSURE = "cve_disclosure"    # ANA-05-02 취약점(CVE) 공개 승인
    KB_FEEDBACK = "kb_feedback"          # ANA-05-03 지식베이스 역피드백(diff) 승인

    @property
    def stage(self) -> Stage:
        return _CHECKPOINT_STAGE[self]


_CHECKPOINT_STAGE: Dict["Checkpoint", Stage] = {
    Checkpoint.COMPAT_CHECK: Stage.CONTROL,
    Checkpoint.SCHEDULE_REVIEW: Stage.SCHEDULE,
    Checkpoint.HARNESS_REVIEW: Stage.GENERATE,
    Checkpoint.CRASH_TRIAGE: Stage.ANALYZE,
    Checkpoint.CVE_DISCLOSURE: Stage.ANALYZE,
    Checkpoint.KB_FEEDBACK: Stage.ANALYZE,
}


class DecisionType(str, Enum):
    """사람(또는 자동 정책)이 리뷰 항목에 대해 내리는 결정."""
    APPROVE = "approve"  # 그대로 승인하고 다음 단계 진행
    REJECT = "reject"    # 반려 - 해당 산출물 폐기(예: 하네스 재생성 유도)
    EDIT = "edit"        # 사람이 payload를 수정한 뒤 승인
    SKIP = "skip"        # 이 항목은 건너뜀(파이프라인은 계속)
    DEFER = "defer"      # 아직 결정 보류(PENDING 유지) - 비동기 검토용


class ReviewStatus(str, Enum):
    """리뷰 항목의 생명주기 상태."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EDITED = "edited"
    SKIPPED = "skipped"
    EXPIRED = "expired"  # 만료(정책상 시한 초과 시)

    @property
    def is_terminal(self) -> bool:
        return self is not ReviewStatus.PENDING


# DecisionType -> 그 결정이 만드는 최종 ReviewStatus
DECISION_STATUS: Dict[DecisionType, ReviewStatus] = {
    DecisionType.APPROVE: ReviewStatus.APPROVED,
    DecisionType.REJECT: ReviewStatus.REJECTED,
    DecisionType.EDIT: ReviewStatus.EDITED,
    DecisionType.SKIP: ReviewStatus.SKIPPED,
    DecisionType.DEFER: ReviewStatus.PENDING,
}


# --------------------------------------------------------------------------- #
# 데이터클래스
# --------------------------------------------------------------------------- #
@dataclass
class Decision:
    """리뷰 항목에 대한 하나의 결정 기록."""
    type: DecisionType
    reviewer: str = "unknown"          # 사람 이름/ID 또는 "auto:<policy>"
    comment: str = ""
    edited_payload: Optional[Dict[str, Any]] = None  # EDIT일 때 수정된 내용
    decided_at: str = field(default_factory=now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type.value,
            "reviewer": self.reviewer,
            "comment": self.comment,
            "edited_payload": self.edited_payload,
            "decided_at": self.decided_at,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Decision":
        return cls(
            type=DecisionType(d["type"]),
            reviewer=d.get("reviewer", "unknown"),
            comment=d.get("comment", ""),
            edited_payload=d.get("edited_payload"),
            decided_at=d.get("decided_at", now_iso()),
        )


@dataclass
class ReviewItem:
    """
    사람 검토를 기다리는(또는 이미 처리된) 하나의 작업 단위.

    payload에는 리뷰어가 판단하는 데 필요한 컨텍스트를 담는다.
    (예: HARNESS_REVIEW -> {"logic_group": "...", "harness_code": "...", "compile_ok": true})
    """
    checkpoint: Checkpoint
    target: str                                   # 대상 식별자(로직 그룹명/크래시 시그니처 등)
    summary: str = ""                             # CLI 목록에 보여줄 한 줄 요약
    payload: Dict[str, Any] = field(default_factory=dict)
    project: str = ""                            # logosfuzz init --project 이름
    status: ReviewStatus = ReviewStatus.PENDING
    decision: Optional[Decision] = None
    id: str = field(default_factory=new_id)
    stage: Optional[Stage] = None
    created_at: str = field(default_factory=now_iso)

    def __post_init__(self) -> None:
        if self.stage is None:
            self.stage = self.checkpoint.stage

    # -- 편의 속성 ---------------------------------------------------------- #
    @property
    def is_pending(self) -> bool:
        return self.status is ReviewStatus.PENDING

    @property
    def effective_payload(self) -> Dict[str, Any]:
        """EDIT로 수정되었다면 수정본을, 아니면 원본 payload를 반환."""
        if self.decision and self.decision.edited_payload is not None:
            return self.decision.edited_payload
        return self.payload

    # -- 직렬화 ------------------------------------------------------------- #
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "checkpoint": self.checkpoint.value,
            "stage": self.stage.value if self.stage else None,
            "target": self.target,
            "summary": self.summary,
            "payload": self.payload,
            "project": self.project,
            "status": self.status.value,
            "decision": self.decision.to_dict() if self.decision else None,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ReviewItem":
        item = cls(
            checkpoint=Checkpoint(d["checkpoint"]),
            target=d["target"],
            summary=d.get("summary", ""),
            payload=d.get("payload", {}),
            project=d.get("project", ""),
            status=ReviewStatus(d.get("status", "pending")),
            decision=Decision.from_dict(d["decision"]) if d.get("decision") else None,
            id=d.get("id", new_id()),
            stage=Stage(d["stage"]) if d.get("stage") else None,
            created_at=d.get("created_at", now_iso()),
        )
        return item
