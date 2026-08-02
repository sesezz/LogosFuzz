"""
CTR-06-02 Human-in-the-loop (HITL) 인터페이스 골격
=================================================

LogosFuzz 자동 퍼징 파이프라인에서 사람의 검토/승인이 필요한 지점을
표준화된 방식으로 처리하기 위한 제어(CTR) 계층 모듈.

공개 API
--------
    from logosfuzz.control.hitl import (
        HITLManager, HITLPolicy, Checkpoint, DecisionType, ReviewStatus,
    )

    hitl = HITLManager.create()                 # 기본 정책 + JSON 저장소
    decision = hitl.request(Checkpoint.CVE_DISCLOSURE, target="CVE-DRAFT-1", ...)
"""
from .gate import HITLManager
from .models import (
    Checkpoint,
    Decision,
    DecisionType,
    ReviewItem,
    ReviewStatus,
    Stage,
)
from .policy import HITLPolicy, Mode
from .store import InMemoryReviewStore, JsonReviewStore, ReviewStore

__all__ = [
    "HITLManager",
    "HITLPolicy",
    "Mode",
    "Checkpoint",
    "Decision",
    "DecisionType",
    "ReviewItem",
    "ReviewStatus",
    "Stage",
    "ReviewStore",
    "JsonReviewStore",
    "InMemoryReviewStore",
]

__version__ = "0.1.0"  # CTR-06-02 골격 착수
