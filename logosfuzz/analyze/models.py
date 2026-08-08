"""
ANA-05-03 지식 베이스 역피드백 및 하네스 재생성 - 데이터 모델
==============================================================

ANA-05-01(정탐/오탐 판별)이 오탐(FALSE_POSITIVE)으로 판정한 크래시에 대해
근본 원인을 분석하고, 그 결과를 지식베이스에 반영하기 위한 제안(diff)과
승인 이후 재생성 시도를 추적하는 타입을 정의한다.

기존 ERD(API_METADATA / HARNESS / CRASH_REPORT)를 그대로 참조하며, 여기서
새로 정의하는 타입은 그 레코드들을 잇는 "역피드백 절차"의 중간 산출물이다.
crash_id / api_id / harness_id 를 모든 타입이 함께 들고 다니는 것은
감사(audit) 추적성 요구사항 때문이다.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from ana_05_02_cve_reporting.schema import Verdict


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


class ProposalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


@dataclass
class CrashRecord:
    """ANA-05-01 산출물을 대신하는 최소 입력 계약(스텁).

    ANA-05-01이 실제로 구현되면 이 필드들만 채워 넘기면 된다. 이 저장소에는
    아직 정탐/오탐 판별 로직 자체가 없으므로(ANA-05-03만 단독으로 검증 가능하도록)
    verdict가 이미 확정된 값으로 들어온다고 전제한다.
    """

    crash_id: str
    api_id: int
    harness_id: str
    run_id: str
    asan_log: str
    verdict: Verdict
    confidence: float = 0.0

    def __post_init__(self) -> None:
        if self.verdict is not Verdict.FALSE_POSITIVE:
            raise ValueError(
                f"CrashRecord.verdict must be FALSE_POSITIVE for ANA-05-03 "
                f"(got {self.verdict.value!r}); this stage only runs after a "
                f"false-positive verdict"
            )


@dataclass
class RootCauseAnalysis:
    """오탐 원인 분석 함수(rootcause.py)의 출력."""

    crash_id: str
    api_id: int
    summary: str  # LLM이 요약한 오탐 근본 원인 (자연어)
    rationale: str = ""  # 요약 근거로 삼은 원문 발췌(있으면)
    model: str = ""  # 예: "deepseek-r1"
    analyzed_at: str = field(default_factory=now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "crash_id": self.crash_id,
            "api_id": self.api_id,
            "summary": self.summary,
            "rationale": self.rationale,
            "model": self.model,
            "analyzed_at": self.analyzed_at,
        }


@dataclass
class KBUpdateProposal:
    """KB 변경 제안(diff). 승인 전까지는 KB에 반영되지 않는다(HITL 게이트 대상)."""

    proposal_id: str
    crash_id: str
    api_id: int
    harness_id: str
    before_text: str  # 현재 오버라이드 텍스트(없으면 "")
    after_text: str  # 반영될 오버라이드 텍스트(root-cause 요약 기반)
    embedding: Optional[List[float]] = None
    status: ProposalStatus = ProposalStatus.PENDING
    created_at: str = field(default_factory=now_iso)
    decided_at: Optional[str] = None
    decided_by: Optional[str] = None
    rejection_reason: str = ""
    hitl_item_id: Optional[str] = None

    @staticmethod
    def new(
        crash_id: str,
        api_id: int,
        harness_id: str,
        before_text: str,
        after_text: str,
        embedding: Optional[List[float]] = None,
    ) -> "KBUpdateProposal":
        return KBUpdateProposal(
            proposal_id=new_id("kbprop"),
            crash_id=crash_id,
            api_id=api_id,
            harness_id=harness_id,
            before_text=before_text,
            after_text=after_text,
            embedding=embedding,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "crash_id": self.crash_id,
            "api_id": self.api_id,
            "harness_id": self.harness_id,
            "before_text": self.before_text,
            "after_text": self.after_text,
            "embedding": self.embedding,
            "status": self.status.value,
            "created_at": self.created_at,
            "decided_at": self.decided_at,
            "decided_by": self.decided_by,
            "rejection_reason": self.rejection_reason,
            "hitl_item_id": self.hitl_item_id,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "KBUpdateProposal":
        return cls(
            proposal_id=d["proposal_id"],
            crash_id=d["crash_id"],
            api_id=d["api_id"],
            harness_id=d["harness_id"],
            before_text=d.get("before_text", ""),
            after_text=d.get("after_text", ""),
            embedding=d.get("embedding"),
            status=ProposalStatus(d.get("status", "pending")),
            created_at=d.get("created_at", now_iso()),
            decided_at=d.get("decided_at"),
            decided_by=d.get("decided_by"),
            rejection_reason=d.get("rejection_reason", ""),
            hitl_item_id=d.get("hitl_item_id"),
        )


@dataclass
class RegenerationRecord:
    """승인된 제안이 유발한 재생성 시도 1건(감사 로그 대상)."""

    regen_id: str
    proposal_id: str
    crash_id: str
    api_id: int
    harness_id: str
    logic_group: str
    outcome: str  # GenerateReport.outcome.value 그대로 저장
    rounds_used: int
    compiled_ok: bool
    triggered_at: str = field(default_factory=now_iso)

    @staticmethod
    def new(
        proposal: "KBUpdateProposal",
        logic_group: str,
        outcome: str,
        rounds_used: int,
        compiled_ok: bool,
    ) -> "RegenerationRecord":
        return RegenerationRecord(
            regen_id=new_id("regen"),
            proposal_id=proposal.proposal_id,
            crash_id=proposal.crash_id,
            api_id=proposal.api_id,
            harness_id=proposal.harness_id,
            logic_group=logic_group,
            outcome=outcome,
            rounds_used=rounds_used,
            compiled_ok=compiled_ok,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "regen_id": self.regen_id,
            "proposal_id": self.proposal_id,
            "crash_id": self.crash_id,
            "api_id": self.api_id,
            "harness_id": self.harness_id,
            "logic_group": self.logic_group,
            "outcome": self.outcome,
            "rounds_used": self.rounds_used,
            "compiled_ok": self.compiled_ok,
            "triggered_at": self.triggered_at,
        }
