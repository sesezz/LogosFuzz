"""
CTR-06-02 HITL 인터페이스 - 개입 정책
=====================================

각 Checkpoint를 "완전 자동(AUTO)"으로 통과시킬지, "사람 검토 필수(MANUAL)"로
막을지, 아니면 "조건부(CONDITIONAL)"로 특정 조건에서만 사람을 부를지 결정한다.

이 정책 한 곳만 바꾸면 파이프라인을 완전 자동 운전 <-> 사람 감독 운전으로 전환할 수 있다.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, Optional

from .models import Checkpoint, Decision, DecisionType, ReviewItem


class Mode(str, Enum):
    AUTO = "auto"              # 사람 개입 없이 자동 결정
    MANUAL = "manual"          # 반드시 사람 검토
    CONDITIONAL = "conditional"  # predicate가 True일 때만 사람 검토


# 조건부 정책에서 "사람을 불러야 하는가?"를 판단하는 함수 시그니처
NeedsHumanFn = Callable[[ReviewItem], bool]
# 자동 결정 시 어떤 결정을 내릴지 정하는 함수 시그니처
AutoDeciderFn = Callable[[ReviewItem], Decision]


@dataclass
class CheckpointRule:
    mode: Mode = Mode.MANUAL
    needs_human: Optional[NeedsHumanFn] = None      # CONDITIONAL에서 사용
    auto_decider: Optional[AutoDeciderFn] = None    # AUTO/조건 미충족 시 사용

    def resolve_needs_human(self, item: ReviewItem) -> bool:
        if self.mode is Mode.MANUAL:
            return True
        if self.mode is Mode.AUTO:
            return False
        # CONDITIONAL
        return bool(self.needs_human and self.needs_human(item))

    def make_auto_decision(self, item: ReviewItem) -> Decision:
        if self.auto_decider:
            return self.auto_decider(item)
        # 기본 자동 결정: 승인
        return Decision(
            type=DecisionType.APPROVE,
            reviewer=f"auto:{self.mode.value}",
            comment="정책에 의한 자동 승인",
        )


# --------------------------------------------------------------------------- #
# 기본 조건부 판정 함수들 (스켈레톤 예시 - 실제 임계값은 팀에서 조정)
# --------------------------------------------------------------------------- #
def _low_confidence_crash(item: ReviewItem) -> bool:
    """ANA 정탐/오탐 신뢰도가 낮을 때만 사람 확인을 요청."""
    conf = item.payload.get("confidence")
    return conf is None or float(conf) < 0.8


def _harness_compile_failed(item: ReviewItem) -> bool:
    """컴파일 실패한 하네스만 사람 검토(성공본은 자동 통과)."""
    return not bool(item.payload.get("compile_ok", False))


@dataclass
class HITLPolicy:
    """체크포인트별 규칙 모음."""
    rules: Dict[Checkpoint, CheckpointRule] = field(default_factory=dict)
    default_rule: CheckpointRule = field(default_factory=lambda: CheckpointRule(Mode.MANUAL))

    def rule_for(self, checkpoint: Checkpoint) -> CheckpointRule:
        return self.rules.get(checkpoint, self.default_rule)

    # 편의 생성자 ----------------------------------------------------------- #
    @classmethod
    def default(cls) -> "HITLPolicy":
        """
        스켈레톤 기본 정책.

        - 취약점 공개(CVE_DISCLOSURE): 항상 사람 승인 필수(가장 민감).
        - 크래시 트리아지(CRASH_TRIAGE): 신뢰도 낮은 건만 사람 확인.
        - 하네스 검토(HARNESS_REVIEW): 컴파일 실패본만 사람 확인.
        - 스케줄/호환성: 기본 자동, 필요 시 MANUAL로 전환.
        """
        return cls(
            rules={
                Checkpoint.COMPAT_CHECK: CheckpointRule(Mode.AUTO),
                Checkpoint.SCHEDULE_REVIEW: CheckpointRule(Mode.AUTO),
                Checkpoint.HARNESS_REVIEW: CheckpointRule(
                    Mode.CONDITIONAL, needs_human=_harness_compile_failed
                ),
                Checkpoint.CRASH_TRIAGE: CheckpointRule(
                    Mode.CONDITIONAL, needs_human=_low_confidence_crash
                ),
                Checkpoint.CVE_DISCLOSURE: CheckpointRule(Mode.MANUAL),
            }
        )

    @classmethod
    def fully_manual(cls) -> "HITLPolicy":
        """모든 체크포인트에서 사람 검토(감독 모드)."""
        return cls(default_rule=CheckpointRule(Mode.MANUAL))

    @classmethod
    def fully_auto(cls) -> "HITLPolicy":
        """모든 체크포인트 자동 통과(무인 운전 - CVE 공개까지 자동이므로 주의)."""
        return cls(default_rule=CheckpointRule(Mode.AUTO))
