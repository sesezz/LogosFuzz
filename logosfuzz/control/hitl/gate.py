"""
CTR-06-02 HITL 인터페이스 - 게이트/매니저
=========================================

HITLManager는 파이프라인 각 단계가 호출하는 진입점이다.

핵심 메서드
-----------
- request(...)  : 체크포인트에 리뷰를 요청한다.
                  정책이 AUTO면 즉시 자동 결정을 반환하고,
                  MANUAL(또는 조건 충족)이면 PENDING 항목을 저장한 뒤
                  * interactive=True  -> 콘솔에서 즉시 사람에게 질의(블로킹)
                  * interactive=False -> DEFER 결정 반환(비동기 검토 대기)
- decide(...)   : 저장된 PENDING 항목에 사람이 결정을 기록(CLI가 사용).
- pending()/get()/stats() : 조회.

이 게이트는 "골격"이다: request() 이후 각 단계가 Decision을 받아 어떻게 흐를지
(예: REJECT -> 하네스 재생성)는 hooks.py의 예시 및 각 단계 구현에서 연결한다.

활성화된 게이트
---------------
- CrashApprovalGate (CRASH_TRIAGE, 4주차): ANA-05-01 판정을 받은 고유 크래시는
  이 게이트를 통과해야만 "검증된 고유 크래시"가 된다. ``logosfuzz analyze`` 가
  기본으로 태운다(아래 클래스 docstring 참조).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from .models import (
    Checkpoint,
    Decision,
    DecisionType,
    DECISION_STATUS,
    ReviewItem,
    ReviewStatus,
    Stage,
)
from .policy import HITLPolicy
from .store import JsonReviewStore, ReviewStore

# interactive 모드에서 사람에게 물어보는 함수(테스트 시 주입 가능)
PromptFn = Callable[[ReviewItem], Decision]


@dataclass
class HITLManager:
    store: ReviewStore
    policy: HITLPolicy
    interactive: bool = False
    reviewer: str = "operator"
    prompt_fn: Optional[PromptFn] = None  # None이면 기본 콘솔 프롬프트 사용

    # -- 팩토리 ------------------------------------------------------------- #
    @classmethod
    def create(
        cls,
        *,
        store: Optional[ReviewStore] = None,
        policy: Optional[HITLPolicy] = None,
        interactive: bool = False,
        reviewer: str = "operator",
    ) -> "HITLManager":
        return cls(
            store=store or JsonReviewStore(),
            policy=policy or HITLPolicy.default(),
            interactive=interactive,
            reviewer=reviewer,
        )

    # -- 리뷰 요청(파이프라인 단계가 호출) --------------------------------- #
    def request(
        self,
        checkpoint: Checkpoint,
        target: str,
        *,
        summary: str = "",
        payload: Optional[Dict[str, Any]] = None,
        project: str = "",
    ) -> Decision:
        """
        체크포인트에 리뷰를 요청하고 Decision을 반환한다.

        반환된 Decision.type이:
          APPROVE/EDIT -> 다음 단계 진행(EDIT면 effective payload 사용)
          REJECT       -> 산출물 폐기/재시도
          SKIP         -> 이 항목 건너뜀
          DEFER        -> 비동기 검토 대기(항목은 PENDING으로 저장됨)
        """
        item = ReviewItem(
            checkpoint=checkpoint,
            target=target,
            summary=summary or f"{checkpoint.value}: {target}",
            payload=payload or {},
            project=project,
        )
        rule = self.policy.rule_for(checkpoint)

        # 1) 정책상 사람이 필요없으면 자동 결정
        if not rule.resolve_needs_human(item):
            decision = rule.make_auto_decision(item)
            self._apply_decision(item, decision, persist=True)
            return decision

        # 2) 사람 필요 -> PENDING 저장
        self.store.add(item)

        # 3) 블로킹(interactive) 모드면 즉시 질의
        if self.interactive:
            decision = (self.prompt_fn or self._console_prompt)(item)
            self._apply_decision(item, decision)
            return decision

        # 4) 비동기 모드 -> 보류 반환
        return Decision(type=DecisionType.DEFER, reviewer="system",
                        comment="사람 검토 대기(logosfuzz review 로 처리)")

    # -- 사람이 나중에 결정(CLI에서 호출) ---------------------------------- #
    def decide(
        self,
        item_id: str,
        decision_type: DecisionType,
        *,
        reviewer: Optional[str] = None,
        comment: str = "",
        edited_payload: Optional[Dict[str, Any]] = None,
    ) -> ReviewItem:
        item = self.store.get(item_id)
        if item is None:
            raise KeyError(f"리뷰 항목을 찾을 수 없음: {item_id}")
        if not item.is_pending:
            raise ValueError(f"이미 처리된 항목입니다(status={item.status.value})")
        decision = Decision(
            type=decision_type,
            reviewer=reviewer or self.reviewer,
            comment=comment,
            edited_payload=edited_payload,
        )
        self._apply_decision(item, decision)
        return item

    # -- 조회 -------------------------------------------------------------- #
    def pending(self, **kw) -> List[ReviewItem]:
        return self.store.pending(**kw)

    def get(self, item_id: str) -> Optional[ReviewItem]:
        return self.store.get(item_id)

    def stats(self) -> Dict[str, int]:
        counts: Dict[str, int] = {s.value: 0 for s in ReviewStatus}
        for it in self.store.list():
            counts[it.status.value] += 1
        counts["total"] = sum(v for k, v in counts.items() if k != "total")
        return counts

    # -- 내부 -------------------------------------------------------------- #
    def _apply_decision(self, item: ReviewItem, decision: Decision, persist: bool = True) -> None:
        item.decision = decision
        item.status = DECISION_STATUS[decision.type]
        if persist:
            # add()로 이미 저장된 경우 update, 아니면 add
            if self.store.get(item.id) is not None:
                self.store.update(item)
            else:
                self.store.add(item)

    def _console_prompt(self, item: ReviewItem) -> Decision:
        """기본 콘솔 프롬프트(블로킹 모드). 실제 TUI/웹 UI로 교체 가능."""
        print()
        print("=" * 68)
        print(f"[HITL] 검토 요청  #{item.id}  ({item.checkpoint.value} / {item.stage.value})")
        print(f"  대상   : {item.target}")
        print(f"  요약   : {item.summary}")
        if item.payload:
            print("  내용   :")
            for k, v in item.payload.items():
                sval = str(v)
                if len(sval) > 200:
                    sval = sval[:200] + " …(생략)"
                print(f"    - {k}: {sval}")
        print("-" * 68)
        print("  [a]승인  [r]반려  [s]건너뜀  [d]보류")
        choice = input("  결정> ").strip().lower()[:1]
        mapping = {
            "a": DecisionType.APPROVE,
            "r": DecisionType.REJECT,
            "s": DecisionType.SKIP,
            "d": DecisionType.DEFER,
        }
        dtype = mapping.get(choice, DecisionType.DEFER)
        comment = input("  코멘트(선택)> ").strip()
        return Decision(type=dtype, reviewer=self.reviewer, comment=comment)


# --------------------------------------------------------------------------- #
# CRASH_TRIAGE: 크래시 승인 게이트 (4주차 활성화)
# --------------------------------------------------------------------------- #
# 판정 문자열은 ANA 의 Verdict 값과 같다. ANA 를 import 하지 않고 문자열 계약으로만
# 연결한다(analyze.models 와 같은 순환 의존 차단 원칙).
TRUE_POSITIVE = "true_positive"
FALSE_POSITIVE = "false_positive"


@dataclass
class CrashApproval:
    """크래시 1건의 승인 게이트 결과.

    Attributes:
        crash_id: 게이트 대상(ANA-05-04 cluster_id).
        auto_verdict: ANA-05-01 자동 판정.
        final_verdict: 승인으로 확정된 판정. 아직 확정 전(검토 대기/건너뜀)이면 None.
        status: 리뷰 항목 상태(approved/edited/rejected/skipped/pending).
        reviewer: 결정한 사람 또는 ``auto:<mode>``.
        item_id: 리뷰 저장소 항목 id (``logosfuzz review show <id>``).
        reused: 이전 실행에서 이미 내려진 결정을 재사용했는가.
    """

    crash_id: str
    auto_verdict: str
    final_verdict: Optional[str]
    status: str
    reviewer: str = ""
    item_id: str = ""
    comment: str = ""
    reused: bool = False

    @property
    def verified(self) -> bool:
        """승인 게이트를 통과한 정탐 = 검증된 고유 크래시."""
        return self.final_verdict == TRUE_POSITIVE

    @property
    def by_human(self) -> bool:
        return bool(self.reviewer) and not self.reviewer.startswith(("auto:", "system"))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "crash_id": self.crash_id,
            "auto_verdict": self.auto_verdict,
            "final_verdict": self.final_verdict,
            "status": self.status,
            "reviewer": self.reviewer,
            "by_human": self.by_human,
            "item_id": self.item_id,
            "comment": self.comment,
            "reused": self.reused,
            "verified": self.verified,
        }


def final_verdict_for(item: ReviewItem, auto_verdict: str) -> Optional[str]:
    """리뷰 결정 → 확정 판정.

    - APPROVE : 자동 판정을 그대로 확정
    - EDIT    : 사람이 고친 ``llm_verdict``(정/오탐 뒤집기)
    - REJECT  : 검증된 크래시로 인정하지 않음 → 오탐으로 확정
    - SKIP/대기: 확정하지 않음(None)
    """
    decision = item.decision
    if decision is None or item.is_pending:
        return None
    if decision.type == DecisionType.APPROVE:
        return auto_verdict
    if decision.type == DecisionType.EDIT:
        edited = decision.edited_payload or {}
        return str(edited.get("llm_verdict") or edited.get("verdict") or auto_verdict)
    if decision.type == DecisionType.REJECT:
        return FALSE_POSITIVE
    return None


class CrashApprovalGate:
    """CRASH_TRIAGE 체크포인트를 실제 분석 흐름에 연결한 승인 게이트.

    판정마다 :meth:`HITLManager.request` 를 부르고, 정책(기본: needs_review 이거나
    신뢰도 0.8 미만이면 사람)에 따라 자동 승인되거나 검토 큐에 쌓인다. 사람이
    ``logosfuzz review approve|edit|reject <id>`` 로 결정한 뒤 ``analyze`` 를 다시
    돌리면 그 결정이 반영된다.

    **재실행에 안전하다.** 같은 프로젝트·같은 크래시(cluster_id)에 이미 항목이
    있으면 새로 쌓지 않는다.
    - 사람이 결정한 항목: 그대로 재사용한다(사람의 판단이 자동 판정보다 우선).
    - 검토 대기 항목: 대기 상태를 그대로 돌려준다(중복 항목을 만들지 않음).
    - 자동 결정 항목: 자동 판정이 그때와 같으면 재사용, 달라졌으면(판별기·KB가
      바뀐 경우) 새로 요청한다.
    """

    def __init__(self, hitl: HITLManager, project: str = "") -> None:
        self.hitl = hitl
        self.project = project

    def _existing(self, crash_id: str) -> Optional[ReviewItem]:
        items = [
            it for it in self.hitl.store.list(checkpoint=Checkpoint.CRASH_TRIAGE,
                                              project=self.project)
            if it.target == crash_id
        ]
        return items[-1] if items else None

    @staticmethod
    def _approval(item: ReviewItem, auto_verdict: str, reused: bool) -> CrashApproval:
        decision = item.decision
        return CrashApproval(
            crash_id=item.target,
            auto_verdict=auto_verdict,
            final_verdict=final_verdict_for(item, auto_verdict),
            status=item.status.value,
            reviewer=decision.reviewer if decision else "",
            item_id=item.id,
            comment=decision.comment if decision else "",
            reused=reused,
        )

    def review(
        self,
        crash_id: str,
        verdict: str,
        confidence: float,
        *,
        summary: str = "",
        payload: Optional[Dict[str, Any]] = None,
    ) -> CrashApproval:
        """크래시 1건을 게이트에 태운다."""
        existing = self._existing(crash_id)
        if existing is not None:
            decided_by_auto = (existing.decision is not None
                               and existing.decision.reviewer.startswith("auto:"))
            same_verdict = existing.payload.get("llm_verdict") == verdict
            if existing.is_pending or not decided_by_auto or same_verdict:
                prior = str(existing.payload.get("llm_verdict") or verdict)
                return self._approval(existing, prior, reused=True)

        body = dict(payload or {})
        body.update({"crash_signature": body.get("crash_signature", crash_id),
                     "llm_verdict": verdict, "confidence": float(confidence)})
        self.hitl.request(
            Checkpoint.CRASH_TRIAGE,
            target=crash_id,
            project=self.project,
            summary=summary or f"{crash_id} → 판정={verdict} (conf={confidence:.2f})",
            payload=body,
        )
        item = self._existing(crash_id)
        return self._approval(item, verdict, reused=False)
