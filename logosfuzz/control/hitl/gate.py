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
