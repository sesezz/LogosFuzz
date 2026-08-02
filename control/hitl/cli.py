"""
CTR-06-02 HITL 인터페이스 - CLI (`logosfuzz review`)
====================================================

사람이 대기 중인 리뷰 항목을 처리하는 명령줄 인터페이스.

사용 예:
    logosfuzz review list [--project P] [--all]
    logosfuzz review show <id>
    logosfuzz review approve <id> [-m "코멘트"]
    logosfuzz review reject  <id> [-m "..."]
    logosfuzz review skip    <id>
    logosfuzz review stats

이 모듈은 argparse 서브파서를 조립해 반환하는 build_parser()와,
상위 logosfuzz CLI에 연결하기 위한 register(subparsers) 진입점을 제공한다.
"""
from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from .gate import HITLManager
from .models import Checkpoint, DecisionType, ReviewItem, ReviewStatus
from .policy import HITLPolicy
from .store import JsonReviewStore


# --------------------------------------------------------------------------- #
# 출력 헬퍼
# --------------------------------------------------------------------------- #
def _fmt_row(it: ReviewItem) -> str:
    return (
        f"{it.id:<12} {it.status.value:<9} {it.checkpoint.value:<16} "
        f"{(it.project or '-'):<12} {it.summary}"
    )


def _print_list(items: List[ReviewItem]) -> None:
    if not items:
        print("(항목 없음)")
        return
    print(f"{'ID':<12} {'STATUS':<9} {'CHECKPOINT':<16} {'PROJECT':<12} SUMMARY")
    print("-" * 78)
    for it in items:
        print(_fmt_row(it))


def _print_detail(it: ReviewItem) -> None:
    print(f"ID        : {it.id}")
    print(f"체크포인트: {it.checkpoint.value}  (stage={it.stage.value})")
    print(f"프로젝트  : {it.project or '-'}")
    print(f"대상      : {it.target}")
    print(f"상태      : {it.status.value}")
    print(f"생성시각  : {it.created_at}")
    print(f"요약      : {it.summary}")
    print("payload   :")
    for k, v in it.payload.items():
        sval = str(v)
        if len(sval) > 500:
            sval = sval[:500] + " …(생략)"
        print(f"  {k}: {sval}")
    if it.decision:
        d = it.decision
        print("결정      :")
        print(f"  type={d.type.value} reviewer={d.reviewer} at={d.decided_at}")
        if d.comment:
            print(f"  comment={d.comment}")


# --------------------------------------------------------------------------- #
# 매니저 생성
# --------------------------------------------------------------------------- #
def _manager(args: argparse.Namespace) -> HITLManager:
    store = JsonReviewStore(getattr(args, "store", None) or JsonReviewStore.DEFAULT_PATH)
    return HITLManager(store=store, policy=HITLPolicy.default(),
                       reviewer=getattr(args, "reviewer", None) or "operator")


# --------------------------------------------------------------------------- #
# 서브커맨드 핸들러
# --------------------------------------------------------------------------- #
def _cmd_list(args: argparse.Namespace) -> int:
    m = _manager(args)
    status = None if args.all else ReviewStatus.PENDING
    cp = Checkpoint(args.checkpoint) if args.checkpoint else None
    items = m.store.list(status=status, checkpoint=cp, project=args.project)
    _print_list(items)
    return 0


def _cmd_show(args: argparse.Namespace) -> int:
    m = _manager(args)
    it = m.get(args.id)
    if it is None:
        print(f"항목을 찾을 수 없음: {args.id}", file=sys.stderr)
        return 1
    _print_detail(it)
    return 0


def _decide(args: argparse.Namespace, dtype: DecisionType) -> int:
    m = _manager(args)
    try:
        it = m.decide(args.id, dtype, comment=getattr(args, "message", "") or "")
    except (KeyError, ValueError) as e:
        print(f"오류: {e}", file=sys.stderr)
        return 1
    print(f"#{it.id} → {it.status.value}")
    return 0


def _cmd_stats(args: argparse.Namespace) -> int:
    m = _manager(args)
    st = m.stats()
    for k in ("pending", "approved", "rejected", "edited", "skipped", "expired", "total"):
        print(f"  {k:<9}: {st.get(k, 0)}")
    return 0


# --------------------------------------------------------------------------- #
# 파서 조립
# --------------------------------------------------------------------------- #
def register(subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """
    상위 logosfuzz 파서에 `review` 서브커맨드를 등록한다.

        p = argparse.ArgumentParser(prog="logosfuzz")
        sub = p.add_subparsers(dest="command")
        register(sub)   # -> logosfuzz review ...
    """
    review = subparsers.add_parser("review", help="HITL 리뷰 항목 관리 (CTR-06-02)")
    review.add_argument("--store", help="리뷰 저장소 경로(JSON)")
    review.add_argument("--reviewer", help="리뷰어 이름/ID")
    rsub = review.add_subparsers(dest="review_command", required=True)

    p_list = rsub.add_parser("list", help="리뷰 항목 목록")
    p_list.add_argument("--project", help="프로젝트로 필터")
    p_list.add_argument("--checkpoint", choices=[c.value for c in Checkpoint])
    p_list.add_argument("--all", action="store_true", help="처리 완료 항목도 표시")
    p_list.set_defaults(func=_cmd_list)

    p_show = rsub.add_parser("show", help="항목 상세")
    p_show.add_argument("id")
    p_show.set_defaults(func=_cmd_show)

    for name, dtype, helptext in [
        ("approve", DecisionType.APPROVE, "승인"),
        ("reject", DecisionType.REJECT, "반려"),
        ("skip", DecisionType.SKIP, "건너뜀"),
    ]:
        p = rsub.add_parser(name, help=helptext)
        p.add_argument("id")
        p.add_argument("-m", "--message", default="", help="코멘트")
        p.set_defaults(func=lambda a, _d=dtype: _decide(a, _d))

    p_stats = rsub.add_parser("stats", help="상태별 집계")
    p_stats.set_defaults(func=_cmd_stats)

    return review


def build_parser() -> argparse.ArgumentParser:
    """review 서브커맨드만 담은 독립 실행용 파서(테스트/단독 실행)."""
    parser = argparse.ArgumentParser(prog="logosfuzz")
    sub = parser.add_subparsers(dest="command", required=True)
    register(sub)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
