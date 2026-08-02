"""
GEN-03 하네스 생성 - CLI (`logosfuzz generate`)
===============================================

    logosfuzz generate --model <name> --max-round <n> [--project P]
                       [--cc clang] [--demo]

- 기본: SubprocessCompiler + OpenAILLMClient(골격) 조합. LLM 미연결 시 안내.
- --demo: FakeCompiler + ScriptedLLMClient로 루프 흐름을 즉시 시연.

상위 logosfuzz CLI에는 register(subparsers)로 붙인다.
"""
from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from .compiler import FakeCompiler, SubprocessCompiler
from .llm import OpenAILLMClient, ScriptedLLMClient
from .models import HarnessDraft, HealRound
from .selfheal import SelfHealLoop, summarize


def _print_round(rnd: HealRound) -> None:
    tag = "OK " if rnd.ok else "ERR"
    kind = "LLM수정" if rnd.repaired_by_llm else "초안  "
    n_err = len(rnd.compile_result.errors)
    print(f"  [R{rnd.index}] {kind} → {tag}"
          + ("" if rnd.ok else f" (에러 {n_err}개)"))


def _demo_drafts(project: str) -> List[HarnessDraft]:
    good = "int LLVMFuzzerTestOneInput(const uint8_t*d,size_t n){return 0;} // COMPILE_OK"
    bad = "int LLVMFuzzerTestOneInput(const uint8_t*d,size_t n){return 0;"  # 중괄호 누락
    return [
        HarnessDraft(logic_group="LG-can-parse", source=good, project=project,
                     target_apis=["can_parse", "can_free"]),
        HarnessDraft(logic_group="LG-uds-session", source=bad, project=project,
                     target_apis=["uds_open", "uds_send"]),
    ]


def _cmd_generate(args: argparse.Namespace) -> int:
    project = args.project or "demo-project"

    if args.demo:
        compiler = FakeCompiler()
        # 라운드1에서 마커를 추가해 '수정 성공'을 흉내내는 스크립트 응답
        llm = ScriptedLLMClient([
            "수정했습니다.\n```c\nint LLVMFuzzerTestOneInput(const uint8_t*d,size_t n)"
            "{return 0;} // COMPILE_OK\n```",
        ])
        drafts = _demo_drafts(project)
    else:
        compiler = SubprocessCompiler(cc=args.cc)
        llm = OpenAILLMClient(model=args.model)
        # 실사용에서는 GEN-03-01 초안 생성기가 drafts를 제공한다.
        print("※ 실사용 모드: GEN-03-01 초안 생성기를 연결해 drafts를 공급하세요.",
              file=sys.stderr)
        print("  지금은 데모 초안으로 대체합니다(--demo 권장).", file=sys.stderr)
        drafts = _demo_drafts(project)

    hitl = None
    if args.hitl:
        try:
            from ..control.hitl import HITLManager, HITLPolicy
            hitl = HITLManager.create(policy=HITLPolicy.default())
        except Exception as e:
            print(f"HITL 연결 실패(무시): {e}", file=sys.stderr)

    loop = SelfHealLoop(
        compiler=compiler, llm=llm, max_round=args.max_round,
        hitl=hitl, on_round=_print_round,
    )

    reports = []
    for d in drafts:
        print(f"\n▶ {d.logic_group}  (max-round={args.max_round})")
        rep = loop.run(d)
        print(f"  결과: {rep.outcome.value} (LLM수정 {rep.rounds_used}라운드)"
              + (f", HITL={rep.hitl_decision}" if rep.hitl_decision else ""))
        reports.append(rep)

    s = summarize(reports)
    print("\n=== 결과 요약 (GEN-03-00) ===")
    print(f"  전체 {s['total']} / 성공 {s['success']} / 실패 {s['failed']}")
    if s["failed_groups"]:
        print("  실패 그룹:")
        for f in s["failed_groups"]:
            print(f"    - {f['group']}: {f['outcome']} (HITL={f['hitl_item_id']})")
    return 0 if s["failed"] == 0 else 2


def register(subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:
    p = subparsers.add_parser("generate", help="LLM 하네스 생성 + 자가 치유 (GEN-03)")
    p.add_argument("--model", default="gpt-4o-mini", help="LLM 모델명")
    p.add_argument("--max-round", type=int, default=3, help="자가 치유 최대 반복 횟수")
    p.add_argument("--project", help="프로젝트명")
    p.add_argument("--cc", default="clang", help="컴파일러 실행 파일")
    p.add_argument("--hitl", action="store_true", help="실패 시 HITL로 에스컬레이션")
    p.add_argument("--demo", action="store_true", help="가짜 컴파일러/LLM로 흐름 시연")
    p.set_defaults(func=_cmd_generate)
    return p


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="logosfuzz")
    sub = parser.add_subparsers(dest="command", required=True)
    register(sub)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
