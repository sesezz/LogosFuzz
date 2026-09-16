"""
GEN-03-02 자가 치유 루프 - 데모 (HITL 연동 포함)
================================================
실행: python -m logosfuzz.generate.demo
"""
from __future__ import annotations

from ..control.hitl import HITLManager, HITLPolicy
from ..control.hitl.store import InMemoryReviewStore
from .compiler import FakeCompiler
from .llm import ScriptedLLMClient
from .models import HarnessDraft, HealRound
from .selfheal import SelfHealLoop, summarize


def _on_round(r: HealRound) -> None:
    kind = "LLM수정" if r.repaired_by_llm else "초안"
    print(f"    · R{r.index} {kind}: {'OK' if r.ok else 'ERR'}")


def run() -> None:
    hitl = HITLManager(store=InMemoryReviewStore(), policy=HITLPolicy.default())
    compiler = FakeCompiler(error_message="expected '}' before end of input")

    good = "int LLVMFuzzerTestOneInput(const uint8_t*d,size_t n){return 0;} // COMPILE_OK"
    bad = "int LLVMFuzzerTestOneInput(const uint8_t*d,size_t n){return 0;"

    print("### 시나리오 A: 초안이 바로 컴파일 성공")
    loop = SelfHealLoop(compiler, ScriptedLLMClient([]), max_round=3,
                        hitl=hitl, on_round=_on_round)
    ra = loop.run(HarnessDraft("LG-ok", good, project="dlt-daemon",
                               target_apis=["dlt_parse"]))
    print(f"  → {ra.outcome.value}\n")

    print("### 시나리오 B: 1회 수정으로 치유 성공")
    fix_ok = ("고쳤습니다.\n```c\n"
              "int LLVMFuzzerTestOneInput(const uint8_t*d,size_t n){return 0;} // COMPILE_OK\n```")
    loop = SelfHealLoop(compiler, ScriptedLLMClient([fix_ok]), max_round=3,
                        hitl=hitl, on_round=_on_round)
    rb = loop.run(HarnessDraft("LG-heal", bad, project="dlt-daemon",
                               target_apis=["dlt_user_log"]))
    print(f"  → {rb.outcome.value} (LLM수정 {rb.rounds_used}라운드)\n")

    print("### 시나리오 C: max-round 소진 → 실패 → HITL 에스컬레이션")
    never = "여전히 문제.\n```c\n" + bad + "\n// still broken\n```"
    loop = SelfHealLoop(compiler, ScriptedLLMClient([never, never, never]),
                        max_round=3, stop_on_stagnation=False,
                        hitl=hitl, on_round=_on_round)
    rc = loop.run(HarnessDraft("LG-hard", bad, project="dlt-daemon",
                               target_apis=["uds_session"]))
    print(f"  → {rc.outcome.value}, HITL결정={rc.hitl_decision}, 항목={rc.hitl_item_id}\n")

    print("### 결과 요약 (GEN-03-00)")
    s = summarize([ra, rb, rc])
    print(f"  전체 {s['total']} / 성공 {s['success']} / 실패 {s['failed']}")
    for f in s["failed_groups"]:
        print(f"    실패: {f['group']} ({f['outcome']}) → HITL {f['hitl_item_id']}")

    print("\n### HITL 대기 큐 (logosfuzz review list로 처리)")
    for it in hitl.pending():
        print(f"    - {it.id} {it.checkpoint.value}: {it.summary}")


if __name__ == "__main__":
    run()
