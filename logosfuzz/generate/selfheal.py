"""
GEN-03-02 컴파일 에러 자가 치유 루프 ★
======================================

동작
----
1. 초안(HarnessDraft)을 컴파일한다.
2. 성공하면 종료(SUCCESS).
3. 실패하면 컴파일 에러를 LLM에 되먹여 수정 소스를 받고 재컴파일한다.
4. --max-round 만큼 3을 반복한다.
5. 그래도 실패하면:
     - 같은 에러가 반복되면 STAGNATED(조기 중단),
     - 아니면 라운드 소진으로 EXHAUSTED.
   두 경우 모두 HITL(HARNESS_REVIEW)로 자동 에스컬레이션할 수 있다(선택).

설계서(GEN-03-00) 대응:
    logosfuzz generate --model <name> --max-round <n>
    "컴파일 오류 로그를 LLM에 재입력하여 자동 수정 후 재컴파일,
     --max-round에 지정된 횟수까지 반복. 실패 시 자기 자신으로 되돌아가는 재시도 루프."
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from .compiler import Compiler
from .llm import LLMClient, RepairPromptBuilder, extract_code, extract_note
from .models import (
    GenerateReport,
    HarnessDraft,
    HealOutcome,
    HealRound,
)

# 라운드 종료 시 호출되는 콜백(진행 상황 표시/모니터링용)
RoundCallback = Callable[[HealRound], None]


@dataclass
class SelfHealLoop:
    """GEN-03-02 자가 치유 루프."""

    compiler: Compiler
    llm: LLMClient
    max_round: int = 3
    prompt_builder: Optional[RepairPromptBuilder] = None
    stop_on_stagnation: bool = True     # 동일 에러 2회 연속 시 조기 중단
    hitl: Optional[object] = None       # logosfuzz.control.hitl.HITLManager (선택)
    on_round: Optional[RoundCallback] = None
    knowledge: Optional[Dict[str, str]] = None  # RAG 힌트(선택)
    # 초안과 **모든 수정 라운드**에 적용할 후처리. `hygiene.sanitize_harness` 를
    # 넣으면 LLM 이 덧붙인 대상 함수 재선언을 결정적으로 걷어낸다.
    #
    # 초안에만 걸면 소용이 없다 - 수정 라운드에서 LLM 이 같은 선언을 다시 써 넣어
    # `conflicting types` 가 부활하고, 루프는 같은 에러를 반복하다 정체로 끝난다.
    # 그래서 훅을 루프 안에 둔다.
    sanitize: Optional[Callable[[str, HarnessDraft], str]] = None

    def __post_init__(self) -> None:
        if self.prompt_builder is None:
            self.prompt_builder = RepairPromptBuilder()
        if self.max_round < 0:
            raise ValueError("max_round는 0 이상이어야 합니다")

    # --------------------------------------------------------------------- #
    def _clean(self, source: str, draft: HarnessDraft) -> str:
        """후처리 훅. 실패해도 루프를 멈추지 않는다."""
        if self.sanitize is None:
            return source
        try:
            return self.sanitize(source, draft)
        except Exception:
            return source

    def run(self, draft: HarnessDraft) -> GenerateReport:
        start = time.monotonic()
        rounds: List[HealRound] = []
        source = self._clean(draft.source, draft)
        outcome = HealOutcome.EXHAUSTED

        # 라운드 0: 초안 컴파일
        try:
            result = self.compiler.compile(draft, source)
        except Exception as e:  # 컴파일러 백엔드 예외
            return self._error_report(draft, rounds, start, f"컴파일러 예외: {e}")

        rounds.append(HealRound(index=0, source=source, compile_result=result))
        self._emit(rounds[-1])

        if result.ok:
            outcome = HealOutcome.SUCCESS
            return self._finish(draft, rounds, source, outcome, start)

        prev_signature = result.signature()

        # 라운드 1..max_round: LLM 수정 → 재컴파일
        for i in range(1, self.max_round + 1):
            prompt = self.prompt_builder.build(
                draft, source, result, round_idx=i, knowledge=self.knowledge
            )
            try:
                response = self.llm.complete(
                    prompt, system=self.prompt_builder.system_prompt()
                )
            except Exception as e:
                return self._error_report(draft, rounds, start, f"LLM 예외: {e}")

            fixed = extract_code(response)
            note = extract_note(response)
            if fixed:
                fixed = self._clean(fixed, draft)
            if not fixed or fixed == source:
                # LLM이 변화를 못 만들면 정체로 간주
                outcome = HealOutcome.STAGNATED
                break
            source = fixed

            try:
                result = self.compiler.compile(draft, source)
            except Exception as e:
                return self._error_report(draft, rounds, start, f"컴파일러 예외: {e}")

            rounds.append(
                HealRound(index=i, source=source, compile_result=result,
                          repaired_by_llm=True, llm_note=note)
            )
            self._emit(rounds[-1])

            if result.ok:
                outcome = HealOutcome.SUCCESS
                break

            sig = result.signature()
            if self.stop_on_stagnation and sig and sig == prev_signature:
                outcome = HealOutcome.STAGNATED
                break
            prev_signature = sig
        else:
            outcome = HealOutcome.EXHAUSTED

        return self._finish(draft, rounds, source, outcome, start)

    def run_many(self, drafts: List[HarnessDraft]) -> List[GenerateReport]:
        """여러 로직 그룹을 순차 처리(설계서: 그룹별 순차 생성)."""
        return [self.run(d) for d in drafts]

    # --------------------------------------------------------------------- #
    def _emit(self, rnd: HealRound) -> None:
        if self.on_round:
            self.on_round(rnd)

    def _finish(
        self,
        draft: HarnessDraft,
        rounds: List[HealRound],
        source: str,
        outcome: HealOutcome,
        start: float,
    ) -> GenerateReport:
        report = GenerateReport(
            logic_group=draft.logic_group,
            project=draft.project,
            outcome=outcome,
            rounds=rounds,
            final_source=source,
            elapsed_sec=time.monotonic() - start,
        )
        if not report.success:
            self._escalate(draft, report)
        return report

    def _error_report(self, draft, rounds, start, msg) -> GenerateReport:
        report = GenerateReport(
            logic_group=draft.logic_group,
            project=draft.project,
            outcome=HealOutcome.ERROR,
            rounds=rounds,
            final_source=rounds[-1].source if rounds else draft.source,
            elapsed_sec=time.monotonic() - start,
        )
        report.hitl_decision = msg
        return report

    def _escalate(self, draft: HarnessDraft, report: GenerateReport) -> None:
        """
        실패한 하네스를 HITL HARNESS_REVIEW로 올린다(연결돼 있을 때만).
        정책이 CONDITIONAL(compile_ok=False → 사람 검토)이므로 큐에 쌓인다.
        """
        if self.hitl is None:
            return
        try:
            from ..control.hitl.models import Checkpoint  # 지연 import(순환 방지)
        except Exception:
            return
        last = report.last_compile
        decision = self.hitl.request(
            Checkpoint.HARNESS_REVIEW,
            target=draft.logic_group,
            project=draft.project,
            summary=f"[{draft.logic_group}] 자가치유 {report.outcome.value} "
                    f"({report.rounds_used}라운드 소진)",
            payload={
                "logic_group": draft.logic_group,
                "compile_ok": False,
                "outcome": report.outcome.value,
                "rounds_used": report.rounds_used,
                "compile_log": last.error_digest() if last else "",
                "harness_code": report.final_source,
                "target_apis": draft.target_apis,
            },
        )
        report.hitl_decision = decision.type.value
        # 방금 쌓인 PENDING 항목 id를 기록(있으면)
        pend = [it for it in self.hitl.pending(project=draft.project)
                if it.target == draft.logic_group]
        if pend:
            report.hitl_item_id = pend[-1].id


def summarize(reports: List[GenerateReport]) -> Dict[str, object]:
    """
    설계서 GEN-03-00 '결과 요약': 성공/실패 그룹 수와 실패 로그 경로 출력.
    """
    ok = [r for r in reports if r.success]
    fail = [r for r in reports if not r.success]
    return {
        "total": len(reports),
        "success": len(ok),
        "failed": len(fail),
        "success_groups": [r.logic_group for r in ok],
        "failed_groups": [
            {"group": r.logic_group, "outcome": r.outcome.value,
             "rounds_used": r.rounds_used, "hitl_item_id": r.hitl_item_id}
            for r in fail
        ],
    }
