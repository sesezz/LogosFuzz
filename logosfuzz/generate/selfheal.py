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

from . import bazel_errors
from .compiler import Compiler
from .errors import BazelErrorReport
from .llm import LLMClient, RepairPromptBuilder, extract_code, extract_note
from .models import (
    GenerateReport,
    HarnessDraft,
    HealOutcome,
    HealRound,
)

# 라운드 종료 시 호출되는 콜백(진행 상황 표시/모니터링용)
RoundCallback = Callable[[HealRound], None]

# 빌드 로그 -> 분류 결과. 기본은 bazel_errors.classify.
Classifier = Callable[..., BazelErrorReport]


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

    # GEN-03-02 에러 분류기. 빌드 로그 전문을 받아 "무엇이 잘못됐고 무엇을 고쳐야
    # 하는지"를 돌려준다. None 이면 bazel_errors.classify 를 쓴다. 분류 결과는
    # 프롬프트 맨 앞에 실려 나가고, 라운드 기록에도 남는다.
    classifier: Optional[Classifier] = None

    # 분류기가 "LLM 재시도로는 못 고친다"고 본 결함에서 조기 중단할지.
    #
    # 왜 필요한가 - 순환 의존은 타깃을 쪼개야 풀린다. 그걸 모르면 루프가 라운드를
    # 전부 태우고 EXHAUSTED 로 끝나는데, 그동안 LLM 호출 비용만 나가고 결과는
    # 같다. 조기에 ESCALATED 로 끊고 사람에게 올리는 편이 낫다.
    stop_on_escalate: bool = True

    # 이 루프가 BUILD 파일도 고칠 수 있는가.
    #
    # 기본은 False 다 - 지금 루프는 하네스 **소스**만 LLM 에게 다시 쓰게 한다.
    # 그런데 분류 결과의 상당수(load() 누락, deps 추가, visibility)는 BUILD 를
    # 고쳐야 풀리고, 소스를 아무리 다시 써도 같은 에러가 반복된다. 분류가 정확할수록
    # 더 확신에 차서 헛도는 상황이라, 고칠 수 없는 산출물을 지목한 경우엔 라운드를
    # 쓰지 않고 바로 에스컬레이션한다.
    #
    # B 파트의 build_file_generator 가 컨트롤러에 편입돼 BUILD 재생성까지 한 몸으로
    # 돌게 되면 True 로 올린다.
    can_edit_build: bool = False

    def __post_init__(self) -> None:
        if self.prompt_builder is None:
            self.prompt_builder = RepairPromptBuilder()
        if self.classifier is None:
            self.classifier = bazel_errors.classify
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

    def _requested_target(self, draft: HarnessDraft) -> Optional[str]:
        """빌드를 요청한 Bazel 타깃 레이블. 알 수 없으면 None.

        분류기가 `no such target` 을 만났을 때 지목된 레이블이 **하네스 자신의
        타깃**인지 **의존 대상**인지 가르는 데 쓴다(코퍼스 발견 A). 처방이 정반대라
        이 값이 있으면 판별이 훨씬 정확해진다.
        """
        target = getattr(self.compiler, "requested_target", None)
        if target:
            return str(target)
        value = draft.context.get("bazel_target") if draft.context else None
        return str(value) if value else None

    def _classify(self, log: str, draft: HarnessDraft) -> Optional[BazelErrorReport]:
        """빌드 로그를 분류한다. 분류기가 죽어도 루프는 계속 간다.

        분류는 '거들 뿐'이다. 실패하면 힌트 없이 로그 원문만 들고 예전처럼 돌면
        되므로, 여기서 예외가 나도 자가치유 자체를 멈추지 않는다.
        """
        if self.classifier is None:
            return None
        target = self._requested_target(draft)
        if target:
            try:
                return self.classifier(log, requested_target=target)
            except TypeError:
                # 타깃 인자를 받지 않는 분류기를 끼운 경우. 인자 없이 다시 시도한다.
                pass
            except Exception:
                return None
        try:
            return self.classifier(log)
        except Exception:
            return None

    def _blocked_reason(self, report: Optional[BazelErrorReport]) -> str:
        """이 루프로는 못 고치는 결함이면 그 이유를, 아니면 빈 문자열."""
        if report is None or report.primary is None:
            return ""
        if self.stop_on_escalate and report.needs_human:
            return f"자동 수정 대상이 아님({report.primary.kind.value}): {report.primary.summary}"
        if not self.can_edit_build and bazel_errors.needs_build_file_edit(report):
            return (
                f"BUILD 파일을 고쳐야 풀리는 결함({report.primary.kind.value})이라 "
                f"하네스 소스 수정으로는 해결되지 않는다: {report.primary.summary}"
            )
        return ""

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

        report = None if result.ok else self._classify(result.log, draft)
        rounds.append(HealRound(index=0, source=source, compile_result=result,
                                classification=report))
        self._emit(rounds[-1])

        if result.ok:
            outcome = HealOutcome.SUCCESS
            return self._finish(draft, rounds, source, outcome, start)

        # 분류 결과가 "여기서는 못 고친다"면 라운드를 쓰지 않고 바로 끊는다.
        blocked = self._blocked_reason(report)
        if blocked:
            return self._finish(draft, rounds, source, HealOutcome.ESCALATED,
                                start, note=blocked)

        prev_signature = result.signature()

        # 라운드 1..max_round: LLM 수정 → 재컴파일
        for i in range(1, self.max_round + 1):
            prompt = self.prompt_builder.build(
                draft, source, result, round_idx=i, knowledge=self.knowledge,
                hint=bazel_errors.prompt_hint(report) if report is not None else "",
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

            report = None if result.ok else self._classify(result.log, draft)
            rounds.append(
                HealRound(index=i, source=source, compile_result=result,
                          repaired_by_llm=True, llm_note=note,
                          classification=report)
            )
            self._emit(rounds[-1])

            if result.ok:
                outcome = HealOutcome.SUCCESS
                break

            blocked = self._blocked_reason(report)
            if blocked:
                return self._finish(draft, rounds, source, HealOutcome.ESCALATED,
                                    start, note=blocked)

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
        note: str = "",
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
            self._escalate(draft, report, note=note)
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

    def _escalate(self, draft: HarnessDraft, report: GenerateReport,
                  note: str = "") -> None:
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
        # 마지막 라운드의 분류 결과를 같이 올린다. 검토자가 로그를 처음부터 읽지
        # 않고 "무엇이 왜 실패했는지"를 바로 보게 하려는 것이다.
        last_round = report.rounds[-1] if report.rounds else None
        classification = getattr(last_round, "classification", None)
        primary = getattr(classification, "primary", None)
        summary = (f"[{draft.logic_group}] 자가치유 {report.outcome.value} "
                   f"({report.rounds_used}라운드 소진)")
        if note:
            summary = f"{summary} - {note}"
        payload = {
            "logic_group": draft.logic_group,
            "compile_ok": False,
            "outcome": report.outcome.value,
            "rounds_used": report.rounds_used,
            "compile_log": last.error_digest() if last else "",
            "harness_code": report.final_source,
            "target_apis": draft.target_apis,
        }
        if note:
            payload["stop_reason"] = note
        if primary is not None:
            payload["diagnosis"] = primary.kind.value
            payload["fix_action"] = primary.action.value
            payload["fix_target"] = bazel_errors.fix_target_artifact(primary.action)
            payload["diagnosis_detail"] = dict(primary.detail)
        decision = self.hitl.request(
            Checkpoint.HARNESS_REVIEW,
            target=draft.logic_group,
            project=draft.project,
            summary=summary,
            payload=payload,
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
