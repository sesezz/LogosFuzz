"""
ANA-05-03 STEP 4: 재생성 트리거 (GEN-03-01 재호출 -> GEN-03-02 자가치유)
=========================================================================

승인된 KB 오버라이드를 반영한 컨텍스트로 새 하네스 초안을 만들고(“GEN-03-01
재호출”), 실제로 동작하는 GEN-03-02 `SelfHealLoop`(컴파일 자가치유 루프)에
태워 컴파일 성공 여부까지 검증한다.

GEN-03-01(초안 생성)은 이 저장소에 재사용 가능한 형태로 구현되어 있지
않다 - `logosfuzz/generate/llm_harness_generator.py`는 하드코딩된 데모 데이터와
OpenAI 직접 호출 전용 `__main__` 스크립트라 함수로 불러 쓸 수 없다. 그래서
"GEN-03-01 재호출"은 이 모듈이 KB 컨텍스트(오버라이드 포함)로 프롬프트를
구성해 `LLMClient`에 초안을 요청하는 `_draft_via_llm()`으로 대체한다.
GEN-03-01이 실제로 구현되면 이 함수만 그 구현으로 교체하면 된다.

무한루프 방지: `SelfHealLoop.max_round`가 이미 GEN-03-02 자체의 컴파일
재시도 상한이므로 새로 만들지 않고 그대로 물려받는다. 재생성이 다시
실패해도(EXHAUSTED/STAGNATED) 여기서 더 재시도하지 않고 `RegenerationRecord`로
결과만 남긴다 - 그 이상은 기존 GEN-03-02 HITL 에스컬레이션 경로
(`SelfHealLoop.hitl` -> Checkpoint.HARNESS_REVIEW)에 맡긴다.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

from logosfuzz.knowledge.kb_adapters import harness_context
from logosfuzz.knowledge.knowledge_base import KnowledgeBase

from logosfuzz.generate.compiler import Compiler
from logosfuzz.generate.llm import LLMClient, extract_code
from logosfuzz.generate.models import GenerateReport, HarnessDraft
from logosfuzz.generate.selfheal import SelfHealLoop

from .kb_feedback import KBOverrideStore
from .models import KBUpdateProposal, RegenerationRecord

DRAFT_SYSTEM_PROMPT = (
    "You are a C/C++ fuzzing-harness author for the LogosFuzz project targeting "
    "automotive open-source libraries. Given API context (signatures, constraints, "
    "and any self-correction notes from prior false positives), write a libFuzzer "
    "harness. Return ONLY the full source inside a single ```c code block. The file "
    "must define LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)."
)

FALLBACK_SOURCE = (
    "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { return 0; }"
)


def _api_context_blocks(
    kb: KnowledgeBase, overrides: KBOverrideStore, target_apis: List[str],
) -> List[str]:
    blocks: List[str] = []
    for name in target_apis:
        document = kb.api(name)
        if document is None:
            continue
        block = harness_context(kb, name)
        override_text = overrides.current_text(document["api_id"])
        if override_text:
            block += f"\n\nself-correction notes (오탐 역피드백):\n{override_text}"
        blocks.append(block)
    return blocks


def _draft_prompt(logic_group: str, context_blocks: List[str]) -> str:
    joined = "\n\n".join(context_blocks) if context_blocks else "(지식베이스 컨텍스트 없음)"
    return f"""\
# 로직 그룹: {logic_group}
# API 컨텍스트 (지식베이스 + 오탐 역피드백 반영)
{joined}

# 지시
위 컨텍스트를 반영해 libFuzzer 하네스 소스를 새로 작성하라. 특히
"self-correction notes"에 적힌 과거 오탐 원인을 반복하지 않도록 하라."""


def draft_via_llm(
    kb: KnowledgeBase,
    overrides: KBOverrideStore,
    llm: LLMClient,
    logic_group: str,
    target_apis: List[str],
    project: str = "",
) -> HarnessDraft:
    """GEN-03-01을 대신하는 어댑터: 갱신된 KB 컨텍스트로 LLM에 초안을 요청한다."""
    context_blocks = _api_context_blocks(kb, overrides, target_apis)
    prompt = _draft_prompt(logic_group, context_blocks)
    response = llm.complete(prompt, system=DRAFT_SYSTEM_PROMPT)
    source = extract_code(response) or FALLBACK_SOURCE

    return HarnessDraft(
        logic_group=logic_group,
        source=source,
        project=project,
        target_apis=list(target_apis),
        context={"blocks": context_blocks},
    )


def trigger_regeneration(
    proposal: KBUpdateProposal,
    kb: KnowledgeBase,
    overrides: KBOverrideStore,
    compiler: Compiler,
    llm: LLMClient,
    logic_group: str,
    target_apis: List[str],
    max_round: int = 3,
    project: str = "",
    hitl: Optional[object] = None,
) -> Tuple[RegenerationRecord, GenerateReport]:
    """승인된 제안 -> 새 초안(GEN-03-01 대체) -> GEN-03-02 자가치유 -> 검증 결과."""
    draft = draft_via_llm(kb, overrides, llm, logic_group, target_apis, project)
    loop = SelfHealLoop(compiler=compiler, llm=llm, max_round=max_round, hitl=hitl)
    report = loop.run(draft)

    record = RegenerationRecord.new(
        proposal=proposal,
        logic_group=logic_group,
        outcome=report.outcome.value,
        rounds_used=report.rounds_used,
        compiled_ok=report.success,
    )
    return record, report
