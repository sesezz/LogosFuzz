"""
ANA-05-03 STEP 1: 오탐 원인 분석
=================================

오탐(false positive)으로 판정된 크래시의 ASAN/TSAN 로그와 콜스택을 추론형
LLM(예: DeepSeek-R1)에 넣어 "왜 오탐인가"를 자연어로 요약한다.

새 LLM 추상화를 만들지 않고 GEN-03의 `logosfuzz.generate.llm.LLMClient`
("프롬프트 -> 텍스트" 인터페이스)를 그대로 재사용한다. 로그 파싱도
`ana_05_02_cve_reporting.asan_parser.parse_asan_log`를 그대로 쓴다
(ANA-05-02가 이미 검증한 파서를 중복 구현하지 않는다).
"""
from __future__ import annotations

from typing import Optional

from ana_05_02_cve_reporting.asan_parser import ParsedAsanLog, parse_asan_log

from logosfuzz.generate.llm import LLMClient
from src.knowledge_base import KnowledgeBase

from .models import FalsePositiveCrash, RootCauseAnalysis

SYSTEM_PROMPT = (
    "You are a root-cause analyst for a fuzzing pipeline. You are given a crash "
    "that a triage step already classified as a FALSE POSITIVE (not a real bug). "
    "Explain, in 2-4 concise sentences, WHY this crash is a false positive - e.g. "
    "an unmocked external dependency, a harness setup bug, a missing precondition "
    "that real callers always satisfy, or an environment artifact. Write the "
    "explanation as a reusable note that a future harness generator can read to "
    "avoid repeating the same false positive. Do not just restate the raw stack "
    "trace back at the reader."
)


def _api_context_block(api_doc: Optional[dict]) -> str:
    if not api_doc:
        return "(지식베이스에 해당 API 항목 없음)"
    constraints = [c["description"] for c in api_doc.get("constraints", [])][:5]
    return (
        f"signature: {api_doc.get('signature', '?')}\n"
        f"file: {api_doc.get('file', '?')}:{api_doc.get('line', '?')}\n"
        f"existing constraints: {constraints or '(없음)'}"
    )


def build_prompt(crash: FalsePositiveCrash, parsed: ParsedAsanLog, api_doc: Optional[dict]) -> str:
    frames = (
        "\n".join(
            f"  #{f['frame']} {f['function']} ({f.get('location') or '?'})"
            for f in parsed.stack_trace[:10]
        )
        or "  (스택트레이스 없음)"
    )

    return f"""\
# 크래시 정보
crash_id: {crash.crash_id}
sanitizer: {parsed.sanitizer}
error_type: {parsed.error_type}
summary: {parsed.raw_summary_line}
access: {parsed.access_type or '-'} size={parsed.access_size or '-'} addr={parsed.fault_address or '-'}

# 스택트레이스
{frames}

# 대상 API 지식베이스 항목 (api_id={crash.api_id})
{_api_context_block(api_doc)}

# 지시
위 크래시는 이미 오탐(false positive)으로 확정되었다. 왜 오탐인지 2~4문장으로
요약하라. 다음에 재생성될 하네스가 같은 오탐을 반복하지 않도록 참고할 수 있는
형태로 써라."""


def analyze_false_positive(
    crash: FalsePositiveCrash,
    kb: KnowledgeBase,
    llm: LLMClient,
) -> RootCauseAnalysis:
    """오탐 크래시 로그 + 콜스택 -> 근본 원인 요약(RootCauseAnalysis).

    `crash.verdict`가 FALSE_POSITIVE가 아니면 `FalsePositiveCrash.__post_init__`에서
    이미 예외가 발생하므로, 이 함수는 항상 오탐 확정 건만 받는다는 전제로 동작한다.
    """
    parsed = parse_asan_log(crash.asan_log)
    api_doc = kb.api(crash.api_id)

    prompt = build_prompt(crash, parsed, api_doc)
    response = llm.complete(prompt, system=SYSTEM_PROMPT)
    summary = (response or "").strip()

    return RootCauseAnalysis(
        crash_id=crash.crash_id,
        api_id=crash.api_id,
        summary=summary,
        rationale=parsed.raw_summary_line,
        model=getattr(llm, "model", ""),
    )
