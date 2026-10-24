"""ANA-05-01 에러계약 근거 — 기존 공개 경로 유지용

``score::Result`` 판별 본체는 GENERIC-C 에서 에러계약 플러그인
``logosfuzz.analyze.contracts.score_result`` 로 이동. 이 모듈은 그 공개 이름을
그대로 재수출해서 ``from logosfuzz.analyze.error_contract import ...`` 와
``error_contract.analyze_error_contract(...)`` 같은 기존 호출 유지

대상별 계약 선택은 :func:`logosfuzz.analyze.contracts.get_contract` 사용
"""

from __future__ import annotations

from logosfuzz.analyze.contracts.frames import NamedFrame, parse_frames, short_name
from logosfuzz.analyze.contracts.score_result import (
    VIOLATED_BY_HARNESS,
    VIOLATED_BY_TARGET,
    ErrorContractEvidence,
    KnowledgeBaseContractProvider,
    analyze_error_contract,
    derive_signals,
    render_for_prompt,
    render_rationale,
)

__all__ = [
    "NamedFrame",
    "parse_frames",
    "short_name",
    "VIOLATED_BY_HARNESS",
    "VIOLATED_BY_TARGET",
    "ErrorContractEvidence",
    "KnowledgeBaseContractProvider",
    "analyze_error_contract",
    "derive_signals",
    "render_for_prompt",
    "render_rationale",
]
