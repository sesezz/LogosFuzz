"""에러계약 플러그인 레지스트리 (GENERIC-C)

대상 라이브러리가 실패를 알리는 규약(에러계약)은 대상마다 상이

    none           계약 미확인(기본값)
    c_return_code  C 반환 코드/NULL 반환 — libsndfile, 임베디드 C 모듈 등
    score_result   S-CORE ``score::Result<T>`` — 자동차(baselibs) 대상

프로필의 ``error_contract`` 값으로 :func:`get_contract` 를 호출해 플러그인 선택
모든 플러그인이 같은 네 함수 제공::

    analyze(record, kb=None, profile=None) -> 근거
    derive_signals(근거, bug_type)         -> (점수 보정치, 신호 목록)
    render_rationale(근거)                 -> HITL 근거문에 덧붙일 문장
    render_for_prompt(근거)                -> LLM 판별기 프롬프트 증거 섹션

판별기(``triage.py``)는 근거 객체만 받는 경우가 있어 :func:`contract_for_evidence`
로 근거 타입에서 플러그인 역조회
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from logosfuzz.analyze.contracts import c_return_code as _c_return_code
from logosfuzz.analyze.contracts import none as _none
from logosfuzz.analyze.contracts import score_result as _score_result

DEFAULT_CONTRACT = "none"


@dataclass(frozen=True)
class ErrorContract:
    """에러계약 플러그인 1종"""

    name: str
    evidence_type: type
    analyze: Callable[..., Any]
    derive_signals: Callable[[Any, str], tuple]
    render_rationale: Callable[[Any], str]
    render_for_prompt: Callable[[Any], str]


def _score_analyze(record, kb=None, profile=None):
    # score::Result 판별은 프로필 미사용(기존 동작 유지)
    return _score_result.analyze_error_contract(record, kb)


_REGISTRY: Dict[str, ErrorContract] = {
    "none": ErrorContract(
        name="none",
        evidence_type=_none.NoContractEvidence,
        analyze=_none.analyze,
        derive_signals=_none.derive_signals,
        render_rationale=_none.render_rationale,
        render_for_prompt=_none.render_for_prompt,
    ),
    "c_return_code": ErrorContract(
        name="c_return_code",
        evidence_type=_c_return_code.CReturnCodeEvidence,
        analyze=_c_return_code.analyze,
        derive_signals=_c_return_code.derive_signals,
        render_rationale=_c_return_code.render_rationale,
        render_for_prompt=_c_return_code.render_for_prompt,
    ),
    "score_result": ErrorContract(
        name="score_result",
        evidence_type=_score_result.ErrorContractEvidence,
        analyze=_score_analyze,
        derive_signals=_score_result.derive_signals,
        render_rationale=_score_result.render_rationale,
        render_for_prompt=_score_result.render_for_prompt,
    ),
}


def available_contracts() -> list[str]:
    return list(_REGISTRY)


def get_contract(name: Optional[str]) -> ErrorContract:
    """이름으로 플러그인 조회. ``None``/빈 문자열이면 ``none``

    Raises:
        ValueError: 등록되지 않은 이름
    """
    key = name or DEFAULT_CONTRACT
    try:
        return _REGISTRY[key]
    except KeyError:
        raise ValueError(
            f"알 수 없는 error_contract: {name!r} (가능: {', '.join(_REGISTRY)})"
        ) from None


def contract_for_profile(profile) -> ErrorContract:
    """프로필의 ``error_contract`` 로 플러그인 선택. 프로필에 값이 없으면 ``none``"""
    return get_contract(getattr(profile, "error_contract", None))


def contract_for_evidence(evidence) -> Optional[ErrorContract]:
    """근거 객체 타입으로 플러그인 조회. 모르는 타입이면 None"""
    for contract in _REGISTRY.values():
        if isinstance(evidence, contract.evidence_type):
            return contract
    return None


class ContractProvider:
    """클러스터 → 에러계약 근거. 판별기의 ``contract_provider`` 로 주입

    Args:
        contract: 플러그인 또는 이름(``"c_return_code"`` 등)
        kb: KnowledgeBase (선택)
        profile: TargetProfile (선택). ``c_return_code`` 는 ``profile.apis`` 사용
    """

    def __init__(self, contract, kb=None, profile=None) -> None:
        self.contract = contract if isinstance(contract, ErrorContract) else get_contract(contract)
        self.kb = kb
        self.profile = profile

    @classmethod
    def for_profile(cls, profile, kb=None) -> "ContractProvider":
        return cls(contract_for_profile(profile), kb=kb, profile=profile)

    def __call__(self, cluster):
        return self.contract.analyze(cluster.representative, kb=self.kb, profile=self.profile)


__all__ = [
    "DEFAULT_CONTRACT",
    "ErrorContract",
    "ContractProvider",
    "available_contracts",
    "get_contract",
    "contract_for_profile",
    "contract_for_evidence",
]
