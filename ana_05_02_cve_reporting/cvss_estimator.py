"""
ANA-05-02: CVSS 3.1 기반 심각도 초안(draft) 산출기

주의: 이 모듈은 실제 CVSS 3.1 표준 산식을 100% 구현한 정밀 계산기가 아니라,
'취약점 유형 + 크래시 특성'으로부터 합리적인 초기값(Base Vector)을 추정해
CVE 리포트 초안에 채워 넣기 위한 휴리스틱이다. 최종 제출 전 사람이
(Attack Vector, 실제 도달 가능성, 영향 범위 등을) 반드시 검토/보정해야 한다.

CVSS 3.1 Base Score 산식은 FIRST.org 공식 문서를 따른다.
"""

from __future__ import annotations

from dataclasses import dataclass

# 취약점 정규화 타입별 기본 CVSS 3.1 메트릭 (보수적 기본값)
# AV: Attack Vector, AC: Attack Complexity, PR: Privileges Required,
# UI: User Interaction, S: Scope, C/I/A: Confidentiality/Integrity/Availability Impact
_DEFAULT_METRICS = {
    "heap-buffer-overflow": dict(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H"),
    "stack-buffer-overflow": dict(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H"),
    "global-buffer-overflow": dict(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="L", A="H"),
    "heap-use-after-free": dict(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H"),
    "use-after-return": dict(AV="N", AC="H", PR="N", UI="N", S="U", C="L", I="L", A="H"),
    "use-after-poison": dict(AV="N", AC="H", PR="N", UI="N", S="U", C="L", I="L", A="H"),
    "double-free": dict(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="L", A="H"),
    "memory-leak": dict(AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="N", A="L"),
    "null-pointer-dereference": dict(AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="N", A="H"),
    "stack-overflow": dict(AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="N", A="H"),
    "integer-overflow": dict(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="L", A="L"),
    "uninitialized-value": dict(AV="N", AC="H", PR="N", UI="N", S="U", C="L", I="N", A="N"),
    "data-race": dict(AV="N", AC="H", PR="N", UI="N", S="U", C="L", I="L", A="L"),
    "timeout": dict(AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="N", A="L"),
}
_UNKNOWN_METRICS = dict(AV="N", AC="H", PR="N", UI="N", S="U", C="N", I="N", A="L")

_WEIGHT = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},  # Scope Unchanged
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.5},  # Scope Changed
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


@dataclass
class CvssEstimate:
    vector: str
    base_score: float
    severity: str  # None/Low/Medium/High/Critical
    is_estimated: bool = True  # 사람 검토 필요 여부 표시용


def _severity_from_score(score: float) -> str:
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def estimate_cvss(sanitizer_error_type: str) -> CvssEstimate:
    """정규화된 sanitizer 에러 타입으로 CVSS 3.1 Base Score 초안을 산출한다."""
    m = _DEFAULT_METRICS.get(sanitizer_error_type, _UNKNOWN_METRICS)

    iss = 1 - (
        (1 - _WEIGHT["CIA"][m["C"]])
        * (1 - _WEIGHT["CIA"][m["I"]])
        * (1 - _WEIGHT["CIA"][m["A"]])
    )
    scope_changed = m["S"] == "C"
    impact = (
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        if scope_changed
        else 6.42 * iss
    )

    pr_table = _WEIGHT["PR_C"] if scope_changed else _WEIGHT["PR_U"]
    exploitability = (
        8.22 * _WEIGHT["AV"][m["AV"]] * _WEIGHT["AC"][m["AC"]]
        * pr_table[m["PR"]] * _WEIGHT["UI"][m["UI"]]
    )

    if impact <= 0:
        base_score = 0.0
    elif scope_changed:
        base_score = min(1.08 * (impact + exploitability), 10.0)
    else:
        base_score = min(impact + exploitability, 10.0)

    base_score = round(_ceil_1dp(base_score), 1)

    vector = (
        f"CVSS:3.1/AV:{m['AV']}/AC:{m['AC']}/PR:{m['PR']}/UI:{m['UI']}"
        f"/S:{m['S']}/C:{m['C']}/I:{m['I']}/A:{m['A']}"
    )

    return CvssEstimate(
        vector=vector,
        base_score=base_score,
        severity=_severity_from_score(base_score),
        is_estimated=True,
    )


def _ceil_1dp(value: float) -> float:
    """CVSS 3.1 스펙에서 요구하는 소수 첫째 자리 올림(round up)."""
    import math

    return math.ceil(value * 10) / 10
