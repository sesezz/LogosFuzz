"""에러계약 플러그인 ``none`` — 계약을 보지 않는다.

대상 라이브러리의 오류 보고 규약을 모르거나(프로필 ``error_contract: "none"``),
규약이 있어도 스택만으로는 증명할 수 없는 경우에 쓴다. 판별기에 아무 신호도
주지 않으므로 결과는 결함 유형·크래시 위치·재현성 신호만으로 정해진다.
"""

from __future__ import annotations

from dataclasses import dataclass

from logosfuzz.analyze.models import CrashRecord

NAME = "none"


@dataclass
class NoContractEvidence:
    """계약을 보지 않았다는 표시. 근거는 항상 비어 있다."""

    violation: str = ""

    @property
    def found(self) -> bool:
        return False

    def to_dict(self) -> dict:
        return {"contract": NAME, "violation": None}


def analyze(record: CrashRecord, kb=None, profile=None) -> NoContractEvidence:
    return NoContractEvidence()


def derive_signals(evidence: NoContractEvidence, bug_type: str = "") -> tuple[float, list[str]]:
    return 0.0, []


def render_rationale(evidence: NoContractEvidence) -> str:
    return ""


def render_for_prompt(evidence: NoContractEvidence) -> str:
    return ""
