"""GEN-03-04 선택 항목: 하네스 소스 vs API 시그니처 정적 리뷰.

설계서 4번 항목("LLM 정적 리뷰")은 하네스 코드와 지식베이스(Vector DB)에
저장된 원본 API 시그니처를 비교해 인자 개수/타입 불일치를 잡아내는 것이
목적이다. 그러나 이 저장소에는 아직 Vector DB나 LLM SDK 연동이 전혀 없다
(requirements.txt에 관련 의존성 없음, 벡터DB 코드 없음).

따라서 `StaticReviewer` 프로토콜로 백엔드를 추상화해 두고, 지금은 정규식
기반으로 호출부 인자 개수만 비교하는 `MockStaticReviewer`를 기본 제공한다.
실제 LLM/Vector DB가 준비되면 이 프로토콜만 구현해 `validate_harness(...,
static_reviewer=RealLLMReviewer(...))` 로 교체하면 된다.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Protocol

from logosfuzz.generate.contracts import ApiSignature


@dataclass
class ArgMismatch:
    api_name: str
    expected_params: int
    found_params: int
    call_site: str


@dataclass
class StaticReviewResult:
    passed: bool
    checked: list[str]
    mismatches: list[ArgMismatch] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "checked": self.checked,
            "mismatches": [asdict(m) for m in self.mismatches],
            "reason": self.reason,
        }


class StaticReviewer(Protocol):
    """하네스 소스 코드와 API 시그니처를 비교해 정적 리뷰 결과를 낸다."""

    def review(self, source_code: str, api_signatures: list[ApiSignature]) -> StaticReviewResult: ...


def _count_args(arg_str: str) -> int:
    """괄호 안 콤마 개수로 인자 수를 센다(중첩 괄호/구조체 리터럴 대응)."""
    arg_str = arg_str.strip()
    if not arg_str:
        return 0
    depth = 0
    count = 1
    for ch in arg_str:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            count += 1
    return count


class MockStaticReviewer:
    """실제 LLM 없이, 정규식으로 찾은 호출부의 인자 개수를 시그니처와 비교한다.

    타입 비교는 하지 않는다(정적 텍스트만으로는 신뢰성 있게 판별 불가) —
    인자 "개수" 불일치만 잡아내는 보수적인 규칙 기반 임시 백엔드다.
    """

    def review(self, source_code: str, api_signatures: list[ApiSignature]) -> StaticReviewResult:
        checked: list[str] = []
        mismatches: list[ArgMismatch] = []
        for sig in api_signatures:
            pattern = re.compile(r"\b" + re.escape(sig.name) + r"\s*\(([^;]*?)\)\s*;")
            match = pattern.search(source_code)
            if not match:
                continue  # 하네스가 이 API를 호출하지 않으면 리뷰 대상이 아니다.
            checked.append(sig.name)
            found_n = _count_args(match.group(1))
            expected_n = len(sig.param_types)
            if found_n != expected_n:
                mismatches.append(
                    ArgMismatch(sig.name, expected_n, found_n, match.group(0).strip())
                )
        passed = not mismatches
        reason = "" if passed else f"인자 개수 불일치 {len(mismatches)}건"
        return StaticReviewResult(passed, checked, mismatches, reason)
