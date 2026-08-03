"""
ANA-05-02: ASAN/TSAN Sanitizer 에러 유형 -> CWE(Common Weakness Enumeration) 매핑

ANA-05-01(LLM 기반 정탐/오탐 판별) 단계에서 넘어오는 crash_report.asan_log 를
파싱한 결과(sanitizer_error_type)를 이 테이블로 CWE ID/이름에 매핑한다.

매핑 근거: MITRE CWE 및 OSS-Fuzz / AddressSanitizer 공식 문서에서 공통적으로
쓰이는 대응 관계를 기반으로 함. 여러 CWE가 후보일 수 있는 경우 가장 대표적인
1개를 primary로 두고 관련 CWE를 related 로 함께 기록한다.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class CweInfo:
    primary_id: str
    primary_name: str
    related_ids: tuple = field(default_factory=tuple)


# key: asan_parser.py 가 산출하는 정규화된 sanitizer_error_type 문자열
CWE_MAPPING: dict[str, CweInfo] = {
    "heap-buffer-overflow": CweInfo(
        "CWE-122", "Heap-based Buffer Overflow", ("CWE-787", "CWE-125")
    ),
    "stack-buffer-overflow": CweInfo(
        "CWE-121", "Stack-based Buffer Overflow", ("CWE-787", "CWE-125")
    ),
    "global-buffer-overflow": CweInfo(
        "CWE-787", "Out-of-bounds Write", ("CWE-125",)
    ),
    "heap-use-after-free": CweInfo(
        "CWE-416", "Use After Free"
    ),
    "use-after-return": CweInfo(
        "CWE-416", "Use After Free", ("CWE-562",)
    ),
    "use-after-poison": CweInfo(
        "CWE-416", "Use After Free"
    ),
    "double-free": CweInfo(
        "CWE-415", "Double Free"
    ),
    "memory-leak": CweInfo(
        "CWE-401", "Missing Release of Memory after Effective Lifetime"
    ),
    "null-pointer-dereference": CweInfo(
        "CWE-476", "NULL Pointer Dereference"
    ),
    "stack-overflow": CweInfo(
        "CWE-674", "Uncontrolled Recursion", ("CWE-121",)
    ),
    "integer-overflow": CweInfo(
        "CWE-190", "Integer Overflow or Wraparound"
    ),
    "uninitialized-value": CweInfo(
        "CWE-457", "Use of Uninitialized Variable"
    ),
    "data-race": CweInfo(
        "CWE-362", "Concurrent Execution using Shared Resource (Race Condition)"
    ),
    "timeout": CweInfo(
        "CWE-400", "Uncontrolled Resource Consumption"
    ),
}

UNKNOWN_CWE = CweInfo("CWE-1035", "Unmapped / Manual Review Required")


def lookup_cwe(sanitizer_error_type: str) -> CweInfo:
    """정규화된 sanitizer 에러 타입 문자열로 CWE 정보를 조회한다.
    매핑되지 않는 신규 에러 타입은 UNKNOWN_CWE 를 반환하여
    사람이 수동으로 검토하도록 표시한다 (자동 오분류 방지).
    """
    return CWE_MAPPING.get(sanitizer_error_type, UNKNOWN_CWE)
