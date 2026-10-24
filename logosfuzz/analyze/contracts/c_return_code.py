"""에러계약 플러그인 ``c_return_code`` — C 반환 코드/NULL 반환 규약

배경
----
C 라이브러리(libsndfile, 임베디드 펌웨어 모듈 등)는 실패를 예외가 아닌
**반환 값**으로 통지. ``sf_open`` 은 실패 시 ``NULL``, ``proto_create`` 는
잘못된 용량이면 ``NULL`` 반환. 호출자가 이를 확인하지 않고 다음 API 에
넘기면 다음 API 안에서 NULL 근처 주소 접근으로 크래시

크래시 위치는 대상 라이브러리 안이지만 대상 결함이 아님(API 는 계약대로 오류 통지,
무시한 쪽은 하네스). sanitizer 만 보면 "대상 코드에서 SEGV" 로 정탐 쪽에
기울기 때문에 스택에서 이 패턴을 별도 증명해 판별기에 전달

판정 규칙(세 조건 모두 만족 시 신호 생성)
----------------------------------------
1. 크래시 최상위 **대상 프레임**(런타임·sanitizer 프레임을 건너뛴 첫 프레임)이
   ``profile.apis`` 중 하나
2. 바로 위 호출자가 **하네스**(``LLVMFuzzerTestOneInput`` 계열 또는 하네스 파일)
3. 잘못된 접근이 **NULL 근처** — ASan ``SEGV on unknown address`` 주소가
   0 페이지(< 0x1000) 안이거나 UBSan 이 ``null pointer`` 로 보고

하나라도 증명하지 못하면 신호 없음(``reachability.py`` 와 같은 원칙)
대상 내부 함수 크래시, 대상 코드가 호출한 API 의 크래시, NULL 이 아닌 주소의
메모리 오류는 판단 대상 외

정답지는 ``tests/fixtures/c_return_code_logs/`` 의 실측 로그
(``examples/embedded`` 를 clang 18 + ASan/UBSan/libFuzzer 로 빌드해 수집)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional, Sequence

from logosfuzz.analyze.contracts.frames import (
    NamedFrame,
    is_harness,
    is_runtime,
    parse_frames,
    short_name,
)
from logosfuzz.analyze.models import CrashRecord

NAME = "c_return_code"

VIOLATED_BY_HARNESS = "harness"

# 0 페이지. 리눅스는 기본으로 첫 페이지(4 KiB) 미매핑 → NULL 포인터 멤버 접근
# (NULL + 오프셋)은 이 범위에서 SEGV. ASan 도 같은 기준으로
# "Hint: address points to the zero page." 출력
NULL_PAGE_LIMIT = 0x1000

_SEGV_ADDR_RE = re.compile(r"SEGV on unknown address (?:0x)?(?P<addr>[0-9a-fA-F]+)")
_ZERO_PAGE_HINT = "address points to the zero page"
# UBSan: member access within null pointer / load of null pointer / store to null pointer ...
_UBSAN_NULL_RE = re.compile(r"runtime error: .*\bnull pointer\b")


@dataclass
class CReturnCodeEvidence:
    """C 반환 코드 계약 관점의 판별 근거(판정은 미수행)

    Attributes:
        violation: ``"harness"`` 또는 ``""``(증명 실패)
        api: 크래시가 난 공개 API(짧은 이름). 최상위 대상 프레임이 API 가 아니면 빈 값
        frame: 해당 API 프레임
        caller: API 호출 프레임
        fault_address: ASan SEGV 주소(있는 경우)
        null_reason: NULL 근처로 판단한 근거 문장(없으면 빈 값)
        crash_function: 최상위 대상 프레임 함수(짧은 이름)
        declared_contracts: KB 에서 찾은 ``api`` 의 error_contract 설명
    """

    violation: str = ""
    api: str = ""
    frame: Optional[NamedFrame] = None
    caller: Optional[NamedFrame] = None
    fault_address: Optional[int] = None
    null_reason: str = ""
    crash_function: str = ""
    declared_contracts: list[str] = field(default_factory=list)

    @property
    def found(self) -> bool:
        return bool(self.violation or self.declared_contracts)

    def to_dict(self) -> dict:
        return {
            "contract": NAME,
            "violation": self.violation or None,
            "api": self.api or None,
            "frame": self.frame.render() if self.frame else None,
            "caller": self.caller.render() if self.caller else None,
            "fault_address": hex(self.fault_address) if self.fault_address is not None else None,
            "null_reason": self.null_reason or None,
            "crash_function": self.crash_function or None,
            "declared_contracts": list(self.declared_contracts),
        }


def _null_fault(record: CrashRecord) -> tuple[Optional[int], str]:
    """(SEGV 주소, NULL 근처로 판단한 근거). 근거가 없으면 빈 문자열"""
    text_lines = [record.error_reason, *record.raw_log]
    address: Optional[int] = None
    for line in text_lines:
        match = _SEGV_ADDR_RE.search(line or "")
        if match:
            address = int(match.group("addr"), 16)
            break
    if address is not None and address < NULL_PAGE_LIMIT:
        return address, f"SEGV 주소 {hex(address)} 가 0 페이지 안이다"
    if any(_ZERO_PAGE_HINT in (line or "") for line in text_lines):
        return address, "ASan 이 0 페이지 접근으로 보고했다"
    for line in text_lines:
        if _UBSAN_NULL_RE.search(line or ""):
            return address, "UBSan 이 null pointer 접근으로 보고했다"
    return address, ""


def _user_frames(frames: Sequence[NamedFrame]) -> list[NamedFrame]:
    return [f for f in frames if not is_runtime(f)]


def _kb_contracts(kb, function: str) -> list[str]:
    if kb is None or not function:
        return []
    try:
        document = kb.api(function)
    except Exception:
        return []
    if not document:
        return []
    return [
        str(c.get("description") or c.get("expression") or "")
        for c in document.get("constraints", [])
        if c.get("kind") == "error_contract"
    ]


def analyze(record: CrashRecord, kb=None, profile=None) -> CReturnCodeEvidence:
    """크래시 레코드 1건의 C 반환 코드 계약 위반 근거 수집

    Args:
        record: 클러스터 대표 레코드
        kb: KnowledgeBase (선택). 있으면 API 의 선언된 error_contract 첨부
        profile: TargetProfile (선택). ``profile.apis`` 가 비어 있으면 1번 조건
            증명 불가로 위반 신호 없음
    """
    apis = set(getattr(profile, "apis", ()) or ())
    user = _user_frames(parse_frames(record.raw_log))
    evidence = CReturnCodeEvidence()
    address, reason = _null_fault(record)
    evidence.fault_address = address
    evidence.null_reason = reason

    if not user:
        return evidence
    top = user[0]
    if is_harness(top):
        return evidence  # 하네스 자체 크래시는 이 계약의 범위 외
    evidence.crash_function = short_name(top.function)
    if evidence.crash_function not in apis:
        return evidence

    evidence.api = evidence.crash_function
    evidence.frame = top
    evidence.caller = user[1] if len(user) > 1 else None
    evidence.declared_contracts = _kb_contracts(kb, evidence.api)
    if evidence.caller is not None and is_harness(evidence.caller) and reason:
        evidence.violation = VIOLATED_BY_HARNESS
    return evidence


# 점수 근거: score_result 의 하네스 위반과 같은 무게(-0.45). 둘 다 "API 는 계약대로
# 오류를 알렸고 하네스가 무시했다"는 증명
_HARNESS_VIOLATION_DELTA = -0.45


def derive_signals(evidence: CReturnCodeEvidence, bug_type: str = "") -> tuple[float, list[str]]:
    """(점수 보정치, 신호 목록)"""
    if evidence.violation == VIOLATED_BY_HARNESS:
        return _HARNESS_VIOLATION_DELTA, ["c-return-unchecked-by-harness"]
    return 0.0, []


def render_rationale(evidence: CReturnCodeEvidence) -> str:
    """HITL 검토자용 한 문장. 근거가 없으면 빈 문자열"""
    if evidence.violation != VIOLATED_BY_HARNESS:
        return ""
    return (
        f" 하네스가 NULL/오류 반환을 검사하지 않고 공개 API {evidence.api} 를 불렀다"
        f"({evidence.caller.render()} → {evidence.frame.render()}, {evidence.null_reason}) — "
        "API 는 반환 코드 계약대로 실패를 알렸으므로 대상 결함이 아니라 하네스 결함이다."
    )


def render_for_prompt(evidence: CReturnCodeEvidence) -> str:
    """LLM 판별기 프롬프트용 증거 섹션"""
    lines = ["[에러계약 증거: C 반환 코드]"]
    if evidence.api:
        lines.append(f"- 크래시가 난 공개 API: {evidence.frame.render()}")
        if evidence.caller is not None:
            who = "하네스" if is_harness(evidence.caller) else "대상 코드"
            lines.append(f"- 호출자: {who} — {evidence.caller.render()}")
    if evidence.null_reason:
        lines.append(f"- NULL 근처 접근: {evidence.null_reason}")
    if evidence.declared_contracts:
        lines.append(f"- {evidence.api} 의 선언된 에러계약(KB):")
        lines.extend(f"    * {c}" for c in evidence.declared_contracts[:5])
    if len(lines) == 1:
        return ""
    lines.append(
        "  판단 기준: 앞선 API 의 NULL/오류 반환을 하네스가 확인하지 않고 다음 API 에 "
        "넘겨 NULL 근처에서 죽었다면 오탐이다. 정상 인자로 재현되면 정탐이다."
    )
    return "\n".join(lines)
