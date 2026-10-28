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
# 하네스가 퍼저 입력(NUL 로 끝나지 않음)을 char * 문자열로 API 에 넘겨 문자열 함수가 버퍼 끝을 넘어 읽은 경우
VIOLATED_BY_HARNESS_STRING = "harness-string"
# 하네스가 할당한 버퍼를 공개 API 가 넘어 쓴 경우. API 가 요구하는 버퍼 크기(예: frames x channels)를
# 하네스가 못 맞췄을 가능성이 커서 의심으로만 표시한다(라이브러리가 요청보다 더 쓴 결함일 수도 있다)
SUSPECT_HARNESS_BUFFER = "harness-buffer-suspect"
_ALLOCATORS = frozenset({"malloc", "calloc", "realloc", "posix_memalign", "aligned_alloc", "memalign",
                         "operator new", "operator new[]"})

# 0 페이지. 리눅스는 기본으로 첫 페이지(4 KiB) 미매핑 → NULL 포인터 멤버 접근
# (NULL + 오프셋)은 이 범위에서 SEGV. ASan 도 같은 기준으로
# "Hint: address points to the zero page." 출력
NULL_PAGE_LIMIT = 0x1000

_SEGV_ADDR_RE = re.compile(r"SEGV on unknown address (?:0x)?(?P<addr>[0-9a-fA-F]+)")
_ZERO_PAGE_HINT = "address points to the zero page"
# UBSan: member access within null pointer / load of null pointer / store to null pointer ...
_UBSAN_NULL_RE = re.compile(r"runtime error: .*\bnull pointer\b")


# 버퍼 끝을 넘어 읽는 크래시가 보고되는 libc 문자열 함수(ASan 인터셉터 프레임 이름)
_STRING_FUNCTIONS = frozenset({
    "strlen", "strnlen", "strcpy", "stpcpy", "strncpy", "strcat", "strncat", "strcmp",
    "strncmp", "strcasecmp", "strncasecmp", "strchr", "strrchr", "strstr", "strdup", "strndup",
})
# 하네스 호출 줄이 입력 data 를 char * 로 바꿔 그대로 넘기는 형태: (const char *)data, reinterpret_cast<const char *>(data)
_DATA_AS_STRING_RE = re.compile(
    r"(?:\(\s*(?:const\s+)?char\s*\*\s*\)|reinterpret_cast\s*<\s*(?:const\s+)?char\s*\*\s*>\s*\()"
    r"\s*data\b")


@dataclass
class CReturnCodeEvidence:
    """C 반환 코드 계약 관점의 판별 근거(판정은 미수행)

    Attributes:
        violation: ``"harness"``(NULL 반환 미검사), ``"harness-string"``(NUL 없는 입력을
            문자열로 전달) 또는 ``""``(증명 실패)
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


def _read_source_line(path: str, line: int) -> str:
    try:
        lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    except OSError:
        return ""
    return lines[line - 1] if 0 < line <= len(lines) else ""


def _unterminated_string(record: CrashRecord, apis: set, kb=None) -> Optional[CReturnCodeEvidence]:
    """하네스가 입력 ``data`` 를 NUL 없는 ``char *`` 문자열로 API 에 넘긴 것을 스택과 소스 줄로 증명

    세 조건을 모두 만족할 때만 증거를 만든다.
    1. ASan 이 버퍼 오버플로를 보고했고 최상위 프레임이 libc 문자열 함수(strlen 등)
    2. 그 아래 호출 체인에서 하네스 바로 위 프레임이 ``profile.apis`` 중 하나
    3. 하네스의 해당 호출 줄이 ``data`` 를 ``char *`` 로 바꿔 넘김(소스를 읽어 확인)

    라이브러리 내부 버그로도 같은 스택이 나올 수 있어서, 3번(소스 줄 확인) 없이는 판정하지 않는다.
    """
    text = " ".join([record.error_reason or "", *record.raw_log[:3]]).lower()
    if "buffer-overflow" not in text:
        return None
    frames = parse_frames(record.raw_log)
    if not frames or short_name(frames[0].function) not in _STRING_FUNCTIONS:
        return None
    harness_at = next((i for i, f in enumerate(frames) if is_harness(f)), -1)
    if harness_at < 1:
        return None
    api_frame, harness_frame = frames[harness_at - 1], frames[harness_at]
    api = short_name(api_frame.function)
    if api not in apis or not harness_frame.file or not harness_frame.line:
        return None
    source_line = _read_source_line(harness_frame.file, harness_frame.line)
    if not _DATA_AS_STRING_RE.search(source_line):
        return None
    evidence = CReturnCodeEvidence(
        violation=VIOLATED_BY_HARNESS_STRING,
        api=api,
        frame=api_frame,
        caller=harness_frame,
        crash_function=short_name(frames[0].function),
        null_reason=(f"하네스 {harness_frame.line}행이 입력 data 를 NUL 로 끝나지 않는 char * 문자열로 "
                     f"넘겼고 {short_name(frames[0].function)} 가 버퍼 끝을 넘어 읽었다"),
        declared_contracts=_kb_contracts(kb, api),
    )
    return evidence


def _harness_allocated_overflow(record: CrashRecord, apis: set, kb=None) -> Optional[CReturnCodeEvidence]:
    """하네스가 할당한 힙 버퍼를 하네스가 직접 부른 공개 API 가 넘어 쓴 크래시를 스택으로 포착

    조건: ASan heap-buffer-overflow, 최상위 대상 프레임이 라이브러리, 그 호출 체인에서 하네스 바로 위
    프레임이 ``profile.apis`` 중 하나, 그리고 ``allocated by`` 스택의 첫 사용자 프레임이 하네스.
    API 가 요구하는 버퍼 크기를 하네스가 못 맞춘 경우(libsndfile ``sf_readf_float`` 는 frames x channels
    개 항목을 쓰는데 하네스가 frames 개만 할당)의 전형이라서 정탐으로 자동 승인하지 않는다.
    """
    if "heap-buffer-overflow" not in (record.error_reason or "").lower():
        return None
    log = list(record.raw_log)
    alloc_at = next((i for i, line in enumerate(log) if "allocated by thread" in line), -1)
    if alloc_at < 0:
        return None
    frames = parse_frames(log)
    user = [f for f in frames if not is_runtime(f)]
    if not user or is_harness(user[0]):
        return None                              # 하네스 자신의 오버플로는 이 규칙의 범위 밖
    harness_at = next((i for i, f in enumerate(frames) if is_harness(f)), -1)
    if harness_at < 1:
        return None
    api_frame, harness_frame = frames[harness_at - 1], frames[harness_at]
    api = short_name(api_frame.function)
    if api not in apis:
        return None
    allocation = [f for f in parse_frames(log[alloc_at + 1:]) if short_name(f.function) not in _ALLOCATORS]
    if not allocation or not is_harness(allocation[0]):
        return None
    return CReturnCodeEvidence(
        violation=SUSPECT_HARNESS_BUFFER,
        api=api,
        frame=api_frame,
        caller=harness_frame,
        crash_function=short_name(user[0].function),
        null_reason=(f"하네스가 할당한 버퍼({allocation[0].render()})를 {api} 가 넘어 썼다"),
        declared_contracts=_kb_contracts(kb, api),
    )


def analyze(record: CrashRecord, kb=None, profile=None) -> CReturnCodeEvidence:
    """크래시 레코드 1건의 C 반환 코드 계약 위반 근거 수집

    Args:
        record: 클러스터 대표 레코드
        kb: KnowledgeBase (선택). 있으면 API 의 선언된 error_contract 첨부
        profile: TargetProfile (선택). ``profile.apis`` 가 비어 있으면 1번 조건
            증명 불가로 위반 신호 없음
    """
    apis = set(getattr(profile, "apis", ()) or ())
    string_misuse = _unterminated_string(record, apis, kb)
    if string_misuse is not None:
        return string_misuse
    undersized = _harness_allocated_overflow(record, apis, kb)
    if undersized is not None:
        return undersized
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
# 하네스 소스 줄까지 읽어서 증명한 문자열 오용은 스택만으로 보는 NULL 미검사보다 증거가 강하다.
# ASan 메모리 오류의 기본 점수(0.95)를 오탐 기준(0.35) 아래로 내리려면 -0.60 이상이 필요
_HARNESS_STRING_DELTA = -0.65
# 의심 단계: 재현성 보너스(+0.10)까지 받은 점수 1.05 에서도 정탐 기준(0.65) 아래로 내려 사람 검토로 보내야 한다.
# -0.35 는 같은 입력군이 3번 이상 재현되면 0.70 으로 정탐이 되었다(libsndfile 8차 실측) -> -0.45 (1.05 -> 0.60)
_HARNESS_BUFFER_DELTA = -0.45


def derive_signals(evidence: CReturnCodeEvidence, bug_type: str = "") -> tuple[float, list[str]]:
    """(점수 보정치, 신호 목록)"""
    if evidence.violation == VIOLATED_BY_HARNESS:
        return _HARNESS_VIOLATION_DELTA, ["c-return-unchecked-by-harness"]
    if evidence.violation == VIOLATED_BY_HARNESS_STRING:
        return _HARNESS_STRING_DELTA, ["c-string-unterminated-by-harness"]
    if evidence.violation == SUSPECT_HARNESS_BUFFER:
        return _HARNESS_BUFFER_DELTA, ["c-harness-buffer-overflow-suspect"]
    return 0.0, []


def render_rationale(evidence: CReturnCodeEvidence) -> str:
    """HITL 검토자용 한 문장. 근거가 없으면 빈 문자열"""
    if evidence.violation == VIOLATED_BY_HARNESS_STRING:
        return (
            f" 하네스가 퍼저 입력을 NUL 로 끝나지 않는 문자열로 공개 API {evidence.api} 에 넘겼다"
            f"({evidence.caller.render()} → {evidence.frame.render()}, {evidence.null_reason}) — "
            "API 는 정상 문자열 인자를 전제로 하므로 대상 결함이 아니라 하네스 결함이다."
        )
    if evidence.violation == SUSPECT_HARNESS_BUFFER:
        return (
            f" 하네스가 할당한 버퍼를 공개 API {evidence.api} 가 넘어 썼다({evidence.null_reason}). "
            "API 문서가 요구하는 버퍼 크기(예: frames x channels 개 항목)를 하네스가 맞췄는지 먼저 "
            "확인해야 하는 하네스 결함 의심 사례다."
        )
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
    if evidence.violation == VIOLATED_BY_HARNESS_STRING:
        lines.append(f"- 문자열 인자 오용: {evidence.null_reason}")
    elif evidence.violation == SUSPECT_HARNESS_BUFFER:
        lines.append(f"- 하네스 할당 버퍼 초과 쓰기: {evidence.null_reason}")
    elif evidence.null_reason:
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
