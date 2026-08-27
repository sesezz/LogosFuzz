"""
ANA-05-02: ASAN/TSAN 원본 로그(CRASH_REPORT.asan_log)를 파싱해서
구조화된 정보(에러 유형, 크래시 위치, 스택트레이스, 접근 정보 등)를 추출한다.

입력: EXE-04-02(동적 분석 새니타이저 실시간 모니터링) 단계가 저장한 원본 텍스트 로그
출력: CVE 리포트 생성기(report_generator.py)가 바로 사용할 수 있는 dict
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ASAN/TSAN summary 라인에 등장하는 원문 토큰 -> cwe_mapping.py 의 정규화 키
_ERROR_TYPE_NORMALIZE = {
    "heap-buffer-overflow": "heap-buffer-overflow",
    "stack-buffer-overflow": "stack-buffer-overflow",
    "global-buffer-overflow": "global-buffer-overflow",
    "heap-use-after-free": "heap-use-after-free",
    "use-after-return": "use-after-return",
    "use-after-poison": "use-after-poison",
    "attempting double-free": "double-free",
    "detected memory leaks": "memory-leak",
    "SEGV on unknown address": "null-pointer-dereference",
    "stack-overflow": "stack-overflow",
    "signed-integer-overflow": "integer-overflow",
    "unsigned-integer-overflow": "integer-overflow",
    "use-of-uninitialized-value": "uninitialized-value",
    "data race": "data-race",
    "timeout": "timeout",
}

_STACK_FRAME_RE = re.compile(r"^\s*#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(.+?)\s+(.+:\d+)?\s*$")
_ACCESS_SIZE_RE = re.compile(r"(READ|WRITE) of size (\d+)")
_ADDRESS_RE = re.compile(r"address (0x[0-9a-fA-F]+)")


@dataclass
class ParsedAsanLog:
    sanitizer: str  # AddressSanitizer / ThreadSanitizer / UBSan 등
    error_type: str  # 정규화된 타입 (cwe_mapping 키와 일치)
    raw_summary_line: str
    access_type: str | None
    access_size: int | None
    fault_address: str | None
    stack_trace: list[dict] = field(default_factory=list)
    crash_location: str | None = None  # 가장 상단(#0) 프레임의 file:line
    freed_at_location: str | None = None  # UAF/double-free 시 free() 호출 위치
    allocated_at_location: str | None = None  # 최초 malloc() 호출 위치


def _detect_sanitizer(log_text: str) -> str:
    if "ThreadSanitizer" in log_text:
        return "ThreadSanitizer"
    if "UndefinedBehaviorSanitizer" in log_text or "runtime error:" in log_text:
        return "UndefinedBehaviorSanitizer"
    if "AddressSanitizer" in log_text:
        return "AddressSanitizer"
    return "Unknown"


def _detect_error_type(log_text: str) -> tuple[str, str]:
    """원본 로그에서 에러 타입을 찾아 (정규화된 타입, 원문 요약 라인)을 반환."""
    for line in log_text.splitlines():
        for token, normalized in _ERROR_TYPE_NORMALIZE.items():
            if token in line:
                return normalized, line.strip()
    return "unknown", log_text.strip().splitlines()[0] if log_text.strip() else ""


def _extract_stack_trace(log_text: str, max_frames: int = 15) -> list[dict]:
    """크래시를 직접 유발한 첫 번째 스택트레이스 블록만 추출한다.

    ASAN 로그는 보통 (1) 크래시 발생 지점 스택, (2) free 지점 스택,
    (3) 최초 할당(malloc) 지점 스택 순서로 빈 줄을 사이에 두고 여러 블록이
    이어지며, 각 블록은 다시 #0 부터 프레임 번호가 시작된다. 여기서는
    "크래시가 실제로 발생한" 첫 번째 블록만 취급하고, 이후 블록(할당/해제
    이력)은 섞이지 않도록 한다. 프레임을 하나 이상 모은 뒤 blank line 을
    만나면 즉시 중단한다.
    """
    frames = []
    for line in log_text.splitlines():
        m = _STACK_FRAME_RE.match(line)
        if m:
            frame_no, func, loc = m.groups()
            frames.append(
                {
                    "frame": int(frame_no),
                    "function": func.strip(),
                    "location": (loc or "").strip() or None,
                }
            )
        elif frames and not line.strip():
            # 첫 스택트레이스 블록 종료 (다음은 freed-by / allocated-by 등 별개 블록)
            break
        if len(frames) >= max_frames:
            break
    return frames


_ALLOCATOR_RUNTIME_FUNCS = {"malloc", "free", "operator new", "operator delete", "calloc", "realloc"}


def _extract_block_first_location(log_text: str, header_token: str) -> str | None:
    """'freed by thread T0 here:' / 'previously allocated by thread T0 here:'
    같은 헤더 라인 다음 블록에서, ASAN 런타임 자체의 malloc/free 래퍼 프레임(#0)은
    건너뛰고 실제로 그 함수를 호출한 애플리케이션 코드 프레임의 file:line 을 반환한다.
    (그렇지 않으면 항상 asan_malloc_linux.cpp 내부 위치만 나와 리포트 가치가 없음)
    """
    lines = log_text.splitlines()
    for i, line in enumerate(lines):
        if header_token in line:
            for follow_line in lines[i + 1 : i + 8]:
                m = _STACK_FRAME_RE.match(follow_line)
                if not m or not m.group(3):
                    if follow_line.strip() == "" and m is None:
                        break
                    continue
                func_name = m.group(2).strip()
                if func_name in _ALLOCATOR_RUNTIME_FUNCS:
                    continue
                return m.group(3).strip()
            break
    return None


def parse_asan_log(log_text: str) -> ParsedAsanLog:
    """ASAN/TSAN raw 텍스트 로그를 구조화된 ParsedAsanLog 로 변환한다.

    포맷이 다르거나 알려지지 않은 sanitizer 출력이 들어와도 예외를 던지지 않고
    최대한 파싱 가능한 부분만 채운 뒤 나머지는 None/unknown 으로 남긴다.
    (크래시 리포트 생성 파이프라인이 파싱 실패로 죽지 않도록 하기 위함)
    """
    sanitizer = _detect_sanitizer(log_text)
    error_type, summary_line = _detect_error_type(log_text)

    access_match = _ACCESS_SIZE_RE.search(log_text)
    access_type = access_match.group(1) if access_match else None
    access_size = int(access_match.group(2)) if access_match else None

    address_match = _ADDRESS_RE.search(log_text)
    fault_address = address_match.group(1) if address_match else None

    stack_trace = _extract_stack_trace(log_text)
    crash_location = stack_trace[0]["location"] if stack_trace else None
    freed_at = _extract_block_first_location(log_text, "freed by thread")
    allocated_at = _extract_block_first_location(log_text, "allocated by thread")

    return ParsedAsanLog(
        sanitizer=sanitizer,
        error_type=error_type,
        raw_summary_line=summary_line,
        access_type=access_type,
        access_size=access_size,
        fault_address=fault_address,
        stack_trace=stack_trace,
        crash_location=crash_location,
        freed_at_location=freed_at,
        allocated_at_location=allocated_at,
    )
