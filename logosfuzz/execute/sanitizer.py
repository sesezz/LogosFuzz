"""EXE-04-02: Sanitizer 로그 스트림 모니터링 및 크래시 시그니처화

ASan/LSan/TSAN 및 UBSan 출력 파싱

UBSan 별도 처리 이유
------------------------------
UBSan 은 ``ERROR: AddressSanitizer:`` 같은 헤더 없이 아래 형식으로 출력

    score/json/json.cc:38:11: runtime error: signed integer overflow: ...
        #0 ... in score::json::Dispatch(...) /proc/self/cwd/score/json/json.cc:38:11
        ...
    SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior score/json/json.cc:38:11

* ``ERROR:`` 기반 정규식으로 검출 불가
* 기본(복구 가능) 모드에서는 종료코드 0 으로 정상 종료하므로 출력 파싱 필수

파서 기준: ``tests/fixtures/sanitizer_logs/`` 실제 출력 원문 (clang 18.1.3)
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

_ERROR_START = re.compile(r"(?:ERROR: (?:Address|Leak)Sanitizer:|WARNING: ThreadSanitizer:)\s*(.+)", re.IGNORECASE)

# UBSan 진단 시작 줄: "<파일>:<행>:<열>: runtime error: <내용>"
# 파일 경로 공백 없음 전제 (_SOURCE_LOCATION 과 동일)
_UBSAN_RUNTIME_ERROR = re.compile(
    r"^(?P<file>\S+):(?P<line>\d+):(?P<col>\d+):\s*runtime error:\s*(?P<message>.+)$"
)
# UBSan 블록 끝 (libFuzzer 요약줄 혼입 및 연속 UB 병합 방지)
_UBSAN_SUMMARY = re.compile(r"^SUMMARY:\s*UndefinedBehaviorSanitizer:", re.IGNORECASE)

_SOURCE_LOCATION = re.compile(r"(?P<file>(?:[A-Za-z]:)?[^\s():]+\.(?:c|cc|cpp|cxx|h|hh|hpp)):(?P<line>\d+)(?::\d+)?")


@dataclass(frozen=True)
class SourceLocation:
    file: str
    line: int


@dataclass
class SanitizerFinding:
    """ANA-05-01/ANA-05-04 전달용 정규화 Sanitizer 결함 이벤트"""
    sanitizer: str
    category: str
    error_reason: str
    traceback: list[SourceLocation] = field(default_factory=list)
    raw_log: list[str] = field(default_factory=list)

    @property
    def signature(self) -> str:
        if self.traceback:
            location = self.traceback[0]
            filename = Path(location.file).name.replace(".", "_")
            return f"{self.category}_{filename}_{location.line}"
        return f"{self.category}_unknown"

    def to_dict(self) -> dict:
        data = asdict(self)
        data["signature"] = self.signature
        return data


def classify_ubsan_error(message: str) -> str:
    """UBSan 진단 메시지의 결함 분류 매핑

    분기 조건은 tests/fixtures/sanitizer_logs 실제 문구 기준
    미분류 UB는 ``undefined-behavior`` 로 처리
    """
    text = message.lower()
    if "signed integer overflow" in text or "unsigned integer overflow" in text:
        return "integer-overflow"
    if "division by zero" in text or "divide by zero" in text:
        return "divide-by-zero"
    if "null pointer" in text:
        # "member access within null pointer of type 'Header'" 등
        return "null-dereference"
    if "shift exponent" in text:
        return "shift-out-of-bounds"
    if "out of bounds for type" in text:
        return "array-out-of-bounds"
    if "misaligned address" in text:
        return "misaligned-access"
    if "outside the range of representable values" in text:
        return "float-cast-overflow"
    if "not a valid value for type" in text:
        # "load of value 201, which is not a valid value for type 'bool'"
        return "invalid-enum-load"
    return "undefined-behavior"


def classify_sanitizer_error(sanitizer: str, reason: str) -> str:
    """Sanitizer 별 결함 분류 규칙"""
    if sanitizer.upper() == "UBSAN":
        return classify_ubsan_error(reason)

    text = reason.lower()
    if "double-free" in text:
        return "double-free"
    if "use-after-free" in text:
        return "use-after-free"
    if "buffer-overflow" in text or "buffer overflow" in text:
        return "buffer-overflow"
    if "memory leak" in text or "detected memory leaks" in text:
        return "memory-leak"
    if "allocation-size-too-big" in text or "exceeds maximum supported" in text:
        return "bad-alloc"
    if "segv" in text:
        # null 역참조 UB 직후 SEGV 종료 케이스 대응
        return "segv"
    if "lock-order-inversion" in text or "deadlock" in text:
        return "deadlock"
    if "data race" in text or "race condition" in text:
        return "race-condition"
    if "mock" in text or "unimplemented protocol" in text:
        # GEN-03-03 mock 주입 가짜 크래시 (ANA triage 오탐 신호)
        return "mocking-fail-fp"
    return "unknown"


class SanitizerMonitor:
    """프로세스 출력 줄 단위 Sanitizer 결함 블록 수집기"""
    def __init__(self, on_finding: Callable[[SanitizerFinding], None] | None = None):
        self.on_finding = on_finding
        self.findings: list[SanitizerFinding] = []
        self._sanitizer: str | None = None
        self._reason = ""
        self._lines: list[str] = []

    def feed(self, line: str) -> None:
        match = _ERROR_START.search(line)
        if match:
            self._flush()
            lowered = line.lower()
            if "threadsanitizer" in lowered:
                self._sanitizer = "TSAN"
            elif "leaksanitizer" in lowered:
                self._sanitizer = "LSAN"
            else:
                self._sanitizer = "ASAN"
            self._reason = match.group(1).strip()
            self._lines = [line]
            return

        ubsan = _UBSAN_RUNTIME_ERROR.match(line.strip())
        if ubsan:
            # 연속 UB를 별개 결함으로 남기기 위해 이전 블록 종료
            self._flush()
            self._sanitizer = "UBSAN"
            self._reason = ubsan.group("message").strip()
            self._lines = [line]
            return

        if self._sanitizer is not None:
            self._lines.append(line)
            # UBSan 블록은 SUMMARY 에서 종료 (libFuzzer 실행 요약 혼입 방지)
            if self._sanitizer == "UBSAN" and _UBSAN_SUMMARY.match(line.strip()):
                self._flush()

    def finish(self) -> list[SanitizerFinding]:
        self._flush()
        return list(self.findings)

    def _flush(self) -> None:
        if self._sanitizer is None:
            return
        traceback: list[SourceLocation] = []
        for line in self._lines:
            match = _SOURCE_LOCATION.search(line)
            if match:
                location = SourceLocation(match.group("file"), int(match.group("line")))
                if location not in traceback:
                    traceback.append(location)
        finding = SanitizerFinding(self._sanitizer, classify_sanitizer_error(self._sanitizer, self._reason), self._reason, traceback, list(self._lines))
        self.findings.append(finding)
        if self.on_finding:
            self.on_finding(finding)
        self._sanitizer, self._reason, self._lines = None, "", []


def write_findings(path: Path, findings: list[SanitizerFinding]) -> None:
    """원문 traceback 보존 ANA 입력 JSON Lines 기록"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(f.to_dict(), ensure_ascii=False) + "\n" for f in findings), encoding="utf-8")
