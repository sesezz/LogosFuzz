"""EXE-04-02: ASAN/TSAN 로그 스트림 모니터링과 크래시 시그니처화."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

_ERROR_START = re.compile(r"(?:ERROR: (?:Address|Leak)Sanitizer:|WARNING: ThreadSanitizer:)\s*(.+)", re.IGNORECASE)
_WATCHDOG_TIMEOUT = re.compile(r"(?:watchdog|rt-timeout).*(?:timeout|expired)|(?:timeout|expired).*?(?:watchdog|rt-timeout)", re.IGNORECASE)
_SOURCE_LOCATION = re.compile(r"(?P<file>(?:[A-Za-z]:)?[^\s():]+\.(?:c|cc|cpp|cxx|h|hh|hpp)):(?P<line>\d+)(?::\d+)?")


@dataclass(frozen=True)
class SourceLocation:
    file: str
    line: int


@dataclass
class SanitizerFinding:
    """ANA-05-01/ANA-05-04에 전달할 정규화된 Sanitizer 결함 이벤트."""
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


def classify_sanitizer_error(sanitizer: str, reason: str) -> str:
    """설계서의 ASAN/TSAN 및 차량 특화 결함 분류 규칙."""
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
    if "lock-order-inversion" in text or "deadlock" in text:
        return "deadlock"
    if "data race" in text or "race condition" in text:
        return "race-condition"
    if "watchdog" in text or "rt-timeout" in text:
        return "watchdog-timeout"
    if "mock" in text or "unimplemented protocol" in text:
        return "mocking-fail-fp"
    return "unknown"


class SanitizerMonitor:
    """프로세스 출력 한 줄씩을 받아 ASAN/TSAN 결함 블록을 수집한다."""
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
            self._sanitizer = "TSAN" if "threadsanitizer" in line.lower() else "ASAN"
            self._reason = match.group(1).strip()
            self._lines = [line]
        elif _WATCHDOG_TIMEOUT.search(line):
            # 차량 실시간성 위반은 TSAN 실행 로그에서 sanitizer header 없이도 발생할 수 있다.
            self._flush()
            self._sanitizer = "TSAN"
            self._reason = line.strip()
            self._lines = [line]
        elif self._sanitizer is not None:
            self._lines.append(line)

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
    """원문 traceback을 보존한 ANA 입력 JSON Lines 파일을 기록한다."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(f.to_dict(), ensure_ascii=False) + "\n" for f in findings), encoding="utf-8")
