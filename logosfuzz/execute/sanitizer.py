"""EXE-04-02: Sanitizer 로그 스트림 모니터링과 크래시 시그니처화.

ASan/LSan/TSAN 에 더해 **UBSan** 출력을 파싱한다.

UBSan 을 따로 다뤄야 하는 이유
------------------------------
ASan/LSan/TSAN 은 ``ERROR: AddressSanitizer:`` 같은 헤더 한 줄로 시작하지만,
UBSan 은 형식이 완전히 다르다.

    score/json/json.cc:38:11: runtime error: signed integer overflow: ...
        #0 ... in score::json::Dispatch(...) /proc/self/cwd/score/json/json.cc:38:11
        ...
    SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior score/json/json.cc:38:11

헤더가 없으므로 ``ERROR:`` 기반 정규식으로는 **한 건도 잡히지 않는다.**

그리고 더 위험한 성질이 하나 있다. UBSan 은 기본값(복구 가능)에서 진단만
찍고 **실행을 계속하며, 프로세스는 종료코드 0 으로 끝난다.**
``-fno-sanitize-recover=undefined`` 가 붙어야 비로소 죽는다(종료코드 1).
즉 종료코드만 보면 "정상 종료 · 크래시 없음" 으로 보이지만 실제로는 UB 가
여러 건 터진 상태일 수 있다. **UBSan 결함은 반드시 출력 파싱으로 잡아야 한다.**

이 모듈의 파서는 GEN 파트가 실제 Bazel 빌드에서 수집해 둔 출력 원문
(``tests/fixtures/sanitizer_logs/``, clang 18.1.3)을 정답지로 삼아 작성했다.
포맷을 추측하지 않았다.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

_ERROR_START = re.compile(r"(?:ERROR: (?:Address|Leak)Sanitizer:|WARNING: ThreadSanitizer:)\s*(.+)", re.IGNORECASE)

# UBSan 진단의 시작 줄. "<파일>:<행>:<열>: runtime error: <내용>" 형태다.
# 파일 경로에 공백이 없다는 전제는 _SOURCE_LOCATION 과 동일하다.
_UBSAN_RUNTIME_ERROR = re.compile(
    r"^(?P<file>\S+):(?P<line>\d+):(?P<col>\d+):\s*runtime error:\s*(?P<message>.+)$"
)
# UBSan 블록의 끝. 여기서 끊어야 뒤따르는 libFuzzer 요약줄이 결함에 섞이지 않고,
# 복구 가능 모드에서 연속으로 터지는 UB 여러 건이 한 덩어리로 합쳐지지 않는다.
_UBSAN_SUMMARY = re.compile(r"^SUMMARY:\s*UndefinedBehaviorSanitizer:", re.IGNORECASE)

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


def classify_ubsan_error(message: str) -> str:
    """UBSan 진단 메시지를 결함 분류로 매핑한다.

    분기 조건은 전부 수집된 출력 원문(tests/fixtures/sanitizer_logs)의 실제
    문구에서 가져왔다. 표본에 없는 UB 종류는 ``undefined-behavior`` 로 떨어져,
    "UB 이긴 한데 분류가 아직 없다" 가 "결함이 아니다" 로 오인되지 않게 한다.
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
    """Sanitizer 별 결함 분류 규칙.

    참고 - 차량 특화 분류였던 ``watchdog-timeout`` 은 제거했다. 대상이
    dlt-daemon(차량 RT)에서 Eclipse S-CORE 로 바뀌면서 워치독/실시간성 위반을
    나타내는 로그가 더는 나오지 않아, 잡히지 않는 분기만 남아 있었다.
    """
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
        # null 역참조 UB 직후 실제 SEGV 로 죽는 경우가 있다(픽스처
        # ubsan_null_deref.txt 에서 확인). 분류가 없으면 unknown 으로 빠져
        # ANA 가 판정 근거를 잃는다.
        return "segv"
    if "lock-order-inversion" in text or "deadlock" in text:
        return "deadlock"
    if "data race" in text or "race condition" in text:
        return "race-condition"
    if "mock" in text or "unimplemented protocol" in text:
        # GEN-03-03 mock 주입이 만든 가짜 크래시. ANA(triage)가 오탐 신호로 쓴다.
        return "mocking-fail-fp"
    return "unknown"


class SanitizerMonitor:
    """프로세스 출력 한 줄씩을 받아 Sanitizer 결함 블록을 수집한다."""
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
            # 복구 가능 모드에서는 UB 가 연속으로 여러 건 터진다. 앞 건을 먼저
            # 닫아야 각각 별개 결함으로 남는다.
            self._flush()
            self._sanitizer = "UBSAN"
            self._reason = ubsan.group("message").strip()
            self._lines = [line]
            return

        if self._sanitizer is not None:
            self._lines.append(line)
            # UBSan 은 SUMMARY 로 블록이 끝난다. 여기서 닫지 않으면 뒤따르는
            # libFuzzer 실행 요약("Executed ... in N ms")까지 결함 로그에 붙는다.
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
    """원문 traceback을 보존한 ANA 입력 JSON Lines 파일을 기록한다."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(f.to_dict(), ensure_ascii=False) + "\n" for f in findings), encoding="utf-8")
