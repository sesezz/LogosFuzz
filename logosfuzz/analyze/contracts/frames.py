"""에러계약 플러그인 공통: 원문 sanitizer 로그에서 함수 이름까지 담은 프레임을 읽는다.

``CrashRecord.traceback`` 은 파일:줄만 담는다. 계약 판별에는 "어떤 함수가 무엇을
불렀는가"가 필요하므로 원문 로그에서 프레임을 다시 읽는다. ``score_result`` 와
``c_return_code`` 플러그인이 같이 쓴다(원래 ``analyze/error_contract.py`` 에 있던 코드).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Sequence

from logosfuzz.analyze.models import Frame
from logosfuzz.analyze.signature import is_harness_frame, is_runtime_frame

# --------------------------------------------------------------------------- #
# 프레임 파싱 — 함수 이름까지 필요하다
# --------------------------------------------------------------------------- #
# CrashRecord.traceback 은 파일:줄만 담는다. 계약 위반 판별에는 "어떤 함수가
# value() 를 불렀는가"가 필요하므로 원문 로그에서 프레임을 다시 읽는다.
#   #12 0x55d0 in score::details::expected<int, E>::value() const & /p/expected.h:503
#   #7 <ADDR> in std::terminate() (/lib/x86_64-linux-gnu/libstdc++.so.6+0xa5a54) (BuildId: ..)
#   #5 <ADDR>  (/lib/x86_64-linux-gnu/libstdc++.so.6+0xa5ff4) (BuildId: ..)   ← 이름 없음
_FRAME_RE = re.compile(r"^\s*#(?P<idx>\d+)\s+(?:0x[0-9a-fA-F]+|<ADDR>)\s+(?P<rest>.*)$")
_BUILD_ID_RE = re.compile(r"\s*\(BuildId:[^)]*\)\s*$")
_LOCATION_RE = re.compile(r"^(?P<file>\S+?):(?P<line>\d+)(?::\d+)?$")

# C/C++ 런타임·표준 라이브러리 프레임. 크래시 지점을 찾을 때 건너뛴다.
_RUNTIME_FUNC_PREFIXES = (
    "std::", "__cxa", "__gxx", "_Unwind", "__GI_", "__pthread", "__libc", "_start",
    "abort", "raise", "__sanitizer", "__asan", "__ubsan", "fuzzer::",
)
_RUNTIME_FILE_MARKERS = (
    "nptl/", "sysdeps/", "stdlib/abort.c", "csu/", "/usr/include/", "libstdc++",
    "libc++", "libgcc_s", "libc.so", "/lib/x86_64-linux-gnu/",
)


@dataclass(frozen=True)
class NamedFrame:
    """함수 이름까지 담은 프레임(원문 로그 1줄)."""

    index: int
    function: str
    file: str = ""
    line: int = 0

    def as_frame(self) -> Frame:
        return Frame(self.file, self.line)

    def render(self) -> str:
        loc = f"{self.file}:{self.line}" if self.file else "?"
        return f"#{self.index} {self.function or '?'} @ {loc}"


def parse_frames(raw_log: Sequence[str]) -> list[NamedFrame]:
    """원문 로그에서 스택 프레임을 함수 이름과 함께 읽는다(첫 스택만)."""
    frames: list[NamedFrame] = []
    for line in raw_log:
        match = _FRAME_RE.match(line)
        if not match:
            continue
        idx = int(match.group("idx"))
        if frames and idx == 0:
            break  # 두 번째 스택(할당 지점 등)은 크래시 지점이 아니다
        rest = _BUILD_ID_RE.sub("", match.group("rest").strip())
        if not rest.startswith("in "):
            frames.append(NamedFrame(idx, ""))
            continue
        body = rest[3:].strip()
        func, _, location = body.rpartition(" ")
        loc = _LOCATION_RE.match(location)
        if loc:
            frames.append(NamedFrame(idx, func.strip(), loc.group("file"), int(loc.group("line"))))
        elif location.startswith("("):
            frames.append(NamedFrame(idx, func.strip()))  # 공유 라이브러리 오프셋
        else:
            frames.append(NamedFrame(idx, body))
    return frames


def is_runtime(frame: NamedFrame) -> bool:
    if not frame.function and not frame.file:
        return True
    if frame.function.startswith(_RUNTIME_FUNC_PREFIXES):
        return True
    text = frame.file.replace("\\", "/").lower()
    if any(m in text for m in _RUNTIME_FILE_MARKERS):
        return True
    return bool(frame.file) and is_runtime_frame(frame.as_frame())


def is_harness(frame: NamedFrame) -> bool:
    if "LLVMFuzzerTestOneInput" in frame.function:
        return True
    return bool(frame.file) and is_harness_frame(frame.as_frame())


def short_name(function: str) -> str:
    """``score::json::Parse(char const*)`` → ``Parse`` (KB 문서의 function 형식)."""
    name = function.split("(", 1)[0].strip()
    depth, cut = 0, len(name)
    # 템플릿 인자 안의 :: 에 속지 않도록 바깥 깊이에서만 자른다.
    for i in range(len(name) - 1, -1, -1):
        ch = name[i]
        if ch == ">":
            depth += 1
        elif ch == "<":
            depth -= 1
        elif depth == 0 and name.startswith("::", i - 1) and i > 0:
            cut = i + 1
            break
    tail = name[cut:] if cut < len(name) else name
    return tail.split("<", 1)[0].strip()
