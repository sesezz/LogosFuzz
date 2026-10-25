"""결과 파일·리포트에 남기는 오류 문자열의 노출 범위를 줄이는 도구.

예외 메시지와 도구의 stderr 에는 절대경로, 홈 디렉터리, 사용자 이름이 그대로 포함됨.
이 문자열이 JSON 결과나 리포트로 저장돼 공유되면 실행 환경 정보가 함께 유출됨
(Python 시큐어코딩 가이드 "오류 메시지 정보노출"). 자세한 원문은 콘솔·로그에만 두고,
저장하는 값은 :func:`redact_error` 를 거쳐야 함.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

_MAX_CHARS = 600
_MAX_LINES = 8
_ABS_PATH = re.compile(r"(?<![\w:/.-])(?:~|(?<!~))/(?:[\w.+@%-]+/)+[\w.+@%-]*")


def _home() -> str:
    try:
        return str(Path.home())
    except RuntimeError:
        return ""


def redact_error(text: object, *, max_chars: int = _MAX_CHARS, max_lines: int = _MAX_LINES) -> str:
    """오류 문자열을 저장 가능한 형태로 축약.

    - 홈 디렉터리는 ``~`` 로, 그 밖의 절대경로는 마지막 이름만 유지.
    - 마지막 ``max_lines`` 줄, 최대 ``max_chars`` 글자만 유지(원인은 보통 끝에 있음).
    """
    raw = "" if text is None else str(text)
    home = _home()
    if home and home != os.sep:
        raw = raw.replace(home, "~")
    raw = _ABS_PATH.sub(lambda m: ".../" + m.group(0).rstrip("/").rsplit("/", 1)[-1], raw)
    lines = [ln.rstrip() for ln in raw.strip().splitlines() if ln.strip()]
    clipped = "\n".join(lines[-max_lines:])
    if len(clipped) > max_chars:
        clipped = "..." + clipped[-max_chars:]
    return clipped
