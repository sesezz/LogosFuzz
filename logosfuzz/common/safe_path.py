"""외부에서 들어온 이름·상대경로를 파일 시스템 경로로 쓸 때의 공용 검증.

그룹명, 케이스명, 패키지 경로는 LLM 출력이나 JSON 입력에서 온다. 이 값을 그대로
``base / name`` 으로 이어 붙이면 ``..`` 나 절대경로로 기준 디렉터리 밖에 쓰거나
지우게 된다(Python 시큐어코딩 가이드 "경로 조작 및 자원 삽입").

- 파일·디렉터리 이름 한 칸으로 쓸 값 -> :func:`safe_component` (안전한 이름으로 변환)
- ``a/b/c`` 처럼 하위 경로가 정상인 값 -> :func:`resolve_within` (밖으로 나가면 거부)
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Union

PathLike = Union[str, "os.PathLike[str]"]

_UNSAFE_CHARS = re.compile(r"[^\w.\-]+", re.UNICODE)
_MAX_COMPONENT_LEN = 100
_HASH_LEN = 8


class UnsafePathError(ValueError):
    """기준 디렉터리 밖을 가리키거나 비어 있는 경로."""


def safe_component(name: str, *, default: str = "unnamed") -> str:
    """``name`` 을 경로 한 칸(파일·디렉터리 이름)으로 안전하게 쓸 수 있는 형태로 변환.

    ``[\\w.-]`` 외 문자는 ``_`` 로 바꾸고, 앞쪽 ``.``/``-`` 는 떼어 낸다. 이미 안전한
    이름은 그대로 돌려준다. 바뀐 이름은 서로 다른 입력이 같은 이름으로 합쳐지지
    않도록 원본의 짧은 해시를 뒤에 추가.
    """
    original = str(name)
    cleaned = _UNSAFE_CHARS.sub("_", original).strip("._-")[:_MAX_COMPONENT_LEN]
    if cleaned == original and cleaned:
        return cleaned
    digest = hashlib.sha256(original.encode("utf-8", "surrogatepass")).hexdigest()[:_HASH_LEN]
    return f"{cleaned or default}-{digest}"


def resolve_within(base: PathLike, *parts: PathLike, allow_base: bool = False) -> Path:
    """``base`` 아래로 ``parts`` 를 이어 붙인 경로를 돌려준다. 밖이면 예외.

    ``..`` 와 절대경로 조각으로 ``base`` 를 벗어나면 :class:`UnsafePathError` 를 발생시킴.
    기본은 ``base`` 자신도 거부한다(패키지 경로가 비어 있을 때 작업 영역 전체를
    지우는 사고를 막으려는 것). 심볼릭 링크는 따라가지 않고 경로 문자열만 정규화
    (``bazel-bin`` 처럼 작업 영역 밖을 가리키는 링크를 쓰는 정상 경로 존재).
    """
    base_abs = os.path.abspath(os.fspath(base))
    for part in parts:
        if "\x00" in os.fspath(part):
            raise UnsafePathError("경로에 NUL 문자가 있다")
    candidate = os.path.abspath(os.path.join(base_abs, *map(os.fspath, parts)))
    if candidate == base_abs:
        if allow_base:
            return Path(candidate)
        raise UnsafePathError(f"기준 디렉터리 자신을 가리키는 경로: {parts!r}")
    if os.path.commonpath([base_abs, candidate]) != base_abs:
        raise UnsafePathError(f"기준 디렉터리 밖을 가리키는 경로: {parts!r}")
    return Path(candidate)
