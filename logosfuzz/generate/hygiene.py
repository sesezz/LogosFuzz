"""GEN-03 하네스 위생 — LLM 출력에서 결정적으로 걷어내야 하는 것들.

왜 프롬프트로 안 되나
--------------------
4단계 검증(dlt-daemon)에서 프롬프트에 "헤더를 include 했으면 대상 함수를 다시
선언하지 마라"고 명시적으로 못 박았는데도 모델이 계속 선언을 써 넣었다. 그
선언이 헤더와 ``const`` 하나만 달라도 ``conflicting types`` 로 컴파일이 깨지고,
GEN-03-02 자가 치유는 같은 에러를 반복하다 stagnated 로 끝난다.

확률적으로 지켜지길 기대하는 대신 **후처리로 지운다.** 그리고 초안에만 걸어서는
소용이 없다 — 수정 라운드에서 LLM 이 같은 선언을 다시 써 넣어 에러가 부활한다.
``SelfHealLoop(sanitize=...)`` 로 모든 라운드에 적용해야 한다.

언어 판별도 같은 이유로 여기에 둔다. SCH 는 언어를 구분하지 않아 C++ 전용
API(``dlt_cpp_extension.hpp`` 의 템플릿 등)가 C 그룹과 나란히 나오고, 그걸 C 로
컴파일하면 ``'map' file not found`` 처럼 원인과 동떨어진 에러가 떠서 자가 치유가
엉뚱한 곳을 고치다 라운드를 소진한다.

표준 라이브러리만 사용한다.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Optional, Sequence

from .models import HarnessDraft

CPP_SUFFIXES = (".cpp", ".cc", ".cxx", ".c++", ".hpp", ".hh", ".hxx")


def strip_redundant_declarations(source: str, target_apis: Sequence[str]) -> str:
    """헤더를 include 했는데도 덧붙은 대상 함수 **선언**을 지운다.

    본문이 있는 정의(``{`` 로 이어지는 것)는 건드리지 않는다 — 하네스가 만든
    보조 함수일 수 있다. 세미콜론으로 끝나는 프로토타입만 대상이다.

    >>> src = 'void f(char *t);\\nint LLVMFuzzerTestOneInput(void){return 0;}'
    >>> "void f(char *t);" in strip_redundant_declarations(src, ["f"])
    False
    """
    if not target_apis:
        return source
    names = "|".join(re.escape(n) for n in target_apis if n)
    if not names:
        return source
    pattern = re.compile(
        rf"^[ \t]*(?:extern[ \t]+)?[A-Za-z_][\w \t\*&]*\b(?:{names})[ \t]*"
        rf"\([^;{{}}]*\)[ \t]*;[ \t]*$",
        re.MULTILINE,
    )
    return pattern.sub("", source)


def infer_language(paths: Iterable[str]) -> str:
    """대상 파일/헤더 경로에서 하네스 언어를 정한다. ``"c"`` 또는 ``"cpp"``."""
    for path in paths:
        if path and str(path).lower().endswith(CPP_SUFFIXES):
            return "cpp"
    return "c"


def is_cpp(draft: HarnessDraft) -> bool:
    return draft.language in ("cpp", "c++", "cxx")


def sanitize_harness(source: str, draft: Optional[HarnessDraft] = None,
                     target_apis: Optional[Sequence[str]] = None) -> str:
    """하네스 소스에 위생 규칙을 모두 적용한다.

    ``SelfHealLoop(sanitize=sanitize_harness)`` 형태로 주입하면 초안과 모든
    수정 라운드에 동일하게 걸린다.
    """
    apis = list(target_apis or (draft.target_apis if draft else []))
    return strip_redundant_declarations(source, apis)


def harness_source_name(draft: HarnessDraft) -> str:
    """드래프트 언어에 맞는 소스 파일 이름."""
    return f"{draft.logic_group}" + (".cpp" if is_cpp(draft) else ".c")


def language_of_group(files: Iterable[str] = (), headers: Iterable[str] = ()) -> str:
    """로직 그룹의 파일·헤더 목록으로 언어를 판별한다(SCH -> GEN 연결용)."""
    return infer_language([*files, *headers])


def basename(path: str) -> str:
    return Path(str(path).replace("\\", "/")).name
