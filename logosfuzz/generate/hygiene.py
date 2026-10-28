"""GEN-03 하네스 위생: LLM 출력의 결정적 후처리

- 헤더 include 후 대상 함수 재선언 제거 (프롬프트 금지만으로는 재발, ``conflicting types`` 유발)
- ``SelfHealLoop(sanitize=...)`` 로 초안과 모든 수정 라운드에 적용 필요
- ``mkstemp`` 템플릿이 ``XXXXXX`` 로 끝나지 않으면 ``mkstemps`` 로 교정 (항상 실패해 라이브러리를 호출하지 못함)
- 하네스 언어(C/C++) 판별 (SCH 는 언어 미구분)

표준 라이브러리만 사용
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Optional, Sequence

from .models import HarnessDraft

CPP_SUFFIXES = (".cpp", ".cc", ".cxx", ".c++", ".hpp", ".hh", ".hxx")


def strip_redundant_declarations(source: str, target_apis: Sequence[str]) -> str:
    """헤더 include 후 덧붙은 대상 함수 **선언** 제거

    세미콜론으로 끝나는 프로토타입만 대상, 본문 있는 정의(보조 함수 가능)는 유지

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


_TEMPLATE_DECL_RE = re.compile(
    r'(?P<decl>char[ \t]+(?P<name>\w+)[ \t]*\[[ \t]*\][ \t]*=[ \t]*"[^"\n]*XXXXXX)(?P<suffix>[^"\n]+)"')


def fix_mkstemp_suffix(source: str) -> str:
    """접미사가 붙은 임시 파일 템플릿에 ``mkstemp`` 를 쓴 호출을 ``mkstemps`` 로 교정

    ``mkstemp`` 는 템플릿이 정확히 ``XXXXXX`` 로 끝나야 한다. ``"/tmp/x_XXXXXX.wav"`` 처럼 접미사가
    있으면 항상 -1 을 돌려주고, 하네스가 ``if (fd == -1) return 0;`` 으로 즉시 반환하면
    라이브러리를 한 번도 호출하지 못한 채 초당 수십만 번 도는 것으로 보인다(libsndfile 실측: cov 2).

    >>> src = 'char t[] = "/tmp/a_XXXXXX.wav"; int fd = mkstemp(t);'
    >>> "mkstemps(t, 4)" in fix_mkstemp_suffix(src)
    True
    """
    for match in _TEMPLATE_DECL_RE.finditer(source):
        name, suffix = match.group("name"), match.group("suffix")
        source = re.sub(rf"\bmkstemp\s*\(\s*{re.escape(name)}\s*\)",
                        f"mkstemps({name}, {len(suffix)})", source)
    return source


def infer_language(paths: Iterable[str]) -> str:
    """대상 파일/헤더 경로로 하네스 언어 결정 (``"c"`` 또는 ``"cpp"``)"""
    for path in paths:
        if path and str(path).lower().endswith(CPP_SUFFIXES):
            return "cpp"
    return "c"


def is_cpp(draft: HarnessDraft) -> bool:
    return draft.language in ("cpp", "c++", "cxx")


def sanitize_harness(source: str, draft: Optional[HarnessDraft] = None,
                     target_apis: Optional[Sequence[str]] = None) -> str:
    """하네스 소스에 위생 규칙 전체 적용

    ``SelfHealLoop(sanitize=sanitize_harness)`` 주입 시 초안과 모든 수정 라운드에 적용
    """
    apis = list(target_apis or (draft.target_apis if draft else []))
    return fix_mkstemp_suffix(strip_redundant_declarations(source, apis))


def harness_source_name(draft: HarnessDraft) -> str:
    """드래프트 언어에 맞는 소스 파일 이름"""
    return f"{draft.logic_group}" + (".cpp" if is_cpp(draft) else ".c")


def language_of_group(files: Iterable[str] = (), headers: Iterable[str] = ()) -> str:
    """로직 그룹의 파일·헤더 목록으로 언어 판별 (SCH -> GEN 연결용)"""
    return infer_language([*files, *headers])


def basename(path: str) -> str:
    return Path(str(path).replace("\\", "/")).name
