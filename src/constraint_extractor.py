"""EXT-01-02: C/C++ 소스에서 API 제약조건(constraint)을 추출한다.

`src.ast_analyzer`가 파일 단위의 거친 구조를 본다면, 이 모듈은 함수 단위로
"이 API를 호출하려면 무엇이 참이어야 하는가"를 추출한다. 추출 결과는
`src.rag_constraints`가 RAG 지식베이스로 색인한다.

추출하는 제약조건 종류:
  - null_check   : 포인터 인자에 대한 NULL 검사 (호출 전 non-NULL 요구)
  - nullable     : NULL을 허용하도록 방어된 인자
  - range_check  : 숫자 인자의 범위/경계 비교
  - assert       : assert() 계열로 명시된 사전조건
  - buffer_size  : (포인터, 길이) 인자 쌍
  - resource     : malloc/fopen 등 자원 획득과 해제 책임
  - return_value : 실패 시 반환값 규약
  - risky_call   : 길이 검증이 필요한 위험 API 사용
  - doc          : 주석에 서술된 제약조건

사용법:
  python -m src.constraint_extractor examples --output build/constraints.json
"""
from __future__ import annotations

import argparse
import bisect
import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

SOURCE_SUFFIXES = (".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp")

# 이름 뒤에 '(' 와 '{' 가 와도 함수 정의가 아닌 토큰들
CONTROL_KEYWORDS = {
    "if", "else", "for", "while", "do", "switch", "case", "return", "sizeof",
    "catch", "try", "alignof", "_Alignof", "decltype", "noexcept",
    "typedef", "static_assert", "_Static_assert", "__attribute__", "and", "or",
    "not", "new", "delete", "throw",
}

# 자원 획득 함수 -> 대응하는 해제 함수
RESOURCE_PAIRS = {
    "malloc": "free",
    "calloc": "free",
    "realloc": "free",
    "strdup": "free",
    "strndup": "free",
    "aligned_alloc": "free",
    "posix_memalign": "free",
    "fopen": "fclose",
    "fdopen": "fclose",
    "freopen": "fclose",
    "open": "close",
    "socket": "close",
    "opendir": "closedir",
    "mmap": "munmap",
}

# 퍼징 관점에서 입력 길이 검증이 필요한 API
RISKY_CALLS = {
    "strcpy": "bounds-unchecked string copy",
    "strcat": "bounds-unchecked string concat",
    "sprintf": "bounds-unchecked formatting",
    "vsprintf": "bounds-unchecked formatting",
    "gets": "unbounded stdin read",
    "scanf": "unbounded %s conversion",
    "sscanf": "unbounded %s conversion",
    "alloca": "stack allocation from untrusted size",
    "memcpy": "size argument must not exceed destination capacity",
    "memmove": "size argument must not exceed destination capacity",
    "strncpy": "may leave the destination without a NUL terminator",
}

ASSERT_RE = re.compile(r"\b(assert|ASSERT|BUG_ON|CHECK|VERIFY|_Static_assert)\s*\(")
CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
IF_RE = re.compile(r"\bif\s*\(")
RETURN_RE = re.compile(r"\breturn\b([^;]*);")
NULL_LITERALS = ("NULL", "nullptr", "0")

NOT_NULL_RE = re.compile(r"!\s*([A-Za-z_]\w*)")
NULL_CMP_RE = re.compile(r"\b([A-Za-z_]\w*)\s*(==|!=)\s*(NULL|nullptr|0)\b")
NULL_CMP_REV_RE = re.compile(r"\b(NULL|nullptr|0)\s*(==|!=)\s*([A-Za-z_]\w*)\b")
COMPARE_RE = re.compile(r"\b([A-Za-z_]\w*)\s*(<=|>=|<|>)\s*([A-Za-z_]\w*|0[xX][0-9a-fA-F]+|\d+)\b")
NUMBER_EQ_RE = re.compile(r"\b([A-Za-z_]\w*)\s*(==|!=)\s*(0[xX][0-9a-fA-F]+|\d+)\b")
NUMBER_EQ_REV_RE = re.compile(r"\b(0[xX][0-9a-fA-F]+|\d+)\s*(==|!=)\s*([A-Za-z_]\w*)\b")

SIZE_NAME_RE = re.compile(
    r"(?i)^_*(?:.*_)?(len|length|size|sz|count|cnt|num|n|nmemb|nbytes|bytes|cap|capacity)$"
)
INT_TYPE_RE = re.compile(
    r"\b(int|long|short|char|size_t|ssize_t|unsigned|signed|uint\w*|u?int\d+_t|"
    r"u?intptr_t|off_t|ptrdiff_t)\b"
)
# 분기 본문이 "입력을 거부하는 경로"인지 "정상 계산 경로"인지 가른다.
# `if (x != 0) { return compute(x); }` 처럼 값을 돌려주는 분기를 거부 검사로
# 오해하면 제약조건의 부등호가 뒤집혀 완전히 틀린 결론이 나온다.
ERROR_RETURN_RE = re.compile(r"\breturn\s*\(?\s*(?:-\s*\d+|NULL|nullptr|false)\s*\)?\s*;")
ERROR_GOTO_RE = re.compile(
    r"\bgoto\s+\w*(?:err|fail|cleanup|bail|invalid|abort|done|end|exit)\w*", re.I
)
FATAL_CALL_RE = re.compile(
    r"\b(?:abort|_?exit|longjmp|siglongjmp|\w*fatal\w*|\w*panic\w*|\w*unreachable\w*)\s*\(",
    re.I,
)
ANY_EXIT_RE = re.compile(r"\b(return|goto|break|continue|throw)\b")

BRANCH_ERROR_EXIT = "error_exit"
BRANCH_PLAIN_EXIT = "plain_exit"
BRANCH_NO_EXIT = "none"
TRAILING_QUALIFIER_RE = re.compile(
    r"(const|volatile|noexcept|override|final|throw\s*\([^)]*\)|__attribute__\s*\(\([^)]*\)\))"
)
REJECT_PREFIX_TAIL = set("=,([?:!+/%<>&|^.~")


@dataclass
class Constraint:
    """함수 하나에 대한 단일 제약조건."""

    kind: str
    target: str
    expression: str
    description: str
    line: int
    confidence: float = 0.5
    occurrences: int = 1

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Param:
    name: str
    type: str
    is_pointer: bool = False
    is_const: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class FunctionFacts:
    """RAG 색인 단위가 되는 함수 하나의 사실 묶음."""

    name: str
    file: str
    line: int
    signature: str
    return_type: str
    params: List[Param] = field(default_factory=list)
    doc: str = ""
    calls: List[str] = field(default_factory=list)
    # 본문에 나타난 순서 그대로의 호출 목록(중복 포함). SCH-02-02 의 call_seq
    # ("소비자 코드에서 뽑은 실제 호출 순서")를 만들려면 순서가 필요하다.
    call_sequence: List[str] = field(default_factory=list)
    constraints: List[Constraint] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "file": self.file,
            "line": self.line,
            "signature": self.signature,
            "return_type": self.return_type,
            "params": [p.to_dict() for p in self.params],
            "doc": self.doc,
            "calls": self.calls,
            "call_sequence": self.call_sequence,
            "constraints": [c.to_dict() for c in self.constraints],
        }


# ---------------------------------------------------------------------------
# 소스 전처리
# ---------------------------------------------------------------------------


def mask_source(text: str) -> str:
    """주석/문자열/전처리기 라인을 공백으로 치환한 텍스트를 만든다.

    오프셋과 줄 번호가 원본과 1:1로 유지되므로, 구조 파싱은 마스킹된 텍스트로
    하고 사람이 읽을 조각은 원본에서 잘라내면 된다.
    """
    out = list(text)
    n = len(text)
    i = 0
    at_line_start = True

    def blank(start: int, end: int) -> None:
        for k in range(start, min(end, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = text[i]
        if c == "\n":
            at_line_start = True
            i += 1
            continue
        if at_line_start and c == "#":
            # 전처리기 지시문: 줄 연속(\)까지 포함해 통째로 제거
            j = i
            while j < n:
                nl = text.find("\n", j)
                if nl == -1:
                    nl = n
                blank(j, nl)
                if nl > j and text[nl - 1] == "\\":
                    j = nl + 1
                    continue
                j = nl
                break
            i = j
            continue
        if not c.isspace():
            at_line_start = False
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            nl = text.find("\n", i)
            nl = n if nl == -1 else nl
            blank(i, nl)
            i = nl
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            end = n if end == -1 else end + 2
            blank(i, end)
            i = end
            continue
        if c in "\"'":
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == c or text[j] == "\n":
                    j += 1
                    break
                j += 1
            blank(i, j)
            i = j
            continue
        i += 1

    return "".join(out)


class LineIndex:
    """문자 오프셋을 1-based 줄 번호로 바꾼다."""

    def __init__(self, text: str) -> None:
        self._starts = [0]
        for idx, ch in enumerate(text):
            if ch == "\n":
                self._starts.append(idx + 1)

    def line_of(self, pos: int) -> int:
        return bisect.bisect_right(self._starts, pos)


def match_delim(text: str, open_pos: int, open_ch: str = "(", close_ch: str = ")") -> Optional[int]:
    """`open_pos`의 여는 기호와 짝이 되는 닫는 기호 위치를 찾는다."""
    if open_pos >= len(text) or text[open_pos] != open_ch:
        return None
    depth = 0
    for i in range(open_pos, len(text)):
        ch = text[i]
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i
    return None


def split_top_level(text: str, sep: str = ",") -> List[str]:
    """괄호 깊이 0에서만 잘라 인자 목록을 나눈다 (함수 포인터 인자 대응)."""
    parts: List[str] = []
    depth = 0
    current: List[str] = []
    for ch in text:
        if ch in "([{<":
            depth += 1
        elif ch in ")]}>":
            depth -= 1
        if ch == sep and depth == 0:
            parts.append("".join(current))
            current = []
            continue
        current.append(ch)
    if current:
        parts.append("".join(current))
    return [p.strip() for p in parts if p.strip()]


def parse_params(param_text: str) -> List[Param]:
    params: List[Param] = []
    for raw in split_top_level(param_text):
        cleaned = raw.strip()
        if not cleaned or cleaned in ("void", "..."):
            continue

        # 함수 포인터 인자: int (*cb)(void *)
        fp = re.search(r"\(\s*\*+\s*([A-Za-z_]\w*)\s*\)", cleaned)
        if fp:
            params.append(Param(name=fp.group(1), type=cleaned, is_pointer=True,
                                is_const="const" in cleaned))
            continue

        without_array = re.sub(r"\[[^\]]*\]", "", cleaned)
        identifiers = re.findall(r"[A-Za-z_]\w*", without_array)
        name = identifiers[-1] if identifiers else ""
        type_part = without_array
        if name and len(identifiers) > 1:
            type_part = without_array[: without_array.rfind(name)]
        else:
            # `int` 처럼 이름이 생략된 인자
            name = ""
            type_part = without_array

        is_pointer = "*" in cleaned or "[" in cleaned
        params.append(
            Param(
                name=name,
                type=" ".join(type_part.split()) or cleaned,
                is_pointer=is_pointer,
                is_const="const" in cleaned,
            )
        )
    return params


def extract_doc_comment(text: str, decl_start: int) -> str:
    """함수 선언 바로 위에 붙은 주석 블록을 원본에서 찾아온다."""
    head = text[:decl_start]
    stripped = head.rstrip()
    if stripped.endswith("*/"):
        open_at = stripped.rfind("/*")
        if open_at != -1:
            body = stripped[open_at + 2 : -2]
            lines = [re.sub(r"^\s*\*+\s?", "", ln).strip() for ln in body.splitlines()]
            return "\n".join(ln for ln in lines if ln).strip()

    # 연속된 // 주석 줄
    collected: List[str] = []
    for line in reversed(stripped.splitlines()):
        candidate = line.strip()
        if candidate.startswith("//"):
            collected.append(candidate.lstrip("/").strip())
            continue
        break
    return "\n".join(reversed(collected)).strip()


# ---------------------------------------------------------------------------
# 함수 탐색
# ---------------------------------------------------------------------------


def _decl_prefix(masked: str, name_start: int) -> str:
    i = name_start - 1
    while i >= 0 and masked[i] not in ";{}":
        i -= 1
    return masked[i + 1 : name_start]


def _skip_ws(text: str, pos: int) -> int:
    while pos < len(text) and text[pos].isspace():
        pos += 1
    return pos


# 함수를 매크로로 감싸 선언·정의하는 라이브러리가 있다. libpng 이 대표적이다.
#
#   PNG_FUNCTION(png_structp, PNGAPI
#   png_create_read_struct,(png_const_charp v, ...), PNG_ALLOCATED)
#   { ... }
#
# 이걸 그대로 스캔하면 함수 이름이 `PNG_FUNCTION` 으로 잡히고, 진짜 API 는
# 지식베이스에서 통째로 사라진다. 실제로 libpng 색인에서
# `png_create_read_struct` 가 빠져 GEN 이 하네스를 만들 때 참조할 수 없었다.
_MACRO_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,}$")


def destructure_macro_declaration(args: str, offset: int = 0):
    """매크로 인자에서 (함수명, 이름 위치, 파라미터 범위, 반환형)을 분해한다.

    규칙은 하나다 — **마지막 최상위 괄호 그룹이 파라미터 목록**이고, 그 앞의
    마지막 식별자가 함수 이름이다. 이 규칙 하나로 선언(PNG_EXPORT)과
    정의(PNG_FUNCTION) 양쪽이 처리된다.

        PNG_EXPORT(64, void, png_destroy_read_struct, (png_structpp a, ...))
                                ^이름                  ^파라미터
        PNG_FUNCTION(png_structp, PNGAPI png_create_read_struct, (...), ATTR)
                                         ^이름                    ^파라미터

    찾지 못하면 None.
    """
    depth = 0
    group = None            # (열린 위치, 닫힌 위치) — 마지막 최상위 괄호 그룹
    start = -1
    for i, ch in enumerate(args):
        if ch == "(":
            if depth == 0:
                start = i
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0 and start >= 0:
                group = (start, i)
    if group is None:
        return None

    head = args[: group[0]]
    identifiers = list(re.finditer(r"[A-Za-z_]\w*", head))
    if not identifiers:
        return None
    name_match = identifiers[-1]

    # 반환형 정리. 매크로마다 앞에 붙는 것이 다르다.
    #   PNG_EXPORT(64, void, name, (...))       -> 색인 번호 64 를 버린다
    #   PNG_FUNCTION(png_structp, PNGAPI name, ...) -> 호출 규약 PNGAPI 를 버린다
    # 숫자만인 조각과 대문자 매크로(호출 규약/속성)를 걷어내고 남은 것을 쓴다.
    segments = [s.strip() for s in head[: name_match.start()].split(",")]
    kept = [s for s in segments if s and not s.isdigit() and not _MACRO_NAME_RE.match(s)]
    if not kept:
        kept = [s for s in segments if s and not s.isdigit()]

    return {
        "name": name_match.group(0),
        "name_start": offset + name_match.start(),
        "params_span": (offset + group[0] + 1, offset + group[1]),
        "return_type": " ".join(" ".join(kept).split()),
    }


def find_functions(masked: str) -> List[dict]:
    """함수 정의의 위치 정보를 찾는다. (중첩된 정의는 건너뛴다)"""
    found: List[dict] = []
    scan_from = 0

    for match in CALL_RE.finditer(masked):
        if match.start() < scan_from:
            continue
        name = match.group(1)
        if name in CONTROL_KEYWORDS:
            continue

        paren_open = match.end() - 1
        paren_close = match_delim(masked, paren_open)
        if paren_close is None:
            continue

        pos = _skip_ws(masked, paren_close + 1)
        while True:
            qualifier = TRAILING_QUALIFIER_RE.match(masked, pos)
            if not qualifier:
                break
            pos = _skip_ws(masked, qualifier.end())
        if pos >= len(masked) or masked[pos] != "{":
            continue

        raw_prefix = _decl_prefix(masked, match.start())
        prefix = raw_prefix.strip()

        # 매크로로 감싼 정의라면 진짜 함수 이름·파라미터로 바꿔 끼운다.
        # 이 판정은 **prefix 검사보다 먼저** 해야 한다. 매크로 정의는 반환형이
        # 매크로 인자 안에 있어서 앞에 아무 토큰도 없고, 그러면 아래 prefix
        # 검사에 걸려 통째로 버려진다. libpng 의 png_create_read_struct 가
        # 정확히 그렇게 사라졌다.
        entry_name, entry_name_start = name, match.start()
        entry_params = (paren_open + 1, paren_close)
        entry_return = " ".join(prefix.split())
        macro_wrapped = False
        if _MACRO_NAME_RE.match(name):
            inner = destructure_macro_declaration(
                masked[paren_open + 1:paren_close], paren_open + 1
            )
            if inner:
                macro_wrapped = True
                entry_name = inner["name"]
                entry_name_start = inner["name_start"]
                entry_params = inner["params_span"]
                entry_return = inner["return_type"] or entry_return

        if not macro_wrapped:
            if not prefix or prefix[-1] in REJECT_PREFIX_TAIL:
                continue
            prefix_tokens = re.findall(r"[A-Za-z_]\w*", prefix)
            if not prefix_tokens or prefix_tokens[-1] in CONTROL_KEYWORDS:
                continue
        elif prefix and prefix[-1] in REJECT_PREFIX_TAIL:
            continue  # 매크로라도 호출식 한가운데면 정의가 아니다

        body_end = match_delim(masked, pos, "{", "}")
        if body_end is None:
            continue

        found.append(
            {
                "name": entry_name,
                # 반환형이 시작되는 위치. 마스킹된 주석은 공백이므로 lstrip 하면
                # 실제 선언 첫 글자로 이동한다 (그 앞이 doc 주석 영역).
                "decl_start": match.start() - len(raw_prefix.lstrip()),
                "name_start": entry_name_start,
                "params_span": entry_params,
                "body_span": (pos, body_end),
                "return_type": entry_return,
            }
        )
        scan_from = body_end + 1

    return found


# ---------------------------------------------------------------------------
# 제약조건 규칙
# ---------------------------------------------------------------------------


def _param_map(params: Sequence[Param]) -> Dict[str, Param]:
    return {p.name: p for p in params if p.name}


def dedupe_constraints(constraints: Sequence[Constraint]) -> List[Constraint]:
    """같은 제약조건의 반복을 하나로 합치고 등장 횟수를 센다.

    생성된 코드는 같은 assert 를 수천 번 반복하기도 한다. 그대로 두면 문서
    하나가 색인 전체의 단어 빈도를 왜곡한다.
    """
    first: Dict[tuple, Constraint] = {}
    ordered: List[Constraint] = []
    for constraint in constraints:
        key = (constraint.kind, constraint.target, constraint.description)
        existing = first.get(key)
        if existing is not None:
            existing.occurrences += 1
            existing.confidence = max(existing.confidence, constraint.confidence)
            continue
        first[key] = constraint
        ordered.append(constraint)
    return ordered


def _snippet(text: str, start: int, end: int) -> str:
    return " ".join(text[start:end].split())


def _branch_segment(masked: str, close_pos: int, window: int = 200) -> str:
    """`if (...)` 의 닫는 괄호 뒤에 오는 분기 본문만 정확히 잘라낸다."""
    start = _skip_ws(masked, close_pos + 1)
    if start >= len(masked):
        return ""
    if masked[start] == "{":
        end = match_delim(masked, start, "{", "}")
        if end is not None:
            return masked[start : end + 1]
        return masked[start : start + window]
    end = masked.find(";", start)
    return masked[start : end + 1] if end != -1 else masked[start : start + window]


def _classify_branch(masked: str, close_pos: int) -> str:
    """분기 본문을 error_exit / plain_exit / none 으로 분류한다.

    error_exit 일 때만 "호출자가 만족시켜야 하는 조건"으로 부등호를 뒤집는다.
    """
    segment = _branch_segment(masked, close_pos)
    if (
        ERROR_RETURN_RE.search(segment)
        or ERROR_GOTO_RE.search(segment)
        or FATAL_CALL_RE.search(segment)
    ):
        return BRANCH_ERROR_EXIT
    if ANY_EXIT_RE.search(segment):
        return BRANCH_PLAIN_EXIT
    return BRANCH_NO_EXIT


def _conditions(masked: str, body_span) -> List[tuple]:
    """본문 안의 모든 `if (...)` 조건에 대해 (조건 시작, 조건 끝, 닫는 괄호) 반환."""
    start, end = body_span
    conditions = []
    for match in IF_RE.finditer(masked, start, end):
        paren_open = match.end() - 1
        paren_close = match_delim(masked, paren_open)
        if paren_close is None or paren_close > end:
            continue
        conditions.append((paren_open + 1, paren_close, paren_close))
    return conditions


def _null_constraints(cond_masked: str, cond_original: str, params: Dict[str, Param],
                      line: int, branch: str) -> List[Constraint]:
    constraints: List[Constraint] = []
    seen: set = set()

    def add(target: str, negated: bool) -> None:
        param = params.get(target)
        if param is None or not param.is_pointer or target in seen:
            return
        seen.add(target)

        # `if (p == NULL) { p = fallback; }` 는 NULL을 금지하는 게 아니라 허용한다.
        if negated and branch == BRANCH_NO_EXIT:
            constraints.append(
                Constraint(
                    kind="nullable",
                    target=target,
                    expression=cond_original,
                    description=(
                        f"'{target}' is NULL-checked but the branch does not bail out, "
                        f"so NULL appears to be handled"
                    ),
                    line=line,
                    confidence=0.5,
                )
            )
        elif negated:
            constraints.append(
                Constraint(
                    kind="null_check",
                    target=target,
                    expression=cond_original,
                    description=f"'{target}' must not be NULL when calling this function",
                    line=line,
                    confidence=0.9 if branch == BRANCH_ERROR_EXIT else 0.6,
                )
            )
        else:
            constraints.append(
                Constraint(
                    kind="nullable",
                    target=target,
                    expression=cond_original,
                    description=f"'{target}' is explicitly guarded, so NULL is an accepted value",
                    line=line,
                    confidence=0.5,
                )
            )

    for match in NOT_NULL_RE.finditer(cond_masked):
        add(match.group(1), negated=True)
    for match in NULL_CMP_RE.finditer(cond_masked):
        add(match.group(1), negated=match.group(2) == "==")
    for match in NULL_CMP_REV_RE.finditer(cond_masked):
        add(match.group(3), negated=match.group(2) == "==")

    return constraints


def _range_constraints(cond_masked: str, cond_original: str, params: Dict[str, Param],
                       line: int, branch: str) -> List[Constraint]:
    constraints: List[Constraint] = []
    flipped = {"<": ">=", "<=": ">", ">": "<=", ">=": "<", "==": "!=", "!=": "=="}
    rejects_input = branch == BRANCH_ERROR_EXIT

    def add(target: str, comparison: str) -> None:
        param = params.get(target)
        if param is None or param.is_pointer:
            return
        if rejects_input:
            left, operator, right = comparison
            required = f"{left} {flipped[operator]} {right}"
            description = f"'{target}' is validated on entry; callers must satisfy {required}"
            confidence = 0.8
        else:
            # 거부 경로가 아니면 부등호를 뒤집으면 안 된다. 다만 비교에 쓰인 값은
            # 퍼징에서 시도해 볼 만한 경계값이다.
            left, operator, right = comparison
            description = (
                f"'{target}' is compared as `{left} {operator} {right}` on a non-rejecting "
                f"branch; treat {right if right != target else left} as a boundary value"
            )
            confidence = 0.4
        constraints.append(
            Constraint(
                kind="range_check",
                target=target,
                expression=cond_original,
                description=description,
                line=line,
                confidence=confidence,
            )
        )

    comparisons = [
        (m.group(1), m.group(2), m.group(3)) for m in COMPARE_RE.finditer(cond_masked)
    ] + [
        (m.group(1), m.group(2), m.group(3)) for m in NUMBER_EQ_RE.finditer(cond_masked)
    ] + [
        (m.group(3), m.group(2), m.group(1)) for m in NUMBER_EQ_REV_RE.finditer(cond_masked)
    ]

    for left, operator, right in comparisons:
        if left in params:
            add(left, (left, operator, right))
        elif right in params:
            add(right, (left, operator, right))

    return constraints


def _assert_constraints(masked: str, original: str, body_span, index: LineIndex) -> List[Constraint]:
    constraints: List[Constraint] = []
    start, end = body_span
    for match in ASSERT_RE.finditer(masked, start, end):
        paren_open = match.end() - 1
        paren_close = match_delim(masked, paren_open)
        if paren_close is None or paren_close > end:
            continue
        expression = _snippet(original, paren_open + 1, paren_close)
        target = ""
        first_identifier = re.search(r"[A-Za-z_]\w*", expression)
        if first_identifier:
            target = first_identifier.group(0)
        constraints.append(
            Constraint(
                kind="assert",
                target=target,
                expression=expression,
                description=f"precondition asserted in the body: {expression}",
                line=index.line_of(match.start()),
                confidence=0.95,
            )
        )
    return constraints


def _buffer_size_constraints(params: Sequence[Param], line: int) -> List[Constraint]:
    constraints: List[Constraint] = []
    for i, param in enumerate(params[:-1]):
        following = params[i + 1]
        if not param.is_pointer or following.is_pointer:
            continue
        if not following.name or not SIZE_NAME_RE.match(following.name):
            continue
        if not INT_TYPE_RE.search(following.type):
            continue
        constraints.append(
            Constraint(
                kind="buffer_size",
                target=f"{param.name},{following.name}",
                expression=f"{param.type} {param.name}, {following.type} {following.name}",
                description=(
                    f"'{following.name}' describes the length of buffer '{param.name}'; "
                    f"the harness must keep them consistent"
                ),
                line=line,
                confidence=0.85,
            )
        )
    return constraints


def _resource_constraints(calls: Sequence[str], line: int) -> List[Constraint]:
    constraints: List[Constraint] = []
    call_set = set(calls)
    for acquire in sorted(call_set):
        release = RESOURCE_PAIRS.get(acquire)
        if not release:
            continue
        paired = release in call_set
        constraints.append(
            Constraint(
                kind="resource",
                target=acquire,
                expression=f"{acquire}() ... {release}()",
                description=(
                    f"acquires a resource via {acquire}(); {release}() is called in the same "
                    f"function" if paired else
                    f"acquires a resource via {acquire}() without a matching {release}(); "
                    f"ownership passes to the caller"
                ),
                line=line,
                confidence=0.7 if paired else 0.8,
            )
        )
    return constraints


def _risky_call_constraints(calls: Sequence[str], line: int) -> List[Constraint]:
    constraints: List[Constraint] = []
    for call in sorted(set(calls)):
        reason = RISKY_CALLS.get(call)
        if not reason:
            continue
        constraints.append(
            Constraint(
                kind="risky_call",
                target=call,
                expression=f"{call}()",
                description=f"calls {call}(): {reason}",
                line=line,
                confidence=0.6,
            )
        )
    return constraints


def _return_constraints(masked: str, original: str, body_span, return_type: str,
                        index: LineIndex) -> List[Constraint]:
    constraints: List[Constraint] = []
    start, end = body_span
    returns_pointer = "*" in return_type
    saw_null = False
    saw_error_code = False

    for match in RETURN_RE.finditer(masked, start, end):
        value = match.group(1).strip()
        if not value:
            continue
        if returns_pointer and not saw_null and re.fullmatch(r"\(?\s*(NULL|nullptr|0)\s*\)?", value):
            saw_null = True
            constraints.append(
                Constraint(
                    kind="return_value",
                    target="return",
                    expression=_snippet(original, match.start(), match.end()),
                    description="may return NULL on failure; callers must check the result",
                    line=index.line_of(match.start()),
                    confidence=0.8,
                )
            )
        elif not returns_pointer and not saw_error_code and re.fullmatch(r"-\s*\d+", value):
            saw_error_code = True
            constraints.append(
                Constraint(
                    kind="return_value",
                    target="return",
                    expression=_snippet(original, match.start(), match.end()),
                    description=f"returns {value} as an error code; callers must check the result",
                    line=index.line_of(match.start()),
                    confidence=0.75,
                )
            )
    return constraints


DOC_OBLIGATION_RE = re.compile(
    r"(?i)(must|must not|shall|should|non-?null|nonnull|not\s+be\s+null|caller|ownership|"
    r"free|thread-?safe|반드시|해야|널|NULL|해제|호출자)"
)


def _doc_constraints(doc: str, line: int) -> List[Constraint]:
    constraints: List[Constraint] = []
    if not doc:
        return constraints

    for raw_line in doc.splitlines():
        text = raw_line.strip()
        if not text:
            continue
        param_match = re.match(r"@(?:param|arg)\s+(\[[^\]]*\]\s*)?([A-Za-z_]\w*)\s+(.*)", text)
        if param_match:
            target, body = param_match.group(2), param_match.group(3).strip()
            if body:
                constraints.append(
                    Constraint(
                        kind="doc",
                        target=target,
                        expression=text,
                        description=f"documented for '{target}': {body}",
                        line=line,
                        confidence=0.7,
                    )
                )
            continue
        if DOC_OBLIGATION_RE.search(text):
            constraints.append(
                Constraint(
                    kind="doc",
                    target="",
                    expression=text,
                    description=f"documented constraint: {text}",
                    line=line,
                    confidence=0.6,
                )
            )
    return constraints


# ---------------------------------------------------------------------------
# 진입점
# ---------------------------------------------------------------------------


def doc_constraints(doc: str, line: int) -> List[Constraint]:
    """주석 텍스트만으로 제약조건을 뽑는다.

    EXT-01-04 가 헤더 선언부의 문서를 구현 함수에 결합할 때 쓴다. C 프로젝트는
    보통 `.h` 의 선언에 문서를 달고 `.c` 의 정의에는 달지 않는다.
    """
    return _doc_constraints(doc, line)


def extract_from_text(text: str, path: str = "<memory>") -> List[FunctionFacts]:
    masked = mask_source(text)
    index = LineIndex(text)
    results: List[FunctionFacts] = []

    for info in find_functions(masked):
        body_span = info["body_span"]
        params_start, params_end = info["params_span"]
        params = parse_params(masked[params_start:params_end])
        param_map = _param_map(params)
        line = index.line_of(info["name_start"])

        signature = _snippet(text, info["name_start"] - len(info["return_type"]) - 1,
                             params_end + 1)
        if not signature.startswith(info["return_type"].split()[0] if info["return_type"] else ""):
            signature = f"{info['return_type']} {_snippet(text, info['name_start'], params_end + 1)}"

        calls = [
            m.group(1)
            for m in CALL_RE.finditer(masked, body_span[0], body_span[1])
            if m.group(1) not in CONTROL_KEYWORDS
        ]

        constraints: List[Constraint] = []
        for cond_start, cond_end, close_pos in _conditions(masked, body_span):
            cond_masked = masked[cond_start:cond_end]
            cond_original = _snippet(text, cond_start, cond_end)
            cond_line = index.line_of(cond_start)
            branch = _classify_branch(masked, close_pos)
            constraints.extend(
                _null_constraints(cond_masked, cond_original, param_map, cond_line, branch)
            )
            constraints.extend(
                _range_constraints(cond_masked, cond_original, param_map, cond_line, branch)
            )

        constraints.extend(_assert_constraints(masked, text, body_span, index))
        constraints.extend(_buffer_size_constraints(params, line))
        constraints.extend(_resource_constraints(calls, line))
        constraints.extend(_risky_call_constraints(calls, line))
        constraints.extend(
            _return_constraints(masked, text, body_span, info["return_type"], index)
        )

        doc = extract_doc_comment(text, info["decl_start"])
        constraints.extend(_doc_constraints(doc, line))

        results.append(
            FunctionFacts(
                name=info["name"],
                file=path,
                line=line,
                signature=signature,
                return_type=info["return_type"],
                params=params,
                doc=doc,
                calls=sorted(set(calls)),
                call_sequence=calls,
                constraints=dedupe_constraints(constraints),
            )
        )

    return results


def extract_from_file(path: str) -> List[FunctionFacts]:
    text = Path(path).read_text(encoding="utf-8", errors="ignore")
    return extract_from_text(text, path=str(path))


def iter_source_files(paths: Iterable[str]) -> Iterable[str]:
    for entry in paths:
        if os.path.isdir(entry):
            for root, _, files in os.walk(entry):
                for name in sorted(files):
                    if name.endswith(SOURCE_SUFFIXES):
                        yield os.path.join(root, name)
        elif str(entry).endswith(SOURCE_SUFFIXES):
            yield str(entry)


def extract_from_paths(paths: Iterable[str]) -> List[FunctionFacts]:
    results: List[FunctionFacts] = []
    for source in iter_source_files(paths):
        try:
            results.extend(extract_from_file(source))
        except OSError:
            continue
    return results


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Extract API constraints from C/C++ sources (EXT-01-02)"
    )
    parser.add_argument("paths", nargs="+", help="Source files or directories")
    parser.add_argument("--output", "-o", help="Output JSON path (defaults to stdout)")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    facts = extract_from_paths(args.paths)
    payload = [f.to_dict() for f in facts]
    rendered = json.dumps(payload, indent=2, ensure_ascii=False)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        print(f"Wrote {args.output} ({len(payload)} functions)")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
