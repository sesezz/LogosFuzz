"""ANA-05-01 보강: 크래시 지점의 **도달 가능성(reachability) 컨텍스트** 수집

결함 유형·sanitizer·콜스택·원문 로그만으로는 판별기가 오탐을 구분하지 못하는 한계 보완
사람이 하던 호출부 확인(공개 API 경로로 해당 인자 상태 생성 가능 여부)을 자동화해 증거로 제공

수집 항목
---------
1. **크래시 함수의 정의**와 결함 라인 주변 소스
2. **호출부 목록을 프로덕션 / 하네스·테스트로 분리** (하네스 전용 호출 시 대상 결함 아닐 가능성)
3. **링키지** (헤더 선언 공개 API 또는 ``static`` 내부 함수)
4. **같은 상태 핸들의 생명주기 API** (``*_init``/``*_free`` 등, 핸들 불변식 유지 주체 판단 근거)

판정 없이 증거만 수집
---------------------
- ``derive_signals()``: 정적으로 증명 가능한 신호만 제공 (하네스 전용 호출부 / 내부 링키지)
- 불변식 추론은 ``render_for_prompt()`` 로 직렬화해 LLM 판별기에 위임

표준 라이브러리만 사용 (``models.py`` 의존성 원칙과 동일)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional, Sequence

from logosfuzz.analyze.models import CrashRecord

SOURCE_SUFFIXES = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp")

# 하네스/테스트/예제 코드 경로 표지
# 이 코드에서만 호출되는 함수의 크래시는 하네스 유발 가능성 높음
_NON_PRODUCTION_MARKERS = (
    "fuzz", "harness", "driver", "/test", "test/", "_test", "test_",
    "/tests/", "example", "sample", "/demo", "benchmark",
)

# 상태 핸들 생명주기 API 접미사 (핸들 불변식 유지 주체 탐색용)
_LIFECYCLE_SUFFIXES = (
    "_init", "_new", "_create", "_alloc", "_open", "_setup",
    "_free", "_delete", "_destroy", "_close", "_cleanup", "_deinit",
)

# 상태를 **기록하는** API (크래시가 읽은 필드에 값을 넣는 쪽)
# 하네스 계약 위반만으로는 오탐 근거 불충분, 계약을 지킨 호출로 같은 값 생성 가능 여부 판단에 본문 필요
# (예: dlt_filter_add_v2 의 apid2len 미캡핑 → 정탐) `_add_v2` 같은 버전 접미사 관례 포함
_STATE_WRITER_RE = re.compile(
    r"_(add|init|set|load|insert|append|push|write|fill|store|new|create)(_v\d+)?$"
)

# 상태 기록 API 본문의 프롬프트 탑재 상한 (토큰 폭주 방지)
_MAX_WRITERS = 3
_MAX_WRITER_LINES = 40

# `#0 0x... in <func> <file>:<line>` — ASAN 프레임의 함수 이름 추출
_ASAN_FRAME_RE = re.compile(r"#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(\S+)\s+(\S+?):(\d+)")

# 함수 이름 = 여는 괄호 바로 앞 식별자
_NAME_BEFORE_PAREN_RE = re.compile(r"([A-Za-z_]\w*)\s*$")

# 시그니처 한 건의 최대 줄 수 (여러 줄 파라미터 대응)
_MAX_SIGNATURE_LINES = 8

_C_KEYWORDS = {
    "if", "for", "while", "switch", "return", "sizeof", "do", "else",
    "typedef", "struct", "union", "enum", "case", "default", "goto",
}


# --------------------------------------------------------------------------- #
# 데이터 모델
# --------------------------------------------------------------------------- #
@dataclass
class CallSite:
    """대상 함수 호출 지점 하나"""

    file: str
    line: int
    caller: str = ""          # 이 호출을 감싼 함수 이름(모르면 빈 문자열)
    text: str = ""            # 호출 소스 한 줄
    production: bool = True   # False = 하네스/테스트/예제 코드

    def render(self) -> str:
        where = f"{self.file}:{self.line}"
        if self.caller:
            where += f" ({self.caller})"
        tag = "" if self.production else "  [하네스/테스트]"
        return f"{where}{tag}\n      {self.text.strip()}"


@dataclass
class ReachabilityContext:
    """크래시 함수 하나의 도달 가능성 증거 묶음"""

    function: str = ""
    definition_file: str = ""
    definition_line: int = 0
    crash_line: int = 0
    crash_source: list[str] = field(default_factory=list)
    declared_in_header: Optional[bool] = None
    is_static: Optional[bool] = None
    handle_types: list[str] = field(default_factory=list)
    lifecycle_apis: list[str] = field(default_factory=list)
    production_callers: list[CallSite] = field(default_factory=list)
    harness_callers: list[CallSite] = field(default_factory=list)
    harness_path: str = ""
    harness_source: list[str] = field(default_factory=list)
    state_writers: list[tuple[str, list[str]]] = field(default_factory=list)
    note: str = ""

    @property
    def resolved(self) -> bool:
        """대상 소스에서 함수 발견 여부"""
        return bool(self.function and self.definition_file)

    def to_dict(self) -> dict:
        return {
            "function": self.function,
            "definition": f"{self.definition_file}:{self.definition_line}",
            "crash_line": self.crash_line,
            "declared_in_header": self.declared_in_header,
            "is_static": self.is_static,
            "handle_types": self.handle_types,
            "lifecycle_apis": self.lifecycle_apis,
            "production_callers": [f"{c.file}:{c.line}" for c in self.production_callers],
            "harness_callers": [f"{c.file}:{c.line}" for c in self.harness_callers],
            "harness_path": self.harness_path,
            "note": self.note,
        }


# --------------------------------------------------------------------------- #
# 소스 탐색 유틸
# --------------------------------------------------------------------------- #
def _is_production_path(path: str) -> bool:
    text = path.replace("\\", "/").lower()
    return not any(m in text for m in _NON_PRODUCTION_MARKERS)


def iter_sources(root: Path, limit: int = 4000) -> list[Path]:
    """대상 트리의 C/C++ 소스 수집 (과대 트리 대비 상한 적용)"""
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        if len(files) >= limit:
            break
        if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES:
            files.append(path)
    return files


@dataclass(frozen=True)
class Signature:
    """소스에서 찾은 함수 시그니처 한 건 (정의 또는 프로토타입)

    여러 줄 파라미터 시그니처도 괄호 균형이 맞을 때까지 이어 붙여 한 건으로 처리
    (정의 줄·헤더 프로토타입 줄의 호출부 오집계 방지)
    """

    name: str
    start: int          # 1-base 시작 줄
    end: int            # 1-base 끝 줄(시그니처가 닫히는 줄)
    text: str           # 이어 붙인 시그니처 한 줄
    is_definition: bool  # True=본문이 따라오는 정의, False=프로토타입


def _signatures(lines: Sequence[str]) -> list[Signature]:
    """열 0에서 시작하는 함수 시그니처 전체 수집 (정의 + 프로토타입)"""
    found: list[Signature] = []
    total = len(lines)
    index = 0
    while index < total:
        raw = lines[index].rstrip()
        # 열 0에서 시작하고 괄호가 있는 줄만 후보 (들여쓴 줄은 호출문)
        if not raw or raw[0] in " \t#/*}" or "(" not in raw:
            index += 1
            continue

        joined = raw
        depth = raw.count("(") - raw.count(")")
        last = index
        while depth > 0 and last + 1 < total and last - index < _MAX_SIGNATURE_LINES:
            last += 1
            joined += " " + lines[last].strip()
            depth += lines[last].count("(") - lines[last].count(")")
        if depth != 0:
            index += 1
            continue

        close = joined.rfind(")")
        head = joined[: joined.find("(")]
        match = _NAME_BEFORE_PAREN_RE.search(head)
        if not match or match.group(1) in _C_KEYWORDS:
            index = last + 1 if last > index else index + 1
            continue
        # 반환형 없이 이름만 있는 줄은 시그니처가 아닌 호출문
        if not head[: match.start(1)].strip():
            index = last + 1 if last > index else index + 1
            continue

        tail = joined[close + 1:].strip()
        if tail.startswith("{"):
            is_definition = True
        elif tail == "":
            probe = last + 1
            while probe < total and not lines[probe].strip():
                probe += 1
            is_definition = probe < total and lines[probe].strip().startswith("{")
        else:
            is_definition = False

        found.append(Signature(match.group(1), index + 1, last + 1, joined, is_definition))
        index = last + 1
    return found


def _function_defs(lines: Sequence[str]) -> list[tuple[str, int, str]]:
    """(함수명, 시작 줄(1-base), 시그니처 문자열) — 본문이 있는 **정의만**"""
    return [(s.name, s.start, s.text) for s in _signatures(lines) if s.is_definition]


def enclosing_function(lines: Sequence[str], line_no: int) -> str:
    """``line_no``(1-base)를 감싼 함수 이름 (미발견 시 빈 문자열)"""
    best = ""
    for name, start, _ in _function_defs(lines):
        if start <= line_no:
            best = name
        else:
            break
    return best


def crashing_function(record: CrashRecord) -> str:
    """ASAN 원문 로그의 ``#0`` 프레임에서 크래시 함수 이름 추출"""
    for line in record.raw_log:
        match = _ASAN_FRAME_RE.search(line)
        if match and match.group(1) == "0":
            return match.group(2)
    return ""


def _handle_types(params: str) -> list[str]:
    """파라미터 문자열에서 포인터로 오가는 프로젝트 타입 이름 추출"""
    found: list[str] = []
    for part in params.split(","):
        if "*" not in part:
            continue
        # `*` 앞쪽만 검사 (뒤쪽 인자 이름까지 보면 `const char *apid` 의 `apid` 를 타입으로 오인)
        for token in re.findall(r"\b[A-Za-z_]\w*\b", part[: part.index("*")]):
            if token in _C_KEYWORDS or token in found:
                continue
            if token in {"const", "void", "char", "int", "unsigned", "signed",
                         "long", "short", "float", "double", "static", "struct"}:
                continue
            if re.match(r"^u?int\d*_t$|^size_t$|^ssize_t$", token):
                continue
            found.append(token)
            break  # 파라미터 하나당 타입 하나로 충분
    return found


# --------------------------------------------------------------------------- #
# 본체
# --------------------------------------------------------------------------- #
def _function_body(lines: Sequence[str], start: int, max_lines: int) -> list[str]:
    """정의 시작 줄(1-base)부터 중괄호 균형이 맞을 때까지 본문 추출"""
    out: list[str] = []
    depth = 0
    opened = False
    for index in range(start - 1, min(len(lines), start - 1 + max_lines)):
        raw = lines[index]
        out.append(f"{index + 1:6d}  {raw}")
        depth += raw.count("{") - raw.count("}")
        if "{" in raw:
            opened = True
        if opened and depth <= 0:
            break
    return out


def crash_fields(crash_source: Sequence[str]) -> list[str]:
    """결함 라인이 접근하는 구조체 필드 이름들 (``filter->apid2len`` -> apid2len)"""
    marked = [l for l in crash_source if ">" in l[:8]] or list(crash_source)
    names: list[str] = []
    for line in marked:
        for name in re.findall(r"(?:->|\.)\s*([A-Za-z_]\w*)", line):
            if name not in names:
                names.append(name)
    return names


def _collect_state_writers(sources: Sequence[Path], read, handle_type: str,
                           exclude: str = "",
                           fields: Sequence[str] = ()) -> list[tuple[str, list[str]]]:
    """``handle_type`` 상태에 값을 기록하는 API 본문 수집

    결함 라인이 읽은 필드를 실제로 쓰는 함수 우선 배치
    (파일 순서 절단 시 문제 값을 저장하는 함수, 예: ``dlt_filter_add_v2`` 누락 방지)
    """
    candidates: list[tuple[int, str, list[str]]] = []
    seen: set[str] = set()
    for path in sources:
        lines = read(path)
        for name, start, header in _function_defs(lines):
            if name == exclude or name in seen:
                continue
            if handle_type not in header or not _STATE_WRITER_RE.search(name):
                continue
            seen.add(name)
            body = _function_body(lines, start, _MAX_WRITER_LINES)
            text = "\n".join(body)
            score = sum(1 for f in fields if re.search(rf"\b{re.escape(f)}\b", text))
            candidates.append((score, name, body))

    candidates.sort(key=lambda c: (-c[0], c[1]))
    return [(name, body) for _, name, body in candidates[:_MAX_WRITERS]]


def find_harness_source(record: CrashRecord, harness_dir: str | Path,
                        max_lines: int = 80) -> tuple[str, list[str]]:
    """콜스택에 등장하는 하네스 소스를 ``harness_dir`` 에서 찾아 로드

    계약 위반 여부 판단의 직접 증거, 콜스택 프레임 파일명으로 역추적
    """
    directory = Path(harness_dir)
    if not directory.exists():
        return "", []
    for frame in record.traceback:
        name = Path(frame.file.replace("\\", "/")).name
        if not name.lower().endswith((".c", ".cc", ".cpp")):
            continue
        candidate = directory / name
        if candidate.exists():
            lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
            return str(candidate), lines[:max_lines]
    return "", []


def analyze_reachability(record: CrashRecord, source_root: str | Path,
                         function: str = "", context_lines: int = 6,
                         max_callers: int = 12,
                         harness_dir: str | Path | None = None) -> ReachabilityContext:
    """크래시 레코드 하나의 도달 가능성 증거 수집

    Args:
        record: 판별 대상 크래시 (대표 레코드)
        source_root: 대상 라이브러리 소스 트리 루트
        function: 크래시 함수 이름 (비우면 ASAN 로그에서 추출)
        context_lines: 결함 라인 앞뒤로 함께 실을 소스 줄 수
        max_callers: 프로덕션/하네스 각각 실을 최대 호출부 수
        harness_dir: 크래시를 낸 하네스 소스 디렉토리 (선택)
    """
    root = Path(source_root)
    # 함수 이름은 대상 소스 역산 우선
    # (ASAN `#0` 프레임은 `malloc`·`strcmp` 등 sanitizer 인터셉터인 경우가 흔함)
    ctx = ReachabilityContext(function=function)

    if harness_dir:
        ctx.harness_path, ctx.harness_source = find_harness_source(record, harness_dir)

    if not root.exists():
        ctx.note = f"소스 트리를 찾을 수 없음: {root}"
        return ctx

    # 크래시 파일/라인 (콜스택 최상단)
    crash_file = record.traceback[0].file if record.traceback else ""
    ctx.crash_line = record.traceback[0].line if record.traceback else 0
    crash_base = Path(crash_file.replace("\\", "/")).name

    sources = iter_sources(root)
    if not sources:
        ctx.note = f"소스 파일이 없음: {root}"
        return ctx

    cache: dict[Path, list[str]] = {}

    def read(path: Path) -> list[str]:
        if path not in cache:
            try:
                cache[path] = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                cache[path] = []
        return cache[path]

    # 1) 크래시 지점 파일에서 함수 이름/정의 확정
    crash_paths = [p for p in sources if p.name == crash_base] if crash_base else []
    for path in crash_paths:
        lines = read(path)
        if not ctx.function and ctx.crash_line:
            ctx.function = enclosing_function(lines, ctx.crash_line)
        if ctx.crash_line and 0 < ctx.crash_line <= len(lines):
            lo = max(0, ctx.crash_line - context_lines - 1)
            hi = min(len(lines), ctx.crash_line + context_lines)
            ctx.crash_source = [
                f"{n + 1:6d}{'>' if n + 1 == ctx.crash_line else ' '} {lines[n]}"
                for n in range(lo, hi)
            ]
        break

    if not ctx.function:
        # 소스 역산 실패 시 ASAN 프레임 이름으로 폴백
        ctx.function = crashing_function(record)
    if not ctx.function:
        ctx.note = "크래시 함수 이름을 특정하지 못했다(소스/ASAN 프레임 모두 실패)."
        return ctx

    # 2) 정의 위치 · 링키지 · 핸들 타입
    call_re = re.compile(r"\b" + re.escape(ctx.function) + r"\s*\(")
    for path in sources:
        lines = read(path)
        for name, start, header in _function_defs(lines):
            if name != ctx.function:
                continue
            ctx.definition_file = str(path.relative_to(root)).replace("\\", "/")
            ctx.definition_line = start
            ctx.is_static = header.strip().startswith("static")
            ctx.handle_types = _handle_types(header[header.find("(") + 1:])
            break
        if ctx.definition_file:
            break

    # 3) 호출부 수집
    #    시그니처(정의 헤더 + 프로토타입) 줄 전체 제외 (여러 줄 선언의 호출부 오집계 방지)
    declared_in_header = False
    for path in sources:
        rel = str(path.relative_to(root)).replace("\\", "/")
        lines = read(path)
        production = _is_production_path(rel)

        signature_lines: set[int] = set()
        for signature in _signatures(lines):
            if signature.name != ctx.function:
                continue
            signature_lines.update(range(signature.start, signature.end + 1))
            if not signature.is_definition and path.suffix.lower() in (".h", ".hpp"):
                declared_in_header = True

        for index, raw in enumerate(lines):
            line_no = index + 1
            if line_no in signature_lines or not call_re.search(raw):
                continue
            site = CallSite(
                file=rel, line=line_no,
                caller=enclosing_function(lines, line_no),
                text=raw.strip(), production=production,
            )
            bucket = ctx.production_callers if production else ctx.harness_callers
            if len(bucket) < max_callers:
                bucket.append(site)

    # 헤더 선언 시 외부 코드가 링크해 호출 가능한 공개 API
    ctx.declared_in_header = declared_in_header

    # 4) 같은 핸들 타입의 생명주기 API
    if ctx.handle_types:
        primary = ctx.handle_types[0]
        seen: set[str] = set()
        for path in sources:
            for name, _, header in _function_defs(read(path)):
                if name in seen or name == ctx.function:
                    continue
                if primary not in header:
                    continue
                if name.endswith(_LIFECYCLE_SUFFIXES):
                    seen.add(name)
                    ctx.lifecycle_apis.append(name)
        ctx.lifecycle_apis.sort()
        ctx.state_writers = _collect_state_writers(
            sources, read, primary, exclude=ctx.function,
            fields=crash_fields(ctx.crash_source),
        )

    if not ctx.definition_file:
        ctx.note = f"'{ctx.function}' 정의를 대상 트리에서 찾지 못했다."
    return ctx


# --------------------------------------------------------------------------- #
# 규칙 기반 판별기에 줄 신호 — 정적으로 증명 가능한 것만
# --------------------------------------------------------------------------- #
def derive_signals(ctx: ReachabilityContext) -> tuple[float, list[str]]:
    """(점수 보정치, 신호 목록)

    **정적으로 확인 가능한 사실**만 신호화 (불변식 추론은 신호화하지 않음)
    """
    if not ctx.resolved:
        return 0.0, []

    delta = 0.0
    signals: list[str] = []

    if ctx.production_callers:
        # 제품 코드가 실제 호출 → 해당 경로 입력의 결함 유발 여부가 쟁점, 점수 변경 없이 근거만 기록
        signals.append("production-caller")
    elif ctx.declared_in_header:
        # 공개 헤더 API 는 의도된 호출자가 트리 밖이므로 in-tree 호출부 부재로 감점하지 않음
        # (감점 시 dlt_filter_delete_v2 같은 공개 API 로직 결함을 오탐으로 뒤집음, 신호만 기록)
        signals.append("public-api-no-in-tree-caller")
    elif ctx.harness_callers:
        # 헤더 미선언 + 하네스/테스트만 호출 → 외부 입력 도달 경로 아님
        delta -= 0.45
        signals.append("harness-only-caller")
    else:
        # 헤더 미선언 + 트리 내 호출 없음 → 죽은 코드에 가까움
        delta -= 0.35
        signals.append("unreferenced-internal-function")

    if ctx.is_static and ctx.declared_in_header is False:
        # 내부 링키지 + 헤더 미노출 → 외부 입력 직접 도달 불가
        delta -= 0.10
        signals.append("internal-linkage")

    return delta, signals


# --------------------------------------------------------------------------- #
# LLM 판별기에 줄 프롬프트 조각
# --------------------------------------------------------------------------- #
def render_for_prompt(ctx: ReachabilityContext, max_callers: int = 6) -> str:
    """도달 가능성 증거의 프롬프트 섹션 문자열 직렬화"""
    harness_block: list[str] = []
    if ctx.harness_source:
        harness_block = [
            f"  이 크래시를 낸 하네스 소스 ({Path(ctx.harness_path).name}):",
            "  ```c",
            *(f"  {l}" for l in ctx.harness_source),
            "  ```",
            "  ↑ 이 하네스가 공개 API 계약을 지켰는지(NULL 금지 인자, 초기화 순서,"
            " 내부 구조체 직접 조작 여부)를 여기서 직접 확인하라.",
        ]

    if not ctx.resolved:
        head = f"[도달 가능성] 대상 함수 정보 수집 실패 — {ctx.note or '대상 소스 미제공'}"
        return "\n".join([head, *harness_block]) if harness_block else head

    out: list[str] = ["[도달 가능성 증거]"]
    linkage = []
    if ctx.declared_in_header is not None:
        linkage.append("헤더에 선언된 공개 API" if ctx.declared_in_header else "헤더 미선언")
    if ctx.is_static is not None:
        linkage.append("static(내부 링키지)" if ctx.is_static else "외부 링키지")
    out.append(
        f"  대상 함수 : {ctx.function}  "
        f"({ctx.definition_file}:{ctx.definition_line}"
        + (f", {' / '.join(linkage)}" if linkage else "") + ")"
    )

    if ctx.crash_source:
        out.append(f"  결함 라인 주변 소스 ({ctx.crash_line} 행에 '>' 표시):")
        out.extend(f"  {l}" for l in ctx.crash_source)

    if ctx.production_callers:
        out.append(f"  프로덕션 호출부 {len(ctx.production_callers)}곳:")
        for site in ctx.production_callers[:max_callers]:
            out.append(f"    - {site.render()}")
    else:
        out.append("  프로덕션 호출부: 없음 (대상 라이브러리 안에서 아무도 부르지 않음)")

    if ctx.harness_callers:
        out.append(f"  하네스/테스트 호출부 {len(ctx.harness_callers)}곳:")
        for site in ctx.harness_callers[:max_callers]:
            out.append(f"    - {site.render()}")

    if ctx.handle_types:
        out.append(f"  상태 핸들 타입 : {', '.join(ctx.handle_types)}")
    if ctx.lifecycle_apis:
        out.append(
            "  이 핸들의 생명주기 API : " + ", ".join(ctx.lifecycle_apis)
            + "  ← 이 API 들이 핸들의 불변식을 유지한다"
        )

    for name, body in ctx.state_writers:
        out.append(f"  이 상태에 값을 기록하는 API — {name}():")
        out.append("  ```c")
        out.extend(f"  {l}" for l in body)
        out.append("  ```")
    if ctx.state_writers:
        out.append(
            "  ↑ 하네스가 계약을 어겼더라도, 위 기록 API 를 정상적으로 호출했을 때"
            " 같은 값(길이·인덱스)이 저장될 수 있으면 그 결함은 진짜다."
        )

    out.extend(harness_block)
    return "\n".join(out)


class SourceReachabilityProvider:
    """크래시 클러스터 → 도달 가능성 컨텍스트 (판별기 주입용)

    같은 함수를 공유하는 클러스터 간 소스 스캔 결과 캐싱

    Args:
        source_root: 대상 라이브러리 소스 트리
        harness_dir: 크래시를 낸 하네스 소스 디렉토리 (선택)
    """

    def __init__(self, source_root: str | Path,
                 harness_dir: str | Path | None = None) -> None:
        self.source_root = Path(source_root)
        self.harness_dir = Path(harness_dir) if harness_dir else None
        self._cache: dict[str, ReachabilityContext] = {}

    def __call__(self, cluster) -> ReachabilityContext:
        record = cluster.representative
        # 하네스 소스는 크래시마다 달라 캐시 키에 포함
        harness_key = ""
        if self.harness_dir:
            harness_key = "|".join(
                Path(f.file.replace("\\", "/")).name for f in record.traceback[:4]
            )
        key = f"{crashing_function(record)}|" + (
            f"{record.traceback[0].file}:{record.traceback[0].line}"
            if record.traceback else ""
        ) + f"|{harness_key}"
        if key not in self._cache:
            self._cache[key] = analyze_reachability(
                record, self.source_root, harness_dir=self.harness_dir
            )
        return self._cache[key]
