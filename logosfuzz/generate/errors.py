"""GEN 파트 예외 정의 + Bazel 빌드 에러 분류 결과 타입

분류 **수행**은 `logosfuzz.generate.bazel_errors` 담당. 여기에는 그 결과를
담는 타입만 정의 — 분류기를 쓰지 않는 모듈(3주차 `selfheal.py`, 리포팅 등)이
분류기 전체를 import 하지 않고 결과 타입만 사용할 수 있도록 분리

타입 설계 근거는 1주차에 실제로 빌드를 깨뜨려 모은 코퍼스
(`docs/GEN-03-02-ERROR-CORPUS.md`, `tests/fixtures/bazel_errors/`). 특히:

- 하나의 빌드 로그에 진단이 여러 개 나오고, 그중 **하나만 근본 원인**
  `load()` 누락은 "load 에러"와 "타깃이 없다" 두 진단을 동시에 생성
  그래서 `BazelDiagnostic.root_cause` 로 증상과 원인을 구분
- 처방(`FixAction`)이 분류(`BazelErrorKind`)와 1:1 이 아님. `no_such_target`
  하나가 레이블 교정일 수도, 전혀 다른 BUILD 작성 오류의 증상일 수도 있음
  따라서 둘을 분리
- 어떤 결함은 LLM 재시도로 해결 불가(순환 의존). `FixAction.ESCALATE` 로
  표시해 자가치유 루프가 라운드를 낭비하지 않고 HITL 로 전달
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class GenerateError(Exception):
    """GEN 파트 공통 예외"""


class HarnessBinaryNotFoundError(GenerateError):
    """검증 대상 하네스 실행 파일(GEN-03-02 산출물)이 없을 때"""


class ManifestError(GenerateError):
    """검증 매니페스트 JSON이 잘못되었을 때"""


# --------------------------------------------------------------------------- #
# Bazel 에러 분류
# --------------------------------------------------------------------------- #
class BazelErrorKind(str, Enum):
    """빌드 로그에서 식별한 결함의 종류

    값은 코퍼스의 파손 케이스 이름(`tests/fixtures/bazel_errors/*.txt`)과 일치
    """

    MISSING_LOAD = "missing_load"
    """BUILD 파일에 `load()` 가 없다. Bazel 9 는 네이티브 cc_* 규칙을 제거했다."""

    BUILD_SYNTAX_ERROR = "build_syntax_error"
    """BUILD 파일 구문 오류."""

    NOT_VISIBLE = "not_visible"
    """대상 타깃이 `visibility` 로 막혀 있다."""

    NO_SUCH_PACKAGE = "no_such_package"
    """deps 에 적은 패키지 경로가 존재하지 않는다."""

    NO_SUCH_TARGET = "no_such_target"
    """deps 에 적은 **의존 대상** 타깃이 존재하지 않는다(이름 오타 등)."""

    TARGET_NOT_DEFINED = "target_not_defined"
    """**하네스 자신의** 타깃이 정의되지 않았다.

    Bazel 은 이것도 `no such target` 으로 보고하지만 원인이 전혀 다르다 —
    BUILD 파일이 파싱에 실패해서 그 안의 타깃이 만들어지지 않은 것이다. 거의 항상
    `MISSING_LOAD`/`BUILD_SYNTAX_ERROR` 의 증상이므로 `root_cause=False` 로 나간다.
    (코퍼스 발견 A. 이걸 deps 문제로 오분류하면 자가치유가 엉뚱한 수정을 반복한다.)
    """

    MISSING_DEP = "missing_dep"
    """include 하는 헤더를 주는 타깃이 deps 에 없다.

    Bazel 이 아니라 **clang** 이 `fatal error: '<헤더>' file not found` 로 보고한다.
    설계표의 `no such target -> deps 추가` 는 입구가 틀렸다(코퍼스 발견 B).
    """

    MISSING_SRCS_FILE = "missing_srcs_file"
    """`srcs` 가 존재하지 않는 파일을 참조한다."""

    DEP_CYCLE = "dep_cycle"
    """의존 그래프에 순환이 있다."""

    UNDEFINED_SYMBOL = "undefined_symbol"
    """링크 단계에서 심볼 정의를 찾지 못했다."""

    MULTIPLE_DEFINITION = "multiple_definition"
    """같은 심볼이 두 번 정의됐다(GNU ld ``multiple definition of``, lld ``duplicate symbol``).

    하네스가 대상 라이브러리 함수를 다시 정의하거나, 모킹 함수가 실제 정의와 겹칠 때 난다.
    """

    MISSING_LIBRARY = "missing_library"
    """링커가 ``-l<이름>`` 라이브러리를 찾지 못했다(``cannot find -l``).

    프로필의 ``build.libraries``/``link_flags`` 문제라 하네스 소스로는 고칠 수 없다.
    """

    UNKNOWN = "unknown"
    """분류하지 못했다. 자가치유는 로그 원문을 그대로 LLM 에 넘긴다."""


class FixAction(str, Enum):
    """분류 결과에 대응하는 처방"""

    ADD_LOAD = "add_load"
    FIX_BUILD_SYNTAX = "fix_build_syntax"
    DEFINE_TARGET = "define_target"
    """BUILD 는 정상인데 그 이름의 타깃이 없다 — 규칙을 추가하거나 이름을 맞춘다."""
    EXPAND_VISIBILITY = "expand_visibility"
    ADD_DEPS = "add_deps"
    FIX_DEP_LABEL = "fix_dep_label"
    ADD_SRCS_FILE = "add_srcs_file"
    BREAK_CYCLE = "break_cycle"
    RESOLVE_SYMBOL = "resolve_symbol"
    REMOVE_DUPLICATE_DEFINITION = "remove_duplicate_definition"
    """하네스에서 대상과 겹치는 정의를 지운다."""
    ESCALATE = "escalate"
    """LLM 재시도로 고칠 수 없다고 판단 — HITL 로 올린다."""
    RETRY_RAW = "retry_raw"
    """분류 실패. 힌트 없이 로그 원문만 넣고 재시도한다."""


@dataclass(frozen=True)
class BazelDiagnostic:
    """빌드 로그에서 식별한 진단 하나"""

    kind: BazelErrorKind
    action: FixAction
    summary: str
    """사람과 LLM 이 같이 읽는 한 줄 설명."""

    block: str = ""
    """이 진단의 원문 블록. 프롬프트에 그대로 실어 보낼 수 있다."""

    file: str = ""
    line: int = 0
    col: int = 0

    detail: Dict[str, str] = field(default_factory=dict)
    """처방에 필요한 구조화된 값.

    키는 종류마다 다르다:
      MISSING_DEP        header  — deps 를 찾아야 할 헤더 경로
      NOT_VISIBLE        label   — 안 보이는 타깃, from — 보려는 쪽 타깃
      NO_SUCH_TARGET     label   — 없는 타깃, suggestion — Bazel 이 제안한 이름(있으면)
      NO_SUCH_PACKAGE    package — 없는 패키지 경로
      MISSING_SRCS_FILE  label   — 없는 소스 파일 레이블
      UNDEFINED_SYMBOL   symbol  — 정의를 못 찾은 심볼, referenced_by — 참조한 곳(있으면)
      MULTIPLE_DEFINITION symbol — 두 번 정의된 심볼
      MISSING_LIBRARY    library — 찾지 못한 라이브러리 이름(-l 뒤)
      TARGET_NOT_DEFINED label   — 정의되지 않은 자기 타깃
    """

    root_cause: bool = True
    """False 면 다른 진단의 증상이다. 처방을 여기에 맞추면 안 된다."""

    @property
    def location(self) -> str:
        if not self.file:
            return ""
        if self.line:
            return f"{self.file}:{self.line}:{self.col}" if self.col else f"{self.file}:{self.line}"
        return self.file

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind.value,
            "action": self.action.value,
            "summary": self.summary,
            "location": self.location,
            "detail": dict(self.detail),
            "root_cause": self.root_cause,
        }


# 근본 원인 선택 시 우선순위. 앞쪽이 먼저
#
# BUILD 파일이 파싱 자체에 실패하는 종류(MISSING_LOAD, BUILD_SYNTAX_ERROR)가 최상위
# 그게 있으면 뒤따르는 "타깃이 없다"는 전부 증상이기 때문(코퍼스 발견 A)
_PRIORITY: List[BazelErrorKind] = [
    BazelErrorKind.MISSING_LOAD,
    BazelErrorKind.BUILD_SYNTAX_ERROR,
    BazelErrorKind.DEP_CYCLE,
    BazelErrorKind.NO_SUCH_PACKAGE,
    BazelErrorKind.NO_SUCH_TARGET,
    BazelErrorKind.NOT_VISIBLE,
    BazelErrorKind.MISSING_SRCS_FILE,
    BazelErrorKind.MISSING_DEP,
    BazelErrorKind.MISSING_LIBRARY,
    BazelErrorKind.MULTIPLE_DEFINITION,
    BazelErrorKind.UNDEFINED_SYMBOL,
    BazelErrorKind.TARGET_NOT_DEFINED,
    BazelErrorKind.UNKNOWN,
]


@dataclass
class BazelErrorReport:
    """빌드 로그 하나에 대한 분류 결과"""

    diagnostics: List[BazelDiagnostic] = field(default_factory=list)
    log: str = ""

    @property
    def ok(self) -> bool:
        """진단이 하나도 없음(=빌드 성공으로 간주)"""
        return not self.diagnostics

    @property
    def root_causes(self) -> List[BazelDiagnostic]:
        return [d for d in self.diagnostics if d.root_cause]

    @property
    def primary(self) -> Optional[BazelDiagnostic]:
        """가장 먼저 고쳐야 할 진단. 없으면 None"""
        pool = self.root_causes or self.diagnostics
        if not pool:
            return None
        return min(pool, key=lambda d: _PRIORITY.index(d.kind))

    @property
    def actions(self) -> List[FixAction]:
        """근본 원인들의 처방(중복 제거, 우선순위 순)"""
        seen: List[FixAction] = []
        for d in sorted(self.root_causes, key=lambda x: _PRIORITY.index(x.kind)):
            if d.action not in seen:
                seen.append(d.action)
        return seen

    @property
    def needs_human(self) -> bool:
        """LLM 재시도로 수정 불가로 판단한 진단 존재 여부"""
        return any(d.action is FixAction.ESCALATE for d in self.root_causes)

    def of_kind(self, kind: BazelErrorKind) -> List[BazelDiagnostic]:
        return [d for d in self.diagnostics if d.kind is kind]

    def to_dict(self) -> Dict[str, Any]:
        primary = self.primary
        return {
            "ok": self.ok,
            "primary": primary.to_dict() if primary else None,
            "actions": [a.value for a in self.actions],
            "needs_human": self.needs_human,
            "diagnostics": [d.to_dict() for d in self.diagnostics],
        }


# --------------------------------------------------------------------------- #
# 컴파일러·링커 원문 분류 (CMake / prebuilt 경로, GENERIC-C)
# --------------------------------------------------------------------------- #
# Bazel 은 진단을 ``ERROR:`` 블록으로 감싸지만, CMake/prebuilt 어댑터는 clang 을 직접
# 호출하므로 로그가 컴파일러·링커 원문 그대로. ``bazel_errors.classify`` 는 ``ERROR:``
# 블록이 없으면 아무것도 못 찾으므로(=성공으로 오판) 원문용 분류기를 별도 구성
# 정규식은 ``tests/fixtures/linker_errors/`` 의 실측 로그(clang 18, GNU ld 2.42, lld 18)에서
# 추출
#
#   GNU ld : <obj>:<file>:<line>:(<section>): undefined reference to `X'
#            ... multiple definition of `X'; <obj>: first defined here
#            /usr/bin/ld: cannot find -lX: No such file or directory
#   lld    : ld.lld: error: undefined symbol: X
#            >>> referenced by <file>:<line> (...)
#            ld.lld: error: duplicate symbol: X
#            ld.lld: error: unable to find library -lX
UNDEFINED_REFERENCE_RE = re.compile(r"undefined reference to [`'](?P<symbol>[^'`]+)'")
UNDEFINED_SYMBOL_RE = re.compile(r"undefined symbol: (?P<symbol>.+?)\s*$")
MULTIPLE_DEFINITION_RE = re.compile(
    r"multiple definition of [`'](?P<symbol>[^'`]+)'|duplicate symbol: (?P<lld>.+?)\s*$"
)
MISSING_LIBRARY_RE = re.compile(
    r"cannot find -l(?P<library>[^\s:]+)|unable to find library -l(?P<lld>[^\s:]+)"
)
_REFERENCED_BY_RE = re.compile(r"^>>> referenced by (?P<where>.+)$")
_GNU_LOCATION_RE = re.compile(r"(?P<file>[^\s:()]+\.(?:c|cc|cpp|cxx|h|hpp)):(?P<line>\d+):\(")
_CLANG_ERROR_RE = re.compile(
    r"^(?P<file>[^\s:][^:\n]*):(?P<line>\d+):(?P<col>\d+): (?:fatal )?error: (?P<msg>.+)$"
)
_FILE_NOT_FOUND_RE = re.compile(r"'(?P<header>[^']+)' file not found")
# 앞선 진단의 결과일 뿐인 줄. 분류 제외
_LINK_CONSEQUENCE_RE = re.compile(r"(?:clang|gcc|cc)(?:\+\+)?: error: linker command failed")


def _diag(kind: BazelErrorKind, action: FixAction, summary: str, block: str,
          detail: Dict[str, str], file: str = "", line: int = 0, col: int = 0) -> BazelDiagnostic:
    return BazelDiagnostic(kind=kind, action=action, summary=summary, block=block,
                           file=file, line=line, col=col, detail=detail)


def _undefined_summary(symbol: str) -> str:
    return (f"심볼 '{symbol}' 의 정의를 찾지 못했다. 정의를 담은 라이브러리를 링크하거나, "
            f"정의가 없는 호출을 없애거나, 외부 장치 함수라면 스텁으로 채워야 한다.")


def classify_toolchain_log(log: str) -> BazelErrorReport:
    """clang/ld 원문 로그 분류(CMake/prebuilt 경로)

    결과 타입은 Bazel 분류기와 같은 :class:`BazelErrorReport` 라서 ``selfheal`` 과
    ``bazel_errors.prompt_hint`` 를 그대로 사용 가능

    분류 규칙:
      * ``undefined reference`` / ``undefined symbol`` → ``UNDEFINED_SYMBOL`` (``RESOLVE_SYMBOL``)
      * ``multiple definition`` / ``duplicate symbol`` → ``MULTIPLE_DEFINITION``
        (``REMOVE_DUPLICATE_DEFINITION``)
      * ``cannot find -l`` / ``unable to find library`` → ``MISSING_LIBRARY`` (``ESCALATE``)
      * 헤더 없음 → ``MISSING_DEP`` (``RETRY_RAW`` — CMake 에는 deps 가 없어서 BUILD 처방 미사용)
      * 그 밖의 clang ``error:`` → ``UNKNOWN`` (``RETRY_RAW``)
    """
    diagnostics: List[BazelDiagnostic] = []
    seen: set = set()

    def add(diag: BazelDiagnostic, key: tuple) -> None:
        if key in seen:
            return
        seen.add(key)
        diagnostics.append(diag)

    lines = (log or "").splitlines()
    for i, raw in enumerate(lines):
        line = raw.rstrip()
        if not line or _LINK_CONSEQUENCE_RE.search(line):
            continue

        m = MISSING_LIBRARY_RE.search(line)
        if m:
            lib = m.group("library") or m.group("lld")
            add(_diag(BazelErrorKind.MISSING_LIBRARY, FixAction.ESCALATE,
                      f"링커가 라이브러리 -l{lib} 를 찾지 못했다. 프로필의 build.libraries/"
                      f"link_flags 를 고쳐야 하며 하네스 소스로는 해결되지 않는다.",
                      line, {"library": lib}),
                (BazelErrorKind.MISSING_LIBRARY, lib))
            continue

        m = MULTIPLE_DEFINITION_RE.search(line)
        if m:
            symbol = (m.group("symbol") or m.group("lld") or "").strip()
            loc = _GNU_LOCATION_RE.search(line)
            add(_diag(BazelErrorKind.MULTIPLE_DEFINITION, FixAction.REMOVE_DUPLICATE_DEFINITION,
                      f"심볼 '{symbol}' 이(가) 두 번 정의됐다. 하네스가 대상 라이브러리 함수를 "
                      f"다시 정의했다면 그 정의를 지워야 한다.",
                      line, {"symbol": symbol},
                      file=loc.group("file") if loc else "",
                      line=int(loc.group("line")) if loc else 0),
                (BazelErrorKind.MULTIPLE_DEFINITION, symbol))
            continue

        m = UNDEFINED_REFERENCE_RE.search(line)
        if m:
            symbol = m.group("symbol").strip()
            detail = {"symbol": symbol}
            loc = _GNU_LOCATION_RE.search(line)
            # GNU ld 는 앞 줄에 "<archive>(<obj>): in function `f':" 출력
            if i > 0 and "in function" in lines[i - 1]:
                detail["referenced_by"] = lines[i - 1].strip()
            add(_diag(BazelErrorKind.UNDEFINED_SYMBOL, FixAction.RESOLVE_SYMBOL,
                      _undefined_summary(symbol), line, detail,
                      file=loc.group("file") if loc else "",
                      line=int(loc.group("line")) if loc else 0),
                (BazelErrorKind.UNDEFINED_SYMBOL, symbol))
            continue

        m = UNDEFINED_SYMBOL_RE.search(line)
        if m:
            symbol = m.group("symbol").strip()
            detail = {"symbol": symbol}
            block = [line]
            for follow in lines[i + 1:i + 3]:
                if not follow.startswith(">>>"):
                    break
                block.append(follow)
                ref = _REFERENCED_BY_RE.match(follow)
                if ref:
                    detail["referenced_by"] = ref.group("where").strip()
            add(_diag(BazelErrorKind.UNDEFINED_SYMBOL, FixAction.RESOLVE_SYMBOL,
                      _undefined_summary(symbol), "\n".join(block), detail),
                (BazelErrorKind.UNDEFINED_SYMBOL, symbol))
            continue

        m = _CLANG_ERROR_RE.match(line)
        if m:
            msg = m.group("msg").strip()
            loc = {"file": m.group("file"), "line": int(m.group("line")),
                   "col": int(m.group("col"))}
            header = _FILE_NOT_FOUND_RE.search(msg)
            if header:
                add(_diag(BazelErrorKind.MISSING_DEP, FixAction.RETRY_RAW,
                          f"헤더 '{header.group('header')}' 를 찾지 못했다. include 이름이 틀렸는지, "
                          f"프로필의 include_dirs 에 경로가 빠졌는지 확인해야 한다.",
                          line, {"header": header.group("header")}, **loc),
                    (BazelErrorKind.MISSING_DEP, header.group("header")))
            else:
                add(_diag(BazelErrorKind.UNKNOWN, FixAction.RETRY_RAW,
                          f"컴파일 에러: {msg}", line, {}, **loc),
                    (BazelErrorKind.UNKNOWN, loc["file"], loc["line"], msg))

    return BazelErrorReport(diagnostics=diagnostics, log=log or "")


def undefined_symbols(report: BazelErrorReport) -> List[str]:
    """분류 결과에서 미정의 심볼 이름만 순서대로 추출"""
    return [d.detail["symbol"] for d in report.of_kind(BazelErrorKind.UNDEFINED_SYMBOL)
            if d.detail.get("symbol")]
