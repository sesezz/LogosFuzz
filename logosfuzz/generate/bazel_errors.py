"""GEN-03-02 Bazel 빌드 에러 분류기 (D 파트 2주차).

빌드 로그 원문을 받아 "무엇이 잘못됐고 무엇을 고쳐야 하는지"를 구조화된
:class:`~logosfuzz.generate.errors.BazelErrorReport` 로 돌려준다. 3주차에
`selfheal.py` 가 이 결과를 리페어 프롬프트에 주입한다.

정규식은 추측이 아니라 1주차에 **실제로 빌드를 깨뜨려 모은 코퍼스**
(`tests/fixtures/bazel_errors/`)에서 나왔다. 분석은
`docs/GEN-03-02-ERROR-CORPUS.md` 에 있고, 그 문서의 발견 세 가지가 이 모듈의
설계를 그대로 결정한다:

발견 A — `no such target` 은 단독 분류 키로 쓸 수 없다
    BUILD 파일이 파싱에 실패하면(`load()` 누락, 구문 오류) 그 안의 타깃이
    정의되지 않으므로 Bazel 은 deps 문제와 **똑같은 문장**을 낸다. 처방은
    정반대다. :func:`classify_block` 은 없다고 지목된 레이블이 *하네스 자신의
    타깃*인지 *의존 대상*인지로 가르고, :func:`classify` 가 후처리에서 앞의
    경우를 증상(`root_cause=False`)으로 내린다.

발견 B — deps 누락의 입구는 `no such target` 이 아니다
    deps 를 비워도 Bazel 로딩·분석은 통과하고, **clang** 이
    ``fatal error: '<헤더>' file not found`` 로 터진다. 이 문구에 헤더 경로가
    그대로 들어 있어 A 파트의 `bazel_query` 로 바로 넘길 수 있다.

발견 C — visibility 판정 문구는 `ERROR:` 줄에 없다
    ``is not visible from`` 은 그 다음 줄에 있고 뒤에서 한 번 더 끊긴다.
    그래서 로그를 줄이 아니라 **블록**으로 쪼갠다(:func:`split_blocks`).

사용 예::

    from logosfuzz.generate.bazel_errors import classify, prompt_hint

    report = classify(build_log, requested_target="//harness:json_fuzzer")
    if report.primary:
        print(report.primary.kind, report.primary.action)
        print(prompt_hint(report))      # 3주차 selfheal 프롬프트에 주입
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional

from .errors import (
    BazelDiagnostic,
    BazelErrorKind,
    BazelErrorReport,
    FixAction,
)

__all__ = [
    "classify",
    "classify_block",
    "split_blocks",
    "prompt_hint",
    "load_statement_for",
]

# --------------------------------------------------------------------------- #
# 블록 분할 (발견 C)
# --------------------------------------------------------------------------- #
# Bazel 은 `ERROR:`/`WARNING:`/`INFO:` 로 시작하는 줄에서 새 진단을 연다. 그 뒤로
# 들여쓰기 없는 줄이 이어져도 같은 진단의 일부다(clang 진단, 링커 에러, visibility
# 상세 설명 등). 줄 단위로 훑으면 이것들이 통째로 떨어져 나간다.
_BLOCK_START_RE = re.compile(r"^(?:ERROR|WARNING|INFO):", re.MULTILINE)

# 진단이 아니라 빌드 전체 결과를 알리는 줄. 분류 대상에서 뺀다.
_SUMMARY_ONLY_RE = re.compile(
    r"^ERROR: (?:Build did NOT complete successfully"
    r"|command succeeded, but"
    r"|Build failed"
    r"|Couldn't start the build)"
)

# 앞선 에러의 **결과**를 알리는 줄. 그 자체로는 아무 처방도 못 준다.
#
# 이걸 걸러내지 않으면 UNKNOWN 근본 원인으로 올라와 `report.actions` 에
# RETRY_RAW 가 섞인다 — 이미 정확히 분류된 결함이 있는데도 "로그 보고 알아서
# 고쳐라"는 지시가 같이 나가는 셈이라 해롭다. visibility 에러 뒤의
# `Analysis of target ... failed`, 입력 파일 누락 뒤의 `N input file(s) do not
# exist` 가 실제로 그랬다.
_CONSEQUENCE_RE = re.compile(
    r"Analysis of target '[^']*'(?: \(config: [^)]*\))? failed"
    r"|\d+ input file\(s\) do not exist"
    r"|errors encountered while analyzing target"
    r"|Target pattern parsing failed"
)


def split_blocks(log: str) -> List[str]:
    """빌드 로그를 진단 블록 목록으로 쪼갠다.

    `ERROR:`/`WARNING:`/`INFO:` 로 시작하는 줄에서 자르고, 그 앞의 머리말은 버린다.
    """
    if not log:
        return []
    starts = [m.start() for m in _BLOCK_START_RE.finditer(log)]
    if not starts:
        return []
    bounds = starts + [len(log)]
    return [log[bounds[i]:bounds[i + 1]].rstrip() for i in range(len(starts))]


# --------------------------------------------------------------------------- #
# 신호 패턴 — 전부 코퍼스 원문에서 따왔다
# --------------------------------------------------------------------------- #
_MISSING_LOAD_RE = re.compile(r"This rule has been removed from Bazel")
# 오토로드를 끈 설정에서 나오는 다른 표현.
_NAME_NOT_DEFINED_RE = re.compile(r"name '(?P<rule>\w+)' is not defined")
_SYNTAX_ERROR_RE = re.compile(r"syntax error at ")

# 발견 C: 줄바꿈을 넘어간다.
_NOT_VISIBLE_RE = re.compile(
    r"target '(?P<label>[^']+)' is not visible from\s+target '(?P<from>[^']+)'"
)

_NO_SUCH_PACKAGE_RE = re.compile(r"no such package '(?P<package>[^']+)'")
_NO_SUCH_TARGET_RE = re.compile(r"no such target '(?P<label>[^']+)'")
_SKIPPING_RE = re.compile(r"Skipping '(?P<label>[^']+)'")
_REFERENCED_BY_RE = re.compile(r"referenced by '(?P<label>[^']+)'")
_DID_YOU_MEAN_RE = re.compile(r"\(did you mean (?P<name>[^)?]+)\?\)")

_DEP_CYCLE_RE = re.compile(r"cycle in dependency graph")
_MISSING_INPUT_RE = re.compile(r"missing input file '(?P<label>[^']+)'")

# 발견 B: deps 누락은 clang 이 보고한다.
_FILE_NOT_FOUND_RE = re.compile(r"fatal error: '(?P<header>[^']+)' file not found")

_UNDEF_SYMBOL_RE = re.compile(r"undefined symbol: (?P<symbol>.+)")
_UNDEF_REF_RE = re.compile(r"undefined reference to [`'](?P<symbol>[^'`]+)'")

# 위치
_ERROR_LOC_RE = re.compile(r"^ERROR: (?P<file>.+?):(?P<line>\d+):(?P<col>\d+): ", re.MULTILINE)
_ERROR_FILE_RE = re.compile(r"^ERROR: (?P<file>\S+?(?:BUILD(?:\.bazel)?|\.bzl)): ", re.MULTILINE)
_TRACEBACK_LOC_RE = re.compile(
    r'File "(?P<file>[^"]+)", line (?P<line>\d+), column (?P<col>\d+)'
)
_CLANG_DIAG_RE = re.compile(
    r"^(?P<file>[^\s:][^:\n]*):(?P<line>\d+):(?P<col>\d+): (?:fatal )?error: ", re.MULTILINE
)
# `load()` 누락 트레이스백에서 호출된 규칙 이름을 집어낸다.
_RULE_CALL_RE = re.compile(r"^\s*(?P<rule>cc_\w+|\w+_(?:library|binary|test))\($", re.MULTILINE)

# 규칙 -> 넣어야 할 load 문. Bazel 9 는 네이티브 cc_* 를 전부 제거했다.
_RULES_CC = ("cc_binary", "cc_library", "cc_test", "cc_import", "cc_shared_library")
_RULES_FUZZING = ("cc_fuzz_test",)


def load_statement_for(rule: str) -> str:
    """규칙 이름에 맞는 `load()` 문을 돌려준다. 모르는 규칙이면 빈 문자열."""
    if rule in _RULES_CC:
        return f'load("@rules_cc//cc:defs.bzl", "{rule}")'
    if rule in _RULES_FUZZING:
        return f'load("@rules_fuzzing//fuzzing:cc_defs.bzl", "{rule}")'
    return ""


# --------------------------------------------------------------------------- #
# 위치 추출
# --------------------------------------------------------------------------- #
def _location(block: str, prefer_clang: bool = False) -> Dict[str, object]:
    """블록에서 파일/행/열을 뽑는다. 못 찾으면 빈 값."""
    if prefer_clang:
        m = _CLANG_DIAG_RE.search(block)
        if m:
            return {"file": m.group("file"), "line": int(m.group("line")),
                    "col": int(m.group("col"))}
    m = _ERROR_LOC_RE.search(block)
    if m:
        return {"file": m.group("file"), "line": int(m.group("line")),
                "col": int(m.group("col"))}
    m = _TRACEBACK_LOC_RE.search(block)
    if m:
        return {"file": m.group("file"), "line": int(m.group("line")),
                "col": int(m.group("col"))}
    m = _ERROR_FILE_RE.search(block)
    if m:
        return {"file": m.group("file"), "line": 0, "col": 0}
    m = _CLANG_DIAG_RE.search(block)
    if m:
        return {"file": m.group("file"), "line": int(m.group("line")),
                "col": int(m.group("col"))}
    return {"file": "", "line": 0, "col": 0}


def _make(kind: BazelErrorKind, action: FixAction, summary: str, block: str,
          detail: Optional[Dict[str, str]] = None,
          prefer_clang: bool = False) -> BazelDiagnostic:
    loc = _location(block, prefer_clang=prefer_clang)
    return BazelDiagnostic(
        kind=kind, action=action, summary=summary, block=block,
        file=str(loc["file"]), line=int(loc["line"]), col=int(loc["col"]),
        detail=detail or {},
    )


# --------------------------------------------------------------------------- #
# 블록 하나 분류
# --------------------------------------------------------------------------- #
def classify_block(block: str, *, requested_target: Optional[str] = None
                   ) -> Optional[BazelDiagnostic]:
    """진단 블록 하나를 분류한다. 진단이 아니면(요약 줄 등) None.

    Args:
        block: :func:`split_blocks` 가 만든 블록.
        requested_target: 빌드를 요청한 타깃 레이블(예 ``//harness:json_fuzzer``).
            주면 발견 A 의 판별이 더 확실해진다. 없어도 로그 안의
            ``Skipping '<label>'`` 로 같은 판정을 한다.

    블록 안에 신호가 여럿 있을 수 있으므로 검사 순서가 곧 우선순위다. BUILD 파일이
    파싱에 실패하는 종류를 먼저 본다 — 그게 있으면 나머지는 전부 그 증상이다.
    """
    if not block.strip() or _SUMMARY_ONLY_RE.search(block):
        return None

    # 1) load() 누락 — Bazel 9 는 네이티브 cc_* 규칙을 제거했다.
    if _MISSING_LOAD_RE.search(block) or _NAME_NOT_DEFINED_RE.search(block):
        rule = ""
        m = _RULE_CALL_RE.search(block)
        if m:
            rule = m.group("rule")
        else:
            m = _NAME_NOT_DEFINED_RE.search(block)
            if m:
                rule = m.group("rule")
        detail = {"rule": rule} if rule else {}
        stmt = load_statement_for(rule) if rule else ""
        if stmt:
            detail["load"] = stmt
        summary = (
            f"BUILD 파일에 `{rule}` 의 load() 문이 없다. Bazel 9 는 네이티브 "
            f"cc_* 규칙을 제거했으므로 맨 위에 `{stmt}` 를 추가해야 한다."
            if stmt else
            "BUILD 파일에 규칙의 load() 문이 없다. Bazel 9 는 네이티브 cc_* 규칙을 제거했다."
        )
        return _make(BazelErrorKind.MISSING_LOAD, FixAction.ADD_LOAD, summary, block, detail)

    # 2) BUILD 구문 오류
    if _SYNTAX_ERROR_RE.search(block):
        return _make(
            BazelErrorKind.BUILD_SYNTAX_ERROR, FixAction.FIX_BUILD_SYNTAX,
            "BUILD 파일 구문 오류다. 괄호·쉼표·따옴표를 확인해야 한다.", block,
        )

    # 3) visibility (발견 C — 문구가 ERROR: 줄 다음에 있다)
    m = _NOT_VISIBLE_RE.search(block)
    if m:
        label, frm = m.group("label"), m.group("from")
        return _make(
            BazelErrorKind.NOT_VISIBLE, FixAction.EXPAND_VISIBILITY,
            f"{label} 이(가) {frm} 에서 보이지 않는다. 대상 패키지의 visibility 를 "
            f"넓히거나, 공개된 다른 타깃을 거쳐야 한다.",
            block, {"label": label, "from": frm},
        )

    # 4) 패키지 자체가 없음
    m = _NO_SUCH_PACKAGE_RE.search(block)
    if m:
        pkg = m.group("package")
        return _make(
            BazelErrorKind.NO_SUCH_PACKAGE, FixAction.FIX_DEP_LABEL,
            f"패키지 '{pkg}' 가 없다(BUILD 파일이 없는 경로다). deps 의 경로를 "
            f"실제 패키지로 고쳐야 한다.",
            block, {"package": pkg},
        )

    # 5) 타깃이 없음 — 발견 A. 자기 타깃인지 의존 대상인지로 완전히 갈린다.
    m = _NO_SUCH_TARGET_RE.search(block)
    if m:
        label = m.group("label")
        skipping = _SKIPPING_RE.search(block)
        is_own = (skipping is not None and skipping.group("label") == label) or (
            requested_target is not None and label == requested_target
        )
        if is_own:
            return _make(
                BazelErrorKind.TARGET_NOT_DEFINED, FixAction.DEFINE_TARGET,
                f"요청한 타깃 {label} 이(가) BUILD 에 정의되어 있지 않다. "
                f"BUILD 파싱이 실패했거나(그 경우 이건 증상이다) 규칙 이름이 다르다.",
                block, {"label": label},
            )
        detail = {"label": label}
        suggestion = _DID_YOU_MEAN_RE.search(block)
        if suggestion:
            detail["suggestion"] = suggestion.group("name").strip()
        referenced_by = _REFERENCED_BY_RE.search(block)
        if referenced_by:
            detail["referenced_by"] = referenced_by.group("label")
        hint = (f" Bazel 이 '{detail['suggestion']}' 를 제안했다."
                if "suggestion" in detail else "")
        return _make(
            BazelErrorKind.NO_SUCH_TARGET, FixAction.FIX_DEP_LABEL,
            f"deps 에 적은 타깃 {label} 이(가) 없다.{hint}", block, detail,
        )

    # 6) 순환 의존 — LLM 재시도로 못 고친다. 구조를 바꿔야 한다.
    if _DEP_CYCLE_RE.search(block):
        return _make(
            BazelErrorKind.DEP_CYCLE, FixAction.ESCALATE,
            "의존 그래프에 순환이 있다. 타깃을 쪼개야 풀리므로 자동 수정 대상이 아니다.",
            block,
        )

    # 7) srcs 가 없는 파일을 가리킴
    m = _MISSING_INPUT_RE.search(block)
    if m:
        label = m.group("label")
        return _make(
            BazelErrorKind.MISSING_SRCS_FILE, FixAction.ADD_SRCS_FILE,
            f"srcs 가 존재하지 않는 파일 {label} 을(를) 참조한다. 파일을 만들거나 "
            f"srcs 에서 빼야 한다.",
            block, {"label": label},
        )

    # 8) deps 누락 (발견 B) — Bazel 이 아니라 clang 이 보고한다.
    m = _FILE_NOT_FOUND_RE.search(block)
    if m:
        header = m.group("header")
        return _make(
            BazelErrorKind.MISSING_DEP, FixAction.ADD_DEPS,
            f"헤더 '{header}' 를 찾지 못했다. 이 헤더를 제공하는 타깃이 deps 에 없다. "
            f"bazel query 로 찾아 추가해야 한다.",
            block, {"header": header}, prefer_clang=True,
        )

    # 9) 링크 단계 미정의 심볼
    m = _UNDEF_SYMBOL_RE.search(block) or _UNDEF_REF_RE.search(block)
    if m:
        symbol = m.group("symbol").strip()
        return _make(
            BazelErrorKind.UNDEFINED_SYMBOL, FixAction.RESOLVE_SYMBOL,
            f"심볼 '{symbol}' 의 정의를 찾지 못했다. 정의를 담은 타깃을 deps 에 "
            f"추가하거나 호출을 없애야 한다.",
            block, {"symbol": symbol}, prefer_clang=True,
        )

    # 10) 아는 신호가 하나도 없다. 앞선 에러의 결과를 알리는 줄이면 버리고,
    #     아니면 UNKNOWN 으로 남겨 로그 원문 재시도에 맡긴다.
    if _CONSEQUENCE_RE.search(block):
        return None
    if block.startswith("ERROR:"):
        first = block.splitlines()[0].strip()
        return _make(
            BazelErrorKind.UNKNOWN, FixAction.RETRY_RAW,
            f"분류하지 못한 빌드 에러다: {first}", block,
        )
    return None


# --------------------------------------------------------------------------- #
# 로그 전체 분류
# --------------------------------------------------------------------------- #
# BUILD 파일이 파싱에 실패하면 그 안의 타깃이 정의되지 않아 "타깃이 없다"가 따라
# 나온다. 그건 증상이므로 근본 원인에서 뺀다(발견 A).
_PARSE_FAILURE_KINDS = frozenset(
    {BazelErrorKind.MISSING_LOAD, BazelErrorKind.BUILD_SYNTAX_ERROR}
)

# 같은 결함을 가리키는 진단을 묶는 키. Bazel 은 하나의 잘못된 deps 를 두 번 보고
# 한다 — 한 번은 대상 패키지 기준으로 위치 없이, 한 번은 참조한 BUILD 위치와
# `referenced by` 를 붙여서. 둘 다 근본 원인으로 세면 같은 문제가 두 건으로 보인다.
_DEDUPE_DETAIL_KEY: Dict[BazelErrorKind, tuple] = {
    BazelErrorKind.NO_SUCH_TARGET: ("label",),
    BazelErrorKind.NO_SUCH_PACKAGE: ("package",),
    BazelErrorKind.NOT_VISIBLE: ("label", "from"),
    BazelErrorKind.MISSING_DEP: ("header",),
    BazelErrorKind.MISSING_SRCS_FILE: ("label",),
    BazelErrorKind.UNDEFINED_SYMBOL: ("symbol",),
    BazelErrorKind.TARGET_NOT_DEFINED: ("label",),
}


def _dedupe_key(diag: BazelDiagnostic) -> tuple:
    keys = _DEDUPE_DETAIL_KEY.get(diag.kind)
    if keys:
        return (diag.kind,) + tuple(diag.detail.get(k, "") for k in keys)
    if diag.kind is BazelErrorKind.UNKNOWN:
        # 분류 못 한 것끼리는 첫 줄이 같을 때만 같은 것으로 본다.
        first = diag.block.splitlines()[0] if diag.block else ""
        return (diag.kind, first)
    return (diag.kind,)


def _richness(diag: BazelDiagnostic) -> tuple:
    """중복 중 어느 쪽을 남길지 — 정보가 많은 쪽을 남긴다."""
    return (len(diag.detail), 1 if diag.line else 0, 1 if diag.file else 0)


def _dedupe(diagnostics: List[BazelDiagnostic]) -> List[BazelDiagnostic]:
    best: Dict[tuple, BazelDiagnostic] = {}
    order: List[tuple] = []
    for diag in diagnostics:
        key = _dedupe_key(diag)
        if key not in best:
            best[key] = diag
            order.append(key)
        elif _richness(diag) > _richness(best[key]):
            best[key] = diag
    return [best[k] for k in order]


def classify(log: str, *, requested_target: Optional[str] = None) -> BazelErrorReport:
    """빌드 로그 전체를 분류한다.

    Args:
        log: `bazel build` 의 stdout+stderr 원문.
        requested_target: 빌드를 요청한 타깃 레이블(선택).

    Returns:
        :class:`BazelErrorReport`. 진단이 하나도 없으면 ``report.ok`` 가 True 다.
    """
    diagnostics: List[BazelDiagnostic] = []
    for block in split_blocks(log):
        diag = classify_block(block, requested_target=requested_target)
        if diag is not None:
            diagnostics.append(diag)

    diagnostics = _dedupe(diagnostics)

    # 후처리: 파싱 실패가 있으면 "자기 타깃이 없다"는 증상으로 내린다.
    if any(d.kind in _PARSE_FAILURE_KINDS for d in diagnostics):
        diagnostics = [
            BazelDiagnostic(
                kind=d.kind, action=d.action, summary=d.summary, block=d.block,
                file=d.file, line=d.line, col=d.col, detail=d.detail,
                root_cause=False,
            )
            if d.kind is BazelErrorKind.TARGET_NOT_DEFINED else d
            for d in diagnostics
        ]

    return BazelErrorReport(diagnostics=diagnostics, log=log)


# --------------------------------------------------------------------------- #
# 프롬프트 힌트 (3주차 selfheal.py 가 쓴다)
# --------------------------------------------------------------------------- #
# 처방별로 LLM 에게 줄 구체적 지시. 분류 결과를 "그래서 뭘 하라"로 번역한다.
_ACTION_INSTRUCTION: Dict[FixAction, str] = {
    FixAction.ADD_LOAD:
        "BUILD 파일 맨 위에 빠진 load() 문을 추가하라. Bazel 9 에는 네이티브 "
        "cc_binary/cc_library 가 없으므로 반드시 명시적으로 load 해야 한다.",
    FixAction.FIX_BUILD_SYNTAX:
        "BUILD 파일의 구문 오류를 고쳐라. 닫히지 않은 괄호와 빠진 쉼표를 먼저 확인하라.",
    FixAction.DEFINE_TARGET:
        "BUILD 파일에 요청된 이름의 타깃을 정의하거나, 기존 규칙의 name 을 그 이름으로 맞춰라.",
    FixAction.EXPAND_VISIBILITY:
        "대상 타깃이 visibility 로 막혀 있다. 하네스가 볼 수 있게 대상 패키지의 "
        "visibility 를 넓히거나, 같은 기능을 공개한 다른 타깃으로 바꿔라. "
        "하네스 쪽 deps 만 고쳐서는 해결되지 않는다.",
    FixAction.ADD_DEPS:
        "include 하는 헤더를 제공하는 타깃을 deps 에 추가하라. 헤더 경로의 디렉터리가 "
        "곧 패키지 경로인 경우가 많다(예: score/json/json.h -> //score/json).",
    FixAction.FIX_DEP_LABEL:
        "deps 에 적은 레이블이 실재하지 않는다. 실제 존재하는 타깃 레이블로 고쳐라.",
    FixAction.ADD_SRCS_FILE:
        "srcs 가 없는 파일을 가리킨다. 해당 파일을 만들거나 srcs 목록에서 제거하라.",
    FixAction.RESOLVE_SYMBOL:
        "링크 단계에서 심볼 정의를 찾지 못했다. 정의를 담은 타깃을 deps 에 추가하거나, "
        "정의가 없는 함수 호출을 제거하라.",
    FixAction.ESCALATE:
        "이 결함은 타깃 구조를 바꿔야 풀린다. 부분 수정으로 시도하지 마라.",
    FixAction.RETRY_RAW:
        "아래 빌드 로그 원문을 보고 원인을 직접 판단해 고쳐라.",
}


def prompt_hint(report: BazelErrorReport, *, max_block_chars: int = 1500) -> str:
    """분류 결과를 리페어 프롬프트에 넣을 텍스트로 만든다.

    3주차 `selfheal.py` 가 로그 원문과 **함께** 이걸 넣는다. 로그만 넣으면 LLM 이
    발견 A/B/C 를 매번 새로 추론해야 하고, 1주차에 확인했듯 그 추론은 자주 틀린다.
    """
    primary = report.primary
    if primary is None:
        return ""

    lines = [
        "# 빌드 에러 분류 결과",
        f"- 종류: {primary.kind.value}",
        f"- 처방: {primary.action.value}",
    ]
    if primary.location:
        lines.append(f"- 위치: {primary.location}")
    for key, value in primary.detail.items():
        lines.append(f"- {key}: {value}")
    lines.append(f"- 판단: {primary.summary}")

    instruction = _ACTION_INSTRUCTION.get(primary.action)
    if instruction:
        lines += ["", "# 지시", instruction]

    others = [d for d in report.root_causes if d is not primary]
    if others:
        lines += ["", "# 같이 잡힌 다른 원인"]
        lines += [f"- [{d.kind.value}] {d.summary}" for d in others]

    symptoms = [d for d in report.diagnostics if not d.root_cause]
    if symptoms:
        lines += [
            "",
            "# 증상(원인 아님. 여기에 맞춰 고치지 마라)",
        ]
        lines += [f"- [{d.kind.value}] {d.summary}" for d in symptoms]

    block = primary.block[:max_block_chars]
    lines += ["", "# 해당 에러 원문", "```", block, "```"]
    return "\n".join(lines)
