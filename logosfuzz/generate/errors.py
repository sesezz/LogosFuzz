"""GEN 파트 예외 정의 + Bazel 빌드 에러 분류 결과 타입.

분류를 **수행**하는 쪽은 `logosfuzz.generate.bazel_errors` 다. 여기에는 그 결과를
담는 타입만 둔다 — 분류기를 쓰지 않는 모듈(3주차 `selfheal.py`, 리포팅 등)이
분류기 전체를 import 하지 않고 결과 타입만 가져다 쓸 수 있게 하기 위해서다.

타입 설계 근거는 1주차에 실제로 빌드를 깨뜨려 모은 코퍼스다
(`docs/GEN-03-02-ERROR-CORPUS.md`, `tests/fixtures/bazel_errors/`). 특히:

- 하나의 빌드 로그에 진단이 여러 개 나오고, 그중 **하나만 근본 원인**이다.
  `load()` 누락은 "load 에러"와 "타깃이 없다" 두 진단을 동시에 만든다.
  그래서 `BazelDiagnostic.root_cause` 로 증상과 원인을 구분한다.
- 처방(`FixAction`)이 분류(`BazelErrorKind`)와 1:1 이 아니다. `no_such_target`
  하나가 레이블 교정일 수도, 전혀 다른 BUILD 작성 오류의 증상일 수도 있다.
  그래서 둘을 분리해 둔다.
- 어떤 결함은 LLM 재시도로 못 고친다(순환 의존). `FixAction.ESCALATE` 로
  표시해 자가치유 루프가 라운드를 낭비하지 않고 HITL 로 올리게 한다.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class GenerateError(Exception):
    """GEN 파트 공통 예외."""


class HarnessBinaryNotFoundError(GenerateError):
    """검증 대상 하네스 실행 파일(GEN-03-02 산출물)이 존재하지 않을 때."""


class ManifestError(GenerateError):
    """검증 매니페스트 JSON이 잘못되었을 때."""


# --------------------------------------------------------------------------- #
# Bazel 에러 분류
# --------------------------------------------------------------------------- #
class BazelErrorKind(str, Enum):
    """빌드 로그에서 식별한 결함의 종류.

    값은 코퍼스의 파손 케이스 이름(`tests/fixtures/bazel_errors/*.txt`)과 맞춰 뒀다.
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

    UNKNOWN = "unknown"
    """분류하지 못했다. 자가치유는 로그 원문을 그대로 LLM 에 넘긴다."""


class FixAction(str, Enum):
    """분류 결과에 대응하는 처방."""

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
    ESCALATE = "escalate"
    """LLM 재시도로 고칠 수 없다고 판단 — HITL 로 올린다."""
    RETRY_RAW = "retry_raw"
    """분류 실패. 힌트 없이 로그 원문만 넣고 재시도한다."""


@dataclass(frozen=True)
class BazelDiagnostic:
    """빌드 로그에서 식별한 진단 하나."""

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
      UNDEFINED_SYMBOL   symbol  — 정의를 못 찾은 심볼
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


# 근본 원인을 고를 때의 우선순위. 앞쪽이 먼저다.
#
# BUILD 파일이 파싱 자체에 실패하는 종류(MISSING_LOAD, BUILD_SYNTAX_ERROR)가 최상위다.
# 그게 있으면 뒤따르는 "타깃이 없다"는 전부 증상이기 때문이다(코퍼스 발견 A).
_PRIORITY: List[BazelErrorKind] = [
    BazelErrorKind.MISSING_LOAD,
    BazelErrorKind.BUILD_SYNTAX_ERROR,
    BazelErrorKind.DEP_CYCLE,
    BazelErrorKind.NO_SUCH_PACKAGE,
    BazelErrorKind.NO_SUCH_TARGET,
    BazelErrorKind.NOT_VISIBLE,
    BazelErrorKind.MISSING_SRCS_FILE,
    BazelErrorKind.MISSING_DEP,
    BazelErrorKind.UNDEFINED_SYMBOL,
    BazelErrorKind.TARGET_NOT_DEFINED,
    BazelErrorKind.UNKNOWN,
]


@dataclass
class BazelErrorReport:
    """빌드 로그 하나에 대한 분류 결과."""

    diagnostics: List[BazelDiagnostic] = field(default_factory=list)
    log: str = ""

    @property
    def ok(self) -> bool:
        """진단이 하나도 없다(=빌드 성공으로 간주)."""
        return not self.diagnostics

    @property
    def root_causes(self) -> List[BazelDiagnostic]:
        return [d for d in self.diagnostics if d.root_cause]

    @property
    def primary(self) -> Optional[BazelDiagnostic]:
        """가장 먼저 고쳐야 할 진단. 없으면 None."""
        pool = self.root_causes or self.diagnostics
        if not pool:
            return None
        return min(pool, key=lambda d: _PRIORITY.index(d.kind))

    @property
    def actions(self) -> List[FixAction]:
        """근본 원인들의 처방(중복 제거, 우선순위 순)."""
        seen: List[FixAction] = []
        for d in sorted(self.root_causes, key=lambda x: _PRIORITY.index(x.kind)):
            if d.action not in seen:
                seen.append(d.action)
        return seen

    @property
    def needs_human(self) -> bool:
        """LLM 재시도로 못 고친다고 본 진단이 있나."""
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
