"""
GEN-03 Bazel 어댑터 - BUILD 파일 자가치유
=========================================

생성기가 **자기가 쓴 BUILD 파일**을 빌드 에러를 보고 고친다.

범위를 분명히 해 둔다 — 여기는 BUILD 룰 수준의 수리만 한다(deps 추가/정정).
하네스 소스(.cc) 자체의 수리는 기존 `selfheal.py` 루프가, 에러 분류기 본체는
D 파트의 `generate/build_errors.py` 가 맡는다.

분류기는 **주입**받는다. D 의 분류기가 나오면 생성자에 넘기면 되고, 없는 동안은
아래 내장 분류기가 쓰인다. 내장 분류기의 정규식은 추측이 아니라
`tests/fixtures/bazel_errors/` 에 수집된 실제 Bazel 출력에서 뽑았다.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional, Sequence

from .build_file import FuzzTargetSpec, parse_label

# no such target '//score/json:jsonn': target 'jsonn' not declared in
# package 'score/json' ... (did you mean json?)
_NO_SUCH_TARGET_RE = re.compile(
    r"no such target '(?P<label>[^']+)'.*?\(did you mean (?P<suggestion>[^?)]+)\?\)"
)
_NO_SUCH_TARGET_PLAIN_RE = re.compile(r"no such target '(?P<label>[^']+)'")

# harness/json_fuzzer.cc:7:10: fatal error: 'score/json/json.h' file not found
_MISSING_HEADER_RE = re.compile(
    r"fatal error: '(?P<header>[^']+)' file not found"
)

# Visibility error:
# target '//score/internal:helper' is not visible from
# target '//harness:json_fuzzer'
_NOT_VISIBLE_RE = re.compile(
    r"target '(?P<label>[^']+)' is not visible from", re.MULTILINE
)


@dataclass(frozen=True)
class BuildFix:
    """분류된 빌드 실패 1건과 그 처방."""

    kind: str                 # "add_dep" | "rename_dep" | "not_visible" | "unknown"
    detail: str               # 사람이 읽을 근거 한 줄
    add: tuple[str, ...] = ()      # deps 에 더할 라벨
    remove: tuple[str, ...] = ()   # deps 에서 뺄 라벨
    repairable: bool = True

    def __str__(self) -> str:
        return f"[{self.kind}] {self.detail}"


def _find_matching_dep(spec: FuzzTargetSpec, label: str) -> Optional[str]:
    """에러에 찍힌 라벨과 같은 대상을 가리키는 deps 항목을 찾는다.

    Bazel 은 에러 메시지에 repo 접두사를 떼고 찍는다(`//score/json:jsonn`).
    deps 에는 `@score_baselibs//score/json:jsonn` 로 들어 있으므로 문자열
    비교로는 안 맞는다. package:target 으로만 비교한다. 실측에서 걸린 건이다.
    """
    want = parse_label(label)
    for dep in spec.deps:
        got = parse_label(dep)
        if (got.package, got.target) == (want.package, want.target):
            return dep
    return None


def _dep_label_for_header(header: str, repo: str) -> Optional[str]:
    """include 경로에서 의존해야 할 Bazel 라벨을 유추한다.

    score/json/json.h  ->  @<repo>//score/json
    헤더가 놓인 디렉터리가 곧 패키지라는 관례에 기댄다. 관례가 안 맞으면
    유추가 빗나가고, 그건 다음 라운드에서 다시 잡힌다.
    """
    package = header.rsplit("/", 1)[0] if "/" in header else ""
    if not package:
        return None
    prefix = f"@{repo}" if repo else ""
    return f"{prefix}//{package}"


def classify(log: str, spec: FuzzTargetSpec) -> Optional[BuildFix]:
    """내장 분류기. D 의 build_errors.py 가 나오면 교체 대상이다."""
    log = log or ""

    m = _NO_SUCH_TARGET_RE.search(log)
    if m:
        reported = m.group("label")
        suggestion = m.group("suggestion").strip()
        # deps 에 실제로 들어 있는 표기를 찾아 repo 접두사를 보존한다.
        existing = _find_matching_dep(spec, reported) or reported
        lbl = parse_label(existing)
        prefix = f"@{lbl.repo}" if lbl.repo else ""
        fixed = f"{prefix}//{lbl.package}:{suggestion}"
        return BuildFix(
            kind="rename_dep",
            detail=f"{reported} 없음 -> {fixed} (Bazel 제안 채택)",
            add=(fixed,),
            remove=(existing,),
        )

    m = _NO_SUCH_TARGET_PLAIN_RE.search(log)
    if m:
        return BuildFix(
            kind="unknown",
            detail=f"{m.group('label')} 없음. 제안 없음 -> 사람 확인 필요",
            repairable=False,
        )

    m = _NOT_VISIBLE_RE.search(log)
    if m:
        # deps 를 더해서 풀리는 문제가 아니다. 패키지 위치(하위 패키지로 이동)나
        # 공개 별칭 사용이 필요하고, 둘 다 생성기 단독으로 결정할 일이 아니다.
        return BuildFix(
            kind="not_visible",
            detail=(
                f"{m.group('label')} 가 {spec.label} 에서 보이지 않는다. "
                "퍼징 패키지를 대상의 하위 패키지로 두거나 공개 별칭을 쓸 것"
            ),
            repairable=False,
        )

    m = _MISSING_HEADER_RE.search(log)
    if m:
        header = m.group("header")
        repo = parse_label(spec.deps[0]).repo if spec.deps else ""
        dep = _dep_label_for_header(header, repo)
        if dep and dep not in spec.deps:
            return BuildFix(
                kind="add_dep",
                detail=f"헤더 {header} 없음 -> {dep} 의존 추가",
                add=(dep,),
            )
        return BuildFix(
            kind="unknown",
            detail=f"헤더 {header} 없음. 라벨 유추 실패",
            repairable=False,
        )

    return None


def apply_fix(spec: FuzzTargetSpec, fix: BuildFix) -> FuzzTargetSpec:
    """처방을 반영한 새 spec 을 만든다(원본은 그대로 둔다)."""
    deps = [d for d in spec.deps if d not in fix.remove]
    for label in fix.add:
        if label not in deps:
            deps.append(label)
    return spec.with_deps(deps)


class BuildFileRepairer:
    """빌드 로그 -> 분류 -> 새 spec.

    classifier 를 주입하면 그걸 쓴다. D 파트의 분류기는 시그니처가
    `(log: str) -> BuildFix | None` 이거나 `(log, spec)` 둘 다 받을 수 있으므로
    호출부에서 얇게 감싸서 넘기면 된다.
    """

    def __init__(
        self,
        classifier: Optional[Callable[[str, FuzzTargetSpec], Optional[BuildFix]]] = None,
    ) -> None:
        self._classify = classifier or classify

    def repair(
        self, spec: FuzzTargetSpec, log: str
    ) -> tuple[Optional[FuzzTargetSpec], Optional[BuildFix]]:
        fix = self._classify(log, spec)
        if fix is None or not fix.repairable:
            return None, fix
        return apply_fix(spec, fix), fix
