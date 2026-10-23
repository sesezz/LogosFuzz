"""EXT-01-04: 통합 지식베이스를 B/D 파트 입력 형태로 변환하는 어댑터

B/D 파트 파일 수정 없이 각 파트의 기존 입력 형태에 맞춤

B (스케줄링, SCH-02-02/02-03)
    `sch_02_02_synergy_scheduler` 의 `ApiMetadata` / `Constraint` 생성

        apis, constraints = to_synergy_inputs(kb)
        results = compute_pairwise_synergy(apis, constraints)

B (하네스 생성, GEN-03-01)
    `harness_context(kb, "parse_header")` -> 시그니처 + 제약조건 + 필요한
    include + 컴파일 플래그를 담은 프롬프트 블록

D (컴파일 에러 자가치유, GEN-03-02)
    `suggest_fixes(kb, compiler_output)` -> gcc/clang 에러 메시지 파싱 후
    지식베이스 기반 수정 방법 반환

D (CVE 리포팅, ANA-05-02)
    `api_reference(kb, name)` -> 리포트 affected 필드용
    api_id/파일/시그니처 참조
"""
from __future__ import annotations

import re
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from pathlib import Path

from logosfuzz.knowledge.knowledge_base import HEADER_SUFFIXES, KnowledgeBase

# ---------------------------------------------------------------------------
# B (SCH-02-02 / SCH-02-03) 지원
# ---------------------------------------------------------------------------

# 제약조건 종류를 B의 source_type(규격/출처 동일성)으로 바꾸는 기본 규칙
# 규격서(UDS/CAN) 기반 제약 도입 시 규격명으로 교체 가능
_DOC_KINDS = {"doc"}


def _build_unit_ref(document: dict) -> str:
    """Return the scheduler boundary for an API.

    Bazel build target when available; source file fallback for older KBs.
    """
    return str(document.get("build_target") or document.get("file") or "unknown")


def default_source_type(constraint: dict, document: dict) -> str:
    """제약조건 출처 문자열

    B `constraint_overlap_score` 의 같은 상태 머신 판단 기준.
    소스코드 기반 제약은 정의 모듈(빌드 타깃/파일) 단위
    """
    import os

    module = document.get("build_target") or os.path.basename(document.get("file", ""))
    module = module or "unknown"
    origin = "DOC" if constraint.get("kind") in _DOC_KINDS else "CODE"
    return f"{origin}:{module}"


def to_synergy_inputs(
    kb: KnowledgeBase,
    source_type: Optional[Callable[[dict, dict], str]] = None,
    min_confidence: float = 0.0,
) -> Tuple[List, List]:
    """SCH-02-02 의 (ApiMetadata 목록, Constraint 목록) 생성

    `sch_02_02_synergy_scheduler` 임포트 불가 시 동일 필드의 대체 객체 사용
    """
    api_cls, constraint_cls = _synergy_classes()
    source_type = source_type or default_source_type

    apis = []
    constraints = []
    constraint_id = 1

    for document in sorted(kb.documents, key=lambda d: d["api_id"]):
        apis.append(
            api_cls(
                api_id=document["api_id"],
                func_signature=document["signature"],
                call_seq=[str(i) for i in document.get("call_seq_ids", [])],
                # `dep_graph_ref`: owning build unit (source path for legacy KBs)
                dep_graph_ref=_build_unit_ref(document),
            )
        )
        for constraint in document["constraints"]:
            if constraint.get("confidence", 0.0) < min_confidence:
                continue
            constraints.append(
                constraint_cls(
                    constraint_id=constraint_id,
                    api_id=document["api_id"],
                    rule_text=constraint["description"],
                    source_type=source_type(constraint, document),
                )
            )
            constraint_id += 1

    return apis, constraints


def _synergy_classes():
    try:  # 실제 B 모듈 우선 사용
        from logosfuzz.schedule.sch_02_02_synergy_scheduler import ApiMetadata, Constraint

        return ApiMetadata, Constraint
    except Exception:  # pragma: no cover - B 모듈이 없는 환경용 대체
        from dataclasses import dataclass, field

        @dataclass
        class ApiMetadata:  # type: ignore[no-redef]
            api_id: int
            func_signature: str
            call_seq: list
            dep_graph_ref: str = ""

        @dataclass
        class Constraint:  # type: ignore[no-redef]
            constraint_id: int
            api_id: int
            rule_text: str
            source_type: str

        return ApiMetadata, Constraint


def call_sequences_by_file(kb: KnowledgeBase) -> Dict[str, List[str]]:
    """파일별 관찰된 내부 API 호출 순서 (SCH-02-01 입력 후보)"""
    sequences: Dict[str, List[str]] = {}
    for document in sorted(kb.documents, key=lambda d: (d["file"], d["line"])):
        if document["calls_internal"]:
            sequences.setdefault(document["file"], []).extend(document["calls_internal"])
    return sequences


def build_unit_metadata(kb: KnowledgeBase) -> List[dict]:
    """Expose normalized build-unit records to scheduler/generator consumers.

    Joins ``kb.build_units`` with per-API ownership and adds owned API ids/names.
    """
    units: Dict[str, dict] = {}
    for raw in kb.build_units:
        target = str(raw.get("target") or raw.get("build_target") or "")
        if not target:
            continue
        units[target] = {
            "build_system": str(raw.get("build_system", "")),
            "build_target": target,
            "build_rule_kind": str(raw.get("rule_kind") or raw.get("build_rule_kind") or ""),
            "build_deps": list(raw.get("deps") or raw.get("build_deps") or []),
            "visibility": list(raw.get("visibility") or []),
            "sources": list(raw.get("sources") or []),
            "headers": list(raw.get("headers") or []),
            "include_dirs": list(raw.get("include_dirs") or []),
            "compile_flags": list(raw.get("compile_flags") or []),
            "build_file": str(raw.get("build_file", "")),
            "api_ids": [],
            "api_names": [],
        }

    for document in sorted(kb.documents, key=lambda d: d["api_id"]):
        target = str(document.get("build_target") or "")
        if not target:
            continue
        unit = units.setdefault(
            target,
            {
                "build_system": str(document.get("build_system", "")),
                "build_target": target,
                "build_rule_kind": str(document.get("build_rule_kind", "")),
                "build_deps": list(document.get("build_deps") or []),
                "visibility": [],
                "sources": [],
                "headers": [],
                "include_dirs": [],
                "compile_flags": list(document.get("compile_flags") or []),
                "build_file": "",
                "api_ids": [],
                "api_names": [],
            },
        )
        unit["api_ids"].append(document["api_id"])
        unit["api_names"].append(document["function"])

    return [units[target] for target in sorted(units)]


def build_unit_for_api(kb: KnowledgeBase, target) -> Optional[dict]:
    """Return the normalized build unit owning an API id/name."""
    document = kb.api(target)
    if document is None or not document.get("build_target"):
        return None
    wanted = document["build_target"]
    return next(
        (unit for unit in build_unit_metadata(kb) if unit["build_target"] == wanted),
        None,
    )


def call_sequences_by_build_unit(kb: KnowledgeBase) -> Dict[str, List[str]]:
    """Return observed internal call order grouped by build-unit boundary.

    Source-file fallback is deliberate for KB v1/legacy inputs that have no
    Bazel ownership attached.
    """
    sequences: Dict[str, List[str]] = {}
    for document in sorted(
        kb.documents,
        key=lambda d: (_build_unit_ref(d), d["file"], d["line"]),
    ):
        if document["calls_internal"]:
            sequences.setdefault(_build_unit_ref(document), []).extend(
                document["calls_internal"]
            )
    return sequences


# ---------------------------------------------------------------------------
# B (GEN-03-01 하네스 초안 생성) 지원
# ---------------------------------------------------------------------------


def harness_context(kb: KnowledgeBase, target: int | str, max_constraints: int = 12) -> str:
    """하네스 생성 프롬프트용 컨텍스트 블록

    EXT-01-02 제약조건 블록 + 컴파일 정보(include, 플래그)
    """
    document = kb.api(target)
    if document is None:
        hits = kb.search(target, top_k=1) if isinstance(target, str) else []
        if not hits:
            return f"# no knowledge-base entry matched '{target}'"
        document = hits[0]["document"]

    lines = [
        f"## {document['function']}  (api_id={document['api_id']})",
        f"defined in: {document['file']}:{document['line']}",
        f"signature: {document['signature']}",
    ]
    if document.get("build_target"):
        lines.append(f"build unit: {document['build_target']}")
        if document.get("build_system") or document.get("build_rule_kind"):
            details = "/".join(
                value for value in (
                    document.get("build_system", ""),
                    document.get("build_rule_kind", ""),
                ) if value
            )
            lines.append(f"build rule: {details}")
        if document.get("build_deps"):
            lines.append("build deps: " + " ".join(document["build_deps"]))
    if document.get("header"):
        # 헤더 이름만 include, 디렉터리는 -I 전달 (하네스 위치 무관, suggest_fixes 와 동일 규칙)
        include_name, include_dir = _include_parts(document["header"])
        lines.append(f'include: #include "{include_name}"')
        flags = list(document.get("compile_flags") or [])
        if include_dir and f"-I{include_dir}" not in flags:
            flags.insert(0, f"-I{include_dir}")
        if flags:
            lines.append(f"compile flags: {' '.join(flags)}")
    elif document.get("compile_flags"):
        lines.append(f"compile flags: {' '.join(document['compile_flags'])}")
    if document.get("doc"):
        lines.append(f"doc: {document['doc']}")

    constraints = document["constraints"][:max_constraints]
    if constraints:
        lines.append("constraints:")
        for constraint in constraints:
            target_note = f" [{constraint['target']}]" if constraint["target"] else ""
            repeats = constraint.get("occurrences", 1)
            repeat_note = f" (x{repeats})" if repeats > 1 else ""
            lines.append(
                f"  - ({constraint['kind']}, conf={constraint['confidence']})"
                f"{target_note} {constraint['description']}{repeat_note}"
            )
            if constraint["expression"]:
                lines.append(f"      evidence: {constraint['expression']}")
    else:
        lines.append("constraints: none extracted")

    if document.get("calls_internal"):
        lines.append("calls (internal): " + ", ".join(document["calls_internal"]))
    if document.get("called_by"):
        lines.append("called by: " + ", ".join(document["called_by"]))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# D (GEN-03-02 컴파일 에러 자가치유) 지원
# ---------------------------------------------------------------------------

_IMPLICIT_DECL_RE = re.compile(
    r"implicit declaration of function ['‘\"]([A-Za-z_]\w*)"
)
_UNDECLARED_RE = re.compile(
    r"['‘\"]([A-Za-z_]\w*)['’\"]?\s+undeclared"
)
_UNKNOWN_TYPE_RE = re.compile(
    r"unknown type name ['‘\"]([A-Za-z_]\w*)"
)
_INCOMPLETE_TYPE_RE = re.compile(
    r"(?:incomplete type|has incomplete type)[^'‘\"]*['‘\"](?:struct\s+)?([A-Za-z_]\w*)"
)
_MISSING_HEADER_RE = re.compile(
    r"['‘\"]([\w./+-]+\.h)['’\"]?\s+file not found|"
    r"([\w./+-]+\.h):\s*No such file or directory"
)
_ARG_COUNT_RE = re.compile(
    r"(too few|too many) arguments (?:to|in) (?:function )?(?:call )?"
    r"(?:['‘\"]([A-Za-z_]\w*))?"
)
_UNDEFINED_REF_RE = re.compile(
    r"undefined reference to ['‘\"`]?([A-Za-z_]\w*)"
)


def suggest_fixes(kb: KnowledgeBase, compiler_output: str) -> List[dict]:
    """gcc/clang 출력에서 수정 가능한 항목의 수정안 생성

    각 항목: {"error", "symbol", "action", "detail", "confidence"}
    `action` 은 D 자동 적용 판단용 고정 값
    """
    suggestions: List[dict] = []
    seen: set = set()

    def add(error: str, symbol: str, action: str, detail: str, confidence: float,
            include_dir: Optional[str] = None) -> None:
        key = (error, symbol, action, detail)
        if key in seen:
            return
        seen.add(key)
        suggestion = {
            "error": error,
            "symbol": symbol,
            "action": action,
            "detail": detail,
            "confidence": confidence,
        }
        if include_dir is not None:
            # 헤더 이름만 include, 디렉터리는 -I 전달 (하네스 위치 무관)
            suggestion["include_dir"] = include_dir
            suggestion["compile_flag"] = f"-I{include_dir}"
        suggestions.append(suggestion)

    for name in _IMPLICIT_DECL_RE.findall(compiler_output):
        _suggest_for_symbol(kb, name, add, "implicit_declaration")

    for name in _UNDECLARED_RE.findall(compiler_output):
        if kb.api(name) or kb.declaring_files(name):
            _suggest_for_symbol(kb, name, add, "undeclared_identifier")

    for name in _UNKNOWN_TYPE_RE.findall(compiler_output):
        _suggest_for_type(kb, name, add, "unknown_type")

    for name in _INCOMPLETE_TYPE_RE.findall(compiler_output):
        _suggest_for_type(kb, name, add, "incomplete_type")

    for match in _MISSING_HEADER_RE.finditer(compiler_output):
        header = match.group(1) or match.group(2)
        if not header:
            continue
        include_dirs = sorted({
            flag for info in kb.files.values() for flag in info.get("flags", [])
            if flag.startswith("-I")
        })
        owners = [p for p in kb.files if p.replace("\\", "/").endswith(header)]
        if owners:
            add("missing_header", header, "add_include_path",
                f"'{header}' is at {owners[0]}; add its directory with -I",
                0.8)
        elif include_dirs:
            add("missing_header", header, "add_include_path",
                f"try the include paths recorded in the knowledge base: "
                f"{' '.join(include_dirs)}",
                0.5)

    for _, name in _ARG_COUNT_RE.findall(compiler_output):
        if not name:
            continue
        document = kb.api(name)
        if document:
            params = ", ".join(
                f"{p['type']} {p['name']}".strip() for p in document["params"]
            ) or "void"
            add("argument_count", name, "fix_call_signature",
                f"{document['signature']}  (params: {params})", 0.9)

    for name in _UNDEFINED_REF_RE.findall(compiler_output):
        document = kb.api(name)
        if document:
            add("undefined_reference", name, "link_source",
                f"'{name}' is defined in {document['file']}; compile/link that "
                f"translation unit", 0.85)
            continue
        # 선언만 있고 정의 미색인(예: 헤더만 색인한 라이브러리) 시 선언 위치 안내
        declared_in = kb.declaring_files(name)
        if declared_in:
            add("undefined_reference", name, "link_library",
                f"'{name}' is declared in {as_include_path(declared_in[0])} but no "
                f"definition is indexed; link the library that provides it", 0.6)

    return suggestions


def as_include_path(path: str) -> str:
    """C 소스용 include 경로 정규화 (Windows 역슬래시를 슬래시로 통일)"""
    return path.replace("\\", "/")


def _include_parts(path: str) -> Tuple[str, str]:
    """헤더 경로를 (#include 용 이름, -I 용 디렉터리) 로 분리"""
    import os

    normalized = as_include_path(path)
    return os.path.basename(normalized), as_include_path(os.path.dirname(normalized))


def _suggest_for_symbol(kb: KnowledgeBase, name: str, add, error: str) -> None:
    header = kb.header_for(name)
    if header:
        include_name, directory = _include_parts(header)
        add(error, name, "add_include", f'#include "{include_name}"', 0.9, directory)
        return
    declared_in = kb.declaring_files(name)
    if declared_in:
        include_name, directory = _include_parts(declared_in[0])
        add(error, name, "add_include", f'#include "{include_name}"', 0.7, directory)
        return
    document = kb.api(name)
    if document:
        add(error, name, "declare_prototype", f"{document['signature']};", 0.6)


def _suggest_for_type(kb: KnowledgeBase, name: str, add, error: str) -> None:
    defining = kb.defines_type(name)
    if defining:
        include_name, directory = _include_parts(defining[0])
        add(error, name, "add_include", f'#include "{include_name}"', 0.85, directory)


# ---------------------------------------------------------------------------
# D (ANA-05-02 CVE 리포팅) 지원
# ---------------------------------------------------------------------------


def api_reference(kb: KnowledgeBase, name: str) -> Optional[dict]:
    """CVE 리포트 affected/참조 필드용 최소 정보"""
    document = kb.api(name)
    if document is None:
        return None
    return {
        "api_id": document["api_id"],
        "function": document["function"],
        "signature": document["signature"],
        "file": document["file"],
        "line": document["line"],
        "header": document.get("header"),
        "build_system": document.get("build_system", ""),
        "build_target": document.get("build_target", ""),
        "build_rule_kind": document.get("build_rule_kind", ""),
        "build_deps": list(document.get("build_deps") or []),
        "constraint_count": len(document["constraints"]),
    }


def constraints_for_triage(kb: KnowledgeBase, name: str,
                           min_confidence: float = 0.7) -> List[dict]:
    """ANA-05-01(정탐/오탐 판별) 근거용 고신뢰 제약조건 목록"""
    document = kb.api(name)
    if document is None:
        return []
    return [
        c for c in document["constraints"]
        if c.get("confidence", 0.0) >= min_confidence
    ]


# ---------------------------------------------------------------------------
# 코드 경로를 여는 설정 API (GEN-03-01 하네스 프롬프트용)
# ---------------------------------------------------------------------------
#
# `png_set_expand` 등 변환 설정 API 활성화로 디코딩 코드 경로 확장
# (Magma libpng 커버리지: 자동 하네스 823 vs OSS-Fuzz 드라이버 1454)
#
# 후보 선정 기준 (이름 패턴 + KB 기존 정보)
#   1. 대상과 같은 상태 핸들을 첫 인자로 받는 함수
#   2. 헤더에 선언된 공개 API (내부 헬퍼 png_colorspace_set_* 제외)
#
# libpng 실측: OSS-Fuzz 활성화 API 7개 전부 회수

_CONFIG_NAME_RE = re.compile(r"_(set|option|enable|disable|add|with)(_|$)")

# 비공개 헤더 표지 (`pngpriv.h` 등 내부용 헤더 선언은 공개 API 에서 제외)
_PRIVATE_HEADER_RE = re.compile(r"(priv|private|internal|impl|detail)", re.I)


def _has_public_header(kb: KnowledgeBase, name: str) -> bool:
    for path in kb.declaring_files(name):
        stem = Path(str(path).replace("\\", "/")).name
        if stem.endswith(HEADER_SUFFIXES) and not _PRIVATE_HEADER_RE.search(stem):
            return True
    return False


def _first_param_type(document: dict) -> str:
    params = document.get("params") or []
    return str(params[0].get("type", "")) if params else ""


def configuration_apis(kb: KnowledgeBase, handle_type: str,
                       public_only: bool = True,
                       limit: int = 60) -> List[dict]:
    """``handle_type`` 의 동작을 바꾸는 공개 설정 API 목록

    Args:
        kb: 통합 지식베이스
        handle_type: 상태 핸들 타입 이름의 일부(예: ``"png_struct"``).
            ``png_structp``/``png_const_structrp`` 등 별칭 포괄용 부분 일치
        public_only: 헤더에 선언된 API 만 유지
        limit: 최대 개수

    Returns:
        ``{"function", "signature", "doc"}`` dict 목록 (이름 순 정렬)
    """
    if not handle_type:
        return []

    picked: Dict[str, dict] = {}
    for document in kb.documents:
        name = document["function"]
        if name in picked:
            continue
        if document.get("is_static") or document.get("is_test"):
            continue
        if not _CONFIG_NAME_RE.search(name):
            continue
        if handle_type not in _first_param_type(document):
            continue
        if public_only and not _has_public_header(kb, name):
            continue
        picked[name] = {
            "function": name,
            "signature": document.get("signature", ""),
            "doc": " ".join((document.get("doc") or "").split())[:160],
        }

    return sorted(picked.values(), key=lambda d: d["function"])[:limit]


def render_configuration_apis(entries: Sequence[dict]) -> str:
    """설정 API 목록의 하네스 프롬프트 조각 직렬화"""
    if not entries:
        return ""
    lines = [
        "[동작을 바꾸는 설정 API — 켜면 새 코드 경로가 열린다]",
        "  기본 경로만 태우면 라이브러리의 일부만 검사하게 된다. 아래에서 서로",
        "  충돌하지 않는 것들을 골라 켜고, 어떤 조합을 쓸지는 퍼징 입력으로 정하라.",
    ]
    for entry in entries:
        lines.append(f"  {entry['signature'] or entry['function']}")
        if entry["doc"]:
            lines.append(f"      {entry['doc']}")
    return "\n".join(lines)
