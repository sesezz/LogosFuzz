"""EXT-01-04: 통합 지식베이스를 B/D 파트가 쓰는 형태로 바꾸는 어댑터.

B/D 파트의 파일은 건드리지 않는다. 각 파트가 이미 정해 둔 입력 형태에
지식베이스를 맞춰 주는 것이 이 모듈의 역할이다.

B (스케줄링, SCH-02-02/02-03)
    `sch_02_02_synergy_scheduler` 의 `ApiMetadata` / `Constraint` 를 그대로
    만들어 준다. 지금 목업으로 하드코딩된 API 목록을 아래 한 줄로 바꿀 수 있다.

        apis, constraints = to_synergy_inputs(kb)
        results = compute_pairwise_synergy(apis, constraints)

B (하네스 생성, GEN-03-01)
    `harness_context(kb, "parse_header")` -> 시그니처 + 제약조건 + 필요한
    include + 컴파일 플래그까지 담은 프롬프트 블록.

D (컴파일 에러 자가치유, GEN-03-02)
    `suggest_fixes(kb, compiler_output)` -> gcc/clang 에러 메시지를 파싱해
    지식베이스에서 찾은 수정 방법을 돌려준다.

D (CVE 리포팅, ANA-05-02)
    `api_reference(kb, name)` -> 리포트의 affected 필드에 넣을 수 있는
    api_id/파일/시그니처 참조.
"""
from __future__ import annotations

import re
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from logosfuzz.knowledge.knowledge_base import KnowledgeBase

# ---------------------------------------------------------------------------
# B (SCH-02-02 / SCH-02-03) 지원
# ---------------------------------------------------------------------------

# 제약조건 종류를 B의 source_type(같은 규격/출처인지) 으로 바꾸는 기본 규칙.
# 규격서(UDS/CAN) 기반 제약이 들어오면 그 규격명을 쓰도록 바꾸면 된다.
_DOC_KINDS = {"doc"}


def default_source_type(constraint: dict, document: dict) -> str:
    """제약조건의 출처를 나타내는 문자열.

    B의 `constraint_overlap_score` 는 두 API가 같은 source_type 을 공유하는지로
    "같은 상태 머신에 속하는가"를 판단한다. 소스코드 기반 제약에서는 같은
    모듈(정의 파일)에서 나온 제약이 그 역할에 가장 가깝다.
    """
    import os

    module = os.path.basename(document.get("file", "")) or "unknown"
    origin = "DOC" if constraint.get("kind") in _DOC_KINDS else "CODE"
    return f"{origin}:{module}"


def to_synergy_inputs(
    kb: KnowledgeBase,
    source_type: Optional[Callable[[dict, dict], str]] = None,
    min_confidence: float = 0.0,
) -> Tuple[List, List]:
    """SCH-02-02 의 (ApiMetadata 목록, Constraint 목록) 을 만든다.

    `sch_02_02_synergy_scheduler` 를 임포트할 수 있으면 그 데이터클래스를 쓰고,
    없으면 같은 필드를 가진 가벼운 대체 객체를 쓴다(테스트/독립 실행용).
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
                dep_graph_ref=document["file"],
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
    try:  # 실제 B 모듈이 있으면 그대로 쓴다
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
    """파일별로 관찰된 내부 API 호출 순서.

    SCH-02-01(Logic Group 추출, 5주차)의 입력 후보로 쓸 수 있다.
    """
    sequences: Dict[str, List[str]] = {}
    for document in sorted(kb.documents, key=lambda d: (d["file"], d["line"])):
        if document["calls_internal"]:
            sequences.setdefault(document["file"], []).extend(document["calls_internal"])
    return sequences


# ---------------------------------------------------------------------------
# B (GEN-03-01 하네스 초안 생성) 지원
# ---------------------------------------------------------------------------


def harness_context(kb: KnowledgeBase, target: str, max_constraints: int = 12) -> str:
    """하네스 생성 프롬프트에 그대로 넣을 수 있는 컨텍스트 블록.

    EXT-01-02 의 제약조건 블록에 "컴파일에 필요한 정보"를 더한 것이다.
    하네스는 결국 컴파일되어야 하므로 include 와 플래그가 함께 있어야 한다.
    """
    document = kb.api(target)
    if document is None:
        hits = kb.search(target, top_k=1)
        if not hits:
            return f"# no knowledge-base entry matched '{target}'"
        document = hits[0]["document"]

    lines = [
        f"## {document['function']}  (api_id={document['api_id']})",
        f"defined in: {document['file']}:{document['line']}",
        f"signature: {document['signature']}",
    ]
    if document.get("header"):
        # 헤더 이름만 쓰고 디렉터리는 -I 로 넘긴다. `#include "..."` 는 그 문을
        # 포함한 파일 기준으로 해석되므로, 저장소 기준 전체 경로를 넣으면
        # 하네스가 다른 폴더에 있을 때 컴파일이 깨진다(suggest_fixes 와 같은 규칙).
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
    """gcc/clang 출력에서 고칠 수 있는 항목을 찾아 수정안을 만든다.

    각 항목: {"error", "symbol", "action", "detail", "confidence"}
    `action` 은 D가 자동 적용을 판단하기 쉽도록 정해진 값만 쓴다.
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
            # `#include "..."` 는 포함하는 파일 기준으로 해석되므로, 헤더 이름만
            # 쓰고 디렉터리는 -I 로 넘겨야 하네스 위치와 무관하게 컴파일된다.
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
                f"try the include paths recorded in compile_commands.json: "
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
        # 선언만 있고 정의가 지식베이스에 없는 경우(예: 헤더만 색인한 라이브러리).
        # 침묵하는 것보다 "어디에 선언되어 있고 왜 못 찾는지"를 알려주는 편이 낫다.
        declared_in = kb.declaring_files(name)
        if declared_in:
            add("undefined_reference", name, "link_library",
                f"'{name}' is declared in {as_include_path(declared_in[0])} but no "
                f"definition is indexed; link the library that provides it", 0.6)

    return suggestions


def as_include_path(path: str) -> str:
    """C 소스에 넣을 수 있는 include 경로로 정규화한다.

    Windows 에서 수집한 경로에는 역슬래시가 섞이는데, `#include "a\\b.h"` 는
    C 에서 이스케이프로 해석되므로 슬래시로 통일해야 한다.
    """
    return path.replace("\\", "/")


def _include_parts(path: str) -> Tuple[str, str]:
    """헤더 경로를 (#include 에 쓸 이름, -I 로 넘길 디렉터리) 로 나눈다."""
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
    """CVE 리포트의 affected/참조 필드에 넣을 최소 정보."""
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
        "constraint_count": len(document["constraints"]),
    }


def constraints_for_triage(kb: KnowledgeBase, name: str,
                           min_confidence: float = 0.7) -> List[dict]:
    """ANA-05-01(정탐/오탐 판별)에 근거로 넣을 신뢰도 높은 제약조건만."""
    document = kb.api(name)
    if document is None:
        return []
    return [
        c for c in document["constraints"]
        if c.get("confidence", 0.0) >= min_confidence
    ]
