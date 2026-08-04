"""SCH-02-01: 상태 기반 Logic Group 추출 + 패키징.

통합 지식베이스(EXT-01-04)에서 "같은 상태를 공유하는 API 묶음"을 뽑아
`logosfuzz.common.models.LogicGroup` 으로 패키징한다. 이 그룹이 SCH-02-02
(시너지 우선순위) / SCH-02-03 (자원 할당) / GEN (하네스 생성) /
EXE-04-03 (타임아웃 산정) 의 공통 작업 단위가 된다.

무엇을 "같은 상태"로 보는가
---------------------------
1순위는 **핸들 타입 공유**다. `uds_open(uds_ctx_t *ctx, ...)` 와
`uds_read_did(uds_ctx_t *ctx, ...)` 처럼 같은 컨텍스트 구조체를 포인터로
주고받는 API 들은 같은 상태 머신에 속한다고 본다.

여기서 중요한 건 **프로젝트가 정의한 타입만 센다**는 점이다. `size_t` 나
`uint8_t` 같은 표준 스칼라 타입으로 묶으면 거의 모든 API 가 한 덩어리가 되어
그룹이 의미를 잃는다. 지식베이스가 타입 정의 위치를 알고 있으므로
(`kb.defines_type`) 프로젝트 내부에서 정의된 타입인지 확인할 수 있다.

핸들 타입이 없는 API 는 호출 관계로 잇고, 그것도 없으면 같은 파일끼리 묶는다.

실시간 신호 결합
----------------
`RealtimeSignal` 문서에 적힌 대로, 규격서/주석에서 추출한 타이밍 제약을
그룹에 붙여 준다. EXE-04-03 은 그룹의 신호 중 가장 빡빡한 주기를 골라
입력별 타임아웃을 정하고, 신호가 없으면 기본값으로 폴백한다.

사용법
------
  python -m src.logic_groups build --paths examples/uds --output build/groups.json
  python -m src.logic_groups show --groups build/groups.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from logosfuzz.common.models import (
    SIGNAL_CAN_CYCLE,
    SIGNAL_CONTROL_LOOP,
    SIGNAL_UDS_P2,
    SIGNAL_WATCHDOG,
    LogicGroup,
    RealtimeSignal,
)
from src.knowledge_base import KnowledgeBase

GROUPS_VERSION = 1

# 타입 문자열에서 식별자를 전부 꺼낸 뒤, 실제 구조체인지는 지식베이스에 묻는다.
# `*_t` 같은 이름 규칙에 기대면 `PyObject` 처럼 접미사 없는 typedef 를 놓친다.
IDENTIFIER_RE = re.compile(r"\b[A-Za-z_]\w*\b")

_C_KEYWORDS = {
    "const", "volatile", "restrict", "struct", "union", "enum", "unsigned",
    "signed", "void", "char", "short", "int", "long", "float", "double",
    "static", "extern", "register", "inline", "_Atomic", "class",
}

# 프로젝트가 정의했더라도 상태 핸들로 보기 어려운 이름들
_SCALAR_TYPE_RE = re.compile(
    r"^(?:u?int\d*_t|u?intptr_t|u?intmax_t|size_t|ssize_t|ptrdiff_t|off_t|"
    r"time_t|clock_t|wchar_t|char\d*_t|bool_t|byte_t)$"
)


# ---------------------------------------------------------------------------
# 실시간 신호 추출
# ---------------------------------------------------------------------------

# 숫자 + 단위 -> 밀리초
_DURATION_RE = re.compile(
    r"(\d+(?:\.\d+)?)\s*(ms|msec|밀리초|us|usec|마이크로초|s\b|sec|seconds?|초)",
    re.I,
)

_SIGNAL_KEYWORDS: Sequence[Tuple[str, re.Pattern]] = (
    (SIGNAL_UDS_P2, re.compile(r"\bP2\*?\b|uds[_ ]?p2", re.I)),
    (SIGNAL_WATCHDOG, re.compile(r"watchdog|워치독|wdt\b", re.I)),
    (SIGNAL_CAN_CYCLE, re.compile(r"\bcan\b[^.]{0,40}(cycle|period|주기)|"
                                  r"(cycle|period|주기)[^.]{0,40}\bcan\b", re.I)),
    (SIGNAL_CONTROL_LOOP, re.compile(r"control[_ ]?loop|제어\s*루프|주기적\s*제어", re.I)),
)

_UNIT_TO_MS = {
    "ms": 1.0, "msec": 1.0, "밀리초": 1.0,
    "us": 0.001, "usec": 0.001, "마이크로초": 0.001,
    "s": 1000.0, "sec": 1000.0, "second": 1000.0, "seconds": 1000.0, "초": 1000.0,
}


def _duration_to_ms(value: str, unit: str) -> Optional[float]:
    factor = _UNIT_TO_MS.get(unit.lower().rstrip("."))
    if factor is None:
        return None
    try:
        millis = float(value) * factor
    except ValueError:
        return None
    return millis if millis > 0 else None


def extract_realtime_signals(texts: Iterable[str], source: str = "") -> List[RealtimeSignal]:
    """문서/제약조건 텍스트에서 타이밍 신호를 뽑는다.

    한 문장 안에 신호 종류 키워드와 시간 값이 함께 있어야 인정한다. 문서 전체를
    한 덩어리로 보면 무관한 숫자가 엮이기 때문이다.
    """
    found: Dict[Tuple[str, float], RealtimeSignal] = {}

    for text in texts:
        if not text:
            continue
        for sentence in re.split(r"[.\n;]|다\.", text):
            duration = _DURATION_RE.search(sentence)
            if not duration:
                continue
            millis = _duration_to_ms(duration.group(1), duration.group(2))
            if millis is None:
                continue
            for kind, pattern in _SIGNAL_KEYWORDS:
                if not pattern.search(sentence):
                    continue
                key = (kind, millis)
                if key not in found:
                    found[key] = RealtimeSignal(
                        kind=kind, period_ms=millis, source=source or "source comment"
                    )
                break

    return sorted(found.values(), key=lambda s: (s.period_ms, s.kind))


# ---------------------------------------------------------------------------
# 상태 타입 판정
# ---------------------------------------------------------------------------


def _candidate_types(text: str) -> List[str]:
    """타입 문자열에서 타입 이름 후보(식별자)를 뽑는다."""
    names: List[str] = []
    for name in IDENTIFIER_RE.findall(text or ""):
        if name in _C_KEYWORDS or name in names:
            continue
        names.append(name)
    return names


def state_types_of(document: dict, kb: KnowledgeBase) -> List[str]:
    """이 API 가 다루는 '상태 핸들' 타입 목록.

    포인터로 주고받는, 프로젝트가 정의한 비스칼라 타입만 인정한다.
    """
    found: List[str] = []
    for param in document.get("params", []):
        if not param.get("is_pointer"):
            continue
        for name in _candidate_types(param.get("type", "")):
            if _SCALAR_TYPE_RE.match(name):
                continue
            # 구조체를 감싼 타입만 상태 핸들로 본다. `Py_ssize_t *out` 처럼
            # 스칼라 별칭에 대한 포인터는 결과를 받는 out-param 이지 상태가 아니다.
            if not kb.defines_struct_type(name):
                continue
            if name not in found:
                found.append(name)
    return found


# ---------------------------------------------------------------------------
# 그룹 추출
# ---------------------------------------------------------------------------


class _UnionFind:
    def __init__(self, items: Iterable) -> None:
        self._parent = {item: item for item in items}

    def find(self, item):
        root = item
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[item] != root:
            self._parent[item], item = root, self._parent[item]
        return root

    def union(self, a, b) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self._parent[rb] = ra

    def groups(self) -> Dict[object, List]:
        clusters: Dict[object, List] = {}
        for item in self._parent:
            clusters.setdefault(self.find(item), []).append(item)
        return clusters


@dataclass
class GroupInfo:
    """패키징 전의 그룹 원본 정보."""

    group_id: str
    name: str
    api_ids: List[int] = field(default_factory=list)
    api_names: List[str] = field(default_factory=list)
    state_types: List[str] = field(default_factory=list)
    files: List[str] = field(default_factory=list)
    basis: str = "file"
    priority: float = 0.0
    realtime_signals: List[RealtimeSignal] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "group_id": self.group_id,
            "name": self.name,
            "api_ids": self.api_ids,
            "api_names": self.api_names,
            "state_types": self.state_types,
            "files": self.files,
            "basis": self.basis,
            "priority": self.priority,
            "realtime_signals": [
                {"kind": s.kind, "period_ms": s.period_ms, "source": s.source}
                for s in self.realtime_signals
            ],
        }


GENERIC_TYPE_RATIO = 0.3
MIN_APIS_FOR_RATIO = 20


def generic_types(owners_by_type: Dict[str, List[int]], total_apis: int,
                  ratio: float = GENERIC_TYPE_RATIO) -> List[str]:
    """너무 흔해서 그룹을 구분하지 못하는 타입을 고른다.

    `PyObject` 처럼 거의 모든 API 가 받는 타입으로 묶으면 그룹 하나에 API 가
    전부 들어가 퍼징 단위로 쓸 수 없다. 검색에서 불용어를 빼는 것과 같은 이유다.
    API 수가 적을 때는 비율이 요동치므로 적용하지 않는다.
    """
    if total_apis < MIN_APIS_FOR_RATIO:
        return []
    return sorted(
        name for name, owners in owners_by_type.items()
        if len(owners) / total_apis > ratio
    )


def extract_groups(kb: KnowledgeBase, link_calls: bool = True,
                   ratio: float = GENERIC_TYPE_RATIO) -> List[GroupInfo]:
    """지식베이스에서 상태 기반 로직 그룹을 추출한다."""
    documents = sorted(kb.documents, key=lambda d: d["api_id"])
    if not documents:
        return []

    by_id = {d["api_id"]: d for d in documents}
    name_to_id = {d["function"]: d["api_id"] for d in documents}
    union = _UnionFind(by_id)

    # 1) 핸들 타입 공유
    types_by_api: Dict[int, List[str]] = {}
    owners_by_type: Dict[str, List[int]] = {}
    for document in documents:
        types = state_types_of(document, kb)
        types_by_api[document["api_id"]] = types
        for type_name in types:
            owners_by_type.setdefault(type_name, []).append(document["api_id"])

    too_generic = set(generic_types(owners_by_type, len(documents), ratio))
    if too_generic:
        for api_id, types in types_by_api.items():
            types_by_api[api_id] = [t for t in types if t not in too_generic]
        owners_by_type = {
            name: owners for name, owners in owners_by_type.items()
            if name not in too_generic
        }

    for owners in owners_by_type.values():
        first = owners[0]
        for other in owners[1:]:
            union.union(first, other)

    # 2) 호출 관계 (핸들 타입이 없는 API 를 흡수)
    if link_calls:
        for document in documents:
            for callee in document.get("calls_internal", []):
                callee_id = name_to_id.get(callee)
                if callee_id is not None:
                    union.union(document["api_id"], callee_id)

    # 3) 남은 단독 API 는 같은 파일끼리
    clusters = union.groups()
    singleton_by_file: Dict[str, int] = {}
    for root, members in list(clusters.items()):
        if len(members) > 1:
            continue
        only = members[0]
        file_path = by_id[only]["file"]
        anchor = singleton_by_file.setdefault(file_path, only)
        if anchor != only:
            union.union(anchor, only)

    groups: List[GroupInfo] = []
    for members in union.groups().values():
        member_ids = sorted(members)
        docs = [by_id[i] for i in member_ids]

        type_counts: Dict[str, int] = {}
        for api_id in member_ids:
            for type_name in types_by_api[api_id]:
                type_counts[type_name] = type_counts.get(type_name, 0) + 1
        state_types = sorted(type_counts, key=lambda t: (-type_counts[t], t))

        files = sorted({d["file"] for d in docs})
        if state_types:
            label, basis = state_types[0], "state_type"
        elif len(files) == 1:
            label, basis = Path(files[0]).stem, "file"
        else:
            label, basis = docs[0]["function"], "call_graph"

        groups.append(
            GroupInfo(
                group_id=f"lg_{label}",
                name=label,
                api_ids=member_ids,
                api_names=[d["function"] for d in docs],
                state_types=state_types,
                files=files,
                basis=basis,
            )
        )

    # group_id 충돌 방지 (같은 라벨이 여러 번 나올 수 있다)
    seen: Dict[str, int] = {}
    for group in groups:
        count = seen.get(group.group_id, 0) + 1
        seen[group.group_id] = count
        if count > 1:
            group.group_id = f"{group.group_id}_{count}"

    groups.sort(key=lambda g: (-len(g.api_ids), g.group_id))
    return groups


# ---------------------------------------------------------------------------
# 패키징
# ---------------------------------------------------------------------------


def attach_realtime_signals(groups: Sequence[GroupInfo], kb: KnowledgeBase) -> None:
    """그룹에 속한 API 의 문서/제약조건에서 타이밍 신호를 뽑아 붙인다.

    출처는 API 단위로 기록한다(`uds.c:uds_read_did`). 그룹의 첫 파일로 뭉뚱그리면
    EXE-04-03 이 타임아웃 근거를 로그에 남길 때 엉뚱한 파일을 가리키게 된다.
    """
    by_id = {d["api_id"]: d for d in kb.documents}
    for group in groups:
        collected: Dict[Tuple[str, float], RealtimeSignal] = {}
        for api_id in group.api_ids:
            document = by_id.get(api_id)
            if not document:
                continue
            texts: List[str] = []
            if document.get("doc"):
                texts.append(document["doc"])
            texts.extend(
                c["description"] for c in document.get("constraints", [])
                if c.get("kind") == "doc"
            )
            if not texts:
                continue
            origin = f"{os.path.basename(document['file'])}:{document['function']}"
            for signal in extract_realtime_signals(texts, source=origin):
                collected.setdefault((signal.kind, signal.period_ms), signal)
        group.realtime_signals = sorted(
            collected.values(), key=lambda s: (s.period_ms, s.kind)
        )


def attach_priorities(groups: Sequence[GroupInfo], kb: KnowledgeBase) -> bool:
    """SCH-02-02 시너지 점수를 그룹 우선순위로 붙인다.

    SCH 모듈을 임포트할 수 없으면 우선순위 0.0 으로 두고 False 를 반환한다.
    """
    try:
        from sch_02_02_synergy_scheduler import (
            compute_pairwise_synergy,
            rank_logic_groups,
        )

        from src.kb_adapters import to_synergy_inputs
    except Exception:
        return False

    apis, constraints = to_synergy_inputs(kb)
    results = compute_pairwise_synergy(apis, constraints)
    ranking = dict(rank_logic_groups({g.group_id: g.api_ids for g in groups}, results))
    for group in groups:
        group.priority = float(ranking.get(group.group_id, 0.0))
    return True


def build_groups(kb: KnowledgeBase, link_calls: bool = True,
                 with_priority: bool = True) -> List[GroupInfo]:
    """추출 + 실시간 신호 결합 + 우선순위까지 한 번에."""
    groups = extract_groups(kb, link_calls=link_calls)
    attach_realtime_signals(groups, kb)
    if with_priority:
        attach_priorities(groups, kb)
        groups.sort(key=lambda g: (-g.priority, g.group_id))
    return groups


def to_logic_groups(groups: Sequence[GroupInfo]) -> List[LogicGroup]:
    """EXE/GEN 이 소비하는 `logosfuzz.common.models.LogicGroup` 으로 변환."""
    return [
        LogicGroup(
            group_id=g.group_id,
            name=g.name,
            api_set=list(g.api_names),
            priority=g.priority,
            realtime_signals=list(g.realtime_signals),
        )
        for g in groups
    ]


def to_group_map(groups: Sequence[GroupInfo]) -> Dict[str, List[int]]:
    """SCH-02-02 `rank_logic_groups` 가 받는 {group_id: [api_id]} 형태."""
    return {g.group_id: list(g.api_ids) for g in groups}


def save_groups(groups: Sequence[GroupInfo], path: str) -> str:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {"version": GROUPS_VERSION, "groups": [g.to_dict() for g in groups]}
    target.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return str(target)


def load_groups(path: str) -> List[GroupInfo]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if payload.get("version") != GROUPS_VERSION:
        raise ValueError(
            f"unsupported logic group version: {payload.get('version')} "
            f"(expected {GROUPS_VERSION})"
        )
    groups: List[GroupInfo] = []
    for entry in payload["groups"]:
        groups.append(
            GroupInfo(
                group_id=entry["group_id"],
                name=entry["name"],
                api_ids=entry["api_ids"],
                api_names=entry["api_names"],
                state_types=entry["state_types"],
                files=entry["files"],
                basis=entry["basis"],
                priority=entry.get("priority", 0.0),
                realtime_signals=[
                    RealtimeSignal(**s) for s in entry.get("realtime_signals", [])
                ],
            )
        )
    return groups


def stats(groups: Sequence[GroupInfo]) -> dict:
    sizes = [len(g.api_ids) for g in groups] or [0]
    by_basis: Dict[str, int] = {}
    for group in groups:
        by_basis[group.basis] = by_basis.get(group.basis, 0) + 1
    return {
        "groups": len(groups),
        "apis": sum(sizes),
        "largest_group": max(sizes),
        "singletons": sum(1 for s in sizes if s == 1),
        "by_basis": dict(sorted(by_basis.items())),
        "groups_with_realtime_signal": sum(1 for g in groups if g.realtime_signals),
        "state_types": sorted({t for g in groups for t in g.state_types}),
    }


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="상태 기반 Logic Group 추출/패키징 (SCH-02-01)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_parser = subparsers.add_parser("build", help="지식베이스에서 그룹 추출")
    build_parser.add_argument("--paths", nargs="*", default=[])
    build_parser.add_argument("--compile-db")
    build_parser.add_argument("--kb", help="이미 만들어 둔 지식베이스 JSON")
    build_parser.add_argument("--output", "-o", required=True)
    build_parser.add_argument("--no-call-links", action="store_true",
                              help="호출 관계로 잇지 않고 핸들 타입만으로 묶는다")
    build_parser.add_argument("--no-priority", action="store_true")

    show_parser = subparsers.add_parser("show", help="그룹 내용 출력")
    show_parser.add_argument("--groups", required=True)

    stats_parser = subparsers.add_parser("stats", help="통계 출력")
    stats_parser.add_argument("--groups", required=True)

    return parser.parse_args(argv)


def _load_kb(args) -> KnowledgeBase:
    if args.kb:
        return KnowledgeBase.load(args.kb)
    return KnowledgeBase.build(paths=args.paths or None, compile_db=args.compile_db)


def main(argv=None):
    args = parse_args(argv)

    if args.command == "build":
        if not (args.kb or args.paths or args.compile_db):
            raise SystemExit("--kb / --paths / --compile-db 중 하나는 필요합니다")
        kb = _load_kb(args)
        groups = build_groups(
            kb,
            link_calls=not args.no_call_links,
            with_priority=not args.no_priority,
        )
        save_groups(groups, args.output)
        print(json.dumps({"output": args.output, **stats(groups)},
                         indent=2, ensure_ascii=False))
        return

    groups = load_groups(args.groups)

    if args.command == "stats":
        print(json.dumps(stats(groups), indent=2, ensure_ascii=False))
        return

    if args.command == "show":
        for group in groups:
            print(f"\n## {group.group_id}  (priority={group.priority})")
            print(f"기준: {group.basis}"
                  + (f" / 상태타입: {', '.join(group.state_types)}" if group.state_types else ""))
            print(f"API {len(group.api_names)}개: {', '.join(group.api_names)}")
            for signal in group.realtime_signals:
                print(f"  실시간 신호: {signal.kind} {signal.period_ms:g}ms "
                      f"(출처: {signal.source})")


if __name__ == "__main__":
    main()
