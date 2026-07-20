"""
SCH-02-02 : API 시너지 점수 기반 우선순위 산정 (목업)

전제
----
SCH-02-01(Logic Group 패키징)에서 이미 "연관 가능성이 있는 API 묶음(Logic Group)"이
생성되어 있다고 가정한다. 이 모듈은 그 묶음 내부/묶음 간에서
"어떤 API 조합을 먼저 GEN 단계로 보낼지" 순위를 매기기 위한 시너지 점수를 계산한다.

시너지 점수 = w1*호출인접도 + w2*타입결합도 + w3*제약조건공유도

각 항목의 근거 (ERD 기준)
--------------------------
1) 호출 인접도 (call_seq)
   API_METADATA.call_seq : 소비자 코드 분석으로 도출한 실제 API 호출 순서.
   같은 시퀀스 안에서 window 이내에 함께 등장하면 상태적으로 연결된 API로 간주.

2) 타입 결합도 (func_signature)
   Clang-AST로 추출한 함수 시그니처에서 파라미터/리턴 타입을 뽑아
   Jaccard 유사도로 계산. 같은 구조체/핸들 타입을 주고받으면 결합도가 높다고 본다.

3) 제약조건 공유도 (CONSTRAINT.rule_text / source_type)
   RAG로 뽑은 규격서 제약이 두 API에 동시에 걸려 있으면(source_type이 같은 규격,
   예: UDS 세션 관리) 같은 상태 머신에 속한다고 판단.

SCH-02-03(미탐색 경로 가중치)은 여기서 만든 synergy_score에
coverage 기반 novelty factor를 곱하는 별도 모듈로 연결한다.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from itertools import combinations
import re


# ---------------------------------------------------------------------
# 1. 데이터 모델 (ERD: API_METADATA / CONSTRAINT 를 목업 형태로 축소)
# ---------------------------------------------------------------------

@dataclass
class ApiMetadata:
    api_id: int
    func_signature: str          # 예: "int uds_session_start(uds_ctx_t *ctx, uint8_t level)"
    call_seq: list[str]          # 예: ["can_open", "uds_session_start", "uds_read_did"]
    dep_graph_ref: str = ""


@dataclass
class Constraint:
    constraint_id: int
    api_id: int
    rule_text: str
    source_type: str             # 예: "UDS_SPEC", "CAN_SPEC"


# ---------------------------------------------------------------------
# 2. 개별 점수 계산 함수
# ---------------------------------------------------------------------

TYPE_TOKEN_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*_t\b|\bstruct\s+\w+|\benum\s+\w+")


def extract_types(signature: str) -> set[str]:
    """함수 시그니처에서 커스텀 타입(핸들/구조체/열거형) 토큰만 추출한다.
    int, char* 같은 기본 타입은 결합도 판단에 노이즈이므로 제외."""
    return set(TYPE_TOKEN_RE.findall(signature))


def call_adjacency_score(seq_a: list[str], seq_b: list[str],
                          api_a: str, api_b: str, window: int = 2) -> float:
    """두 API가 실제 호출 시퀀스 상에서 window 이내에 함께 등장한 비율.
    call_seq는 API별로 여러 소비자 코드에서 뽑힌 시퀀스 리스트를 이어붙인 것으로 가정."""
    combined = seq_a if seq_a else seq_b
    if not combined:
        return 0.0
    hits, total = 0, 0
    for i, token in enumerate(combined):
        if token != api_a:
            continue
        total += 1
        window_slice = combined[max(0, i - window): i + window + 1]
        if api_b in window_slice:
            hits += 1
    return hits / total if total else 0.0


def type_coupling_score(sig_a: str, sig_b: str) -> float:
    """파라미터/리턴 타입의 Jaccard 유사도."""
    types_a, types_b = extract_types(sig_a), extract_types(sig_b)
    if not types_a or not types_b:
        return 0.0
    inter = types_a & types_b
    union = types_a | types_b
    return len(inter) / len(union)


def constraint_overlap_score(api_a_id: int, api_b_id: int,
                              constraints: list[Constraint]) -> float:
    """같은 source_type(같은 규격 문서)의 제약을 동시에 갖는지 여부.
    완전 일치면 1.0, 일부 겹치면 겹치는 source_type 비율."""
    types_a = {c.source_type for c in constraints if c.api_id == api_a_id}
    types_b = {c.source_type for c in constraints if c.api_id == api_b_id}
    if not types_a or not types_b:
        return 0.0
    inter = types_a & types_b
    union = types_a | types_b
    return len(inter) / len(union)


# ---------------------------------------------------------------------
# 3. 시너지 점수 종합 및 우선순위 산정
# ---------------------------------------------------------------------

@dataclass
class SynergyWeights:
    call_adjacency: float = 0.5
    type_coupling: float = 0.3
    constraint_overlap: float = 0.2


@dataclass
class SynergyResult:
    api_a: int
    api_b: int
    score: float
    detail: dict = field(default_factory=dict)


def compute_pairwise_synergy(apis: list[ApiMetadata],
                              constraints: list[Constraint],
                              weights: SynergyWeights = SynergyWeights()
                              ) -> list[SynergyResult]:
    results = []
    by_id = {a.api_id: a for a in apis}

    for a, b in combinations(apis, 2):
        adj = call_adjacency_score(a.call_seq, b.call_seq,
                                    str(a.api_id), str(b.api_id))
        typ = type_coupling_score(a.func_signature, b.func_signature)
        con = constraint_overlap_score(a.api_id, b.api_id, constraints)

        score = (weights.call_adjacency * adj
                 + weights.type_coupling * typ
                 + weights.constraint_overlap * con)

        results.append(SynergyResult(
            api_a=a.api_id, api_b=b.api_id, score=round(score, 4),
            detail={"call_adjacency": round(adj, 4),
                    "type_coupling": round(typ, 4),
                    "constraint_overlap": round(con, 4)}
        ))

    return sorted(results, key=lambda r: r.score, reverse=True)


def rank_logic_groups(logic_groups: dict[str, list[int]],
                       synergy_results: list[SynergyResult]) -> list[tuple[str, float]]:
    """SCH-02-01에서 만들어진 Logic Group(예: {"lg_1": [101, 102, 103]})을 받아
    그룹 내부 API 쌍들의 평균 시너지 점수로 그룹 순위를 매긴다.
    SCH-02-03에서 여기에 novelty(미탐색 비율) 가중치를 곱해 최종 큐를 만든다."""
    score_map = {(r.api_a, r.api_b): r.score for r in synergy_results}
    score_map.update({(b, a): s for (a, b), s in score_map.items()})

    ranking = []
    for group_name, api_ids in logic_groups.items():
        pairs = list(combinations(sorted(api_ids), 2))
        if not pairs:
            ranking.append((group_name, 0.0))
            continue
        avg = sum(score_map.get(p, 0.0) for p in pairs) / len(pairs)
        ranking.append((group_name, round(avg, 4)))

    return sorted(ranking, key=lambda x: x[1], reverse=True)


# ---------------------------------------------------------------------
# 4. 목업 실행 예시 (CLI: logosfuzz schedule 목업 데이터)
# ---------------------------------------------------------------------

if __name__ == "__main__":
    apis = [
        ApiMetadata(101, "int can_open(can_ctx_t *ctx)",
                    ["101", "102", "103", "101", "102"]),
        ApiMetadata(102, "int uds_session_start(uds_ctx_t *ctx, uint8_t level)",
                    ["101", "102", "103"]),
        ApiMetadata(103, "int uds_read_did(uds_ctx_t *ctx, uint16_t did)",
                    ["102", "103"]),
        ApiMetadata(201, "int json_parse(const char *buf, size_t len)",
                    ["201", "202"]),
        ApiMetadata(202, "void json_free(json_val_t *v)",
                    ["201", "202"]),
    ]

    constraints = [
        Constraint(1, 102, "session start must precede read_did", "UDS_SPEC"),
        Constraint(2, 103, "read_did requires active session", "UDS_SPEC"),
        Constraint(3, 101, "can_open must be called before any UDS API", "CAN_SPEC"),
    ]

    logic_groups = {
        "lg_1_uds": [101, 102, 103],
        "lg_2_json": [201, 202],
    }

    print("=== Pairwise Synergy ===")
    results = compute_pairwise_synergy(apis, constraints)
    for r in results:
        print(f"{r.api_a} <-> {r.api_b} : score={r.score}  {r.detail}")

    print("\n=== Logic Group Priority (SCH-02-02 output) ===")
    ranked = rank_logic_groups(logic_groups, results)
    for name, score in ranked:
        print(f"{name} : avg_synergy={score}")