"""
SCH-02-03 : 미탐색 경로 자원 집중 할당 (목업)

전제
----
SCH-02-02에서 계산된 Logic Group별 시너지 점수(synergy_score)를 입력으로 받는다.
여기서는 퍼징 실행 이력(FUZZING_RUN.coverage)을 바탕으로
"얼마나 탐색되지 않은 경로인가(novelty)"를 계산하고,

최종 우선순위 점수 = synergy_score * novelty_factor

를 산정하여 GEN 단계로 넘길 Logic Group 순서(퍼징 큐)를 결정한다.

novelty_factor 계산 방식
------------------------
- coverage_ratio : 현재까지 탐색된 경로 비율 (0.0 ~ 1.0)
  예: 전체 브랜치 1000개 중 300개 탐색 → coverage_ratio = 0.3
- novelty_factor = 1.0 - coverage_ratio
  탐색 많이 됐을수록 낮아지고, 안 됐을수록 높아진다.
- 단, novelty_factor가 너무 낮아지면 아예 스킵되는 문제가 생기므로
  MIN_NOVELTY(0.1)로 하한을 보장한다.

자원 할당 전략
--------------
최종 점수 기반으로 각 Logic Group에 퍼징 시간(timeout)을 비례 배분한다.
총 예산(budget_sec)을 점수 비율에 따라 나눠주는 방식.
"""

from __future__ import annotations
from dataclasses import dataclass, field

# SCH-02-02 모듈에서 가져옴
from sch_02_02_synergy_scheduler import (
    ApiMetadata, Constraint,
    compute_pairwise_synergy, rank_logic_groups,
    SynergyWeights
)

MIN_NOVELTY = 0.1   # novelty_factor 하한값


# ---------------------------------------------------------------------
# 1. 데이터 모델 (FUZZING_RUN 테이블 축소판)
# ---------------------------------------------------------------------

@dataclass
class FuzzingRun:
    """EXE 단계에서 기록된 퍼징 실행 이력 (ERD: FUZZING_RUN)"""
    run_id: int
    group_name: str
    total_branches: int     # 전체 브랜치 수 (정적 분석으로 추출)
    covered_branches: int   # 현재까지 커버된 브랜치 수

    @property
    def coverage_ratio(self) -> float:
        if self.total_branches == 0:
            return 0.0
        return self.covered_branches / self.total_branches


# ---------------------------------------------------------------------
# 2. Novelty Factor 계산
# ---------------------------------------------------------------------

def compute_novelty_factor(coverage_ratio: float) -> float:
    """미탐색 비율을 novelty_factor로 변환.
    coverage가 높을수록 낮아지고, MIN_NOVELTY로 하한 보장."""
    raw = 1.0 - coverage_ratio
    return max(raw, MIN_NOVELTY)


# ---------------------------------------------------------------------
# 3. 최종 우선순위 점수 및 자원 할당
# ---------------------------------------------------------------------

@dataclass
class ScheduleResult:
    group_name: str
    synergy_score: float
    coverage_ratio: float
    novelty_factor: float
    final_score: float
    allocated_sec: int      # 배분된 퍼징 시간 (초)


def allocate_resources(
    synergy_ranking: list[tuple[str, float]],
    fuzzing_runs: list[FuzzingRun],
    budget_sec: int = 3600,         # 총 퍼징 예산 (기본 1시간)
) -> list[ScheduleResult]:
    """
    SCH-02-02 시너지 순위 + EXE 단계 coverage 이력을 합산해
    최종 점수와 퍼징 시간을 배분한다.

    Parameters
    ----------
    synergy_ranking : SCH-02-02의 rank_logic_groups() 출력
    fuzzing_runs    : 각 Logic Group의 퍼징 실행 이력
    budget_sec      : 전체 퍼징 예산 (초 단위)
    """
    # group_name → FuzzingRun 매핑
    run_map: dict[str, FuzzingRun] = {r.group_name: r for r in fuzzing_runs}

    results = []
    for group_name, synergy_score in synergy_ranking:
        run = run_map.get(group_name)

        # 퍼징 이력 없으면 미탐색으로 간주 (novelty 최대)
        coverage_ratio = run.coverage_ratio if run else 0.0
        novelty_factor = compute_novelty_factor(coverage_ratio)
        final_score = round(synergy_score * novelty_factor, 4)

        results.append(ScheduleResult(
            group_name=group_name,
            synergy_score=synergy_score,
            coverage_ratio=round(coverage_ratio, 4),
            novelty_factor=round(novelty_factor, 4),
            final_score=final_score,
            allocated_sec=0,    # 아래에서 채움
        ))

    # 최종 점수 기준 내림차순 정렬
    results.sort(key=lambda r: r.final_score, reverse=True)

    # 점수 비율에 따라 퍼징 시간 배분
    total_score = sum(r.final_score for r in results)
    for r in results:
        if total_score > 0:
            r.allocated_sec = int(budget_sec * (r.final_score / total_score))
        else:
            r.allocated_sec = budget_sec // len(results)

    return results


# ---------------------------------------------------------------------
# 4. 목업 실행 예시
# ---------------------------------------------------------------------

if __name__ == "__main__":

    # SCH-02-02 목업 데이터 재사용
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

    # SCH-02-02 실행
    synergy_results = compute_pairwise_synergy(apis, constraints)
    synergy_ranking = rank_logic_groups(logic_groups, synergy_results)

    print("=== SCH-02-02 시너지 순위 ===")
    for name, score in synergy_ranking:
        print(f"  {name} : synergy={score}")

    # SCH-02-03: 퍼징 이력 목업
    # lg_1_uds는 이미 40% 탐색됨, lg_2_json은 아직 미탐색
    fuzzing_runs = [
        FuzzingRun(run_id=1, group_name="lg_1_uds",
                   total_branches=1000, covered_branches=400),
        FuzzingRun(run_id=2, group_name="lg_2_json",
                   total_branches=500,  covered_branches=0),
    ]

    print("\n=== SCH-02-03 최종 우선순위 및 자원 할당 (budget=3600초) ===")
    schedule = allocate_resources(synergy_ranking, fuzzing_runs, budget_sec=3600)
    for r in schedule:
        print(
            f"  {r.group_name} | "
            f"synergy={r.synergy_score} | "
            f"coverage={r.coverage_ratio:.0%} | "
            f"novelty={r.novelty_factor} | "
            f"final={r.final_score} | "
            f"할당시간={r.allocated_sec}초"
        )