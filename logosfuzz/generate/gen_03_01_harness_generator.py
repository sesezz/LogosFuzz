"""
GEN-03-01 : 실시간 컨텍스트 주입 기반 하네스 초안 생성 (목업)

전제
----
SCH-02-03에서 최종 우선순위가 결정된 Logic Group을 입력으로 받는다.
Vector DB에서 해당 API의 제약조건, 호출순서, 함수 시그니처를 실시간으로 꺼내
LLM 프롬프트에 주입하고, GPT-4o-mini가 퍼징 하네스 코드를 생성한다.

처리 흐름 (GEN 단계)
--------------------
1. SCH-02-03 출력(ScheduleResult)에서 Logic Group 순서대로 꺼냄
2. Vector DB(목업: dict)에서 해당 API들의 컨텍스트 수집
3. 컨텍스트를 프롬프트에 주입해 GPT-4o-mini API 호출
4. 생성된 하네스 코드를 FuzzDriver 객체로 반환
5. 컴파일 성공 여부 확인 (GEN-03-02로 연결)

목업 범위
---------
- Vector DB 대신 dict로 API 컨텍스트를 직접 정의
- 실제 GPT-4o-mini API 호출 포함 (OPENAI_API_KEY 환경변수 필요)
- 컴파일 검증은 GEN-03-02에서 담당
"""

from __future__ import annotations
import os
from dataclasses import dataclass, field
from openai import OpenAI

# SCH 단계 모듈에서 가져옴
from logosfuzz.schedule.sch_02_02_synergy_scheduler import (
    ApiMetadata, Constraint,
    compute_pairwise_synergy, rank_logic_groups,
)
from logosfuzz.schedule.sch_02_03_resource_allocator import (
    FuzzingRun, allocate_resources, ScheduleResult
)


# ---------------------------------------------------------------------
# 1. 데이터 모델
# ---------------------------------------------------------------------

@dataclass
class ApiContext:
    """Vector DB에서 꺼낸 API 1개의 컨텍스트 (목업: dict로 대체)"""
    api_id: int
    func_signature: str
    call_order: list[str]        # 호출 순서 (예: ["can_open", "uds_session_start"])
    constraints: list[str]       # 제약 조건 텍스트 (예: ["session must be active"])
    source_type: str             # 규격 출처 (예: "UDS_SPEC")


@dataclass
class FuzzDriver:
    """LLM이 생성한 퍼징 하네스 코드"""
    group_name: str
    code: str
    prompt_used: str = ""


# ---------------------------------------------------------------------
# 2. Vector DB 목업 (실제 구현 시 ChromaDB / FAISS 등으로 교체)
# ---------------------------------------------------------------------

VECTOR_DB_MOCK: dict[int, ApiContext] = {
    101: ApiContext(
        api_id=101,
        func_signature="int can_open(can_ctx_t *ctx)",
        call_order=["can_open", "uds_session_start", "uds_read_did"],
        constraints=["must be called before any UDS API"],
        source_type="CAN_SPEC"
    ),
    102: ApiContext(
        api_id=102,
        func_signature="int uds_session_start(uds_ctx_t *ctx, uint8_t level)",
        call_order=["can_open", "uds_session_start", "uds_read_did"],
        constraints=["session start must precede read_did"],
        source_type="UDS_SPEC"
    ),
    103: ApiContext(
        api_id=103,
        func_signature="int uds_read_did(uds_ctx_t *ctx, uint16_t did)",
        call_order=["uds_session_start", "uds_read_did"],
        constraints=["read_did requires active session"],
        source_type="UDS_SPEC"
    ),
    201: ApiContext(
        api_id=201,
        func_signature="int json_parse(const char *buf, size_t len)",
        call_order=["json_parse", "json_free"],
        constraints=["buf must not be NULL", "len must match actual buffer size"],
        source_type="INTERNAL"
    ),
    202: ApiContext(
        api_id=202,
        func_signature="void json_free(json_val_t *v)",
        call_order=["json_parse", "json_free"],
        constraints=["must be called after json_parse"],
        source_type="INTERNAL"
    ),
}


# ---------------------------------------------------------------------
# 3. 컨텍스트 수집 (Vector DB 조회 역할)
# ---------------------------------------------------------------------

def collect_context(api_ids: list[int]) -> list[ApiContext]:
    """Logic Group의 API ID 목록으로 Vector DB에서 컨텍스트를 꺼낸다."""
    return [VECTOR_DB_MOCK[aid] for aid in api_ids if aid in VECTOR_DB_MOCK]


# ---------------------------------------------------------------------
# 4. 프롬프트 생성
# ---------------------------------------------------------------------

def build_prompt(group_name: str, contexts: list[ApiContext]) -> str:
    """수집된 컨텍스트를 LLM 프롬프트로 변환한다."""

    api_block = ""
    for ctx in contexts:
        api_block += f"""
- 함수 시그니처 : {ctx.func_signature}
  호출 순서     : {" → ".join(ctx.call_order)}
  제약 조건     : {", ".join(ctx.constraints)}
  규격 출처     : {ctx.source_type}
"""

    prompt = f"""당신은 C/C++ 보안 테스트 전문가입니다.
아래 API 정보를 바탕으로 libFuzzer 형식의 퍼징 하네스(fuzz driver) C 코드를 작성하세요.

[Logic Group: {group_name}]
{api_block}

요구사항:
1. LLVMFuzzerTestOneInput 함수 형식을 반드시 따를 것
2. API 호출 순서와 제약 조건을 반드시 반영할 것
3. 입력 데이터(data, size)를 API 파라미터에 적절히 매핑할 것
4. 메모리 할당/해제를 명시적으로 처리할 것
5. 주석으로 각 API 호출 의도를 설명할 것

C 코드만 출력하고 다른 설명은 하지 마세요.
"""
    return prompt


# ---------------------------------------------------------------------
# 5. LLM 하네스 생성
# ---------------------------------------------------------------------

def generate_harness(schedule: list[ScheduleResult],
                     logic_groups: dict[str, list[int]]) -> list[FuzzDriver]:
    """
    SCH-02-03 순위대로 Logic Group을 순회하며 하네스를 생성한다.

    Parameters
    ----------
    schedule     : SCH-02-03 allocate_resources() 출력
    logic_groups : {"lg_1_uds": [101, 102, 103], ...}
    """
    client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
    drivers = []

    for result in schedule:
        group_name = result.group_name
        api_ids = logic_groups.get(group_name, [])

        print(f"\n[GEN] {group_name} 하네스 생성 중... (할당시간={result.allocated_sec}초)")

        # Vector DB에서 컨텍스트 수집
        contexts = collect_context(api_ids)
        if not contexts:
            print(f"  [WARN] {group_name} 컨텍스트 없음, 스킵")
            continue

        # 프롬프트 생성 및 LLM 호출
        prompt = build_prompt(group_name, contexts)
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=1000,
            temperature=0.2,
        )
        code = response.choices[0].message.content.strip()

        drivers.append(FuzzDriver(
            group_name=group_name,
            code=code,
            prompt_used=prompt,
        ))
        print(f"  [DONE] {group_name} 하네스 생성 완료 ({len(code)}자)")

    return drivers


# ---------------------------------------------------------------------
# 6. 목업 실행 예시
# ---------------------------------------------------------------------

if __name__ == "__main__":

    # SCH 단계 데이터 재사용
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
    fuzzing_runs = [
        FuzzingRun(1, "lg_1_uds", total_branches=1000, covered_branches=400),
        FuzzingRun(2, "lg_2_json", total_branches=500,  covered_branches=0),
    ]

    # SCH-02-02 → SCH-02-03
    synergy_results = compute_pairwise_synergy(apis, constraints)
    synergy_ranking = rank_logic_groups(logic_groups, synergy_results)
    schedule = allocate_resources(synergy_ranking, fuzzing_runs, budget_sec=3600)

    print("=== GEN-03-01 하네스 생성 시작 ===")
    drivers = generate_harness(schedule, logic_groups)

    print("\n=== 생성된 하네스 코드 ===")
    for d in drivers:
        print(f"\n--- {d.group_name} ---")
        print(d.code)
