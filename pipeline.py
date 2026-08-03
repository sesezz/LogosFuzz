"""
pipeline.py : EXT → SCH → GEN 전체 파이프라인 연계

실행 방법
---------
python pipeline.py --source test_target.c --output harness_output.c
"""

from __future__ import annotations
import os
import json
import argparse
from dotenv import load_dotenv

load_dotenv(r"C:\Users\suhwo\Desktop\한이음\LogosFuzz\.env")

# EXT 단계
from src.ast_analyzer import analyze_file

# SCH 단계
from sch_02_02_synergy_scheduler import (
    ApiMetadata, Constraint,
    compute_pairwise_synergy, rank_logic_groups,
)
from sch_02_03_resource_allocator import (
    FuzzingRun, allocate_resources,
)

# GEN 단계
from gen_03_01_harness_generator import (
    ApiContext, collect_context, build_prompt,
    generate_harness, VECTOR_DB_MOCK,
)


# ---------------------------------------------------------------------
# EXT 출력 → ApiMetadata 변환
# ---------------------------------------------------------------------

def ext_to_api_metadata(ext_json: list[dict]) -> list[ApiMetadata]:
    """ast_analyzer 출력 JSON에서 FUNCTION_DECL만 뽑아 ApiMetadata로 변환."""
    apis = []
    api_id = 100

    for file_result in ext_json:
        source_file = file_result.get("file", "")
        nodes = file_result.get("nodes", [])

        # 시스템 헤더 제외하고 타겟 소스파일 함수만 추출
        func_nodes = [
            n for n in nodes
            if n["kind"] == "FUNCTION_DECL"
            and n.get("location", "")
            and source_file in n.get("location", "")
        ]

        # 파라미터 타입 추출
        func_params: dict[str, list[str]] = {}
        current_func = None
        for n in nodes:
            if n["kind"] == "FUNCTION_DECL" and source_file in (n.get("location") or ""):
                current_func = n["spelling"]
                func_params[current_func] = []
            elif n["kind"] == "PARM_DECL" and current_func:
                if n["spelling"]:
                    func_params[current_func].append(n["spelling"])
            elif n["kind"] == "TYPE_REF" and current_func:
                func_params[current_func].append(n["spelling"])

        for fn in func_nodes:
            name = fn["spelling"]
            params = func_params.get(name, [])
            param_str = ", ".join(params) if params else "void"
            signature = f"int {name}({param_str})"

            apis.append(ApiMetadata(
                api_id=api_id,
                func_signature=signature,
                call_seq=[str(api_id)],
                dep_graph_ref=fn.get("location", ""),
            ))

            # Vector DB에도 동적으로 추가
            VECTOR_DB_MOCK[api_id] = ApiContext(
                api_id=api_id,
                func_signature=signature,
                call_order=[name],
                constraints=[f"{name} must be called with valid parameters"],
                source_type="TARGET"
            )

            api_id += 1

    return apis


def auto_group(apis: list[ApiMetadata]) -> dict[str, list[int]]:
    """API를 간단히 2개씩 묶어 Logic Group 생성 (SCH-02-01 역할 대체)."""
    groups = {}
    ids = [a.api_id for a in apis]
    for i in range(0, len(ids), 2):
        group_ids = ids[i:i+2]
        group_name = f"lg_{i//2 + 1}"
        groups[group_name] = group_ids
    return groups


# ---------------------------------------------------------------------
# 전체 파이프라인 실행
# ---------------------------------------------------------------------

def run_pipeline(source_path: str, output_path: str, budget_sec: int = 3600):

    print(f"\n[EXT] {source_path} 분석 중...")
    ext_result = analyze_file(source_path)
    ext_json = [ext_result]
    print(f"  분석 완료: FUNCTION_DECL {ext_result['counts'].get('FUNCTION_DECL', 0)}개 발견")

    print("\n[SCH] API 메타데이터 변환 및 스케줄링...")
    apis = ext_to_api_metadata(ext_json)
    if not apis:
        print("  [ERROR] 추출된 API가 없습니다.")
        return

    print(f"  추출된 API: {[a.func_signature for a in apis]}")

    constraints: list[Constraint] = []
    logic_groups = auto_group(apis)
    print(f"  Logic Group: {logic_groups}")

    synergy_results = compute_pairwise_synergy(apis, constraints)
    synergy_ranking = rank_logic_groups(logic_groups, synergy_results)

    fuzzing_runs: list[FuzzingRun] = []
    schedule = allocate_resources(synergy_ranking, fuzzing_runs, budget_sec=budget_sec)

    print("\n  우선순위:")
    for r in schedule:
        print(f"    {r.group_name} | final={r.final_score} | 할당={r.allocated_sec}초")

    print("\n[GEN] 하네스 생성 중...")
    drivers = generate_harness(schedule, logic_groups)

    print(f"\n[OUT] {output_path} 저장 중...")
    with open(output_path, "w", encoding="utf-8") as f:
        for d in drivers:
            f.write(f"// === {d.group_name} ===\n")
            code = d.code.replace("```c", "").replace("```", "").strip()
            f.write(code + "\n\n")

    print(f"  저장 완료: {output_path}")
    print("\n=== 파이프라인 완료 ===")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, help="분석할 C/C++ 소스 파일")
    parser.add_argument("--output", default="harness_output.c", help="출력 하네스 파일")
    parser.add_argument("--budget", type=int, default=3600, help="총 퍼징 예산(초)")
    args = parser.parse_args()

    run_pipeline(args.source, args.output, args.budget)
