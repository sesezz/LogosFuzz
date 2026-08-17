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
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()  # cwd부터 상위로 .env 자동 탐색 (팀원 환경마다 경로가 다르므로 하드코딩 금지)

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
    """ast_analyzer 출력 JSON에서 FUNCTION_DECL만 뽑아 ApiMetadata로 변환.

    다음 함수는 퍼징 대상에서 제외한다:
      - 파라미터가 없는 함수 : 퍼징 입력(data, size)을 매핑할 자리가 없어서
        LLM이 억지로 존재하지 않는 인자/함수를 지어내는 원인이 됐다.
      - ``main`` : 엔트리포인트일 뿐 API가 아니다.
      - ``static`` 함수 : 내부 링키지라 별도 컴파일되는 하네스에서
        ``extern`` 선언으로 링크할 수 없다 (해당 .c 파일에 하네스를
        직접 포함시키는 방식이 아니라면 애초에 대상이 될 수 없음).
    """
    apis = []
    api_id = 100

    for file_result in ext_json:
        source_file = file_result.get("file", "")
        nodes = file_result.get("nodes", [])

        func_nodes = [
            n for n in nodes
            if n["kind"] == "FUNCTION_DECL"
            and n.get("location", "")
            and source_file in n.get("location", "")
        ]

        for fn in func_nodes:
            name = fn["spelling"]
            params = fn.get("params") or []

            if name == "main":
                continue
            if not params:
                continue
            if fn.get("is_static"):
                continue

            return_type = fn.get("return_type") or "int"
            param_str = ", ".join(
                f"{p['type']} {p['name']}".strip() for p in params
            )
            signature = f"{return_type} {name}({param_str})"

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

    # 소스 파일과 같은 디렉토리의 .h 파일을 모두 읽어서 프롬프트에 주입한다.
    # LLM이 타입(struct/typedef)을 모르면 빈 껍데기 구조체를 지어내므로,
    # 헤더 내용을 직접 넘겨주는 것이 컴파일 성공률을 올리는 핵심 조치다.
    header_content = ""
    header_filenames = []
    source_dir = Path(source_path).parent
    header_files = sorted(source_dir.glob("*.h"))
    if header_files:
        parts = []
        for h in header_files:
            try:
                parts.append(f"// --- {h.name} ---\n" + h.read_text(encoding="utf-8", errors="replace"))
                header_filenames.append(h.name)
            except Exception:
                pass
        header_content = "\n".join(parts)
        print(f"  헤더 {len(header_files)}개 주입: {[h.name for h in header_files]}")
    else:
        print("  [WARN] 헤더 파일 없음 - LLM이 타입을 추측할 수 있음")

    drivers = generate_harness(schedule, logic_groups,
                               header_content=header_content,
                               header_filenames=header_filenames)

    # 그룹별로 별도 파일에 저장한다. 한 파일에 이어 붙이면 그룹마다
    # LLVMFuzzerTestOneInput이 중복 정의돼 컴파일이 안 되고, 사용자가 매번
    # 손으로 잘라내야 했다. 원본 소스 경로도 헤더 주석에 남겨서
    # "무엇과 링크해야 하는지"가 하네스 파일만 봐도 드러나게 한다.
    output_dir = Path(output_path).resolve().parent
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = Path(output_path).stem

    print(f"\n[OUT] {output_dir}/ 에 그룹별 하네스 저장 중...")
    written = []
    for d in drivers:
        harness_path = output_dir / f"{stem}_{d.group_name}.c"
        code = d.code.replace("```c", "").replace("```", "").strip()
        header = (
            f"// === {d.group_name} ===\n"
            f"// Link against original target source: {source_path}\n"
            f"// Suggested build (see logosfuzz_fixes patch notes: -Dmain=main_disabled\n"
            f"// avoids a link clash if the target source defines its own main()):\n"
            f"//   clang -g -O1 -fsanitize=address,fuzzer -Dmain=main_disabled "
            f"-o {harness_path.stem} {harness_path.name} {source_path}\n\n"
        )
        with open(harness_path, "w", encoding="utf-8") as f:
            f.write(header + code + "\n")
        written.append(harness_path)
        print(f"  저장 완료: {harness_path}")

    print("\n=== 파이프라인 완료 ===")
    print("\n다음 단계 - 각 하네스를 원본 소스와 함께 링크해서 컴파일:")
    print("  (타겟 소스가 자체 main()을 갖고 있어도 안전하도록 -Dmain=main_disabled 포함)")
    for p in written:
        print(f"  clang -g -O1 -fsanitize=address,fuzzer -Dmain=main_disabled "
              f"-o {p.stem} {p.name} {source_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, help="분석할 C/C++ 소스 파일")
    parser.add_argument("--output", default="harness_output.c", help="출력 하네스 파일")
    parser.add_argument("--budget", type=int, default=3600, help="총 퍼징 예산(초)")
    args = parser.parse_args()

    run_pipeline(args.source, args.output, args.budget)
