from __future__ import annotations
import os
import json
import argparse
from dotenv import load_dotenv

load_dotenv(r"C:\Users\suhwo\Desktop\한이음\LogosFuzz\.env")

from src.ast_analyzer import analyze_file
from sch_02_02_synergy_scheduler import ApiMetadata, Constraint, compute_pairwise_synergy, rank_logic_groups
from sch_02_03_resource_allocator import FuzzingRun, allocate_resources
from gen_03_01_harness_generator import ApiContext, collect_context, build_prompt, generate_harness, VECTOR_DB_MOCK

def ext_to_api_metadata(ext_json):
    apis = []
    api_id = 100
    for file_result in ext_json:
        source_file = file_result.get("file", "")
        nodes = file_result.get("nodes", [])
        func_nodes = [n for n in nodes if n["kind"] == "FUNCTION_DECL" and source_file in (n.get("location") or "")]
        for fn in func_nodes:
            name = fn["spelling"]
            signature = f"int {name}(void *ctx)"
            apis.append(ApiMetadata(api_id=api_id, func_signature=signature, call_seq=[str(api_id)]))
            VECTOR_DB_MOCK[api_id] = ApiContext(api_id=api_id, func_signature=signature, call_order=[name], constraints=[f"{name} must be called with valid parameters"], source_type="TARGET")
            api_id += 1
    return apis

def auto_group(apis):
    groups = {}
    ids = [a.api_id for a in apis]
    for i in range(0, len(ids), 2):
        group_ids = ids[i:i+2]
        groups[f"lg_{i//2+1}"] = group_ids
    return groups

def run_pipeline(source_path, output_path, budget_sec=3600):
    print(f"\n[EXT] Analyzing {source_path}...")
    ext_result = analyze_file(source_path)
    apis = ext_to_api_metadata([ext_result])
    print(f"  Found {len(apis)} APIs: {[a.func_signature for a in apis]}")
    logic_groups = auto_group(apis)
    synergy_results = compute_pairwise_synergy(apis, [])
    synergy_ranking = rank_logic_groups(logic_groups, synergy_results)
    schedule = allocate_resources(synergy_ranking, [], budget_sec=budget_sec)
    print("\n[GEN] Generating harness...")
    drivers = generate_harness(schedule, logic_groups)
    with open(output_path, "w", encoding="utf-8") as f:
        for d in drivers:
            f.write(f"// === {d.group_name} ===\n")
            code = d.code.replace("`c", "").replace("`", "").strip()
            f.write(code + "\n\n")
    print(f"\n[DONE] Saved to {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", default="harness_output.c")
    parser.add_argument("--budget", type=int, default=3600)
    args = parser.parse_args()
    run_pipeline(args.source, args.output, args.budget)
