"""
GEN-03-01 : Context-based Harness Generation

Generates fuzzing harness code using LLM based on API context
retrieved from Vector DB (mock: dict).
"""

from __future__ import annotations
import os
from dotenv import load_dotenv
from dataclasses import dataclass, field
from openai import OpenAI

load_dotenv()  # cwd부터 상위로 .env 자동 탐색 (팀원 환경마다 경로가 다르므로 하드코딩 금지)

from logosfuzz.schedule.sch_02_02_synergy_scheduler import (
    ApiMetadata, Constraint,
    compute_pairwise_synergy, rank_logic_groups,
)
from logosfuzz.schedule.sch_02_03_resource_allocator import (
    FuzzingRun, allocate_resources, ScheduleResult
)


# ---------------------------------------------------------------------
# 1. Data Models
# ---------------------------------------------------------------------

@dataclass
class ApiContext:
    api_id: int
    func_signature: str
    call_order: list[str]
    constraints: list[str]
    source_type: str


@dataclass
class FuzzDriver:
    group_name: str
    code: str
    prompt_used: str = ""


# ---------------------------------------------------------------------
# 2. Vector DB Mock
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
# 3. Context Collection
# ---------------------------------------------------------------------

def collect_context(api_ids: list[int]) -> list[ApiContext]:
    return [VECTOR_DB_MOCK[aid] for aid in api_ids if aid in VECTOR_DB_MOCK]


# ---------------------------------------------------------------------
# 4. Prompt Builder
# ---------------------------------------------------------------------

def build_prompt(group_name: str, contexts: list[ApiContext],
                 header_content: str = "",
                 header_filenames: list[str] | None = None) -> str:
    api_block = ""
    extern_decls = ""
    for ctx in contexts:
        api_block += f"""
- Function signature : {ctx.func_signature}
  Call order        : {" -> ".join(ctx.call_order)}
  Constraints       : {", ".join(ctx.constraints)}
  Spec source       : {ctx.source_type}
"""
        extern_decls += f"extern {ctx.func_signature};\n"

    # 헤더 include 지시 — 내용을 복붙하는 게 아니라 #include 한 줄로 쓰도록 명시
    # "복붙하라"고 시키면 LLM이 구조체를 중복 정의하는 원인이 됐음
    header_include_lines = ""
    header_section = ""
    if header_filenames:
        header_include_lines = "\n".join(f'#include "{h}"' for h in header_filenames)
        header_section = f"""
HEADER FILES:
The target source is compiled with these headers available.
Start your harness with EXACTLY these lines (in this order, nothing else before them):

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
{header_include_lines}

The headers above already define all necessary types (structs, typedefs, etc).
DO NOT redefine or redeclare any type — just use them directly after the includes.

For reference, the header content is shown below (READ ONLY — do not copy-paste structs):
```c
{header_content}
```
"""

    prompt = f"""You are a C/C++ security testing expert.
Write a libFuzzer fuzz driver in C for the following APIs.

[Logic Group: {group_name}]
{api_block}

These functions are REAL functions that already exist in the target source
file. At compile time, your driver file will be compiled together with the
original target source file, so the real implementation will be linked in.
{header_section}
Use exactly these extern declarations AFTER the includes (copy verbatim):
{extern_decls}

STRICT RULES:
1. Return type of LLVMFuzzerTestOneInput MUST be int, NEVER void
2. All comments MUST be in English only, NEVER use Korean
3. Reflect API call order and constraints
4. Map input data(data, size) to API parameters appropriately
5. Handle memory allocation/deallocation explicitly
6. Output ONLY raw C code, no markdown, no explanation
7. Do NOT write a function body for any extern function listed above.
   Their real implementation is linked from the original target source.
8. Do NOT invent or call any function not explicitly listed above.
9. Do NOT define `main`. The fuzzing runtime provides its own `main`.
10. Do NOT redefine or redeclare any struct, typedef, or function already
    declared in the included headers. No duplicate typedefs. No empty structs.
11. The FIRST lines of your output must be the #include lines shown above.
    Do not add any code or comments before them.
12. NEVER cast the fuzzer input (const uint8_t *data) directly to a mutable
    pointer and pass it to a function that writes through that pointer.
    Always malloc() + memcpy() a separate buffer first.
    Direct const-cast causes libFuzzer to abort with
    "fuzz target overwrites its const input".
"""
    return prompt



# ---------------------------------------------------------------------
# 5. Harness Generator
# ---------------------------------------------------------------------

def generate_harness(schedule: list[ScheduleResult],
                     logic_groups: dict[str, list[int]],
                     header_content: str = "",
                     header_filenames: list[str] | None = None) -> list[FuzzDriver]:
    client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
    drivers = []

    for result in schedule:
        group_name = result.group_name
        api_ids = logic_groups.get(group_name, [])

        print(f"\n[GEN] {group_name} generating harness... (budget={result.allocated_sec}s)")

        contexts = collect_context(api_ids)
        if not contexts:
            print(f"  [WARN] {group_name} no context found, skipping")
            continue

        prompt = build_prompt(group_name, contexts,
                              header_content=header_content,
                              header_filenames=header_filenames)
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=1500,
            temperature=0.2,
        )
        code = response.choices[0].message.content.strip()

        drivers.append(FuzzDriver(
            group_name=group_name,
            code=code,
            prompt_used=prompt,
        ))
        print(f"  [DONE] {group_name} harness generated ({len(code)} chars)")

    return drivers


# ---------------------------------------------------------------------
# 6. Mock Run
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
    fuzzing_runs = [
        FuzzingRun(1, "lg_1_uds", total_branches=1000, covered_branches=400),
        FuzzingRun(2, "lg_2_json", total_branches=500, covered_branches=0),
    ]

    synergy_results = compute_pairwise_synergy(apis, constraints)
    synergy_ranking = rank_logic_groups(logic_groups, synergy_results)
    schedule = allocate_resources(synergy_ranking, fuzzing_runs, budget_sec=3600)

    print("=== GEN-03-01 Harness Generation Start ===")
    drivers = generate_harness(schedule, logic_groups)

    print("\n=== Generated Harness Code ===")
    for d in drivers:
        print(f"\n--- {d.group_name} ---")
        print(d.code)