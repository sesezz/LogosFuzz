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

# GEN-03-02 자가 치유(컴파일 에러 자동 복구)
from logosfuzz.generate.compiler import SubprocessCompiler
from logosfuzz.generate.llm import OpenAILLMClient
from logosfuzz.generate.models import HarnessDraft
from logosfuzz.generate.selfheal import SelfHealLoop


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
            # 가변인자 함수는 `...`까지 살려야 헤더 선언과 타입이 일치한다.
            # 빠뜨리면 하네스의 extern 선언이 conflicting types를 낸다.
            if fn.get("is_variadic"):
                param_str = f"{param_str}, ..." if param_str else "..."
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

def resolve_include_dirs(source_path: str, extra: list[str] | None = None) -> list[str]:
    """EXT 분석과 컴파일에서 공통으로 쓸 include 경로를 정한다.

    소스 디렉터리와 그 안의 ``include/``는 자동으로 잡고, 프로젝트 헤더가
    저장소 최상단(``<repo>/include``)이나 빌드 산출물(``build/include``)에
    있는 경우를 위해 ``--include``로 추가 지정할 수 있게 한다.
    """
    source_dir = Path(source_path).resolve().parent
    dirs: list[str] = []
    for d in (extra or []):
        p = Path(d).expanduser().resolve()
        if p.is_dir():
            dirs.append(str(p))
    bundled = source_dir / "include"
    if bundled.is_dir():
        dirs.append(str(bundled))
    dirs.append(str(source_dir))
    # 순서 유지 중복 제거
    return list(dict.fromkeys(dirs))


def run_pipeline(source_path: str, output_path: str, budget_sec: int = 3600,
                 max_round: int = 3, cc: str = "clang",
                 include: list[str] | None = None):

    # EXT에도 include 경로를 넘겨야 한다. 넘기지 않으면 libclang이 프로젝트
    # 헤더를 찾지 못해 typedef된 struct 포인터를 전부 `int *`로 보고한다
    # (dlt-daemon에서 실제로 `DltMessage *msg` → `int * msg`로 추출됐다).
    # 그 상태로 GEN에 넘기면 잘못된 타입의 하네스가 대량 생성된다.
    include_dirs = resolve_include_dirs(source_path, include)
    clang_args = ["-std=c11"] + [f"-I{d}" for d in include_dirs]

    print(f"\n[EXT] {source_path} 분석 중...")
    if include_dirs:
        print(f"  include 경로: {include_dirs}")
    ext_result = analyze_file(source_path, clang_args=clang_args)
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

    # GEN-03-02: 생성된 하네스를 실제로 컴파일해보고, 실패하면 컴파일 에러를
    # LLM에 되먹여 고친다. 이 단계가 없으면 컴파일 불가 하네스가 그대로
    # 저장돼서 사용자가 손으로 고쳐야 했다.
    # 대상 프로젝트가 커널 UAPI 헤더를 동봉하는 경우(can-utils의 include/)
    # 시스템 헤더보다 먼저 오도록 include 경로 앞에 넣는다.
    # EXT 분석에 쓴 경로를 그대로 재사용해서, 분석과 컴파일이 같은 헤더를
    # 보도록 맞춘다(둘이 어긋나면 자가 치유가 멀쩡한 하네스를 실패로 잡는다).

    heal_reports = []
    if max_round > 0:
        print(f"\n[GEN-03-02] 자가 치유 (max-round={max_round})...")
        # 컴파일 조건은 아래 [OUT]이 안내하는 실제 빌드 명령과 맞춰야 한다.
        # `-std=c11`(엄격 ISO)을 주면 struct timespec 같은 POSIX 타입이 가려져,
        # 실제 빌드는 되는 하네스가 자가 치유 단계에서만 실패로 잡힌다.
        loop = SelfHealLoop(
            compiler=SubprocessCompiler(
                cc=cc, sanitizers="address", include_dirs=include_dirs,
            ),
            llm=OpenAILLMClient(),
            max_round=max_round,
            on_round=lambda r: print(
                f"    [R{r.index}] {'LLM수정' if r.repaired_by_llm else '초안  '}"
                f" → {'OK' if r.ok else 'ERR'}"
            ),
        )
        for d in drivers:
            code = d.code.replace("```c", "").replace("```", "").strip()
            print(f"  ▶ {d.group_name}")
            report = loop.run(HarnessDraft(
                logic_group=d.group_name,
                source=code,
                project=Path(source_path).stem,
            ))
            heal_reports.append(report)
            print(f"    결과: {report.outcome.value}")
            if report.success:
                d.code = report.final_source
    else:
        print("\n[GEN-03-02] 자가 치유 생략(--max-round 0)")

    # 그룹별로 별도 파일에 저장한다. 한 파일에 이어 붙이면 그룹마다
    # LLVMFuzzerTestOneInput이 중복 정의돼 컴파일이 안 되고, 사용자가 매번
    # 손으로 잘라내야 했다. 원본 소스 경로도 헤더 주석에 남겨서
    # "무엇과 링크해야 하는지"가 하네스 파일만 봐도 드러나게 한다.
    output_dir = Path(output_path).resolve().parent
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = Path(output_path).stem

    inc_flags = "".join(f" -I{d}" for d in include_dirs)

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
            f"//   clang -g -O1 -fsanitize=address,fuzzer -Dmain=main_disabled"
            f"{inc_flags} -o {harness_path.stem} {harness_path.name} {source_path}\n\n"
        )
        with open(harness_path, "w", encoding="utf-8") as f:
            f.write(header + code + "\n")
        written.append(harness_path)
        print(f"  저장 완료: {harness_path}")

    if heal_reports:
        ok = sum(1 for r in heal_reports if r.success)
        repaired = sum(1 for r in heal_reports if r.success and r.rounds_used > 0)
        print(f"\n[GEN-03-02] 컴파일 성공 {ok}/{len(heal_reports)} "
              f"(그중 LLM 복구 {repaired}건)")

    print("\n=== 파이프라인 완료 ===")
    print("\n다음 단계 - 각 하네스를 원본 소스와 함께 링크해서 컴파일:")
    print("  (타겟 소스가 자체 main()을 갖고 있어도 안전하도록 -Dmain=main_disabled 포함)")
    for p in written:
        print(f"  clang -g -O1 -fsanitize=address,fuzzer -Dmain=main_disabled"
              f"{inc_flags} -o {p.stem} {p.name} {source_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, help="분석할 C/C++ 소스 파일")
    parser.add_argument("--output", default="harness_output.c", help="출력 하네스 파일")
    parser.add_argument("--budget", type=int, default=3600, help="총 퍼징 예산(초)")
    parser.add_argument("--max-round", type=int, default=3,
                        help="GEN-03-02 자가 치유 최대 반복(0이면 생략)")
    parser.add_argument("--cc", default="clang", help="컴파일러 실행 파일")
    parser.add_argument("--include", "-I", action="append", metavar="DIR",
                        help="추가 include 경로(반복 지정 가능). 프로젝트 헤더가 "
                             "소스와 다른 디렉터리에 있으면 반드시 지정해야 한다 "
                             "— 없으면 EXT가 struct 포인터를 int로 오인한다.")
    args = parser.parse_args()

    run_pipeline(args.source, args.output, args.budget,
                 max_round=args.max_round, cc=args.cc,
                 include=args.include)
