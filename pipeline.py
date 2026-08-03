"""
pipeline.py : EXT → SCH → GEN 전체 파이프라인 연계

EXT 단계는 EXT-01-04 통합 지식베이스(KnowledgeBase)를 사용한다. 제약조건,
호출 순서, 시그니처, include 정보를 한 번에 얻어 SCH/GEN 단계로 넘긴다.

실행 방법
---------
python pipeline.py --source examples/uds --output harness_output.c
python pipeline.py --source test_target.c --dry-run      # LLM 호출 없이 프롬프트만 확인
python pipeline.py --compile-db build/compile_commands.json --output out.c
"""

from __future__ import annotations
import argparse
import os
import sys

# EXT 단계 (EXT-01-01/02/03 을 통합한 EXT-01-04)
from src.knowledge_base import KnowledgeBase
from src.kb_adapters import harness_context, to_api_contexts, to_synergy_inputs

# SCH 단계
from sch_02_02_synergy_scheduler import (
    compute_pairwise_synergy, rank_logic_groups,
)
from sch_02_03_resource_allocator import (
    FuzzingRun, allocate_resources,
)


def load_env() -> None:
    """저장소 루트의 .env 를 읽는다(있으면).

    python-dotenv 가 없거나 .env 가 없어도 그냥 넘어간다. API 키는 환경변수로
    직접 넣어도 된다.
    """
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.exists(env_path):
        load_dotenv(env_path)


# ---------------------------------------------------------------------
# Logic Group 구성 (SCH-02-01 이 나오기 전까지의 임시 규칙)
# ---------------------------------------------------------------------

def auto_group(kb: KnowledgeBase, group_size: int = 0) -> dict[str, list[int]]:
    """API를 Logic Group으로 묶는다.

    기본은 **정의된 소스 파일 단위**로 묶는다. 같은 파일의 API는 같은 상태를
    공유할 가능성이 높아서, 순서대로 N개씩 자르는 것보다 그룹의 의미가 산다.
    `group_size`를 주면 예전처럼 고정 개수로 자른다.
    """
    if group_size > 0:
        ids = sorted(d["api_id"] for d in kb.documents)
        return {
            f"lg_{i // group_size + 1}": ids[i:i + group_size]
            for i in range(0, len(ids), group_size)
        }

    groups: dict[str, list[int]] = {}
    for document in sorted(kb.documents, key=lambda d: d["api_id"]):
        name = os.path.basename(document["file"]) or "unknown"
        groups.setdefault(f"lg_{name}", []).append(document["api_id"])
    return groups


# ---------------------------------------------------------------------
# 전체 파이프라인 실행
# ---------------------------------------------------------------------

def run_pipeline(source_path: str | None, output_path: str, budget_sec: int = 3600,
                 compile_db: str | None = None, dry_run: bool = False,
                 group_size: int = 0) -> int:

    # ---- EXT ----------------------------------------------------------
    print(f"\n[EXT] {source_path or compile_db} 분석 중...")
    kb = KnowledgeBase.build(
        paths=[source_path] if source_path else None,
        compile_db=compile_db,
    )
    stats = kb.stats()
    if not kb.documents:
        print("  [ERROR] 추출된 API가 없습니다.")
        return 1
    print(f"  API {stats['apis']}개 / 제약조건 {stats['constraints']}개 "
          f"/ 호출엣지 {stats['call_edges']}개 / 헤더해석 {stats['apis_with_header']}개")

    # ---- SCH ----------------------------------------------------------
    print("\n[SCH] API 메타데이터 변환 및 스케줄링...")
    apis, constraints = to_synergy_inputs(kb)
    print(f"  ApiMetadata {len(apis)}개, Constraint {len(constraints)}개")

    logic_groups = auto_group(kb, group_size=group_size)
    print(f"  Logic Group: { {k: len(v) for k, v in logic_groups.items()} }")

    synergy_results = compute_pairwise_synergy(apis, constraints)
    synergy_ranking = rank_logic_groups(logic_groups, synergy_results)

    if synergy_results:
        names = {d["api_id"]: d["function"] for d in kb.documents}
        print("  상위 시너지 쌍:")
        for r in synergy_results[:3]:
            print(f"    {names.get(r.api_a, r.api_a)} <-> {names.get(r.api_b, r.api_b)}"
                  f" : {r.score}  {r.detail}")

    fuzzing_runs: list[FuzzingRun] = []
    schedule = allocate_resources(synergy_ranking, fuzzing_runs, budget_sec=budget_sec)

    print("\n  우선순위:")
    for r in schedule:
        print(f"    {r.group_name} | final={r.final_score} | 할당={r.allocated_sec}초")

    # ---- GEN ----------------------------------------------------------
    print("\n[GEN] 하네스 생성 중...")
    if dry_run:
        print("  (--dry-run: LLM 호출 없이 주입될 컨텍스트만 출력)")
        first = schedule[0].group_name if schedule else None
        for api_id in logic_groups.get(first, [])[:3]:
            document = kb.api(api_id)
            if document:
                print("\n" + harness_context(kb, document["function"]))
        return 0

    # openai 의존성은 여기서만 필요하므로 늦게 임포트한다.
    try:
        from logosfuzz.generate.gen_03_01_harness_generator import (
            VECTOR_DB_MOCK, generate_harness,
        )
    except ImportError as exc:
        print(f"  [ERROR] GEN 모듈을 불러오지 못했습니다: {exc}")
        print("  openai 패키지가 필요합니다:  pip install openai")
        print("  LLM 없이 컨텍스트만 확인하려면 --dry-run 을 쓰세요.")
        return 1

    # 목업 Vector DB 자리에 실제 지식베이스를 넣는다.
    VECTOR_DB_MOCK.clear()
    VECTOR_DB_MOCK.update(to_api_contexts(kb))

    drivers = generate_harness(schedule, logic_groups)

    print(f"\n[OUT] {output_path} 저장 중...")
    with open(output_path, "w", encoding="utf-8") as f:
        for d in drivers:
            f.write(f"// === {d.group_name} ===\n")
            code = d.code.replace("```c", "").replace("```", "").strip()
            f.write(code + "\n\n")

    print(f"  저장 완료: {output_path}")
    print("\n=== 파이프라인 완료 ===")
    return 0


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="EXT → SCH → GEN 파이프라인")
    parser.add_argument("--source", help="분석할 C/C++ 소스 파일 또는 디렉터리")
    parser.add_argument("--compile-db", help="compile_commands.json 경로 (EXT-01-03)")
    parser.add_argument("--output", default="harness_output.c", help="출력 하네스 파일")
    parser.add_argument("--budget", type=int, default=3600, help="총 퍼징 예산(초)")
    parser.add_argument("--group-size", type=int, default=0,
                        help="0이면 소스 파일 단위로 묶고, N이면 N개씩 묶는다")
    parser.add_argument("--dry-run", action="store_true",
                        help="LLM을 호출하지 않고 주입될 컨텍스트만 출력")
    args = parser.parse_args(argv)
    if not args.source and not args.compile_db:
        parser.error("--source 또는 --compile-db 중 하나는 필요합니다")
    return args


def main(argv=None) -> int:
    load_env()
    args = parse_args(argv)
    return run_pipeline(
        args.source, args.output, args.budget,
        compile_db=args.compile_db, dry_run=args.dry_run, group_size=args.group_size,
    )


if __name__ == "__main__":
    sys.exit(main())
