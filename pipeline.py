"""
pipeline.py : EXT → SCH → GEN 전체 파이프라인 연계

실행 방법
---------
python pipeline.py --source test_target.c --output harness_output.c
"""

from __future__ import annotations
import os
import re
import json
import argparse
import subprocess
import tempfile
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
from gen_03_03_mock_injector import build_mock_plan, insert_mocks


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

_UNDEF_RE = re.compile(
    r"undefined (?:reference to|symbol:)\s*[`']?([A-Za-z_][A-Za-z0-9_]*)"
)


def build_signature_map(ext_json: list[dict]) -> dict[str, str]:
    """심볼명 → 시그니처 문자열. mock stub의 원형을 헤더 선언과 맞추기 위한 것.

    ``ext_to_api_metadata``와 달리 대상 소스에 정의된 함수로 한정하지 않는다.
    모킹해야 할 심볼은 대개 다른 번역 단위에 있고, 그 선언은 헤더에서만
    보이기 때문이다(그래서 include 경로가 EXT에 반드시 전달돼야 한다).
    """
    sigs: dict[str, str] = {}
    for file_result in ext_json:
        for n in file_result.get("nodes", []):
            if n.get("kind") != "FUNCTION_DECL":
                continue
            name = n.get("spelling")
            if not name or name in sigs:
                continue
            params = n.get("params") or []
            param_str = ", ".join(
                f"{p['type']} {p['name']}".strip() for p in params
            ) or "void"
            if n.get("is_variadic"):
                param_str = f"{param_str}, ..." if params else "..."
            sigs[name] = f"{n.get('return_type') or 'int'} {name}({param_str})"
    return sigs


def collect_undefined_symbols(harness_code: str, source_path: str,
                              include_dirs: list[str], *, cc: str = "clang",
                              group: str = "h") -> list[str]:
    """하네스를 대상 소스와 실제로 링크해보고 미정의 심볼 목록을 돌려준다.

    컴파일(-c)만으로는 알 수 없다. 링크를 해봐야 다른 번역 단위의 함수가
    빠졌다는 사실이 드러난다.
    """
    with tempfile.TemporaryDirectory(prefix="logosfuzz_link_") as tmp:
        src = Path(tmp) / f"{group}.c"
        src.write_text(harness_code, encoding="utf-8")
        argv = [
            cc, "-g", "-O1", "-fsanitize=address,fuzzer",
            "-Dmain=main_disabled",
            *[f"-I{d}" for d in include_dirs],
            "-o", str(Path(tmp) / group),
            str(src), source_path,
        ]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=180)
        except (OSError, subprocess.TimeoutExpired):
            return []
        if proc.returncode == 0:
            return []
        # 순서를 유지하며 중복 제거
        return list(dict.fromkeys(_UNDEF_RE.findall(proc.stderr)))


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
                 include: list[str] | None = None, mock: bool = True):

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

    # GEN-03-03: 링크 단계에서 미정의 심볼이 남으면 mock stub을 주입한다.
    #
    # 컴파일(-c)만으로는 드러나지 않는다. 대상이 다른 번역 단위의 함수를
    # 부르면 컴파일은 통과하고 링크에서만 깨진다. dlt-daemon이 정확히 이
    # 경우로, dlt_common.c가 dlt_log.c의 함수(dlt_vlog 등 6개)를 호출해
    # 하네스 65개가 전부 컴파일 65/65 · 링크 0/65였다.
    #
    # can-utils(3단계)는 lib.c가 자기 완결적이라 이 단계가 필요 없었고,
    # 그래서 Mocking을 검증할 기회 자체가 없었다.
    if mock:
        print("\n[GEN-03-03] Mock 주입 (링크 미정의 심볼 대상)...")
        signatures = build_signature_map(ext_json)
        mock_stats = []
        for d in drivers:
            code = d.code.replace("```c", "").replace("```", "").strip()
            undefined = collect_undefined_symbols(
                code, source_path, include_dirs, cc=cc,
                group=d.group_name,
            )
            if not undefined:
                mock_stats.append((d.group_name, 0, True))
                continue
            plan = build_mock_plan(
                harness=d.group_name,
                defined=[],          # 미정의 심볼만 넘기므로 defined는 비운다
                called=undefined,
                signatures=signatures,
            )
            d.code = insert_mocks(code, plan)
            # 주입 후 실제로 링크가 되는지 재확인한다. 여기서 비어야 성공.
            remaining = collect_undefined_symbols(
                d.code, source_path, include_dirs, cc=cc,
                group=d.group_name,
            )
            mock_stats.append((d.group_name, len(plan.stubs), not remaining))
            print(f"  ▶ {d.group_name}: stub {len(plan.stubs)}개 주입"
                  f" → {'링크 OK' if not remaining else f'미해결 {remaining}'}")
        linked = sum(1 for _, _, ok in mock_stats if ok)
        total_stubs = sum(n for _, n, _ in mock_stats)
        print(f"\n[GEN-03-03] 링크 성공 {linked}/{len(mock_stats)}"
              f" (주입한 stub 총 {total_stubs}개)")
    else:
        print("\n[GEN-03-03] Mock 주입 생략(--no-mock)")

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
    parser.add_argument("--no-mock", dest="mock", action="store_false",
                        help="GEN-03-03 mock 주입 생략. 기본은 활성 — 대상이 "
                             "다른 번역 단위의 함수를 부르면 컴파일은 되고 "
                             "링크만 깨지므로 mock 없이는 퍼저를 만들 수 없다.")
    parser.add_argument("--include", "-I", action="append", metavar="DIR",
                        help="추가 include 경로(반복 지정 가능). 프로젝트 헤더가 "
                             "소스와 다른 디렉터리에 있으면 반드시 지정해야 한다 "
                             "— 없으면 EXT가 struct 포인터를 int로 오인한다.")
    args = parser.parse_args()

    run_pipeline(args.source, args.output, args.budget,
                 max_round=args.max_round, cc=args.cc,
                 include=args.include, mock=args.mock)
