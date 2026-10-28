"""시드 스모크 자가치유 데모 (GENERIC-B)

결함이 있는 하네스 하나를 빌드해서 시드 스모크로 실행하고, 하네스 결함 증거가 나오면 실제 LLM 으로 고쳐 다시 빌드한다.
전체 `logosfuzz run` 을 돌리지 않고 수정 단계만 보고 싶을 때 쓴다(LLM 호출 1~2회, 1~2분).

    python scripts/demo_smoke_repair.py \\
        --harness out/libsndfile-run12-depth/build/harness/lg_sndfile.c

기본 대상은 `targets/libsndfile.json`, 모델은 `gpt-4o`. OPENAI_API_KEY 가 필요하다.
결과는 임시 폴더(`--work-dir`)에만 쓰고 저장소 파일은 건드리지 않는다.
"""
from __future__ import annotations

import argparse
import difflib
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="시드 스모크 자가치유 데모")
    parser.add_argument("--harness", required=True, type=Path, help="결함이 있는 하네스 소스(.c)")
    parser.add_argument("--profile", type=Path, default=REPO / "targets" / "libsndfile.json")
    parser.add_argument("--model", default="gpt-4o")
    parser.add_argument("--rounds", type=int, default=2)
    parser.add_argument("--work-dir", type=Path, default=None)
    args = parser.parse_args(argv)

    from logosfuzz.common.target_profile import load_profile
    from logosfuzz.execute.seeds import profile_seed_paths
    from logosfuzz.generate.build import HarnessSpec, adapter_for
    from logosfuzz.generate.hygiene import sanitize_harness
    from logosfuzz.generate.llm import OpenAILLMClient
    from logosfuzz.generate.smoke import smoke_repair

    profile = load_profile(args.profile, base_dir=REPO)
    seeds = profile_seed_paths(profile)
    source = args.harness.read_text(encoding="utf-8")
    work = args.work_dir or Path(tempfile.mkdtemp(prefix="smoke-demo-"))

    adapter = adapter_for(profile, work_dir=work)
    prepared = adapter.prepare()
    print(f"[PREPARE] {'OK' if prepared.ok else 'FAIL'} ({prepared.duration_s:.1f}s)")
    if not prepared.ok:
        print(prepared.short_log)
        return 1

    spec = HarnessSpec(name="demo_harness", srcs=("demo_harness.c",))

    def build(text: str):
        adapter.emit_build_definition(spec, text)
        result = adapter.build(spec)
        if not result.ok:
            print(result.short_log)
        return Path(result.binary) if result.ok and result.binary else None

    binary = build(source)
    if binary is None:
        print("[오류] 원본 하네스가 빌드되지 않는다")
        return 1
    print(f"[BUILD] 원본 하네스 빌드 OK -> {binary}")

    llm = OpenAILLMClient(model=args.model)
    outcome = smoke_repair(
        binary, source, seeds=seeds, profile=profile,
        complete=lambda prompt, system: llm.complete(prompt, system=system),
        rebuild=build, rounds=args.rounds, sanitize=sanitize_harness,
        log=print,
    )

    print(f"\n[결과] 상태={outcome.status} LLM수정={outcome.rounds}회 {outcome.detail}")
    if outcome.source != source:
        print("\n--- 하네스 변경 내용 (원본 -> 수정) ---")
        diff = difflib.unified_diff(source.splitlines(), outcome.source.splitlines(),
                                    "원본", "수정", lineterm="", n=2)
        print("\n".join(diff))
    return 0 if outcome.status in ("clean", "repaired") else 1


if __name__ == "__main__":
    raise SystemExit(main())
