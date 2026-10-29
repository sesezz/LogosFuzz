"""기존 `logosfuzz run` 결과 폴더로 validation-summary.json 을 다시 만든다 (GENERIC-B)

웹 리포트의 '하네스 생성 요약'이 "GEN 단계 미실행"으로 나오는 이전 실행 결과를, 다시 실행하지 않고 고칠 때 쓴다.

    python scripts/rebuild_validation_summary.py out/libsndfile-demo
    python scripts/rebuild_validation_summary.py out/libsndfile-demo --model gpt-4o

모델 이름은 `--model` > 결과 폴더의 `run_summary.json` 의 `model` 순으로 정한다.
모델을 기록하기 전에 만든 결과 폴더는 `--model` 로 직접 지정해야 리포트의 '모델' 칸이 채워진다.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))


def main(argv=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="logosfuzz run 결과 폴더로 validation-summary.json 을 다시 만든다")
    parser.add_argument("out", type=Path, help="결과 폴더 (예: out/libsndfile-demo)")
    parser.add_argument("--model", default="", help="LLM 모델 이름 (기본: run_summary.json 의 model)")
    args = parser.parse_args(argv)
    out = args.out
    load = lambda name: json.loads((out / name).read_text(encoding="utf-8"))

    from logosfuzz.common.target_profile import load_profile
    from logosfuzz.control.generic_run import generation_summary_from_groups
    from logosfuzz.reporting.summary import build_validation_summary, profile_metadata, write_validation_summary

    run = load("run_summary.json")
    profile = load_profile(Path(run["profile"]), base_dir=REPO)
    model = args.model or str(run.get("model") or "")
    result = build_validation_summary(
        load("fuzz_summary.json"),
        load("analysis.json") if (out / "analysis.json").is_file() else None,
        metadata=profile_metadata(profile),
        generation_summary=generation_summary_from_groups(run.get("groups", []), model),
    )
    write_validation_summary(out / "validation-summary.json", result)
    print(f"다시 만들었다: {out / 'validation-summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
