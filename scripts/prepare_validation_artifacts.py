"""최종 EC2 검증 기록을 표준 JSON 입력으로 변환한다.

사용 예:
    python scripts/prepare_validation_artifacts.py \
      --legacy validation-summary-ec2-final.json

원본 최종 보고서를 수정하지 않고, 대상 선정 결과·GEN 메타데이터를 별도
입력으로 만든 뒤 생성된 SCORE 최종 실행을 표준 validation-summary로
정규화한다. GEN-03-04 실제 게이트 로그가 없는 경우에는 결과에
``gen.gate_status=not_run``이 남아 과장된 성공으로 기록되지 않는다.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from logosfuzz.reporting.summary import build_validation_summary, write_validation_summary


def _write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy", type=Path, required=True, help="validation-summary-ec2-final.json")
    parser.add_argument("--gen-gate", type=Path, default=None,
                        help="GEN-03-04 gen_validation_summary.json 경로(선택)")
    parser.add_argument("--output-dir", type=Path, default=None)
    args = parser.parse_args(argv)

    legacy = json.loads(args.legacy.read_text(encoding="utf-8"))
    output_dir = args.output_dir or args.legacy.parent
    output_dir.mkdir(parents=True, exist_ok=True)

    selection = {
        "status": "completed",
        "source": "validation-summary-ec2-final.json / ext_sch",
        "targets": [
            {"target": name, **value}
            for name, value in legacy.get("ext_sch", {}).items()
            if isinstance(value, dict)
        ],
        "known_issues": [
            "score_common은 제약 조건 커버리지 0.0으로 기록되어 후속 대상 선정 개선이 필요하다.",
            "score_broad는 대상 그룹이 682개로 넓어 우선순위 필터가 필요하다.",
        ],
    }
    selection_path = output_dir / "validation-target-selection-ec2.json"
    _write_json(selection_path, selection)

    gen = legacy.get("gen", {})
    if not isinstance(gen, dict):
        gen = {"status": "not_run"}
    if args.gen_gate:
        gate = json.loads(args.gen_gate.read_text(encoding="utf-8"))
        compact = gen.get("real", {})
        compact_by_id = compact if isinstance(compact, dict) else {}
        # 게이트 결과에는 실행 상태가, 기존 최종 기록에는 생성/수선 시도가
        # 있으므로 두 기록을 group_id 기준으로 합친다.
        merged = dict(gate)
        merged["model"] = (
            compact.get("model", "") if isinstance(compact, dict) else ""
        )
        outcomes = []
        for outcome in gate.get("outcomes", []):
            item = dict(outcome)
            info = compact_by_id.get(item.get("group_id"), {})
            if not isinstance(info, dict):
                info = {}
            item.update({
                key: info[key]
                for key in ("generation_attempts", "repair_attempts", "source", "binary")
                if key in info
            })
            outcomes.append(item)
        merged["outcomes"] = outcomes
        gen = merged
    gen_path = output_dir / "validation-gen-ec2.json"
    _write_json(gen_path, gen)

    exe_ana = legacy.get("exe_ana", {})
    run = exe_ana.get("generated_score_300s_fixed")
    analysis = exe_ana.get("generated_score_300s_fixed_ana")
    if not isinstance(run, dict):
        raise SystemExit("legacy 보고서에 exe_ana.generated_score_300s_fixed가 없습니다")
    if not isinstance(analysis, dict):
        analysis = None

    summary = build_validation_summary(
        run,
        analysis,
        metadata={
            "project": "LogosFuzz",
            "environment": "ec2",
            "target": "generated_score_fuzzer",
            "instance": legacy.get("instance", ""),
            "region": legacy.get("region", ""),
            "source_report": args.legacy.name,
        },
        generation_summary=gen,
        selection_summary=selection,
    )
    summary_path = output_dir / "validation-summary-ec2-generated-score-fixed.json"
    write_validation_summary(summary_path, summary)

    print(f"selection: {selection_path}")
    print(f"generation: {gen_path}")
    print(f"summary: {summary_path}")
    print(
        f"gen gate={summary['gen']['gate_status']} | "
        f"selection targets={len(summary['selection']['targets'])} | "
        f"crashes={summary['metrics']['crashes']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
