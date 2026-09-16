"""기존에 생성된 하네스 바이너리에 GEN-03-04 게이트를 실행한다.

이 스크립트는 LLM을 호출하지 않는다. 이미 컴파일된 HarnessArtifact를
짧은 smoke/coverage/mock 단계로 검증하고, `gen_validation_summary.json`과
그룹별 로그를 남긴다.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from logosfuzz.generate.contracts import HarnessArtifact
from logosfuzz.generate.feedback_loop import run_validation_pipeline
from logosfuzz.generate.validation import ValidationConfig


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=100)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument(
        "artifacts", nargs="+", metavar="GROUP=BINARY[:SOURCE]",
        help="생성 하네스 그룹명=실행 파일 경로[:소스 경로]",
    )
    args = parser.parse_args(argv)

    artifacts = []
    for spec in args.artifacts:
        try:
            group_id, paths = spec.split("=", 1)
            binary, _, source = paths.partition(":")
        except ValueError as exc:
            raise SystemExit(f"아티팩트 형식 오류: {spec!r}") from exc
        artifacts.append(HarnessArtifact(
            group_id=group_id,
            harness_path=Path(binary),
            source_path=Path(source) if source else None,
        ))

    summary = run_validation_pipeline(
        artifacts,
        max_round=0,
        output_dir=args.output_dir,
        config=ValidationConfig(runs=args.runs, timeout_sec=args.timeout),
    )
    print(f"summary: {args.output_dir / 'gen_validation_summary.json'}")
    print(f"validated={len(summary.passed_groups)} failed={len(summary.failed_groups)}")
    return 0 if not summary.failed_groups else 3


if __name__ == "__main__":
    raise SystemExit(main())
