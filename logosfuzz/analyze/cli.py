"""ANA 파트 CLI.

설계서 기능 흐름도의 ``analyze`` 단계(Step 5)를 담당한다.

    python -m logosfuzz.analyze.cli dedup <sanitizer-jsonl|dir|summary.json>... [-o out.json]

``dedup``: ANA-05-04. 크래시 결함 스트림 → 고유 클러스터 목록(JSON).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from logosfuzz.analyze.dedup import CrashDeduplicator
from logosfuzz.analyze.loader import load_records


def _write(path: str | None, payload: dict) -> None:
    if path:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _run_dedup(args: argparse.Namespace) -> int:
    dedup = CrashDeduplicator(depth=args.depth)
    dedup.extend(load_records(args.inputs))
    result = dedup.to_dict()
    _write(args.output, result)

    stats = result["stats"]
    print(
        f"[ANA-05-04] 결함 {stats['total_records']}건 → 고유 크래시 "
        f"{stats['unique_clusters']}개 (중복 {stats['duplicates_removed']}건 제거, "
        f"제거율 {stats['dedup_ratio']:.0%})"
    )
    for c in result["clusters"]:
        print(f"  - {c['cluster_id']}  x{c['count']:<3} {c['bug_type']:<18} @ {c['crash_location'] or 'unknown'}")
    if args.output:
        print(f"  → {args.output}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="logosfuzz-analyze", description="ANA 크래시 분석 단계")
    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser("dedup", help="ANA-05-04 크래시 중복 제거")
    d.add_argument("inputs", nargs="+",
                   help="sanitizer JSONL 파일 / 디렉터리(out/logs/sanitizer) / fuzz_summary.json")
    d.add_argument("--depth", type=int, default=3, help="시그니처 상위 프레임 수(기본 3)")
    d.add_argument("--output", "-o", help="클러스터 결과 JSON 저장 경로")
    d.set_defaults(func=_run_dedup)
    return p


def main(argv: list | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
