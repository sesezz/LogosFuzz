"""ANA 파트 CLI.

설계서 기능 흐름도의 ``analyze`` 단계(Step 5/6)를 담당한다.

    python -m logosfuzz.analyze.cli dedup   <sanitizer-jsonl|dir|summary.json>... [-o out.json]
    python -m logosfuzz.analyze.cli triage  <dedup.json | sanitizer 입력...>     [-o out.json]
    python -m logosfuzz.analyze.cli analyze <sanitizer 입력...>                   [-o out.json]

``dedup``  : ANA-05-04. 크래시 결함 스트림 → 고유 클러스터 목록(JSON).
``triage`` : ANA-05-01. 클러스터(또는 원시 입력) → 정/오탐 판별 결과(JSON).
``analyze``: dedup → triage 를 한 번에 실행하는 파이프라인 편의 명령.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from logosfuzz.analyze.dedup import CrashDeduplicator
from logosfuzz.analyze.loader import load_records
from logosfuzz.analyze.models import CrashCluster
from logosfuzz.analyze.reachability import SourceReachabilityProvider
from logosfuzz.analyze.triage import (
    RuleBasedTriager,
    summarize,
    triage_clusters,
)


def _write(path: str | None, payload: dict) -> None:
    if path:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _clusters_from_inputs(inputs: list[str], depth: int) -> tuple[list[CrashCluster], dict]:
    """입력이 dedup.json이면 클러스터를 복원하고, 원시 입력이면 dedup을 실행한다."""
    if len(inputs) == 1 and Path(inputs[0]).suffix == ".json":
        data = json.loads(Path(inputs[0]).read_text(encoding="utf-8"))
        if isinstance(data, dict) and "clusters" in data:
            clusters = [CrashCluster.from_dict(c) for c in data["clusters"]]
            return clusters, {"source": "dedup-json", **data.get("stats", {})}
    dedup = CrashDeduplicator(depth=depth)
    dedup.extend(load_records(inputs))
    return dedup.clusters(), {"source": "raw-sanitizer", **dedup.stats().to_dict()}


def _triager_for_args(args: argparse.Namespace) -> tuple[RuleBasedTriager, SourceReachabilityProvider | None]:
    """CLI 옵션에 따라 도달 가능성 증거를 주입한 판별기를 만든다.

    ``--source-root``를 주지 않으면 기존 규칙 기반 동작을 그대로 유지한다.
    소스 루트를 지정한 경우에만 ANA-05-01이 대상 함수의 정의, 공개 헤더,
    프로덕션/하네스 호출부를 수집한다. 하네스 디렉터리는 선택 사항이라,
    크래시 콜스택의 하네스 소스까지 연결할 때만 지정하면 된다.
    """
    provider = None
    if args.source_root:
        provider = SourceReachabilityProvider(args.source_root, args.harness_dir)
    return RuleBasedTriager(context_provider=provider), provider


def _reachability_dict(provider, cluster: CrashCluster) -> dict | None:
    """판별 결과에 소스 근거를 보존한다(ANA/JSON 소비용)."""
    if provider is None:
        return None
    try:
        return provider(cluster).to_dict()
    except Exception as exc:  # 분석 실패가 판별 전체를 막지 않도록 한다.
        return {"error": f"reachability analysis failed: {exc}"}


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


def _run_triage(args: argparse.Namespace) -> int:
    clusters, meta = _clusters_from_inputs(args.inputs, args.depth)
    triager, provider = _triager_for_args(args)
    results = triage_clusters(clusters, triager)
    summary = summarize(results)

    by_id = {c.cluster_id: c for c in clusters}
    payload = {
        "triage_model": RuleBasedTriager.model_name,
        "input": meta,
        "summary": summary,
        "results": [
            {
                "cluster_id": r.cluster_id,
                "bug_type": by_id[r.cluster_id].bug_type if r.cluster_id in by_id else "",
                "signature": by_id[r.cluster_id].signature if r.cluster_id in by_id else "",
                "count": by_id[r.cluster_id].count if r.cluster_id in by_id else 0,
                "triage_result": r.to_triage_dict(),  # ← ANA-05-02 입력 계약
                "signals": r.signals,
                "reachability": _reachability_dict(provider, by_id[r.cluster_id])
                if r.cluster_id in by_id else None,
            }
            for r in results
        ],
    }
    _write(args.output, payload)

    print(
        f"[ANA-05-01] 고유 크래시 {len(results)}개 판별 → "
        f"정탐 {summary['true_positive']} · 오탐 {summary['false_positive']} · "
        f"검토필요 {summary['needs_review']}"
    )
    for item in payload["results"]:
        tr = item["triage_result"]
        print(f"  - {item['cluster_id']}  {tr['verdict']:<14} conf={tr['confidence']:.2f}  {item['bug_type']}")
    if args.output:
        print(f"  → {args.output}")
    return 0


def _run_analyze(args: argparse.Namespace) -> int:
    """dedup → triage 파이프라인 한 번에."""
    dedup = CrashDeduplicator(depth=args.depth)
    dedup.extend(load_records(args.inputs))
    clusters = dedup.clusters()
    triager, provider = _triager_for_args(args)
    results = triage_clusters(clusters, triager)
    summary = summarize(results)
    tri_by_id = {r.cluster_id: r for r in results}

    payload = {
        "dedup": dedup.to_dict(),
        "triage_model": RuleBasedTriager.model_name,
        "summary": summary,
        "findings": [
            {
                **c.to_dict(),
                "triage_result": tri_by_id[c.cluster_id].to_triage_dict(),
                "signals": tri_by_id[c.cluster_id].signals,
                "reachability": _reachability_dict(provider, c),
            }
            for c in clusters
        ],
    }
    _write(args.output, payload)

    st = dedup.stats()
    print(
        f"[ANA analyze] 결함 {st.total_records}건 → 고유 {st.unique_clusters}개 "
        f"| 정탐 {summary['true_positive']} · 오탐 {summary['false_positive']} · "
        f"검토필요 {summary['needs_review']}"
    )
    for item in payload["findings"]:
        tr = item["triage_result"]
        print(f"  - {item['cluster_id']} x{item['count']:<3} {tr['verdict']:<14} "
              f"conf={tr['confidence']:.2f}  {item['bug_type']} @ {item['crash_location'] or 'unknown'}")
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

    t = sub.add_parser("triage", help="ANA-05-01 정/오탐 판별")
    t.add_argument("inputs", nargs="+", help="dedup.json 또는 원시 sanitizer 입력")
    t.add_argument("--depth", type=int, default=3, help="원시 입력일 때 dedup 프레임 수(기본 3)")
    t.add_argument("--output", "-o", help="판별 결과 JSON 저장 경로")
    t.add_argument("--source-root", help="대상 C/C++ 소스 트리(도달 가능성 증거 수집)")
    t.add_argument("--harness-dir", help="크래시를 낸 하네스 소스 디렉터리(선택)")
    t.set_defaults(func=_run_triage)

    a = sub.add_parser("analyze", help="dedup→triage 파이프라인")
    a.add_argument("inputs", nargs="+", help="원시 sanitizer 입력(JSONL/dir/summary)")
    a.add_argument("--depth", type=int, default=3, help="시그니처 상위 프레임 수(기본 3)")
    a.add_argument("--output", "-o", help="통합 결과 JSON 저장 경로")
    a.add_argument("--source-root", help="대상 C/C++ 소스 트리(도달 가능성 증거 수집)")
    a.add_argument("--harness-dir", help="크래시를 낸 하네스 소스 디렉터리(선택)")
    a.set_defaults(func=_run_analyze)
    return p


def main(argv: list | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
