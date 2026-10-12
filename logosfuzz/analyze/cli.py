"""ANA 파트 CLI.

설계서 기능 흐름도의 ``analyze`` 단계(Step 5/6)를 담당한다.

    python -m logosfuzz.analyze.cli dedup   <sanitizer-jsonl|dir|summary.json>... [-o out.json]
    python -m logosfuzz.analyze.cli triage  <dedup.json | sanitizer 입력...>     [-o out.json]
    python -m logosfuzz.analyze.cli analyze <sanitizer 입력...>                   [-o out.json]

``dedup``  : ANA-05-04. 크래시 결함 스트림 → 고유 클러스터 목록(JSON).
``triage`` : ANA-05-01. 클러스터(또는 원시 입력) → 정/오탐 판별 결과(JSON).
``analyze``: dedup → triage 를 한 번에 실행하는 파이프라인 편의 명령.

크래시 승인 게이트 (CTR-06-02 CRASH_TRIAGE, 4주차 활성화)
--------------------------------------------------------
``triage``/``analyze`` 는 판정을 낸 고유 크래시마다 승인 게이트를 태운다.
자동 판정이 확실하면(정책: 신뢰도 0.8 이상, needs_review 아님) 자동 승인되고,
아니면 리뷰 저장소(기본 ``.logosfuzz/hitl/reviews.json``)에 쌓인다. 사람이
``logosfuzz review approve|edit|reject <id>`` 로 결정한 뒤 다시 돌리면 반영된다.

출력의 ``verified_crashes`` 가 **검증된 고유 크래시 목록**이다 - 게이트에서 정탐으로
확정된 것만 담는다. ``summary`` 는 지금처럼 자동 판정 집계이고(ANA-05-02 계약
유지), 게이트 결과는 ``approval_summary`` 에 따로 둔다. ``--no-approval-gate`` 면
게이트를 건너뛰고 예전 출력 그대로다.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from logosfuzz.analyze.dedup import CrashDeduplicator
from logosfuzz.analyze.error_contract import KnowledgeBaseContractProvider
from logosfuzz.analyze.loader import load_records
from logosfuzz.analyze.models import CrashCluster
from logosfuzz.analyze.reachability import SourceReachabilityProvider
from logosfuzz.analyze.triage import (
    LLMTriager,
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


def _triager_for_args(
    args: argparse.Namespace,
) -> tuple[RuleBasedTriager | LLMTriager, SourceReachabilityProvider | None]:
    """CLI 옵션에 따라 도달 가능성 증거를 주입한 판별기를 만든다.

    ``--source-root``를 주지 않으면 기존 규칙 기반 동작을 그대로 유지한다.
    소스 루트를 지정한 경우에만 ANA-05-01이 대상 함수의 정의, 공개 헤더,
    프로덕션/하네스 호출부를 수집한다. 하네스 디렉터리는 선택 사항이라,
    크래시 콜스택의 하네스 소스까지 연결할 때만 지정하면 된다.
    """
    provider = None
    if getattr(args, "source_root", None):
        provider = SourceReachabilityProvider(args.source_root, args.harness_dir)
    contracts = _contract_provider_for_args(args)

    fallback = RuleBasedTriager(context_provider=provider, contract_provider=contracts)
    if not getattr(args, "llm", False):
        return fallback, provider

    from logosfuzz.generate.llm import OpenAILLMClient

    model = getattr(args, "model", "gpt-4o-mini")
    return (
        LLMTriager(
            client=OpenAILLMClient(model=model),
            model_name=model,
            fallback=fallback,
            context_provider=provider,
            contract_provider=contracts,
        ),
        provider,
    )


def _contract_provider_for_args(args: argparse.Namespace) -> KnowledgeBaseContractProvider:
    """에러계약 근거 공급자. ``--kb`` 가 있으면 선언된 계약·Bazel 타깃까지 본다."""
    cached = getattr(args, "_contract_provider", None)
    if cached is not None:
        return cached
    kb = None
    if getattr(args, "kb", None):
        from logosfuzz.knowledge.knowledge_base import KnowledgeBase

        kb = KnowledgeBase.load(args.kb)
    provider = KnowledgeBaseContractProvider(kb)
    args._contract_provider = provider
    return provider


def _contract_dict(args: argparse.Namespace, cluster: CrashCluster) -> dict:
    try:
        return _contract_provider_for_args(args)(cluster).to_dict()
    except Exception as exc:  # 근거 수집 실패가 출력 전체를 막지 않도록 한다.
        return {"error": f"error-contract analysis failed: {exc}"}


# --------------------------------------------------------------------------- #
# 크래시 승인 게이트
# --------------------------------------------------------------------------- #
def _approval_gate_for_args(args: argparse.Namespace):
    if getattr(args, "no_approval_gate", False):
        return None
    from logosfuzz.control.hitl import (
        CrashApprovalGate,
        HITLManager,
        HITLPolicy,
        JsonReviewStore,
    )

    store = JsonReviewStore(getattr(args, "review_store", None) or JsonReviewStore.DEFAULT_PATH)
    hitl = HITLManager(store=store, policy=HITLPolicy.default())
    return CrashApprovalGate(hitl, project=getattr(args, "project", "") or "")


def _gate_results(gate, clusters: dict, results, evidence: dict) -> dict:
    """판정 결과를 승인 게이트에 태운다. cluster_id -> CrashApproval."""
    approvals = {}
    for r in results:
        cluster = clusters.get(r.cluster_id)
        if cluster is None:
            continue
        rep = cluster.representative
        contract = evidence.get(r.cluster_id) or {}
        location = cluster.to_dict()["crash_location"] or "unknown"
        approvals[r.cluster_id] = gate.review(
            r.cluster_id,
            r.verdict.value,
            r.confidence,
            summary=(f"[{cluster.bug_type} x{cluster.count}] {cluster.signature} → "
                     f"판정={r.verdict.value} (conf={r.confidence:.2f})"),
            payload={
                "crash_signature": cluster.signature,
                "bug_type": cluster.bug_type,
                "count": cluster.count,
                "sanitizer": rep.sanitizer,
                "crash_location": location,
                "rationale": r.rationale,
                "signals": list(r.signals),
                "error_contract": contract,
                "build_target": contract.get("build_target"),
                "stacktrace": "\n".join(rep.raw_log[:40]),
            },
        )
    return approvals


def _approval_summary(approvals: dict) -> dict:
    counts = {"verified": 0, "approved": 0, "edited": 0, "rejected": 0,
              "skipped": 0, "pending": 0, "by_human": 0}
    for a in approvals.values():
        counts[a.status] = counts.get(a.status, 0) + 1
        counts["verified"] += int(a.verified)
        counts["by_human"] += int(a.by_human)
    counts["total"] = len(approvals)
    return counts


def _verified_crashes(clusters: dict, results, approvals: dict, evidence: dict) -> list:
    """검증된 고유 크래시 목록 - 승인 게이트에서 정탐으로 확정된 것만."""
    verified = []
    for r in results:
        approval = approvals.get(r.cluster_id)
        if approval is None or not approval.verified:
            continue
        c = clusters[r.cluster_id].to_dict()
        contract = evidence.get(r.cluster_id) or {}
        verified.append({
            "cluster_id": r.cluster_id,
            "signature": c["signature"],
            "bug_type": c["bug_type"],
            "count": c["count"],
            "crash_location": c["crash_location"],
            "crash_function": contract.get("crash_function"),
            "build_target": contract.get("build_target"),
            "crash_inputs": c["crash_inputs"],
            "auto_verdict": approval.auto_verdict,
            "auto_confidence": round(float(r.confidence), 4),
            "approved_by": approval.reviewer,
            "by_human": approval.by_human,
            "review_item_id": approval.item_id,
        })
    return verified


def _print_gate(approvals: dict, verified: list) -> None:
    if not approvals:
        return
    s = _approval_summary(approvals)
    print(
        f"[CRASH_TRIAGE 게이트] 검증된 고유 크래시 {s['verified']}개 | "
        f"승인 {s['approved']} · 수정 {s['edited']} · 반려 {s['rejected']} · "
        f"검토대기 {s['pending']} (사람 결정 {s['by_human']}건)"
    )
    for v in verified:
        print(f"  ✓ {v['cluster_id']}  {v['bug_type']} @ {v['crash_location'] or 'unknown'}"
              f"  ({'사람' if v['by_human'] else '자동'} 승인)")
    if s["pending"]:
        print("  → 대기 항목은 'logosfuzz review list' 로 확인 후 approve/edit/reject")


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
    evidence = {c.cluster_id: _contract_dict(args, c) for c in clusters}
    gate = _approval_gate_for_args(args)
    approvals = _gate_results(gate, by_id, results, evidence) if gate else {}
    payload = {
        "triage_model": triager.model_name,
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
                "error_contract": evidence.get(r.cluster_id),
                "approval": approvals[r.cluster_id].to_dict()
                if r.cluster_id in approvals else None,
            }
            for r in results
        ],
    }
    if gate is not None:
        verified = _verified_crashes(by_id, results, approvals, evidence)
        payload["approval_summary"] = _approval_summary(approvals)
        payload["verified_crashes"] = verified
    _write(args.output, payload)

    print(
        f"[ANA-05-01] 고유 크래시 {len(results)}개 판별 → "
        f"정탐 {summary['true_positive']} · 오탐 {summary['false_positive']} · "
        f"검토필요 {summary['needs_review']}"
    )
    for item in payload["results"]:
        tr = item["triage_result"]
        print(f"  - {item['cluster_id']}  {tr['verdict']:<14} conf={tr['confidence']:.2f}  {item['bug_type']}")
    if gate is not None:
        _print_gate(approvals, payload["verified_crashes"])
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
    by_id = {c.cluster_id: c for c in clusters}
    evidence = {c.cluster_id: _contract_dict(args, c) for c in clusters}
    gate = _approval_gate_for_args(args)
    approvals = _gate_results(gate, by_id, results, evidence) if gate else {}

    payload = {
        "dedup": dedup.to_dict(),
        "triage_model": triager.model_name,
        "summary": summary,
        "findings": [
            {
                **c.to_dict(),
                "triage_result": tri_by_id[c.cluster_id].to_triage_dict(),
                "signals": tri_by_id[c.cluster_id].signals,
                "reachability": _reachability_dict(provider, c),
                "error_contract": evidence.get(c.cluster_id),
                "approval": approvals[c.cluster_id].to_dict()
                if c.cluster_id in approvals else None,
            }
            for c in clusters
        ],
    }
    if gate is not None:
        payload["approval_summary"] = _approval_summary(approvals)
        payload["verified_crashes"] = _verified_crashes(by_id, results, approvals, evidence)
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
    if gate is not None:
        _print_gate(approvals, payload["verified_crashes"])
    if args.output:
        print(f"  → {args.output}")
    return 0


def add_gate_arguments(parser: argparse.ArgumentParser) -> None:
    """triage/analyze 공통: 에러계약 KB 와 크래시 승인 게이트 옵션."""
    parser.add_argument("--kb", help="지식베이스 JSON(에러계약·Bazel 타깃 근거, 선택)")
    parser.add_argument("--review-store", dest="review_store",
                        help="HITL 리뷰 저장소 경로(기본 .logosfuzz/hitl/reviews.json)")
    parser.add_argument("--project", default="", help="리뷰 항목에 붙일 프로젝트 이름")
    parser.add_argument("--no-approval-gate", dest="no_approval_gate", action="store_true",
                        help="CRASH_TRIAGE 승인 게이트를 건너뛴다(예전 출력)")


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
    t.add_argument("--llm", action="store_true", help="LLM 기반 판별 사용(기본: 규칙 기반)")
    t.add_argument("--model", default="gpt-4o-mini", help="--llm일 때 사용할 모델")
    add_gate_arguments(t)
    t.set_defaults(func=_run_triage)

    a = sub.add_parser("analyze", help="dedup→triage 파이프라인")
    a.add_argument("inputs", nargs="+", help="원시 sanitizer 입력(JSONL/dir/summary)")
    a.add_argument("--depth", type=int, default=3, help="시그니처 상위 프레임 수(기본 3)")
    a.add_argument("--output", "-o", help="통합 결과 JSON 저장 경로")
    a.add_argument("--source-root", help="대상 C/C++ 소스 트리(도달 가능성 증거 수집)")
    a.add_argument("--harness-dir", help="크래시를 낸 하네스 소스 디렉터리(선택)")
    a.add_argument("--llm", action="store_true", help="LLM 기반 판별 사용(기본: 규칙 기반)")
    a.add_argument("--model", default="gpt-4o-mini", help="--llm일 때 사용할 모델")
    add_gate_arguments(a)
    a.set_defaults(func=_run_analyze)
    return p


def main(argv: list | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
