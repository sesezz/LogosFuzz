"""ANA-05-01 정/오탐 판별 회귀 테스트."""

from __future__ import annotations

from pathlib import Path

from logosfuzz.analyze.dedup import deduplicate
from logosfuzz.analyze.loader import load_jsonl_findings
from logosfuzz.analyze.models import CrashCluster, CrashRecord, Frame, Verdict
from logosfuzz.analyze.triage import (
    LLMTriager,
    RuleBasedTriager,
    build_triage_prompt,
    parse_llm_verdict,
    rule_triage,
    summarize,
    triage_clusters,
)

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "sanitizer_dlt.jsonl"


def _cluster(category, frames, count=1, sanitizer="ASAN"):
    rep = CrashRecord(
        sanitizer=sanitizer,
        category=category,
        error_reason=f"{category} detected",
        traceback=[Frame(f, ln) for f, ln in frames],
    )
    return CrashCluster(
        cluster_id="CL-test",
        signature=f"{category}@test",
        bug_type=category,
        representative=rep,
        members=[rep] * count,
    )


def test_mocking_failure_is_false_positive():
    c = _cluster("mocking-fail-fp", [("/src/harness/mock_can_transport.c", 88)])
    r = rule_triage(c)
    assert r.verdict is Verdict.FALSE_POSITIVE
    assert r.confidence >= 0.85
    assert "mocking-fail-fp" in r.signals


def test_memory_bug_in_app_code_is_true_positive():
    c = _cluster(
        "use-after-free",
        [("/src/dlt-daemon/src/shared/dlt_common.c", 842),
         ("/src/harness/h.c", 41)],
        count=3,
    )
    r = rule_triage(c)
    assert r.verdict is Verdict.TRUE_POSITIVE
    assert r.confidence <= 0.95  # 절대 확신 회피
    assert "target-code-frame" in r.signals
    assert "highly-reproducible" in r.signals


def test_harness_only_crash_not_true_positive():
    c = _cluster("heap-buffer-overflow", [("/src/harness/only_harness.c", 12)])
    r = rule_triage(c)
    assert r.verdict is not Verdict.TRUE_POSITIVE
    assert "harness-only-frame" in r.signals


def test_ambiguous_realtime_timeout_needs_review():
    # watchdog-timeout(0.35) + 대상코드(+0.20) = 0.55 → 판정 모호
    c = _cluster("watchdog-timeout", [("/src/dlt-daemon/src/core/loop.c", 50)])
    r = rule_triage(c)
    assert r.verdict is Verdict.NEEDS_REVIEW


def test_confidence_in_unit_range():
    for cat, frames in [
        ("use-after-free", [("/src/x/a.c", 1)]),
        ("unknown", [("/src/harness/h.c", 2)]),
        ("race-condition", [("/src/x/b.c", 3)]),
    ]:
        r = rule_triage(_cluster(cat, frames))
        assert 0.0 <= r.confidence <= 1.0


def test_triage_dict_matches_ana0502_contract():
    r = rule_triage(_cluster("use-after-free", [("/src/x/a.c", 1)], count=2))
    d = r.to_triage_dict()
    assert set(d.keys()) == {"verdict", "confidence", "rationale", "triage_model"}
    assert d["verdict"] in {"true_positive", "false_positive", "needs_review"}


def test_summarize_counts():
    clusters, _ = deduplicate(load_jsonl_findings(SAMPLE))
    results = triage_clusters(clusters, RuleBasedTriager())
    summary = summarize(results)
    assert sum(summary.values()) == len(clusters) == 4
    # 샘플: UAF/double-free/buffer-overflow 는 정탐 계열, mocking-fail-fp 는 오탐
    assert summary["false_positive"] >= 1
    assert summary["true_positive"] >= 1


# --- LLM 판별기 ---

class _ScriptedClient:
    def __init__(self, response):
        self.response = response
        self.last_prompt = None

    def complete(self, prompt, *, system=""):
        self.last_prompt = prompt
        return self.response


class _FailingClient:
    def complete(self, prompt, *, system=""):
        raise RuntimeError("no model")


def test_llm_triager_uses_valid_response():
    client = _ScriptedClient('여기 결과: {"verdict": "false_positive", "confidence": 0.8, "rationale": "하네스 문제"}')
    c = _cluster("use-after-free", [("/src/x/a.c", 1)])
    r = LLMTriager(client, model_name="deepseek-r1").triage(c)
    assert r.verdict is Verdict.FALSE_POSITIVE
    assert r.triage_model == "deepseek-r1"
    assert "llm-judgment" in r.signals


def test_llm_triager_falls_back_on_bad_json():
    client = _ScriptedClient("판별 불가, JSON 없음")
    c = _cluster("use-after-free", [("/src/dlt/a.c", 1)], count=2)
    r = LLMTriager(client).triage(c)
    # 폴백은 규칙 기반 결과 + 사유 신호
    assert "llm-parse-failed" in r.signals


def test_llm_triager_falls_back_on_exception():
    c = _cluster("use-after-free", [("/src/dlt/a.c", 1)])
    r = LLMTriager(_FailingClient()).triage(c)
    assert "llm-call-failed" in r.signals


def test_parse_llm_verdict_rejects_invalid_verdict():
    assert parse_llm_verdict('{"verdict": "maybe", "confidence": 0.5}') is None
    assert parse_llm_verdict("no json here") is None
    assert parse_llm_verdict('{"confidence": 0.5}') is None


def test_build_prompt_contains_key_fields():
    c = _cluster("use-after-free", [("/src/x/a.c", 42)], count=5)
    prompt = build_triage_prompt(c)
    assert "use-after-free" in prompt
    assert "a.c:42" in prompt
    assert "5" in prompt
