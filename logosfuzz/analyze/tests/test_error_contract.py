"""ANA-05-01 에러계약 위반 근거 회귀 테스트.

정답지는 실제 baselibs ``score/result`` 로 빌드해 수집한 크래시 원문이다
(``tests/fixtures/error_contract_logs``). EXE 의 sanitizer 파서부터 dedup,
판별까지 실제 경로를 그대로 태운다.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from logosfuzz.analyze.dedup import deduplicate
from logosfuzz.analyze.error_contract import (
    KnowledgeBaseContractProvider,
    analyze_error_contract,
    parse_frames,
    short_name,
)
from logosfuzz.analyze.models import CrashCluster, CrashRecord, Frame, Verdict
from logosfuzz.analyze.triage import LLMTriager, RuleBasedTriager, build_triage_prompt, rule_triage
from logosfuzz.execute.sanitizer import SanitizerMonitor
from logosfuzz.knowledge.knowledge_base import KnowledgeBase

FIXTURES = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "error_contract_logs"


def _record(name: str) -> CrashRecord:
    monitor = SanitizerMonitor()
    for line in (FIXTURES / name).read_text(encoding="utf-8").splitlines():
        monitor.feed(line)
    findings = monitor.finish()
    assert len(findings) == 1
    return CrashRecord.from_finding(findings[0].to_dict())


def _cluster(record: CrashRecord) -> CrashCluster:
    clusters, _ = deduplicate([record])
    return clusters[0]


# --------------------------------------------------------------------------- #
# 실제 로그
# --------------------------------------------------------------------------- #
def test_harness_ignoring_result_error_is_false_positive():
    record = _record("harness_unchecked.txt")
    evidence = analyze_error_contract(record)

    assert evidence.violation == "harness"
    assert "LLVMFuzzerTestOneInput" in evidence.caller.function
    assert "::value()" in evidence.accessor.function

    result = rule_triage(_cluster(record))
    assert result.verdict is Verdict.FALSE_POSITIVE
    assert "error-contract-violated-by-harness" in result.signals
    assert "하네스의 계약 위반" in result.rationale


def test_library_ignoring_result_error_is_true_positive():
    record = _record("library_unchecked.txt")
    evidence = analyze_error_contract(record)

    assert evidence.violation == "target"
    assert evidence.crash_function == "PayloadEnd"
    # operator* → value() 로 겹친 접근자 중 호출자 쪽(operator*)을 잡는다
    assert "operator*" in evidence.accessor.function

    result = rule_triage(_cluster(record))
    assert result.verdict is Verdict.TRUE_POSITIVE
    assert "error-contract-violated-by-target" in result.signals
    # 근거문 위치가 abort/raise 런타임 프레임이 아니라 실제 코드여야 한다
    assert "pthread_kill" not in result.rationale


def test_two_contract_violations_are_not_merged_by_dedup():
    """glibc abort 프레임이 시그니처를 차지하면 두 결함이 한 클러스터로 합쳐진다."""
    clusters, stats = deduplicate(
        [_record("harness_unchecked.txt"), _record("library_unchecked.txt")]
    )
    assert stats.unique_clusters == 2
    assert all("pthread_kill" not in c.signature for c in clusters)


def test_kb_attaches_build_target_and_declared_contracts():
    kb = KnowledgeBase(documents=[{
        "api_id": 7, "function": "PayloadEnd", "signature": "std::size_t PayloadEnd(...)",
        "file": "score/demo/length.cc", "line": 33, "text": "PayloadEnd",
        "build_target": "//score/demo:length",
        "constraints": [{
            "kind": "error_contract", "target": "return",
            "description": "score::Result may fail with `LengthErrc::kTooShort`",
            "confidence": 0.95,
        }],
    }])
    evidence = KnowledgeBaseContractProvider(kb)(_cluster(_record("library_unchecked.txt")))

    assert evidence.api_id == 7
    assert evidence.build_target == "//score/demo:length"
    assert evidence.declared_contracts == ["score::Result may fail with `LengthErrc::kTooShort`"]


# --------------------------------------------------------------------------- #
# 증명되지 않으면 신호를 내지 않는다
# --------------------------------------------------------------------------- #
def _synthetic(lines, category="heap-buffer-overflow", reason="heap-buffer-overflow"):
    rep = CrashRecord(
        sanitizer="ASAN", category=category, error_reason=reason,
        traceback=[Frame("/src/score/json/json.cc", 40)], raw_log=list(lines),
    )
    return CrashCluster(cluster_id="CL-x", signature="x", bug_type=category,
                        representative=rep, members=[rep])


def test_accessor_below_user_frame_is_not_a_violation():
    """value() 가 스택 아래쪽에 있을 뿐, 크래시는 그 위 사용자 코드에서 났다."""
    cluster = _synthetic([
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1",
        "    #0 0x1 in score::json::Walk(char const*) /src/score/json/json.cc:40",
        "    #1 0x2 in score::details::expected<int, score::result::Error>::value() & /b/expected.h:493",
        "    #2 0x3 in LLVMFuzzerTestOneInput /src/harness/json_fuzzer.cc:12",
    ])
    evidence = analyze_error_contract(cluster.representative)
    assert evidence.violation == ""
    assert not any(s.startswith("error-contract") for s in rule_triage(cluster).signals)


def test_declared_contract_bypassed_by_memory_error_adds_evidence():
    cluster = _synthetic([
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1",
        "    #0 0x1 in score::json::Parse(char const*, unsigned long) /src/score/json/json.cc:40",
        "    #1 0x2 in LLVMFuzzerTestOneInput /src/harness/json_fuzzer.cc:12",
    ])
    kb = KnowledgeBase(documents=[{
        "api_id": 1, "function": "Parse", "signature": "Result<Any> Parse(...)",
        "file": "/src/score/json/json.cc", "line": 30, "text": "Parse",
        "constraints": [{"kind": "error_contract", "description": "may fail with kParseError"}],
    }])
    baseline = rule_triage(cluster)
    contract = KnowledgeBaseContractProvider(kb)(cluster)
    boosted = rule_triage(cluster, contract=contract)

    assert "error-contract-bypassed" in boosted.signals
    assert "에러계약을 선언한 API" in boosted.rationale
    assert "error-contract-bypassed" not in baseline.signals


def test_triager_survives_failing_contract_provider():
    def boom(_cluster):
        raise RuntimeError("kb offline")

    cluster = _cluster(_record("library_unchecked.txt"))
    result = RuleBasedTriager(contract_provider=boom).triage(cluster)
    # 공급자가 죽으면 원문 로그만으로 계산한 근거로 돌아간다
    assert "error-contract-violated-by-target" in result.signals


# --------------------------------------------------------------------------- #
# LLM 판별기
# --------------------------------------------------------------------------- #
def test_prompt_carries_error_contract_evidence():
    prompt = build_triage_prompt(_cluster(_record("harness_unchecked.txt")))
    assert "[에러계약 증거]" in prompt
    assert "확인(has_value)을 빠뜨린 쪽: 하네스" in prompt


class _Client:
    def __init__(self, reply):
        self.reply = reply

    def complete(self, prompt, system=""):
        return self.reply


def test_llm_triager_tags_error_contract_context():
    cluster = _cluster(_record("library_unchecked.txt"))
    result = LLMTriager(
        _Client('{"verdict": "true_positive", "confidence": 0.9, "rationale": "x"}')
    ).triage(cluster)
    assert "error-contract-context" in result.signals


# --------------------------------------------------------------------------- #
# 파서
# --------------------------------------------------------------------------- #
def test_parse_frames_handles_unnamed_and_shared_object_frames():
    frames = parse_frames([
        "    #5 <ADDR>  (/lib/x86_64-linux-gnu/libstdc++.so.6+<ADDR>) (BuildId: <BUILDID>)",
        "    #6 <ADDR> in std::terminate() (/lib/x86_64-linux-gnu/libstdc++.so.6+<ADDR>) (BuildId: x)",
        "    #7 0x55 in score::demo::PayloadEnd(unsigned char const*, unsigned long) score/demo/length.cc:35:12",
        "    #0 0x1 in malloc asan_malloc_linux.cpp:69",  # 두 번째 스택은 읽지 않는다
    ])
    assert [f.index for f in frames] == [5, 6, 7]
    assert frames[0].function == ""
    assert frames[1].function == "std::terminate()" and frames[1].file == ""
    assert frames[2].file == "score/demo/length.cc" and frames[2].line == 35


@pytest.mark.parametrize("raw, expected", [
    ("score::demo::PayloadEnd(unsigned char const*, unsigned long)", "PayloadEnd"),
    ("score::details::expected<int, score::result::Error>::value() const &", "value"),
    ("LLVMFuzzerTestOneInput", "LLVMFuzzerTestOneInput"),
    ("score::json::Reader<score::json::Any>::Read(char const*)", "Read"),
])
def test_short_name_matches_kb_function_field(raw, expected):
    assert short_name(raw) == expected
