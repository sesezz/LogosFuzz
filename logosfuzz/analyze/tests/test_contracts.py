"""GENERIC-C 에러계약 플러그인 테스트.

정답지는 ``examples/embedded`` 를 clang 18 + ASan/UBSan/libFuzzer 로 빌드해 받은 실측
로그다(``tests/fixtures/c_return_code_logs``). EXE sanitizer 파서 → dedup → 판별의
실제 경로를 그대로 태운다.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from logosfuzz.analyze import cli as ana_cli
from logosfuzz.analyze import error_contract
from logosfuzz.analyze.contracts import (
    ContractProvider,
    available_contracts,
    contract_for_evidence,
    contract_for_profile,
    get_contract,
)
from logosfuzz.analyze.contracts.c_return_code import CReturnCodeEvidence
from logosfuzz.analyze.contracts.none import NoContractEvidence
from logosfuzz.analyze.contracts.score_result import ErrorContractEvidence
from logosfuzz.analyze.dedup import deduplicate
from logosfuzz.analyze.models import CrashCluster, CrashRecord, Verdict
from logosfuzz.analyze.triage import RuleBasedTriager, build_triage_prompt, rule_triage
from logosfuzz.common.target_profile import load_profile
from logosfuzz.execute.sanitizer import SanitizerMonitor

REPO = Path(__file__).resolve().parents[3]
C_LOGS = REPO / "tests" / "fixtures" / "c_return_code_logs"
SCORE_LOGS = REPO / "tests" / "fixtures" / "error_contract_logs"


@pytest.fixture(scope="module")
def embedded_profile():
    return load_profile(REPO / "targets" / "embedded-sample.json", base_dir=REPO)


@pytest.fixture(scope="module")
def automotive_profile():
    return load_profile(REPO / "targets" / "automotive.json", base_dir=REPO)


@pytest.fixture(scope="module")
def generic_profile():
    return load_profile(REPO / "targets" / "libsndfile.json", base_dir=REPO)


def _records(path: Path) -> list[CrashRecord]:
    monitor = SanitizerMonitor()
    for line in path.read_text(encoding="utf-8").splitlines():
        monitor.feed(line)
    return [CrashRecord.from_finding(f.to_dict()) for f in monitor.finish()]


def _cluster(record: CrashRecord) -> CrashCluster:
    clusters, _ = deduplicate([record])
    return clusters[0]


def _by_category(path: Path, category: str) -> CrashRecord:
    return next(r for r in _records(path) if r.category == category)


# --------------------------------------------------------------------------- #
# 레지스트리
# --------------------------------------------------------------------------- #
def test_registry_has_three_contracts():
    assert available_contracts() == ["none", "c_return_code", "score_result"]
    assert get_contract(None).name == "none"
    assert get_contract("").name == "none"
    with pytest.raises(ValueError, match="알 수 없는 error_contract"):
        get_contract("exceptions")


def test_contract_for_profile_and_evidence(embedded_profile, automotive_profile):
    assert contract_for_profile(embedded_profile).name == "c_return_code"
    assert contract_for_profile(automotive_profile).name == "score_result"
    assert contract_for_evidence(CReturnCodeEvidence()).name == "c_return_code"
    assert contract_for_evidence(ErrorContractEvidence()).name == "score_result"
    assert contract_for_evidence(NoContractEvidence()).name == "none"
    assert contract_for_evidence(object()) is None


def test_error_contract_module_keeps_public_api():
    """score::Result 판별을 옮겨도 기존 import 경로는 같은 객체를 가리킨다."""
    from logosfuzz.analyze.contracts import score_result

    assert error_contract.analyze_error_contract is score_result.analyze_error_contract
    assert error_contract.ErrorContractEvidence is score_result.ErrorContractEvidence
    assert error_contract.KnowledgeBaseContractProvider is score_result.KnowledgeBaseContractProvider


# --------------------------------------------------------------------------- #
# c_return_code — 실측 로그
# --------------------------------------------------------------------------- #
def test_harness_unchecked_null_segv_is_harness_defect(embedded_profile):
    """proto_create 의 NULL 을 확인하지 않고 proto_parse 에 넘겨 0x14 에서 SEGV."""
    record = _by_category(C_LOGS / "harness_unchecked_null.txt", "segv")
    evidence = get_contract("c_return_code").analyze(record, profile=embedded_profile)

    assert evidence.violation == "harness"
    assert evidence.api == "proto_parse"
    assert evidence.fault_address == 0x14
    assert "LLVMFuzzerTestOneInput" in evidence.caller.function

    result = rule_triage(_cluster(record), profile=embedded_profile)
    assert result.verdict is Verdict.FALSE_POSITIVE
    assert "c-return-unchecked-by-harness" in result.signals
    assert "하네스 결함" in result.rationale


def test_harness_unchecked_null_ubsan_stack_is_harness_defect(embedded_profile):
    """Docker 실행 조건(UBSAN print_stacktrace=1, halt_on_error=1)에서 같은 입력."""
    (record,) = _records(C_LOGS / "harness_unchecked_null_ubsan_stack.txt")
    evidence = get_contract("c_return_code").analyze(record, profile=embedded_profile)
    assert evidence.violation == "harness"
    assert evidence.fault_address is None
    assert "null pointer" in evidence.null_reason

    result = rule_triage(_cluster(record), profile=embedded_profile)
    assert result.verdict is Verdict.FALSE_POSITIVE


def test_ubsan_line_without_stack_is_not_judged(embedded_profile):
    """스택이 없는 UBSan 한 줄은 호출자를 증명할 수 없으므로 신호를 내지 않는다."""
    record = _by_category(C_LOGS / "harness_unchecked_null.txt", "null-dereference")
    evidence = get_contract("c_return_code").analyze(record, profile=embedded_profile)
    assert evidence.violation == ""
    assert "c-return-unchecked-by-harness" not in rule_triage(
        _cluster(record), profile=embedded_profile).signals


def test_target_heap_overflow_is_target_defect(embedded_profile):
    """길이 필드를 믿는 memcpy 의 힙 OOB. NULL 근처가 아니므로 하네스 탓이 아니다."""
    (record,) = _records(C_LOGS / "target_heap_overflow.txt")
    evidence = get_contract("c_return_code").analyze(record, profile=embedded_profile)
    assert evidence.violation == ""
    assert evidence.api == "proto_parse"
    assert evidence.null_reason == ""

    result = rule_triage(_cluster(record), profile=embedded_profile)
    assert result.verdict is Verdict.TRUE_POSITIVE
    assert "c-return-unchecked-by-harness" not in result.signals


def test_api_not_in_profile_gives_no_signal(generic_profile):
    """profile.apis 에 없는 함수(libsndfile 프로필에는 proto_parse 가 없다)는 판단하지 않는다."""
    record = _by_category(C_LOGS / "harness_unchecked_null.txt", "segv")
    evidence = get_contract("c_return_code").analyze(record, profile=generic_profile)
    assert evidence.violation == ""
    assert evidence.api == ""
    assert evidence.crash_function == "proto_parse"


def test_c_return_code_prompt_and_dict(embedded_profile):
    record = _by_category(C_LOGS / "harness_unchecked_null.txt", "segv")
    evidence = get_contract("c_return_code").analyze(record, profile=embedded_profile)
    data = evidence.to_dict()
    assert data["contract"] == "c_return_code"
    assert data["fault_address"] == "0x14"
    prompt = build_triage_prompt(_cluster(record), profile=embedded_profile)
    assert "[에러계약 증거: C 반환 코드]" in prompt
    assert "score::Result" not in prompt


def test_contract_provider_for_profile(embedded_profile):
    record = _by_category(C_LOGS / "harness_unchecked_null.txt", "segv")
    provider = ContractProvider.for_profile(embedded_profile)
    triager = RuleBasedTriager(contract_provider=provider, profile=embedded_profile)
    result = triager.triage(_cluster(record))
    assert result.verdict is Verdict.FALSE_POSITIVE
    assert "c-return-unchecked-by-harness" in result.signals


# --------------------------------------------------------------------------- #
# 도메인 격리: score::Result 는 자동차에서만
# --------------------------------------------------------------------------- #
def test_score_result_only_with_automotive_profile(automotive_profile, generic_profile):
    (record,) = _records(SCORE_LOGS / "harness_unchecked.txt")
    cluster = _cluster(record)

    legacy = rule_triage(cluster)  # 프로필 없음 = 기존 자동차 모드
    auto = rule_triage(cluster, profile=automotive_profile)
    generic = rule_triage(cluster, profile=generic_profile)

    assert "error-contract-violated-by-harness" in legacy.signals
    assert auto.signals == legacy.signals and auto.rationale == legacy.rationale
    assert not any(s.startswith("error-contract") for s in generic.signals)
    assert "score::Result" not in generic.rationale
    assert "score::Result" not in build_triage_prompt(cluster, profile=generic_profile)


def _mocking_cluster() -> CrashCluster:
    record = CrashRecord(sanitizer="ASAN", category="mocking-fail-fp", error_reason="mock")
    return _cluster(record)


def test_mocking_rationale_is_domain_specific(automotive_profile, embedded_profile):
    cluster = _mocking_cluster()
    assert "CAN/UDS" in rule_triage(cluster).rationale
    assert "CAN/UDS" in rule_triage(cluster, profile=automotive_profile).rationale
    embedded = rule_triage(cluster, profile=embedded_profile).rationale
    assert "CAN/UDS" not in embedded
    assert "외부 장치·주변장치(HAL) 모킹" in embedded


# --------------------------------------------------------------------------- #
# CLI --profile
# --------------------------------------------------------------------------- #
def test_cli_analyze_with_profile(tmp_path, monkeypatch):
    monkeypatch.chdir(REPO)
    findings = tmp_path / "findings.jsonl"
    monitor = SanitizerMonitor()
    for line in (C_LOGS / "harness_unchecked_null_ubsan_stack.txt").read_text().splitlines():
        monitor.feed(line)
    findings.write_text("".join(json.dumps(f.to_dict()) + "\n" for f in monitor.finish()))
    out = tmp_path / "analyze.json"

    rc = ana_cli.main(["analyze", str(findings), "--profile", "targets/embedded-sample.json",
                       "--no-approval-gate", "-o", str(out)])
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["summary"]["false_positive"] == 1
    text = json.dumps(data, ensure_ascii=False)
    assert "c-return-unchecked-by-harness" in text
    assert '"contract": "c_return_code"' in text
