"""
ANA-05-02: 취약점(CVE) 리포트 생성기

입력 계약(Input Contract)
--------------------------
이 리포지토리에는 ANA-05-01 실제 구현체가 없으므로, 기존 ERD
(API_METADATA / HARNESS / CRASH_REPORT)와 개발보고서에 기술된
"LLM 기반 정탐/오탐 자동 판별" 출력을 근거로 아래와 같은 입력 딕셔너리
구조를 가정한다. 실제 ANA-05-01 모듈의 출력 필드명이 다르다면
`build_cve_report()` 상단의 필드 매핑 부분만 수정하면 된다.

crash_report = {
    "crash_id": "CR-000123",
    "run_id": "RUN-2026-0007",
    "asan_log": "<raw sanitizer log text>",
}
api_metadata = {
    "api_id": "API-0042",
    "lib_id": "dlt-daemon",
    "lib_version": "2.18.10",
    "func_signature": "int dlt_message_read(DltMessage *msg, uint8_t *buffer, ...)",
    "repository_url": "https://github.com/COVESA/dlt-daemon",
}
harness = {
    "harness_id": "H-0099",
    "code_path": "harness/dlt_message_read_harness.c",
    "gen_model": "gpt-4o-mini",
}
triage_result = {  # ANA-05-01 출력
    "verdict": "true_positive",
    "confidence": 0.91,
    "rationale": "스택트레이스 상 free 이후 동일 포인터를 재사용하는 UAF 패턴이며,
                  ...",
    "triage_model": "deepseek-r1",
}
poc_input_path = "corpus/crashes/id_000012"
"""

from __future__ import annotations

from datetime import datetime, timezone

from asan_parser import parse_asan_log
from cwe_mapping import lookup_cwe
from cvss_estimator import estimate_cvss
from schema import (
    AffectedComponent,
    CrashDetails,
    CVEReport,
    CweInfoField,
    CvssField,
    ReproductionInfo,
    TriageInfo,
    Verdict,
)


def _build_reproduction_steps(
    harness: dict, poc_input_path: str | None, crash_loc: str | None
) -> list[str]:
    steps = [
        f"1. 대상 라이브러리를 빌드하고 하네스({harness.get('code_path', 'N/A')})를 컴파일한다.",
        "2. 아래 PoC 입력값을 하네스의 표준 입력/인자로 전달하여 실행한다.",
    ]
    if poc_input_path:
        steps.append(f"   실행 예: ./harness_bin {poc_input_path}")
    if crash_loc:
        steps.append(f"3. {crash_loc} 위치에서 sanitizer 크래시가 재현되는지 확인한다.")
    else:
        steps.append("3. sanitizer 크래시 로그가 출력되는지 확인한다.")
    return steps


def _build_title(lib_name: str, error_type: str, crash_loc: str | None) -> str:
    loc = f" ({crash_loc})" if crash_loc else ""
    readable_type = error_type.replace("-", " ")
    return f"{lib_name}: {readable_type}{loc}"


def _build_description(
    lib_name: str,
    func_sig: str | None,
    parsed_log,
    triage: TriageInfo,
) -> str:
    func_part = f" 함수 `{func_sig}` 호출 경로에서" if func_sig else ""
    return (
        f"LogosFuzz 퍼징 과정에서{func_part} {parsed_log.sanitizer}가 "
        f"{parsed_log.error_type.replace('-', ' ')}를 탐지했다. "
        f"대상 라이브러리: {lib_name}. "
        f"LLM 기반 정탐/오탐 판별 결과: {triage.verdict.value} "
        f"(신뢰도 {triage.confidence:.2f}). {triage.rationale}"
    )


def build_cve_report(
    crash_report: dict,
    api_metadata: dict,
    harness: dict,
    triage_result: dict,
    poc_input_path: str | None = None,
    sequence: int = 1,
) -> CVEReport:
    """CRASH_REPORT + API_METADATA + HARNESS + ANA-05-01 출력을 종합해
    CVEReport(취약점 리포트 초안)를 생성한다.
    """
    parsed_log = parse_asan_log(crash_report["asan_log"])
    cwe_info = lookup_cwe(parsed_log.error_type)
    cvss_estimate = estimate_cvss(parsed_log.error_type)

    triage = TriageInfo(
        verdict=Verdict(triage_result["verdict"]),
        confidence=float(triage_result["confidence"]),
        rationale=triage_result["rationale"],
        triage_model=triage_result.get("triage_model", "unknown"),
    )

    lib_name = api_metadata.get("lib_id", "unknown-library")

    report = CVEReport(
        report_id=CVEReport.new_report_id(sequence),
        crash_id=crash_report["crash_id"],
        title=_build_title(lib_name, parsed_log.error_type, parsed_log.crash_location),
        description=_build_description(
            lib_name, api_metadata.get("func_signature"), parsed_log, triage
        ),
        cwe=CweInfoField(
            id=cwe_info.primary_id,
            name=cwe_info.primary_name,
            related_ids=cwe_info.related_ids,
        ),
        cvss=CvssField(
            version="3.1",
            vector=cvss_estimate.vector,
            base_score=cvss_estimate.base_score,
            severity=cvss_estimate.severity,
            is_estimated=cvss_estimate.is_estimated,
        ),
        affected_component=AffectedComponent(
            library_name=lib_name,
            version=api_metadata.get("lib_version"),
            function_signature=api_metadata.get("func_signature"),
            repository_url=api_metadata.get("repository_url"),
        ),
        reproduction=ReproductionInfo(
            harness_id=harness["harness_id"],
            harness_code_path=harness.get("code_path", ""),
            poc_input_path=poc_input_path,
            run_id=crash_report["run_id"],
            reproduction_steps=_build_reproduction_steps(
                harness, poc_input_path, parsed_log.crash_location
            ),
        ),
        crash_details=CrashDetails(
            sanitizer=parsed_log.sanitizer,
            error_type=parsed_log.error_type,
            summary_line=parsed_log.raw_summary_line,
            crash_location=parsed_log.crash_location,
            access_type=parsed_log.access_type,
            access_size=parsed_log.access_size,
            fault_address=parsed_log.fault_address,
            stack_trace=parsed_log.stack_trace,
            freed_at_location=parsed_log.freed_at_location,
            allocated_at_location=parsed_log.allocated_at_location,
            raw_asan_log=crash_report["asan_log"],
        ),
        triage=triage,
        discovered_at=datetime.now(timezone.utc).isoformat(),
        discovery_tool="LogosFuzz + AFL++/libFuzzer + " + parsed_log.sanitizer,
        references=[
            f"harness:{harness['harness_id']}",
            f"run:{crash_report['run_id']}",
            f"api:{api_metadata.get('api_id', 'N/A')}",
        ],
    )
    return report
