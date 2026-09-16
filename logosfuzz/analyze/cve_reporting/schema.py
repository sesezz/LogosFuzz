"""
ANA-05-02: 취약점(CVE) 리포팅 포맷 스키마

설계 근거:
  - MITRE CVE Record Format (CVE JSON 5.0)의 핵심 필드(affected, description,
    problemTypes(CWE), metrics(CVSS), references)를 참고하여 최소 호환 구조로 정의
  - CVSS 3.1 Base Metrics
  - OSS-Fuzz 이슈 리포트 관례 (재현 절차 / PoC / 크래시 스택트레이스를 함께 제공)
  - 기존 ERD의 CRASH_REPORT 테이블(crash_id, run_id, asan_log, verdict)을
    입력 소스로 하고, HARNESS/API_METADATA 테이블과 조인 가능한 참조 필드를 포함

이 스키마는 "실제 CVE 번호 발급"이 아니라 CNA(CVE Numbering Authority) 제보 전
단계의 "취약점 리포트 초안(draft)"을 표준화하는 것이 목적이다.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum


class Verdict(str, Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"


class ReportStatus(str, Enum):
    DRAFT = "draft"
    READY_FOR_SUBMISSION = "ready_for_submission"
    SUBMITTED = "submitted"


@dataclass
class TriageInfo:
    """ANA-05-01(LLM 기반 정탐/오탐 자동 판별) 출력을 그대로 담는 서브 구조."""
    verdict: Verdict
    confidence: float  # 0.0 ~ 1.0
    rationale: str  # LLM이 정탐/오탐으로 판단한 근거 요약
    triage_model: str  # 예: "deepseek-r1"


@dataclass
class CweInfoField:
    id: str
    name: str
    related_ids: tuple = field(default_factory=tuple)


@dataclass
class CvssField:
    version: str  # "3.1"
    vector: str
    base_score: float
    severity: str
    is_estimated: bool  # True면 휴리스틱 초안이므로 사람 검토 필요


@dataclass
class AffectedComponent:
    library_name: str  # API_METADATA.lib_id 로부터 조회된 라이브러리명
    version: str | None
    function_signature: str | None  # API_METADATA.func_signature
    repository_url: str | None = None


@dataclass
class ReproductionInfo:
    harness_id: str  # HARNESS.harness_id
    harness_code_path: str  # HARNESS.code_path
    poc_input_path: str | None  # 크래시를 유발한 실제 입력 파일 경로
    run_id: str  # FUZZING_RUN 참조 (CRASH_REPORT.run_id)
    reproduction_steps: list[str] = field(default_factory=list)


@dataclass
class CrashDetails:
    sanitizer: str  # AddressSanitizer / ThreadSanitizer 등
    error_type: str  # 정규화된 sanitizer 에러 타입
    summary_line: str
    crash_location: str | None
    access_type: str | None
    access_size: int | None
    fault_address: str | None
    stack_trace: list[dict] = field(default_factory=list)
    freed_at_location: str | None = None  # UAF/double-free 시 free() 위치
    allocated_at_location: str | None = None  # 최초 malloc() 위치
    raw_asan_log: str = ""  # 원본 로그 전문 (CRASH_REPORT.asan_log)


@dataclass
class CVEReport:
    """ANA-05-02 최종 산출물: 취약점(CVE) 리포트 초안."""

    report_id: str  # 임시 ID, 예: "LOGOSFUZZ-2026-000123"
    crash_id: str  # CRASH_REPORT.crash_id (원본 레코드 추적용)
    title: str
    description: str

    cwe: CweInfoField
    cvss: CvssField
    affected_component: AffectedComponent
    reproduction: ReproductionInfo
    crash_details: CrashDetails
    triage: TriageInfo

    discovered_at: str  # ISO-8601
    discovery_tool: str  # 예: "LogosFuzz v1.0 + AFL++ + AddressSanitizer"
    status: ReportStatus = ReportStatus.DRAFT
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        # Enum -> value 로 직렬화
        d["triage"]["verdict"] = self.triage.verdict.value
        d["status"] = self.status.value
        return d

    @staticmethod
    def new_report_id(sequence: int, year: int | None = None) -> str:
        year = year or datetime.now(timezone.utc).year
        return f"LOGOSFUZZ-{year}-{sequence:06d}"
