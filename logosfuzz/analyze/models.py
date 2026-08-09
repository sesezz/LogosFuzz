"""
ANA-05-03 지식 베이스 역피드백 및 하네스 재생성 - 데이터 모델

ANA-05-01(정탐/오탐 판별)이 오탐(FALSE_POSITIVE)으로 판정한 크래시에 대해
근본 원인을 분석하고, 그 결과를 지식베이스에 반영하기 위한 제안(diff)과
승인 이후 재생성 시도를 추적하는 타입을 정의한다.

기존 ERD(API_METADATA / HARNESS / CRASH_REPORT)를 그대로 참조하며, 여기서
새로 정의하는 타입은 그 레코드들을 잇는 "역피드백 절차"의 중간 산출물이다.
crash_id / api_id / harness_id 를 모든 타입이 함께 들고 다니는 것은
감사(audit) 추적성 요구사항 때문이다.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from ana_05_02_cve_reporting.schema import Verdict


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


class ProposalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
"""ANA 파트 공용 데이터 모델.

파이프라인 위치:
    EXT → SCH → GEN → EXE-04-01(격리 실행) → EXE-04-02(Sanitizer 모니터링)
        → **ANA-05-04(Crash Deduplication)** → **ANA-05-01(정/오탐 판별)**
        → ANA-05-02(CVE 리포트)

EXE-04-02(``logosfuzz/execute/sanitizer.py``)가 남긴 ``SanitizerFinding`` JSONL을
ANA 파트가 소비한다. 이 모듈은 그 원시 이벤트를 감싸는 정규화 레코드
(:class:`CrashRecord`), 중복 제거 결과(:class:`CrashCluster`), 그리고
정/오탐 판별 결과(:class:`TriageResult`)를 정의한다.

의존성 원칙: 표준 라이브러리만 사용한다(프로젝트 pyproject ``dependencies=[]``).
ANA-05-02(``ana_05_02_cve_reporting``)와는 코드 import가 아니라 **문자열 계약**
(verdict 값 = ``"true_positive"``/``"false_positive"``/``"needs_review"``)으로만
연결한다. 두 패키지가 서로를 import하지 않아 순환 의존을 원천 차단한다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Verdict(str, Enum):
    """ANA-05-01 정/오탐 판별 결과.

    문자열 값은 ``ana_05_02_cve_reporting/schema.py``의 ``Verdict`` enum과
    **정확히 동일**하게 맞춘다. ANA-05-01의 출력 dict를 ANA-05-02
    ``build_cve_report(triage_result=...)``가 그대로 소비하기 때문이다.
    """

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"


@dataclass(frozen=True)
class Frame:
    """콜스택 프레임 1개(파일 경로 + 줄 번호).

    EXE-04-02가 남긴 traceback 항목(``{"file","line"}``)을 그대로 담는다.
    """

    file: str
    line: int

    @property
    def basename(self) -> str:
        """디렉터리를 제거한 파일명. Windows/Unix 경로 모두 처리."""
        norm = self.file.replace("\\", "/")
        return norm.rsplit("/", 1)[-1]


@dataclass
class CrashRecord:
    """ANA-05-01 산출물을 대신하는 최소 입력 계약(스텁).

    ANA-05-01이 실제로 구현되면 이 필드들만 채워 넘기면 된다. 이 저장소에는
    아직 정탐/오탐 판별 로직 자체가 없으므로(ANA-05-03만 단독으로 검증 가능하도록)
    verdict가 이미 확정된 값으로 들어온다고 전제한다.
    """

    crash_id: str
    api_id: int
    harness_id: str
    run_id: str
    asan_log: str
    verdict: Verdict
    confidence: float = 0.0

    def __post_init__(self) -> None:
        if self.verdict is not Verdict.FALSE_POSITIVE:
            raise ValueError(
                f"CrashRecord.verdict must be FALSE_POSITIVE for ANA-05-03 "
                f"(got {self.verdict.value!r}); this stage only runs after a "
                f"false-positive verdict"
            )


@dataclass
class RootCauseAnalysis:
    """오탐 원인 분석 함수(rootcause.py)의 출력."""

    crash_id: str
    api_id: int
    summary: str  # LLM이 요약한 오탐 근본 원인 (자연어)
    rationale: str = ""  # 요약 근거로 삼은 원문 발췌(있으면)
    model: str = ""  # 예: "deepseek-r1"
    analyzed_at: str = field(default_factory=now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "crash_id": self.crash_id,
            "api_id": self.api_id,
            "summary": self.summary,
            "rationale": self.rationale,
            "model": self.model,
            "analyzed_at": self.analyzed_at,
        }


@dataclass
class KBUpdateProposal:
    """KB 변경 제안(diff). 승인 전까지는 KB에 반영되지 않는다(HITL 게이트 대상)."""

    proposal_id: str
    crash_id: str
    api_id: int
    harness_id: str
    before_text: str  # 현재 오버라이드 텍스트(없으면 "")
    after_text: str  # 반영될 오버라이드 텍스트(root-cause 요약 기반)
    embedding: Optional[List[float]] = None
    status: ProposalStatus = ProposalStatus.PENDING
    created_at: str = field(default_factory=now_iso)
    decided_at: Optional[str] = None
    decided_by: Optional[str] = None
    rejection_reason: str = ""
    hitl_item_id: Optional[str] = None

    @staticmethod
    def new(
        crash_id: str,
        api_id: int,
        harness_id: str,
        before_text: str,
        after_text: str,
        embedding: Optional[List[float]] = None,
    ) -> "KBUpdateProposal":
        return KBUpdateProposal(
            proposal_id=new_id("kbprop"),
            crash_id=crash_id,
            api_id=api_id,
            harness_id=harness_id,
            before_text=before_text,
            after_text=after_text,
            embedding=embedding,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "crash_id": self.crash_id,
            "api_id": self.api_id,
            "harness_id": self.harness_id,
            "before_text": self.before_text,
            "after_text": self.after_text,
            "embedding": self.embedding,
            "status": self.status.value,
            "created_at": self.created_at,
            "decided_at": self.decided_at,
            "decided_by": self.decided_by,
            "rejection_reason": self.rejection_reason,
            "hitl_item_id": self.hitl_item_id,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "KBUpdateProposal":
        return cls(
            proposal_id=d["proposal_id"],
            crash_id=d["crash_id"],
            api_id=d["api_id"],
            harness_id=d["harness_id"],
            before_text=d.get("before_text", ""),
            after_text=d.get("after_text", ""),
            embedding=d.get("embedding"),
            status=ProposalStatus(d.get("status", "pending")),
            created_at=d.get("created_at", now_iso()),
            decided_at=d.get("decided_at"),
            decided_by=d.get("decided_by"),
            rejection_reason=d.get("rejection_reason", ""),
            hitl_item_id=d.get("hitl_item_id"),
        )


@dataclass
class RegenerationRecord:
    """승인된 제안이 유발한 재생성 시도 1건(감사 로그 대상)."""

    regen_id: str
    proposal_id: str
    crash_id: str
    api_id: int
    harness_id: str
    logic_group: str
    outcome: str  # GenerateReport.outcome.value 그대로 저장
    rounds_used: int
    compiled_ok: bool
    triggered_at: str = field(default_factory=now_iso)

    @staticmethod
    def new(
        proposal: "KBUpdateProposal",
        logic_group: str,
        outcome: str,
        rounds_used: int,
        compiled_ok: bool,
    ) -> "RegenerationRecord":
        return RegenerationRecord(
            regen_id=new_id("regen"),
            proposal_id=proposal.proposal_id,
            crash_id=proposal.crash_id,
            api_id=proposal.api_id,
            harness_id=proposal.harness_id,
            logic_group=logic_group,
            outcome=outcome,
            rounds_used=rounds_used,
            compiled_ok=compiled_ok,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "regen_id": self.regen_id,
            "proposal_id": self.proposal_id,
            "crash_id": self.crash_id,
            "api_id": self.api_id,
            "harness_id": self.harness_id,
            "logic_group": self.logic_group,
            "outcome": self.outcome,
            "rounds_used": self.rounds_used,
            "compiled_ok": self.compiled_ok,
            "triggered_at": self.triggered_at,
    """EXE-04-02 ``SanitizerFinding`` 1건을 감싼 ANA 입력 레코드.

    Attributes:
        sanitizer: "ASAN" | "TSAN" 등.
        category: EXE-04-02가 정규화한 결함 유형(예: ``use-after-free``).
        error_reason: sanitizer 원인 문자열 원문.
        traceback: 콜스택 프레임 목록(상단이 크래시 지점).
        raw_log: 결함 블록 원문 로그 라인.
        base_signature: EXE-04-02가 만든 1-프레임 기본 시그니처
            (``category_file_line``). ANA-05-04는 이보다 정교한 다중 프레임
            시그니처를 새로 만든다.
        group: 산출한 로직 그룹명(로그 파일 기준).
        crash_input: 이 결함을 유발한 크래시 입력 파일 경로(있으면).
    """

    sanitizer: str
    category: str
    error_reason: str = ""
    traceback: list[Frame] = field(default_factory=list)
    raw_log: list[str] = field(default_factory=list)
    base_signature: str = ""
    group: str = ""
    crash_input: str | None = None

    @classmethod
    def from_finding(cls, data: dict, group: str = "", crash_input: str | None = None) -> "CrashRecord":
        """EXE-04-02 ``SanitizerFinding.to_dict()`` 결과 dict에서 생성."""
        frames = [
            Frame(str(f.get("file", "")), int(f.get("line", 0)))
            for f in data.get("traceback", [])
            if f.get("file")
        ]
        return cls(
            sanitizer=data.get("sanitizer", "unknown"),
            category=data.get("category", "unknown"),
            error_reason=data.get("error_reason", ""),
            traceback=frames,
            raw_log=list(data.get("raw_log", [])),
            base_signature=data.get("signature", ""),
            group=group or data.get("group", ""),
            crash_input=crash_input,
        )


@dataclass
class CrashCluster:
    """ANA-05-04 산출물: 같은 결함으로 판정된 크래시 묶음 1개.

    Attributes:
        cluster_id: 시그니처 다이제스트 기반 안정적 식별자.
        signature: 사람이 읽는 다중 프레임 시그니처 문자열.
        bug_type: 대표 결함 유형(=대표 레코드 category).
        count: 이 묶음에 병합된 원시 결함 개수.
        representative: 대표 레코드(처음 관측된 결함).
        members: 병합된 모든 레코드.
        crash_inputs: 병합된 크래시 입력 파일 경로 목록(중복 제거).
        first_seen_index: 전체 입력 순서상 처음 등장한 위치(재현성/정렬용).
    """

    cluster_id: str
    signature: str
    bug_type: str
    representative: CrashRecord
    members: list[CrashRecord] = field(default_factory=list)
    first_seen_index: int = 0

    @property
    def count(self) -> int:
        return len(self.members)

    @property
    def crash_inputs(self) -> list[str]:
        seen: list[str] = []
        for m in self.members:
            if m.crash_input and m.crash_input not in seen:
                seen.append(m.crash_input)
        return seen

    @property
    def groups(self) -> list[str]:
        seen: list[str] = []
        for m in self.members:
            if m.group and m.group not in seen:
                seen.append(m.group)
        return seen

    @classmethod
    def from_dict(cls, data: dict) -> "CrashCluster":
        """``to_dict()`` 결과(예: dedup.json의 clusters 항목)에서 복원한다.

        ANA-05-01 triage가 저장된 Dedup 결과 파일을 입력으로 받을 때 사용한다.
        판별에 필요한 대표 레코드/유형/개수를 복원하며, members는 개수를 보존하기
        위한 대표 레코드의 반복으로 채운다(정/오탐 판별은 개수·대표만 사용).
        """
        rep = CrashRecord(
            sanitizer=data.get("sanitizer", "unknown"),
            category=data.get("bug_type", "unknown"),
            error_reason=data.get("error_reason", ""),
            traceback=[Frame(str(f["file"]), int(f["line"])) for f in data.get("traceback", [])],
            raw_log=list(data.get("raw_log", [])),
            base_signature=data.get("base_signature", ""),
            group=(data.get("groups") or [""])[0],
        )
        count = int(data.get("count", 1))
        return cls(
            cluster_id=data.get("cluster_id", ""),
            signature=data.get("signature", ""),
            bug_type=data.get("bug_type", rep.category),
            representative=rep,
            members=[rep] * max(1, count),
            first_seen_index=int(data.get("first_seen_index", 0)),
        )

    def to_dict(self) -> dict:
        rep = self.representative
        return {
            "cluster_id": self.cluster_id,
            "signature": self.signature,
            "bug_type": self.bug_type,
            "count": self.count,
            "sanitizer": rep.sanitizer,
            "error_reason": rep.error_reason,
            "crash_location": (
                f"{rep.traceback[0].file}:{rep.traceback[0].line}" if rep.traceback else None
            ),
            "traceback": [{"file": f.file, "line": f.line} for f in rep.traceback],
            "groups": self.groups,
            "crash_inputs": self.crash_inputs,
            "first_seen_index": self.first_seen_index,
            "base_signature": rep.base_signature,
            "raw_log": rep.raw_log,
        }


@dataclass
class TriageResult:
    """ANA-05-01 산출물: 하나의 크래시 묶음에 대한 정/오탐 판별.

    ``to_triage_dict()``는 ANA-05-02 ``build_cve_report(triage_result=...)``가
    바로 소비하는 계약 dict를 반환한다.
    """

    verdict: Verdict
    confidence: float  # 0.0 ~ 1.0
    rationale: str
    triage_model: str
    cluster_id: str = ""
    signals: list[str] = field(default_factory=list)  # 판단에 쓰인 근거 신호(설명가능성)

    def to_triage_dict(self) -> dict:
        """ANA-05-02 입력 계약(triage_result) 형식."""
        return {
            "verdict": self.verdict.value,
            "confidence": round(float(self.confidence), 4),
            "rationale": self.rationale,
            "triage_model": self.triage_model,
        }

    def to_dict(self) -> dict:
        d = self.to_triage_dict()
        d["cluster_id"] = self.cluster_id
        d["signals"] = self.signals
        return d
