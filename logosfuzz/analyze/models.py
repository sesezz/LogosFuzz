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
