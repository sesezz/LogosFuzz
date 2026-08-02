"""
GEN-03 하네스 생성 - 데이터 모델 & 컴파일 로그 파서
===================================================

GEN-03-01(초안 생성), GEN-03-02(자가 치유 루프), GEN-03-03(Mocking 삽입)이 공유하는
데이터 타입을 정의한다. 표준 라이브러리만 사용한다.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
# 하네스 초안
# --------------------------------------------------------------------------- #
@dataclass
class HarnessDraft:
    """GEN-03-01이 생성한 하네스 초안(자가 치유 루프의 입력)."""
    logic_group: str                      # 대상 로직 그룹명
    source: str                           # 하네스 C/C++ 소스
    project: str = ""
    target_apis: List[str] = field(default_factory=list)   # 타깃 API 세트
    language: str = "c"                   # "c" | "cpp"
    context: Dict[str, Any] = field(default_factory=dict)  # RAG/Mock 컨텍스트 등


# --------------------------------------------------------------------------- #
# 컴파일 진단 & 결과
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Diagnostic:
    """컴파일러가 뱉은 개별 진단(에러/경고)."""
    file: str
    line: int
    col: int
    severity: str   # "error" | "warning" | "note"
    message: str

    def short(self) -> str:
        return f"{self.file}:{self.line}:{self.col}: {self.severity}: {self.message}"


# gcc/clang 스타일 진단 라인: path:line:col: severity: message
_DIAG_RE = re.compile(
    r"^(?P<file>[^\s:][^:\n]*):(?P<line>\d+):(?:(?P<col>\d+):)?\s*"
    r"(?P<sev>error|warning|note|fatal error):\s*(?P<msg>.*)$",
    re.MULTILINE,
)


def parse_diagnostics(log: str) -> List[Diagnostic]:
    """컴파일 로그에서 진단을 추출한다."""
    out: List[Diagnostic] = []
    for m in _DIAG_RE.finditer(log or ""):
        sev = m.group("sev")
        if sev == "fatal error":
            sev = "error"
        out.append(
            Diagnostic(
                file=m.group("file").strip(),
                line=int(m.group("line")),
                col=int(m.group("col") or 0),
                severity=sev,
                message=m.group("msg").strip(),
            )
        )
    return out


@dataclass
class CompileResult:
    """컴파일 시도 결과."""
    ok: bool
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""
    artifact_path: Optional[str] = None
    duration_sec: float = 0.0

    @property
    def log(self) -> str:
        return (self.stdout + "\n" + self.stderr).strip()

    @property
    def diagnostics(self) -> List[Diagnostic]:
        return parse_diagnostics(self.log)

    @property
    def errors(self) -> List[Diagnostic]:
        return [d for d in self.diagnostics if d.severity == "error"]

    def signature(self) -> Tuple[Tuple[int, str], ...]:
        """
        에러 시그니처. (line, message) 집합으로 표현하여
        라운드 간 '같은 에러가 반복되는지(정체)'를 판별하는 데 쓴다.
        """
        return tuple(sorted((d.line, d.message) for d in self.errors))

    def error_digest(self, limit: int = 10) -> str:
        """LLM 프롬프트/로그용 간결한 에러 요약."""
        errs = self.errors
        if not errs:
            # 진단 파싱이 안 되면 원본 로그 꼬리를 사용
            tail = self.log[-1500:]
            return tail
        lines = [d.short() for d in errs[:limit]]
        if len(errs) > limit:
            lines.append(f"... (+{len(errs) - limit} more errors)")
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# 자가 치유 루프 산출물
# --------------------------------------------------------------------------- #
class HealOutcome(str, Enum):
    SUCCESS = "success"        # 컴파일 성공(초안 그대로 또는 수정 후)
    EXHAUSTED = "exhausted"    # max-round 소진, 여전히 실패
    STAGNATED = "stagnated"    # 동일 에러 반복으로 조기 중단
    ERROR = "error"            # 루프 자체 오류(LLM/컴파일러 예외 등)


@dataclass
class HealRound:
    """자가 치유 루프의 한 라운드 기록."""
    index: int                       # 0 = 초안 컴파일, 1.. = LLM 수정 후
    source: str
    compile_result: CompileResult
    repaired_by_llm: bool = False
    llm_note: str = ""               # LLM 응답에서 추출한 설명(있으면)
    timestamp: str = field(default_factory=now_iso)

    @property
    def ok(self) -> bool:
        return self.compile_result.ok


@dataclass
class GenerateReport:
    """한 로직 그룹에 대한 GEN-03-02 실행 결과."""
    logic_group: str
    project: str
    outcome: HealOutcome
    rounds: List[HealRound] = field(default_factory=list)
    final_source: str = ""
    elapsed_sec: float = 0.0
    hitl_item_id: Optional[str] = None   # 실패 시 HITL로 에스컬레이션된 항목
    hitl_decision: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.outcome is HealOutcome.SUCCESS

    @property
    def rounds_used(self) -> int:
        """LLM 수정 라운드 수(초안 컴파일 제외)."""
        return sum(1 for r in self.rounds if r.repaired_by_llm)

    @property
    def last_compile(self) -> Optional[CompileResult]:
        return self.rounds[-1].compile_result if self.rounds else None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "logic_group": self.logic_group,
            "project": self.project,
            "outcome": self.outcome.value,
            "success": self.success,
            "rounds_used": self.rounds_used,
            "elapsed_sec": round(self.elapsed_sec, 3),
            "hitl_item_id": self.hitl_item_id,
            "hitl_decision": self.hitl_decision,
            "rounds": [
                {
                    "index": r.index,
                    "ok": r.ok,
                    "repaired_by_llm": r.repaired_by_llm,
                    "errors": len(r.compile_result.errors),
                    "digest": r.compile_result.error_digest(limit=3) if not r.ok else "",
                }
                for r in self.rounds
            ],
        }
