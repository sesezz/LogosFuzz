"""ANA-05-01 보강: 크래시의 ``score::Result`` **에러계약** 위반 여부 판별

에러계약 플러그인 ``score_result`` (GENERIC-C). 기존 ``analyze/error_contract.py``
판별 로직 이동. ``error_contract.py`` 는 이 모듈 재수출

배경
----
S-CORE API 는 실패를 예외나 크래시가 아닌 ``score::Result<T>`` 의 오류 대안으로
반환. ``constraint_extractor`` 가 이 규약을 ``error_contract`` 로 추출해 KB 에 저장
— "이 API 는 이런 입력에서 오류 반환, 호출자는 ``has_value()`` 확인 후에만
``value()`` 사용"

``score::Result<T>`` 는 ``details::expected<T, Error>`` 이고 저장소가
``std::variant`` (baselibs ``score/result/details/expected/expected.h``)
오류 상태에서 ``value()`` 호출 시 ``std::get<0>`` 이 ``bad_variant_access`` 를
던지고, ``operator*`` 는 ``noexcept`` 라 즉시 ``std::terminate``
sanitizer 에는 ``ABRT`` 하나로만 보이고 EXE 는 ``unknown`` 으로 분류 — 결함
유형만으로는 판별 근거 없음. 대신 스택에 **확인을 빠뜨린 쪽**이 남아 있음

- 하네스가 ``value()`` 호출 → API 는 계약대로 오류 반환, 무시한 쪽은 하네스.
  대상 결함 아님(오탐)
- 대상 라이브러리 코드가 하위 API 의 ``Result`` 를 확인 없이 사용 → 공개 API 를
  정상 호출했는데 라이브러리가 계약 위반. 공격자 입력 하나로 프로세스 종료가
  가능한 실제 결함(정탐)

두 로그는 실제 baselibs ``score/result`` 로 빌드해 ``tests/fixtures/error_contract_logs/``
에 수집, 이 모듈의 정답지로 사용

KB 가 있으면 추가 확인: 메모리 오류가 난 함수가 ``error_contract`` 를 선언한 API 면
잘못된 입력을 **거부하는 정해진 통로**가 있었다는 의미. 거부 없이 메모리를
깨뜨렸다면 입력 검증 누락이므로 정탐 쪽 근거

설계 원칙 — reachability.py 와 동일
-----------------------------------
증명 가능한 것만 신호로 생성. 스택에서 계약 위반 지점을 찾지 못하면 신호 없음.
판별기 대신 결론을 내리지 않고 근거만 기록
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional, Sequence

from logosfuzz.analyze.categories import SANITIZER_MEMORY_BUGS
from logosfuzz.analyze.contracts.frames import (
    NamedFrame,
    parse_frames,
    short_name,
)
from logosfuzz.analyze.contracts.frames import is_harness as _is_harness
from logosfuzz.analyze.contracts.frames import is_runtime as _is_runtime
from logosfuzz.analyze.models import CrashRecord

# --------------------------------------------------------------------------- #
# score::Result 값 접근자
# --------------------------------------------------------------------------- #
# score::Result 의 값 접근자. Result<T> 는 details::expected 의 별칭이라 심볼에서는
# expected 로 표기. futurecpp 의 score::cpp::expected 도 같은 계약
_RESULT_ACCESSOR_RE = re.compile(
    r"(?:score::(?:details::|cpp::)?(?:expected|Result)|std::(?:__\w+::)?expected)"
    r"<.*>::(?:value|operator\*|operator->)\s*\("
)

# 접근 실패 표지(예외 경로). 접근자 프레임 위에는 이 프레임만 허용
_ACCESS_FAILURE_MARKERS = ("bad_variant_access", "bad_expected_access", "bad_optional_access")


def _is_accessor(frame: NamedFrame) -> bool:
    return bool(_RESULT_ACCESSOR_RE.search(frame.function))


# --------------------------------------------------------------------------- #
# 근거
# --------------------------------------------------------------------------- #
VIOLATED_BY_HARNESS = "harness"
VIOLATED_BY_TARGET = "target"


@dataclass
class ErrorContractEvidence:
    """에러계약 관점의 판별 근거(판정은 미수행)

    Attributes:
        violation: 계약 위반 주체 — ``"harness"`` / ``"target"`` / ``""``(위반 없음)
        accessor: 오류 상태에서 값을 꺼낸 접근자 프레임
        caller: 접근자를 호출한(=확인을 빠뜨린) 프레임
        crash_function: 크래시가 난 첫 대상 코드 함수(짧은 이름)
        declared_contracts: KB 에서 찾은 ``crash_function`` 의 error_contract 설명
        api_id / build_target: KB 매칭 결과(있는 경우). 역피드백과 리포트에서 사용
    """

    violation: str = ""
    accessor: Optional[NamedFrame] = None
    caller: Optional[NamedFrame] = None
    crash_function: str = ""
    declared_contracts: list[str] = field(default_factory=list)
    api_id: Optional[int] = None
    build_target: str = ""

    @property
    def found(self) -> bool:
        return bool(self.violation or self.declared_contracts)

    def to_dict(self) -> dict:
        return {
            "violation": self.violation or None,
            "accessor": self.accessor.render() if self.accessor else None,
            "caller": self.caller.render() if self.caller else None,
            "crash_function": self.crash_function or None,
            "declared_contracts": list(self.declared_contracts),
            "api_id": self.api_id,
            "build_target": self.build_target or None,
        }


def _unchecked_access(frames: Sequence[NamedFrame]) -> tuple[Optional[NamedFrame], Optional[NamedFrame]]:
    """(접근자, 호출자). 크래시 지점이 Result 값 접근 실패가 아니면 (None, None)

    접근자 위(더 안쪽)에 런타임/표준 라이브러리 프레임만 있어야 "값 접근 중
    크래시"로 증명. 사용자 코드 프레임이 끼어 있으면 접근자는 스택 아래쪽에
    있을 뿐 크래시 원인이 아님
    """
    for i, frame in enumerate(frames):
        if _is_accessor(frame):
            above = frames[:i]
            if not all(_is_runtime(f) for f in above):
                return None, None
            # operator* → value() 처럼 접근자가 겹치면 가장 바깥(호출자 쪽) 사용
            j = i
            while j + 1 < len(frames) and _is_accessor(frames[j + 1]):
                j += 1
            caller = next((f for f in frames[j + 1:] if not _is_runtime(f)), None)
            return frames[j], caller
        if not _is_runtime(frame):
            return None, None
    return None, None


def _access_failure_marked(record: CrashRecord, frames: Sequence[NamedFrame]) -> bool:
    text = " ".join(f.function for f in frames) + " " + " ".join(record.raw_log)
    return any(m in text for m in _ACCESS_FAILURE_MARKERS) or "ABRT" in record.error_reason.upper()


def _crash_function(frames: Sequence[NamedFrame]) -> str:
    for frame in frames:
        if not _is_runtime(frame) and not _is_accessor(frame) and not _is_harness(frame):
            return short_name(frame.function)
    return ""


def _kb_lookup(kb, function: str):
    if kb is None or not function:
        return None
    try:
        return kb.api(function)
    except Exception:
        return None


def analyze_error_contract(record: CrashRecord, kb=None) -> ErrorContractEvidence:
    """크래시 레코드 1건의 에러계약 위반 근거 수집

    Args:
        record: 클러스터 대표 레코드
        kb: :class:`~logosfuzz.knowledge.knowledge_base.KnowledgeBase` (선택)
            있으면 크래시 함수의 선언된 error_contract 와 Bazel 타깃 첨부
    """
    frames = parse_frames(record.raw_log)
    evidence = ErrorContractEvidence(crash_function=_crash_function(frames))

    accessor, caller = _unchecked_access(frames)
    if accessor is not None and caller is not None and _access_failure_marked(record, frames):
        evidence.accessor = accessor
        evidence.caller = caller
        evidence.violation = VIOLATED_BY_HARNESS if _is_harness(caller) else VIOLATED_BY_TARGET
        if evidence.violation == VIOLATED_BY_TARGET:
            evidence.crash_function = short_name(caller.function)

    document = _kb_lookup(kb, evidence.crash_function)
    if document is not None:
        evidence.api_id = document.get("api_id")
        evidence.build_target = str(document.get("build_target") or "")
        evidence.declared_contracts = [
            str(c.get("description") or c.get("expression") or "")
            for c in document.get("constraints", [])
            if c.get("kind") == "error_contract"
        ]
    return evidence


# --------------------------------------------------------------------------- #
# 규칙 기반 판별기용 신호
# --------------------------------------------------------------------------- #
# 점수 근거: 하네스 위반은 reachability.derive_signals 의 harness-only-caller(-0.45)와
# 같은 무게로 감점 — 둘 다 "대상이 아닌 하네스가 만든 상황"의 증명
# 대상 위반은 정상 호출로 재현되는 결함의 증명이라 결함 유형 사전확률(unknown=0.30)
# 을 정탐 임계치(0.65) 위로 올리는 가중치 부여. 0.30 이면 실측 로그가 정확히 0.80 이
# 되어 자동 승인 경계(신뢰도 0.8)에 걸림 - 부동소수 반올림에 따라 사람 검토 여부가
# 갈리지 않도록 여유 확보
_HARNESS_VIOLATION_DELTA = -0.45
_TARGET_VIOLATION_DELTA = 0.35
_CONTRACT_BYPASSED_DELTA = 0.10

# 메모리 계열 판단은 analyze/categories.py 어휘 사용 (NULL 역참조 포함)
_MEMORY_LIKE = SANITIZER_MEMORY_BUGS


def derive_signals(evidence: ErrorContractEvidence, bug_type: str = "") -> tuple[float, list[str]]:
    """(점수 보정치, 신호 목록)"""
    if evidence.violation == VIOLATED_BY_HARNESS:
        return _HARNESS_VIOLATION_DELTA, ["error-contract-violated-by-harness"]
    if evidence.violation == VIOLATED_BY_TARGET:
        return _TARGET_VIOLATION_DELTA, ["error-contract-violated-by-target"]
    if evidence.declared_contracts and bug_type in _MEMORY_LIKE:
        return _CONTRACT_BYPASSED_DELTA, ["error-contract-bypassed"]
    return 0.0, []


def render_rationale(evidence: ErrorContractEvidence) -> str:
    """HITL 검토자용 한 문장. 근거가 없으면 빈 문자열"""
    if evidence.violation == VIOLATED_BY_HARNESS:
        return (
            " 하네스가 score::Result 의 오류 대안을 has_value() 로 확인하지 않고 값을 "
            f"꺼냈다({evidence.caller.render()}) — API 는 에러계약대로 오류를 반환했으므로 "
            "대상 결함이 아니라 하네스의 계약 위반이다."
        )
    if evidence.violation == VIOLATED_BY_TARGET:
        return (
            f" 대상 코드 {evidence.crash_function}가 하위 API 의 score::Result 를 확인 "
            f"없이 꺼냈다({evidence.caller.render()}) — 하네스는 공개 API 를 정상 호출했고 "
            "라이브러리 스스로 에러계약을 어겨 프로세스가 종료된다."
        )
    if evidence.declared_contracts:
        return (
            f" {evidence.crash_function}는 잘못된 입력을 score::Result 오류로 거부하는 "
            "에러계약을 선언한 API 인데, 거부하지 않고 메모리 오류로 이어졌다 — 입력 "
            "검증이 이 경로를 놓쳤다."
        )
    return ""


def render_for_prompt(evidence: ErrorContractEvidence) -> str:
    """LLM 판별기 프롬프트용 증거 섹션"""
    lines = ["[에러계약 증거]"]
    if evidence.violation:
        who = "하네스" if evidence.violation == VIOLATED_BY_HARNESS else "대상 라이브러리"
        lines.append(f"- score::Result 오류 상태에서 값 접근: {evidence.accessor.render()}")
        lines.append(f"- 확인(has_value)을 빠뜨린 쪽: {who} — {evidence.caller.render()}")
    if evidence.declared_contracts:
        lines.append(f"- {evidence.crash_function} 의 선언된 에러계약(KB):")
        lines.extend(f"    * {c}" for c in evidence.declared_contracts[:5])
    if len(lines) == 1:
        return ""
    lines.append(
        "  판단 기준: 오류를 반환한 API 를 하네스가 확인 없이 쓴 것은 오탐이고, "
        "라이브러리 내부가 확인 없이 쓴 것은 정탐이다."
    )
    return "\n".join(lines)


class KnowledgeBaseContractProvider:
    """클러스터 → 에러계약 근거. 판별기에 주입해 사용(KB 선택)"""

    def __init__(self, kb=None) -> None:
        self.kb = kb

    def __call__(self, cluster) -> ErrorContractEvidence:
        return analyze_error_contract(cluster.representative, self.kb)
