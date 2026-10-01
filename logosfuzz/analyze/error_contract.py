"""ANA-05-01 보강: 크래시가 ``score::Result`` **에러계약**을 어겼는가.

왜 필요한가
-----------
S-CORE API 는 실패를 예외나 크래시가 아니라 ``score::Result<T>`` 의 오류 대안으로
돌려준다. A 파트 3주차가 ``constraint_extractor`` 에서 그 규약을 ``error_contract``
로 뽑아 KB 에 넣었다 — "이 API 는 이런 입력에서 오류를 반환하고, 호출자는
``has_value()`` 를 확인한 뒤에만 ``value()`` 를 꺼내야 한다".

이 계약을 기준으로 보면 정/오탐이 지금까지와 다른 축에서 갈린다.

``score::Result<T>`` 는 ``details::expected<T, Error>`` 이고 저장소가
``std::variant`` 다(baselibs ``score/result/details/expected/expected.h``).
오류 상태에서 ``value()`` 를 부르면 ``std::get<0>`` 이 ``bad_variant_access`` 를
던지고, ``operator*`` 는 ``noexcept`` 라 그 자리에서 ``std::terminate`` 로 죽는다.
sanitizer 에는 ``ABRT`` 하나로만 보이고 EXE 는 ``unknown`` 으로 분류한다 — 결함
유형만으로는 판별기가 쓸 근거가 하나도 없다. 그런데 이 크래시의 정체는 스택에
그대로 남아 있다. **확인을 빠뜨린 쪽이 누구인가**다.

- 하네스가 ``value()`` 를 꺼냈다 → API 는 계약대로 오류를 돌려줬고, 그걸 무시한
  건 하네스다. 대상 결함이 아니다(오탐).
- 대상 라이브러리 코드가 하위 API 의 ``Result`` 를 확인 없이 꺼냈다 → 하네스가
  공개 API 를 정상 호출했는데 라이브러리가 스스로 계약을 어겼다. 공격자 입력
  하나로 프로세스를 끝낼 수 있는 실제 결함이다(정탐).

두 로그는 ``tests/fixtures/error_contract_logs/`` 에 실제 baselibs ``score/result``
로 빌드해 수집해 두었고, 이 모듈은 그 원문을 정답지로 삼아 작성했다.

KB 가 있으면 하나를 더 본다. 메모리 오류가 난 함수가 ``error_contract`` 를
선언한 API 라면, 그 API 에는 잘못된 입력을 **거부하는 정해진 통로**가 있었다는
뜻이다. 거부하지 않고 메모리를 깨뜨렸다면 입력 검증이 그 경로를 놓친 것이므로
정탐 쪽 근거가 된다.

설계 원칙 — reachability.py 와 같다
-----------------------------------
증명 가능한 것만 신호로 만든다. 스택에서 계약 위반 지점을 찾지 못하면 아무
신호도 내지 않는다. 판별기를 대신해 결론을 내리지 않고, 근거만 남긴다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional, Sequence

from logosfuzz.analyze.models import CrashRecord, Frame
from logosfuzz.analyze.signature import is_harness_frame, is_runtime_frame

# --------------------------------------------------------------------------- #
# 프레임 파싱 — 함수 이름까지 필요하다
# --------------------------------------------------------------------------- #
# CrashRecord.traceback 은 파일:줄만 담는다. 계약 위반 판별에는 "어떤 함수가
# value() 를 불렀는가"가 필요하므로 원문 로그에서 프레임을 다시 읽는다.
#   #12 0x55d0 in score::details::expected<int, E>::value() const & /p/expected.h:503
#   #7 <ADDR> in std::terminate() (/lib/x86_64-linux-gnu/libstdc++.so.6+0xa5a54) (BuildId: ..)
#   #5 <ADDR>  (/lib/x86_64-linux-gnu/libstdc++.so.6+0xa5ff4) (BuildId: ..)   ← 이름 없음
_FRAME_RE = re.compile(r"^\s*#(?P<idx>\d+)\s+(?:0x[0-9a-fA-F]+|<ADDR>)\s+(?P<rest>.*)$")
_BUILD_ID_RE = re.compile(r"\s*\(BuildId:[^)]*\)\s*$")
_LOCATION_RE = re.compile(r"^(?P<file>\S+?):(?P<line>\d+)(?::\d+)?$")

# score::Result 의 값 접근자. Result<T> 는 details::expected 의 별칭이라 심볼에는
# expected 로 찍힌다. futurecpp 의 score::cpp::expected 도 같은 계약이다.
_RESULT_ACCESSOR_RE = re.compile(
    r"(?:score::(?:details::|cpp::)?(?:expected|Result)|std::(?:__\w+::)?expected)"
    r"<.*>::(?:value|operator\*|operator->)\s*\("
)

# 접근 실패를 알리는 표지(예외 경로). 접근자 프레임 위에 이것만 있어야 한다.
_ACCESS_FAILURE_MARKERS = ("bad_variant_access", "bad_expected_access", "bad_optional_access")

# C/C++ 런타임·표준 라이브러리 프레임. 크래시 지점을 찾을 때 건너뛴다.
_RUNTIME_FUNC_PREFIXES = (
    "std::", "__cxa", "__gxx", "_Unwind", "__GI_", "__pthread", "__libc", "_start",
    "abort", "raise", "__sanitizer", "__asan", "__ubsan", "fuzzer::",
)
_RUNTIME_FILE_MARKERS = (
    "nptl/", "sysdeps/", "stdlib/abort.c", "csu/", "/usr/include/", "libstdc++",
    "libc++", "libgcc_s", "libc.so", "/lib/x86_64-linux-gnu/",
)


@dataclass(frozen=True)
class NamedFrame:
    """함수 이름까지 담은 프레임(원문 로그 1줄)."""

    index: int
    function: str
    file: str = ""
    line: int = 0

    def as_frame(self) -> Frame:
        return Frame(self.file, self.line)

    def render(self) -> str:
        loc = f"{self.file}:{self.line}" if self.file else "?"
        return f"#{self.index} {self.function or '?'} @ {loc}"


def parse_frames(raw_log: Sequence[str]) -> list[NamedFrame]:
    """원문 로그에서 스택 프레임을 함수 이름과 함께 읽는다(첫 스택만)."""
    frames: list[NamedFrame] = []
    for line in raw_log:
        match = _FRAME_RE.match(line)
        if not match:
            continue
        idx = int(match.group("idx"))
        if frames and idx == 0:
            break  # 두 번째 스택(할당 지점 등)은 크래시 지점이 아니다
        rest = _BUILD_ID_RE.sub("", match.group("rest").strip())
        if not rest.startswith("in "):
            frames.append(NamedFrame(idx, ""))
            continue
        body = rest[3:].strip()
        func, _, location = body.rpartition(" ")
        loc = _LOCATION_RE.match(location)
        if loc:
            frames.append(NamedFrame(idx, func.strip(), loc.group("file"), int(loc.group("line"))))
        elif location.startswith("("):
            frames.append(NamedFrame(idx, func.strip()))  # 공유 라이브러리 오프셋
        else:
            frames.append(NamedFrame(idx, body))
    return frames


def _is_runtime(frame: NamedFrame) -> bool:
    if not frame.function and not frame.file:
        return True
    if frame.function.startswith(_RUNTIME_FUNC_PREFIXES):
        return True
    text = frame.file.replace("\\", "/").lower()
    if any(m in text for m in _RUNTIME_FILE_MARKERS):
        return True
    return bool(frame.file) and is_runtime_frame(frame.as_frame())


def _is_accessor(frame: NamedFrame) -> bool:
    return bool(_RESULT_ACCESSOR_RE.search(frame.function))


def _is_harness(frame: NamedFrame) -> bool:
    if "LLVMFuzzerTestOneInput" in frame.function:
        return True
    return bool(frame.file) and is_harness_frame(frame.as_frame())


def short_name(function: str) -> str:
    """``score::json::Parse(char const*)`` → ``Parse`` (KB 문서의 function 형식)."""
    name = function.split("(", 1)[0].strip()
    depth, cut = 0, len(name)
    # 템플릿 인자 안의 :: 에 속지 않도록 바깥 깊이에서만 자른다.
    for i in range(len(name) - 1, -1, -1):
        ch = name[i]
        if ch == ">":
            depth += 1
        elif ch == "<":
            depth -= 1
        elif depth == 0 and name.startswith("::", i - 1) and i > 0:
            cut = i + 1
            break
    tail = name[cut:] if cut < len(name) else name
    return tail.split("<", 1)[0].strip()


# --------------------------------------------------------------------------- #
# 근거
# --------------------------------------------------------------------------- #
VIOLATED_BY_HARNESS = "harness"
VIOLATED_BY_TARGET = "target"


@dataclass
class ErrorContractEvidence:
    """에러계약 관점의 판별 근거. 판정은 하지 않는다.

    Attributes:
        violation: 계약을 어긴 쪽 — ``"harness"`` / ``"target"`` / ``""``(위반 없음).
        accessor: 오류 상태에서 값을 꺼낸 접근자 프레임.
        caller: 그 접근자를 부른(=확인을 빠뜨린) 프레임.
        crash_function: 크래시가 난 첫 대상 코드 함수(짧은 이름).
        declared_contracts: KB 에서 찾은 ``crash_function`` 의 error_contract 설명.
        api_id / build_target: KB 매칭 결과(있으면). 역피드백과 리포트가 쓴다.
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
    """(접근자, 호출자). 크래시 지점이 Result 값 접근 실패가 아니면 (None, None).

    접근자 위(더 안쪽)에 런타임/표준 라이브러리 프레임만 있어야 "값을 꺼내다
    죽었다"가 증명된다. 사용자 코드 프레임이 끼어 있으면 접근자는 그냥 스택
    아래쪽에 있을 뿐 크래시 원인이 아니다.
    """
    for i, frame in enumerate(frames):
        if _is_accessor(frame):
            above = frames[:i]
            if not all(_is_runtime(f) for f in above):
                return None, None
            # operator* → value() 처럼 접근자가 겹치면 가장 바깥(호출자 쪽)을 쓴다.
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
    """크래시 레코드 1건에서 에러계약 위반 근거를 모은다.

    Args:
        record: 클러스터 대표 레코드.
        kb: :class:`~logosfuzz.knowledge.knowledge_base.KnowledgeBase` (선택).
            있으면 크래시 함수의 선언된 error_contract 와 Bazel 타깃을 붙인다.
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
# 규칙 기반 판별기에 줄 신호
# --------------------------------------------------------------------------- #
# 점수 근거: reachability.derive_signals 의 harness-only-caller(-0.45)와 같은 무게로
# 하네스 위반을 깎는다 — 둘 다 "대상이 아니라 하네스가 만든 상황"의 증명이다.
# 대상 위반은 정상 호출로 재현되는 결함의 증명이라 결함 유형 사전확률(unknown=0.30)
# 을 정탐 임계치(0.65) 위로 올릴 만큼 준다.
_HARNESS_VIOLATION_DELTA = -0.45
_TARGET_VIOLATION_DELTA = 0.30
_CONTRACT_BYPASSED_DELTA = 0.10

_MEMORY_LIKE = {
    "use-after-free", "double-free", "heap-buffer-overflow", "buffer-overflow",
    "stack-buffer-overflow", "global-buffer-overflow", "null-pointer-dereference",
    "segv", "array-bounds", "null-deref",
}


def derive_signals(evidence: ErrorContractEvidence, bug_type: str = "") -> tuple[float, list[str]]:
    """(점수 보정치, 신호 목록)."""
    if evidence.violation == VIOLATED_BY_HARNESS:
        return _HARNESS_VIOLATION_DELTA, ["error-contract-violated-by-harness"]
    if evidence.violation == VIOLATED_BY_TARGET:
        return _TARGET_VIOLATION_DELTA, ["error-contract-violated-by-target"]
    if evidence.declared_contracts and bug_type in _MEMORY_LIKE:
        return _CONTRACT_BYPASSED_DELTA, ["error-contract-bypassed"]
    return 0.0, []


def render_rationale(evidence: ErrorContractEvidence) -> str:
    """HITL 검토자가 읽을 한 문장. 근거가 없으면 빈 문자열."""
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
    """LLM 판별기 프롬프트에 실을 증거 섹션."""
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
    """클러스터 → 에러계약 근거. 판별기에 주입해서 쓴다(KB 선택)."""

    def __init__(self, kb=None) -> None:
        self.kb = kb

    def __call__(self, cluster) -> ErrorContractEvidence:
        return analyze_error_contract(cluster.representative, self.kb)
