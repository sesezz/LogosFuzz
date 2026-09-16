"""ANA-05-04: 다중 프레임 기반 크래시 시그니처 생성.

배경
----
EXE-04-02는 "결함유형_파일명_줄번호" 형태의 **1-프레임 기본 시그니처**를 만든다
(예: ``use-after-free_uds_c_73``). EXE-04-02 개발보고서는 "정교한 다중 프레임
해싱과 중복 병합은 ANA-05-04의 책임으로 남긴다"고 명시한다.

1-프레임만 쓰면 다음 문제가 생긴다.
- **과분리(over-split)**: 같은 버그가 서로 다른 경로(호출처)로 도달하면, 최상단
  프레임이 얕은 래퍼/인라인 차이로 달라져 별개 버그처럼 흩어진다.
- **과병합(under-merge)**: 서로 다른 버그가 우연히 같은 파일·줄에서 최종
  크래시하면(공용 유틸 함수 등) 하나로 합쳐진다.

그래서 업계 표준(ClusterFuzz, AFL 계열)처럼 **상위 N개 애플리케이션 프레임**을
결합해 시그니처를 만든다. 런타임/할당자/퍼저 하네스 프레임은 버그 정체성과
무관한 잡음이므로 걸러낸다.

설계 파라미터 근거
------------------
- ``depth`` 기본값 **3**: ClusterFuzz의 스택 기반 중복 판정이 상위 소수 프레임을
  쓰는 관례를 따랐다. 1은 과분리, 너무 깊으면(전체 스택) 사소한 하단 차이로
  과분리된다. 자동차 오픈소스 콜스택(dlt-daemon 등)에서 2~3 프레임이면 결함
  지점과 직접 호출자를 포착하기에 충분하다는 판단. 값은 CLI로 조정 가능하다.
"""

from __future__ import annotations

import hashlib

from logosfuzz.analyze.models import CrashRecord, Frame

# --------------------------------------------------------------------------- #
# 프레임 분류 — 어떤 프레임이 "버그 정체성"에 기여하는가
# --------------------------------------------------------------------------- #

# sanitizer 런타임 / 할당자 / 퍼저 드라이버 프레임: 모든 크래시에 공통으로 끼는
# 잡음이므로 시그니처에서 제외한다. (경로/파일명 부분 문자열로 판정)
_RUNTIME_MARKERS = (
    "compiler-rt",
    "/asan_",
    "asan_malloc",
    "sanitizer_common",
    "/tsan_",
    "/lsan_",
    "/ubsan_",
    "fuzzerloop",
    "fuzzerdriver",
    "fuzzermain",
    "libfuzzer",
    "/llvm/",
)

# 퍼징 하네스 프레임: 버그가 애플리케이션 코드에 있는지 판단할 때 필요하므로
# 별도로 식별한다. (하네스만 등장하면 하네스 자체 문제일 수 있음 → 오탐 신호)
_HARNESS_MARKERS = (
    "harness",
    "llvmfuzzertestoneinput",
    "fuzz_target",
    "fuzzer_test",
    # GEN-03-01 산출물은 보통 ``*_generated.c(pp)`` 또는 ``/gen/`` 아래에
    # 저장된다. 이 경로는 대상 라이브러리와 분리된 하네스 코드이므로
    # 대상 프레임으로 세면 ANA-05-01이 하네스 자체 버그를 정탐으로 올린다.
    "_generated.",
    "/gen/",
)


def is_runtime_frame(frame: Frame) -> bool:
    """sanitizer/할당자/퍼저 런타임 프레임이면 True(시그니처에서 제외 대상)."""
    text = frame.file.replace("\\", "/").lower()
    return any(m in text for m in _RUNTIME_MARKERS)


def is_harness_frame(frame: Frame) -> bool:
    """퍼징 하네스 코드 프레임이면 True."""
    text = frame.file.replace("\\", "/").lower()
    return any(m in text for m in _HARNESS_MARKERS)


def application_frames(record: CrashRecord) -> list[Frame]:
    """런타임 프레임을 제거하고, 애플리케이션(+하네스) 프레임만 상단 순서로 반환."""
    return [f for f in record.traceback if not is_runtime_frame(f)]


def has_application_frame(record: CrashRecord) -> bool:
    """하네스가 아닌 실제 대상 라이브러리 코드 프레임이 하나라도 있으면 True.

    정/오탐 판별(ANA-05-01)에서 "버그가 대상 코드에 있는가"를 판단하는 신호.
    """
    return any(
        (not is_runtime_frame(f)) and (not is_harness_frame(f))
        for f in record.traceback
    )


def _normalize_token(frame: Frame) -> str:
    """프레임을 시그니처 토큰(파일명:줄)으로 정규화.

    경로 앞부분(빌드 머신마다 다른 ``/src/...`` 등)은 버리고 파일명만 남겨
    환경 독립적으로 만든다.
    """
    return f"{frame.basename}:{frame.line}"


def signature_key(record: CrashRecord, depth: int = 3) -> str:
    """사람이 읽는 다중 프레임 시그니처 문자열.

    형식: ``<bug_type>@<file1:line1>|<file2:line2>|...``  (상위 depth개 앱 프레임)

    앱 프레임이 하나도 없으면(예: 런타임/하네스만) 기본 시그니처로 폴백하고,
    그것도 없으면 ``<bug_type>@unknown``.
    """
    frames = application_frames(record)[: max(1, depth)]
    if frames:
        chain = "|".join(_normalize_token(f) for f in frames)
        return f"{record.category}@{chain}"
    if record.base_signature:
        return f"{record.category}@{record.base_signature}"
    return f"{record.category}@unknown"


def signature_digest(key: str) -> str:
    """시그니처 문자열 → 짧고 안정적인 다이제스트(클러스터 ID용)."""
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]


def cluster_id_for(record: CrashRecord, depth: int = 3) -> str:
    """레코드의 클러스터 ID(``CL-<digest>``)."""
    return "CL-" + signature_digest(signature_key(record, depth))
