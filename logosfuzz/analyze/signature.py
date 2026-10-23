"""ANA-05-04: 다중 프레임 기반 크래시 시그니처 생성

EXE-04-02의 1-프레임 기본 시그니처(예: ``use-after-free_uds_c_73``) 대신
상위 N개 애플리케이션 프레임 결합 시그니처 사용 (과분리·과병합 방지)
런타임/할당자/퍼저 하네스 프레임은 제외

- ``depth`` 기본값 3 (CLI로 조정 가능)
"""

from __future__ import annotations

import hashlib

from logosfuzz.analyze.models import CrashRecord, Frame

# --------------------------------------------------------------------------- #
# 프레임 분류
# --------------------------------------------------------------------------- #

# sanitizer 런타임 / 할당자 / 퍼저 드라이버 프레임: 시그니처에서 제외 (경로/파일명 부분 문자열로 판정)
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
    # glibc / C++ 표준 라이브러리. abort 로 끝나는 크래시(score::Result 오류
    # 접근 → std::terminate 등)는 상단 5~10 프레임이 전부 여기라, 거르지 않으면
    # 서로 다른 결함이 ``pthread_kill.c:44|...`` 한 시그니처로 합쳐진다
    # (tests/fixtures/error_contract_logs 의 두 크래시가 실제로 그랬다).
    "nptl/",
    "sysdeps/",
    "stdlib/abort.c",
    "csu/libc-start",
    "/usr/include/c++/",
    "libstdc++",
)

# 퍼징 하네스 프레임: 별도 식별 (하네스만 등장 시 오탐 신호)
_HARNESS_MARKERS = (
    "harness",
    "llvmfuzzertestoneinput",
    "fuzz_target",
    "fuzzer_test",
    # GEN-03-01 산출물(``*_generated.c(pp)`` 또는 ``/gen/`` 아래)은 대상과 분리된 하네스 코드
    # 대상 프레임으로 세면 ANA-05-01이 하네스 자체 버그를 정탐으로 판정
    "_generated.",
    "/gen/",
)


def is_runtime_frame(frame: Frame) -> bool:
    """sanitizer/할당자/퍼저 런타임 프레임 여부 (시그니처 제외 대상)"""
    text = frame.file.replace("\\", "/").lower()
    return any(m in text for m in _RUNTIME_MARKERS)


def is_harness_frame(frame: Frame) -> bool:
    """퍼징 하네스 코드 프레임 여부"""
    text = frame.file.replace("\\", "/").lower()
    return any(m in text for m in _HARNESS_MARKERS)


def application_frames(record: CrashRecord) -> list[Frame]:
    """런타임 프레임 제거 후 애플리케이션(+하네스) 프레임만 상단 순서로 반환"""
    return [f for f in record.traceback if not is_runtime_frame(f)]


def has_application_frame(record: CrashRecord) -> bool:
    """대상 라이브러리 코드 프레임 존재 여부 (ANA-05-01 판별 신호)"""
    return any(
        (not is_runtime_frame(f)) and (not is_harness_frame(f))
        for f in record.traceback
    )


def _normalize_token(frame: Frame) -> str:
    """프레임의 시그니처 토큰(파일명:줄) 정규화 (경로 앞부분 제거)"""
    return f"{frame.basename}:{frame.line}"


def collapse_repeated_frames(frames: list[Frame]) -> list[Frame]:
    """정규화 후 동일한 연속 프레임 병합

    1. UBSan 헤더 줄과 ``#0`` 프레임의 같은 위치 중복 제거
    2. 재귀 호출로 쌓인 동일 프레임 접기 (과분리 방지)

    비연속 동일 위치는 다른 호출 경로이므로 유지
    """
    collapsed: list[Frame] = []
    previous_token: str | None = None
    for frame in frames:
        token = _normalize_token(frame)
        if token == previous_token:
            continue
        collapsed.append(frame)
        previous_token = token
    return collapsed


def signature_key(record: CrashRecord, depth: int = 3) -> str:
    """다중 프레임 시그니처 문자열

    형식: ``<bug_type>@<file1:line1>|<file2:line2>|...``  (상위 depth개 앱 프레임)
    앱 프레임 부재 시 기본 시그니처, 그것도 없으면 ``<bug_type>@unknown``
    """
    frames = collapse_repeated_frames(application_frames(record))[: max(1, depth)]
    if frames:
        chain = "|".join(_normalize_token(f) for f in frames)
        return f"{record.category}@{chain}"
    if record.base_signature:
        return f"{record.category}@{record.base_signature}"
    return f"{record.category}@unknown"


def signature_digest(key: str) -> str:
    """시그니처 문자열의 클러스터 ID용 다이제스트"""
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]


def cluster_id_for(record: CrashRecord, depth: int = 3) -> str:
    """레코드의 클러스터 ID (``CL-<digest>``)"""
    return "CL-" + signature_digest(signature_key(record, depth))
