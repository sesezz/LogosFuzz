"""GEN-03-02 자가치유 에러 코퍼스 고정 테스트 (D 파트 1주차).

`scripts/collect_selfheal_corpus.sh` 가 실제 Bazel/clang 실행으로 모아 온 원문이
`docs/GEN-03-02-ERROR-CORPUS.md` 의 대응표와 계속 일치하는지 지킨다.

여기서 Bazel 을 돌리지 않는다 — 커밋된 픽스처 텍스트만 읽는다. 그래서 CI 가
툴체인 없이도 돈다. 툴체인을 바꿔 코퍼스를 다시 수집했는데 문구가 달라졌다면
이 테스트가 먼저 깨지고, 그때 문서와 2주차 분류기를 같이 고치면 된다.

2주차 `generate/bazel_errors.py` 는 이 파일의 DECISIVE_PHRASES 를 정답지로 삼는다.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
BAZEL_ERRORS = FIXTURES / "bazel_errors"
SANITIZER_LOGS = FIXTURES / "sanitizer_logs"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


# --------------------------------------------------------------------------- #
# 1. Bazel 에러 — 문서 대응표 10행
# --------------------------------------------------------------------------- #
# (케이스, 분류를 가르는 결정적 문구)
DECISIVE_PHRASES = [
    ("no_such_target", "no such target '//score/json:jsonn'"),
    ("no_such_package", "no such package 'score/jsonx'"),
    ("not_visible", "is not visible from"),
    ("missing_dep", "fatal error: 'score/json/json.h' file not found"),
    ("undeclared_inclusion", "fatal error: 'score/internal/helper.h' file not found"),
    ("dep_cycle", "cycle in dependency graph:"),
    ("missing_srcs_file", "missing input file '//harness:json_fuzzer_extra.cc'"),
    ("no_load_statement", "This rule has been removed from Bazel"),
    ("bad_syntax", "syntax error at 'newline': expected expression"),
    ("link_undefined", "ld.lld: error: undefined symbol: score::json::ParseStrict"),
]


@pytest.mark.parametrize("case,phrase", DECISIVE_PHRASES)
def test_bazel_error_contains_decisive_phrase(case: str, phrase: str) -> None:
    log = _read(BAZEL_ERRORS / f"{case}.txt")
    assert phrase in log, f"{case}.txt 에서 결정적 문구를 찾지 못함: {phrase!r}"


def test_baseline_builds_clean() -> None:
    """대조군: 파손하지 않은 워크스페이스는 빌드에 성공해야 한다.

    이게 깨지면 위 파손 케이스들이 '의도한 파손' 때문인지 워크스페이스가 원래
    고장난 건지 구분할 수 없다.
    """
    log = _read(BAZEL_ERRORS / "_baseline_ok.txt")
    assert "Build completed successfully" in log
    assert "ERROR:" not in log


def test_no_such_target_alone_is_ambiguous() -> None:
    """발견 A — `no such target` 은 단독 분류 키로 쓸 수 없다.

    BUILD 파일이 파싱에 실패하면(load 누락/구문 오류) 그 안의 타깃이 정의되지
    않으므로 Bazel 은 deps 문제와 똑같은 `no such target` 문장을 낸다. 처방은
    정반대(BUILD 수정 vs deps 수정)이므로, 분류기는 없다고 지목된 레이블이
    **하네스 자신의 타깃인지 의존 대상인지**로 갈라야 한다.
    """
    own_target = "no such target '//harness:json_fuzzer'"
    for case in ("no_load_statement", "bad_syntax"):
        assert own_target in _read(BAZEL_ERRORS / f"{case}.txt"), (
            f"{case} 가 더 이상 하네스 자신의 타깃을 'no such target' 으로 "
            f"보고하지 않는다 — 문서의 발견 A 를 재확인할 것"
        )
    # 진짜 deps 문제는 '의존 대상' 레이블을 지목한다.
    assert own_target not in _read(BAZEL_ERRORS / "no_such_target.txt")


def test_missing_dep_surfaces_as_clang_not_bazel() -> None:
    """발견 B — deps 누락은 `no such target` 이 아니라 clang 헤더 에러로 나온다.

    설계표의 `no such target -> deps 추가` 매핑이 어긋나는 지점이다. deps 를
    비워도 Bazel 로딩·분석은 통과하고 컴파일 단계에서 터진다.
    """
    log = _read(BAZEL_ERRORS / "missing_dep.txt")
    assert "file not found" in log
    assert "no such target" not in log


def test_visibility_phrase_is_not_on_the_error_line() -> None:
    """발견 C — visibility 판정 문구는 `ERROR:` 줄이 아니라 그 다음 줄에 있다.

    `ERROR:` 로 시작하는 줄만 훑는 분류기는 대상 타깃명을 얻지 못한다.
    로그는 줄 단위가 아니라 블록 단위로 파싱해야 한다.
    """
    lines = _read(BAZEL_ERRORS / "not_visible.txt").splitlines()
    hits = [ln for ln in lines if "is not visible from" in ln]
    assert hits, "visibility 에러 문구가 사라졌다"
    assert not any(ln.startswith("ERROR:") for ln in hits), (
        "이제는 ERROR: 줄에 문구가 있다 — 문서의 발견 C 와 분류기 파싱 방식을 재확인할 것"
    )


# --------------------------------------------------------------------------- #
# 2. Sanitizer 출력
# --------------------------------------------------------------------------- #
# (케이스, UBSan runtime error 줄의 고유 문구)
UBSAN_PHRASES = [
    ("ubsan_signed_overflow", "signed integer overflow:"),
    ("ubsan_shift_exponent", "shift exponent 33 is too large"),
    ("ubsan_null_deref", "member access within null pointer"),
    ("ubsan_divide_by_zero", "division by zero"),
    ("ubsan_array_bounds", "index 9 out of bounds for type 'int[8]'"),
    ("ubsan_misaligned_load", "load of misaligned address"),
    ("ubsan_float_cast_overflow", "outside the range of representable values"),
    ("ubsan_invalid_bool", "is not a valid value for type 'bool'"),
]

# 발견 D — 기본 `--config=asan_ubsan_lsan` 에서 프로세스가 살아남는(=크래시로
# 기록되지 않는) UB 종류. 6/8 이다.
RECOVERABLE_UB = {
    "ubsan_signed_overflow",
    "ubsan_shift_exponent",
    "ubsan_divide_by_zero",
    "ubsan_misaligned_load",
    "ubsan_float_cast_overflow",
    "ubsan_invalid_bool",
}


def _exit_code(path: Path) -> int:
    for line in _read(path).splitlines():
        if line.startswith("[exit code] "):
            return int(line.removeprefix("[exit code] ").strip())
    raise AssertionError(f"{path.name} 에 [exit code] 줄이 없다")


@pytest.mark.parametrize("case,phrase", UBSAN_PHRASES)
def test_ubsan_runtime_error_phrase(case: str, phrase: str) -> None:
    log = _read(SANITIZER_LOGS / f"{case}.txt")
    assert "runtime error:" in log
    assert phrase in log, f"{case}.txt 에서 UBSan 문구를 찾지 못함: {phrase!r}"


@pytest.mark.parametrize("case", sorted(RECOVERABLE_UB))
def test_recoverable_ub_exits_zero_but_halt_config_does_not(case: str) -> None:
    """발견 D — 기본 설정에서 UB 는 진단만 찍고 정상 종료(exit 0)한다.

    exit 0 이면 libFuzzer 가 크래시 아티팩트를 만들지 않고, 파이프라인은 정상
    종료로 집계하며, ANA 단계에 판별 대상이 도착하지 않는다. `_halt` 설정
    (`-fno-sanitize-recover=undefined`)에서만 프로세스가 죽는다.
    """
    assert _exit_code(SANITIZER_LOGS / f"{case}.txt") == 0
    assert _exit_code(SANITIZER_LOGS / f"halt_{case}.txt") != 0


@pytest.mark.parametrize("case", sorted(RECOVERABLE_UB))
def test_diagnostic_text_identical_across_configs(case: str) -> None:
    """발견 D — 두 설정의 진단 텍스트는 같다. 로그만으로는 구분할 수 없다."""

    def runtime_errors(path: Path) -> list[str]:
        return [ln for ln in _read(path).splitlines() if "runtime error:" in ln]

    assert runtime_errors(SANITIZER_LOGS / f"{case}.txt") == runtime_errors(
        SANITIZER_LOGS / f"halt_{case}.txt"
    )


@pytest.mark.parametrize("case", ["ubsan_null_deref", "ubsan_array_bounds"])
def test_single_event_yields_two_diagnostics(case: str) -> None:
    """발견 E — 한 사건에 UBSan·ASan 진단이 둘 다 붙고 마지막 SUMMARY 는 ASan 이다.

    마지막 SUMMARY 만 읽는 파서는 근본 원인(널 역참조/인덱스 초과)을 버리고
    증상(SEGV/stack-buffer-overflow)만 남긴다. 시그니처는 **첫** 진단으로 잡아야 한다.
    """
    summaries = [ln for ln in _read(SANITIZER_LOGS / f"{case}.txt").splitlines()
                 if ln.startswith("SUMMARY:")]
    assert len(summaries) == 2, f"{case}: SUMMARY 가 2개가 아니다 -> {summaries}"
    assert summaries[0].startswith("SUMMARY: UndefinedBehaviorSanitizer")
    assert summaries[-1].startswith("SUMMARY: AddressSanitizer")


def test_ubsan_summary_does_not_name_the_check() -> None:
    """발견 F — UBSan SUMMARY 는 어느 검사든 항상 `undefined-behavior` 다.

    구체적 종류는 `runtime error:` 줄에만 있다. SUMMARY 를 파싱하면 UBSan 결함이
    전부 한 덩어리로 뭉개진다.
    """
    for case, phrase in UBSAN_PHRASES:
        for line in _read(SANITIZER_LOGS / f"{case}.txt").splitlines():
            if line.startswith("SUMMARY: UndefinedBehaviorSanitizer"):
                assert "undefined-behavior" in line
                assert phrase not in line, (
                    f"{case}: 이제 SUMMARY 가 검사 종류를 담는다 — 발견 F 재확인"
                )


def test_leak_exit_code_is_77() -> None:
    """발견 G — LSan 은 exit 77 로 끝나고, ERROR 와 SUMMARY 의 도구 이름이 엇갈린다."""
    log = _read(SANITIZER_LOGS / "lsan_memory_leak.txt")
    assert _exit_code(SANITIZER_LOGS / "lsan_memory_leak.txt") == 77
    assert "ERROR: LeakSanitizer: detected memory leaks" in log
    assert "SUMMARY: AddressSanitizer:" in log and "leaked in" in log


def test_clean_case_has_no_diagnostic() -> None:
    """대조군: 정상 경로는 진단도 없고 종료 코드도 0 이어야 한다."""
    log = _read(SANITIZER_LOGS / "clean_no_diagnostic.txt")
    assert "runtime error:" not in log
    assert "SUMMARY:" not in log
    assert _exit_code(SANITIZER_LOGS / "clean_no_diagnostic.txt") == 0


# --------------------------------------------------------------------------- #
# 3. 메타데이터
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("directory", [BAZEL_ERRORS, SANITIZER_LOGS])
def test_meta_is_valid_and_records_toolchain(directory: Path) -> None:
    meta = json.loads(_read(directory / "_META.json"))
    for key in ("purpose", "collected_at", "bazel_version", "clang_version", "normalization"):
        assert key in meta, f"{directory.name}/_META.json 에 {key} 가 없다"
    assert meta["bazel_version"], "bazel 버전이 비어 있다"
    assert meta["clang_version"], "clang 버전이 비어 있다"


@pytest.mark.parametrize("directory", [BAZEL_ERRORS, SANITIZER_LOGS])
def test_no_absolute_paths_leaked(directory: Path) -> None:
    """정규화 확인 — 수집한 머신의 절대경로가 커밋되면 안 된다."""
    for path in directory.glob("*.txt"):
        text = _read(path)
        for leak in ("/home/", "/mnt/c/", "C:\\Users"):
            assert leak not in text, f"{path.name} 에 절대경로가 남아 있다: {leak}"
