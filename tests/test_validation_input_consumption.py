"""GEN-03-04 입력 소비 검증 테스트 (D 파트 3주차).

하네스가 퍼즈 입력을 실제로 쓰는지 판정하는 단계다. 커버리지 검사와 무엇이 다른지가
이 테스트들의 핵심 — 커버리지가 0이면 "타겟에 못 닿았다"이고, 커버리지는 나오는데
입력을 안 쓰면 "닿긴 했는데 항상 같은 값으로 닿는다"이다. 후자는 커버리지 임계치를
통과하므로 기존 단계로는 절대 걸리지 않는데, 퍼징을 몇 시간 돌려도 새 경로가 하나도
안 나온다.

게이트 설계 원칙: **증명 가능한 경우에만 실패**시킨다. 진입점을 파싱하지 못한 건
하네스가 잘못됐다는 뜻이 아니라 검사기의 한계일 수 있으므로 통과시키되
`checked=False` 로 "근거 없이 통과시켰다"는 사실을 남긴다.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from logosfuzz.generate.contracts import HarnessArtifact
from logosfuzz.generate.validation import (
    STEP_COVERAGE,
    STEP_INPUT_CONSUMPTION,
    STEP_SMOKE,
    RunResult,
    ValidationConfig,
    check_input_consumption,
    parse_entry_point,
    parse_new_units_added,
    strip_comments_and_strings,
    validate_harness,
)

CONSUMING = """
#include <cstdint>
#include <cstddef>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 4) return 0;
  score::json::Parse(data, size);
  return 0;
}
"""

IGNORING = """
#include <cstdint>
#include <cstddef>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  score::json::Parse("hardcoded", 9);
  return 0;
}
"""


# --------------------------------------------------------------------------- #
# 판정
# --------------------------------------------------------------------------- #
def test_harness_that_uses_its_input_passes() -> None:
    result = check_input_consumption(CONSUMING)
    assert result.passed
    assert result.checked
    assert result.used_params == ["data", "size"]


def test_harness_that_hardcodes_its_arguments_fails() -> None:
    """LLM 이 만든 하네스의 대표적 실패 — 대상 API 를 부르긴 하는데 인자가 상수다."""
    result = check_input_consumption(IGNORING)
    assert not result.passed
    assert result.checked
    assert result.used_params == []
    assert "한 번도 쓰지 않는다" in result.reason


def test_explicitly_discarded_parameters_do_not_count_as_use() -> None:
    """`(void)data;` 는 입력을 쓴다는 증거가 아니라 안 쓴다는 증거다."""
    source = """
    extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
      (void)data;
      (void)size;
      return 0;
    }
    """
    assert not check_input_consumption(source).passed


@pytest.mark.parametrize(
    "discard",
    ["(void)data;", "(void) data ;", "(void)(data);", "std::ignore = data",
     "UNUSED(data)", "MAYBE_UNUSED(data)"],
)
def test_discard_idioms_are_recognised(discard: str) -> None:
    source = f"""
    extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
      {discard};
      (void)size;
      return 0;
    }}
    """
    assert not check_input_consumption(source).passed


def test_parameters_mentioned_only_in_comments_do_not_count() -> None:
    """주석에 적힌 `data` 를 사용 증거로 세면 안 된다."""
    source = """
    extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
      // TODO: data 와 size 를 써야 한다
      /* data 를 여기서 파싱할 것 */
      Run("fixed");
      return 0;
    }
    """
    assert not check_input_consumption(source).passed


def test_parameters_mentioned_only_in_string_literals_do_not_count() -> None:
    source = """
    extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
      Log("data and size are ignored");
      return 0;
    }
    """
    assert not check_input_consumption(source).passed


def test_fuzzed_data_provider_counts_as_consumption() -> None:
    """C++ 하네스의 표준 형태. 인자를 FDP 에 넘기는 것만으로 소비다."""
    source = """
    extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
      FuzzedDataProvider fdp(data, size);
      Parse(fdp.ConsumeRandomLengthString());
      return 0;
    }
    """
    result = check_input_consumption(source)
    assert result.passed
    assert result.used_params == ["data", "size"]


def test_using_only_the_length_passes_but_warns() -> None:
    """크기에만 반응하는 하네스는 돌긴 하지만 탐색 폭이 거의 없다.

    증명 가능한 '입력 무시'는 아니므로 막지 않되, 경고로 남긴다.
    """
    source = """
    extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
      if (size > 100) Boom();
      return 0;
    }
    """
    result = check_input_consumption(source)
    assert result.passed
    assert result.used_params == ["size"]
    assert "버퍼(data)는 쓰지 않는다" in result.warning


# --------------------------------------------------------------------------- #
# 검사기 한계를 실패로 오인하지 않는가
# --------------------------------------------------------------------------- #
def test_missing_source_passes_but_is_marked_unchecked() -> None:
    result = check_input_consumption(None)
    assert result.passed
    assert not result.checked


def test_missing_entry_point_passes_but_is_marked_unchecked() -> None:
    result = check_input_consumption("int main(void) { return 0; }")
    assert result.passed
    assert not result.checked
    assert "찾지 못해" in result.reason


def test_declaration_without_definition_is_skipped() -> None:
    """선언만 있고 정의가 없으면 본문이 없으므로 판정할 수 없다."""
    source = """
    extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
    """
    result = check_input_consumption(source)
    assert result.passed
    assert not result.checked


def test_declaration_followed_by_definition_is_analysed() -> None:
    """선언이 앞에 있어도 뒤의 정의를 찾아내야 한다."""
    source = f"""
    extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
    {CONSUMING}
    """
    result = check_input_consumption(source)
    assert result.checked
    assert result.passed


def test_nested_braces_in_body_are_handled() -> None:
    source = """
    extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
      if (size) { for (size_t i = 0; i < size; ++i) { Use(data[i]); } }
      return 0;
    }
    """
    assert check_input_consumption(source).passed


# --------------------------------------------------------------------------- #
# 헬퍼
# --------------------------------------------------------------------------- #
def test_parse_entry_point_returns_names_and_body() -> None:
    params, body = parse_entry_point(CONSUMING)
    assert params == ["data", "size"]
    assert "score::json::Parse" in body


def test_strip_comments_preserves_length() -> None:
    """오프셋이 어긋나지 않게 같은 길이의 공백으로 바꾼다."""
    source = 'int x; // 주석\n/* 블록 */ char *s = "문자열";'
    assert len(strip_comments_and_strings(source)) == len(source)


def test_parse_new_units_added() -> None:
    log = "stat::number_of_executed_units: 100\nstat::new_units_added:          7\n"
    assert parse_new_units_added(log) == 7
    assert parse_new_units_added("아무것도 없음") is None


def test_zero_new_units_is_reported_as_a_warning_not_a_failure() -> None:
    """돌연변이가 새 경로를 못 여는 건 하네스 결함이 아닐 수 있다(시드 문제 등)."""
    result = check_input_consumption(CONSUMING, "stat::new_units_added:          0")
    assert result.passed
    assert result.new_units_added == 0
    assert "코퍼스 단위가 0" in result.warning


# --------------------------------------------------------------------------- #
# 오케스트레이션에 끼워졌는가
# --------------------------------------------------------------------------- #
def _artifact(tmp_path: Path, source: str | None) -> HarnessArtifact:
    binary = tmp_path / "harness"
    binary.write_text("not a real binary", encoding="utf-8")
    source_path = None
    if source is not None:
        source_path = tmp_path / "harness.cc"
        source_path.write_text(source, encoding="utf-8")
    return HarnessArtifact(group_id="LG-1", harness_path=binary, source_path=source_path)


def _runner(log: str):
    def run(argv, timeout):
        return RunResult(exit_code=0, timed_out=False, log=log)
    return run


GOOD_LOG = "#2 INITED cov: 12 ft: 13\nstat::new_units_added:          3\n"


def test_step_runs_between_coverage_and_mock_trace(tmp_path: Path) -> None:
    report = validate_harness(
        _artifact(tmp_path, CONSUMING), ValidationConfig(), _runner(GOOD_LOG)
    )
    assert report.passed
    assert report.steps_run[:3] == [STEP_SMOKE, STEP_COVERAGE, STEP_INPUT_CONSUMPTION]


def test_ignoring_harness_fails_validation_despite_good_coverage(tmp_path: Path) -> None:
    """이 단계가 존재하는 이유 — 커버리지는 통과하는데 퍼징이 성립하지 않는 경우."""
    report = validate_harness(
        _artifact(tmp_path, IGNORING), ValidationConfig(), _runner(GOOD_LOG)
    )
    assert not report.passed
    assert report.failed_step == STEP_INPUT_CONSUMPTION
    assert report.coverage is not None and report.coverage.passed
    assert "한 번도 쓰지 않는다" in report.reason


def test_report_serialises_the_new_step(tmp_path: Path) -> None:
    import json

    report = validate_harness(
        _artifact(tmp_path, CONSUMING), ValidationConfig(), _runner(GOOD_LOG)
    )
    data = report.to_dict()
    json.dumps(data, ensure_ascii=False)
    assert data["input_consumption"]["checked"] is True
    assert data["input_consumption"]["used_params"] == ["data", "size"]


def test_warnings_surface_on_the_report(tmp_path: Path) -> None:
    source = """
    extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
      if (size > 100) Boom();
      return 0;
    }
    """
    report = validate_harness(
        _artifact(tmp_path, source), ValidationConfig(), _runner(GOOD_LOG)
    )
    assert report.passed
    assert any(STEP_INPUT_CONSUMPTION in w for w in report.warnings)


def test_validation_without_source_still_runs_the_step(tmp_path: Path) -> None:
    """소스가 없어도 단계는 돌되 근거 없이 통과시켰음을 남긴다."""
    report = validate_harness(
        _artifact(tmp_path, None), ValidationConfig(), _runner(GOOD_LOG)
    )
    assert report.passed
    assert STEP_INPUT_CONSUMPTION in report.steps_run
    assert report.input_consumption is not None
    assert not report.input_consumption.checked
