"""reporting/summary.py 빌드 단위 키 테스트 (4주차)."""
from __future__ import annotations

import json

import pytest

from logosfuzz.cli import main
from logosfuzz.reporting.summary import (
    SUMMARY_SCHEMA_VERSION,
    UNASSIGNED_BUILD_TARGET,
    ValidationSummaryError,
    build_validation_summary,
    render_build_units_markdown,
    validate_validation_summary,
)

JSON_UNIT = "@score_baselibs//score/json"
DIGEST_UNIT = "//score/crypto:sha256"


def _run():
    return {
        "engine": "libfuzzer",
        "timeout_sec": 30,
        "groups": [
            # EXE 가 Logic Group 이름으로 기록한 경우
            {"group": "lg_json", "exit_code": 1, "crashed": True, "execs": 100,
             "duration_sec": 10, "coverage": 40,
             "crashes": ["crash-1"], "sanitizer_findings": [{"category": "heap-buffer-overflow"}]},
            # 같은 빌드 단위의 두 번째 그룹 — cc_fuzz_test _bin 이름으로 기록된 경우
            {"group": "lg_json_writer_fuzz_test_bin", "exit_code": 0, "execs": 50,
             "duration_sec": 5, "coverage": 55, "crashes": [], "sanitizer_findings": []},
            # 그룹 자체에 build_target 이 들어 있는 경우 (BUILD 결과보다 우선)
            {"group": "lg_digest", "build_target": DIGEST_UNIT, "build_system": "bazel",
             "exit_code": 0, "timed_out": True, "execs": 7, "duration_sec": 30,
             "crashes": [], "sanitizer_findings": []},
            # 빌드 정보가 전혀 없는 레거시 그룹
            {"group": "dlt_fuzzer", "exit_code": 0, "execs": 1, "duration_sec": 1,
             "crashes": [], "sanitizer_findings": []},
        ],
    }


def _build():
    return {
        "schema_version": "1.0",
        "build_system": "bazel",
        "config": "fuzz",
        "units": [
            {"group": "lg_json", "build_target": JSON_UNIT, "build_system": "bazel",
             "fuzz_target": "//score/json/fuzz/lg_json:lg_json_fuzz_test",
             "binary": "/ws/bazel-out/k8-fuzz/bin/score/json/fuzz/lg_json/lg_json_fuzz_test_bin",
             "status": "built", "rounds_used": 1},
            {"group": "lg_json_writer", "build_target": JSON_UNIT, "build_system": "bazel",
             "fuzz_target": "//score/json/fuzz/lg_json_writer:lg_json_writer_fuzz_test",
             "binary": "/ws/bin/lg_json_writer_fuzz_test_bin",
             "status": "repaired", "rounds_used": 2},
            # 빌드는 실패해서 실행 기록이 없는 단위
            {"group": "lg_broken", "build_target": "//score/broken:x", "build_system": "bazel",
             "fuzz_target": "//score/broken/fuzz/lg_broken:lg_broken_fuzz_test",
             "binary": None, "status": "failed", "rounds_used": 3},
        ],
    }


def _units(result):
    return {u["build_target"]: u for u in result["build_units"]["units"]}


def test_groups_get_build_unit_fields_from_build_summary():
    result = build_validation_summary(_run(), build_summary=_build())
    groups = {g["target"]: g for g in result["run"]["groups"]}

    assert groups["lg_json"]["build_target"] == JSON_UNIT
    assert groups["lg_json"]["build_system"] == "bazel"
    assert groups["lg_json"]["fuzz_target"].endswith(":lg_json_fuzz_test")
    # _bin 이름으로 기록돼도 붙는다
    assert groups["lg_json_writer_fuzz_test_bin"]["build_target"] == JSON_UNIT
    # 그룹 자체 값이 우선
    assert groups["lg_digest"]["build_target"] == DIGEST_UNIT
    # 모르는 그룹은 None
    assert groups["dlt_fuzzer"]["build_target"] is None


def test_build_units_are_aggregated_per_target():
    result = build_validation_summary(_run(), build_summary=_build())
    section = result["build_units"]
    units = _units(result)

    assert section["status"] == "completed"
    assert section["config"] == "fuzz"

    json_unit = units[JSON_UNIT]
    # EXE 가 `_bin` 이름으로 기록한 그룹은 build 결과의 Logic Group 이름으로 합쳐진다
    assert json_unit["groups"] == ["lg_json", "lg_json_writer"]
    assert json_unit["build_status"] == "repaired"      # built + repaired -> repaired
    assert json_unit["rounds_used"] == 2
    assert json_unit["run_status"] == "crashed"
    assert json_unit["run_groups"] == 2
    assert json_unit["crashes"] == 1
    assert json_unit["sanitizer_findings"] == 1
    assert json_unit["execs"] == 150
    assert json_unit["coverage"] == 55

    assert units[DIGEST_UNIT]["run_status"] == "timeout"
    assert units[DIGEST_UNIT]["build_status"] == "not_built"

    broken = units["//score/broken:x"]
    assert broken["build_status"] == "failed"
    assert broken["run_status"] == "not_run"

    assert units[UNASSIGNED_BUILD_TARGET]["groups"] == ["dlt_fuzzer"]
    # 미할당은 맨 뒤, 집계 수에서 제외
    assert result["build_units"]["units"][-1]["build_target"] == UNASSIGNED_BUILD_TARGET
    assert section["total_units"] == 3
    assert section["built_units"] == 1
    assert section["repaired_units"] == 1
    assert section["failed_units"] == 1
    assert section["crashed_units"] == 1


def test_group_names_are_not_duplicated_across_build_and_exe_names():
    """같은 그룹이 build 이름·EXE 이름 두 개로 build_units.groups 에 중복 등장하지 않는다."""
    run = {"groups": [
        {"group": "lg_json_fuzz_test", "exit_code": 0},                 # cc_fuzz_test 이름
        {"group": "x", "harness_name": "x", "exit_code": 0,
         "binary": "/elsewhere/lg_json_writer_fuzz_test_bin"},          # 바이너리 이름으로만 식별
    ]}
    result = build_validation_summary(run, build_summary=_build())
    groups = _units(result)[JSON_UNIT]["groups"]
    assert groups == ["lg_json", "lg_json_writer"]
    assert len(groups) == len(set(groups))


def test_existing_contract_is_unchanged():
    """빌드 단위는 선택 필드 추가일 뿐 — schema_version·metrics 는 그대로다."""
    with_build = build_validation_summary(_run(), build_summary=_build())
    without = build_validation_summary(_run())
    assert with_build["schema_version"] == SUMMARY_SCHEMA_VERSION == "1.0"
    assert with_build["metrics"] == without["metrics"]
    assert without["build_units"]["status"] == "not_run"


def test_validation_rejects_malformed_build_units():
    data = build_validation_summary(_run(), build_summary=_build())
    data["build_units"]["units"][0]["build_target"] = ""
    with pytest.raises(ValidationSummaryError, match="build_target"):
        validate_validation_summary(data)

    legacy = build_validation_summary(_run())
    del legacy["build_units"]
    validate_validation_summary(legacy)  # 없는 건 허용(예전 산출물)


def test_markdown_table():
    md = render_build_units_markdown(build_validation_summary(_run(), build_summary=_build()))
    assert "빌드 단위 3개" in md
    assert f"| `{JSON_UNIT}` |" in md
    assert "repaired" in md and "crashed" in md


def test_cli_summary_with_build(tmp_path, capsys):
    run_path = tmp_path / "fuzz_summary.json"
    build_path = tmp_path / "build_summary.json"
    out = tmp_path / "validation-summary.json"
    md = tmp_path / "build_units.md"
    run_path.write_text(json.dumps(_run()), encoding="utf-8")
    build_path.write_text(json.dumps(_build()), encoding="utf-8")

    assert main([
        "summary", "--run", str(run_path), "--build", str(build_path),
        "--output", str(out), "--markdown", str(md),
    ]) == 0

    saved = json.loads(out.read_text(encoding="utf-8"))
    assert saved["build_units"]["built_units"] == 1
    assert md.read_text(encoding="utf-8").startswith("빌드 단위 3개")
    assert "빌드 단위 3개" in capsys.readouterr().out
