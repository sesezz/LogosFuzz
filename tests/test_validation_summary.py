import json

import pytest

from logosfuzz.cli import main
from logosfuzz.reporting.summary import (
    SUMMARY_SCHEMA_VERSION,
    ValidationSummaryError,
    build_validation_summary,
    load_json,
    validate_validation_summary,
    write_validation_summary,
)


def _run_summary():
    return {
        "engine": "libfuzzer",
        "timeout_sec": 30,
        "started_at": 1,
        "finished_at": 31,
        "groups": [
            {
                "group": "dlt_fuzzer",
                "exit_code": 0,
                "timed_out": False,
                "crashed": False,
                "duration_sec": 30.2,
                "execs": 1200,
                "exec_per_sec": 39.7,
                "coverage": 18,
                "crashes": [],
                "sanitizer_findings": [],
            },
            {
                "group": "score_fuzzer",
                "exit_code": 1,
                "timed_out": False,
                "crashed": True,
                "duration_sec": 0.3,
                "exec_per_sec": 0,
                "coverage": 4,
                "crashes": ["crashes/crash-1"],
                "sanitizer_findings": [{"category": "buffer-overflow"}],
            },
        ],
    }


def test_build_summary_passes_through_stdout_and_stderr_log_paths():
    """표준 출력/표준 오류 로그 경로는 화면이 쓸 수 있도록 그대로 보존된다.

    docker_runner.run_group()이 채우는 선택 필드다 - 다연 스키마의 호환성
    규칙("새 화면 기능은 선택 필드를 추가하는 방식")을 따른다.
    """
    run = _run_summary()
    run["groups"][0]["stdout_log"] = "out/logs/dlt_fuzzer/run.stdout.log"
    run["groups"][0]["stderr_log"] = "out/logs/dlt_fuzzer/run.stderr.log"

    result = build_validation_summary(run)

    group = result["run"]["groups"][0]
    assert group["stdout_log"] == "out/logs/dlt_fuzzer/run.stdout.log"
    assert group["stderr_log"] == "out/logs/dlt_fuzzer/run.stderr.log"


def test_build_summary_defaults_log_paths_to_none_when_absent():
    run = _run_summary()
    result = build_validation_summary(run)
    group = result["run"]["groups"][0]
    assert group["stdout_log"] is None
    assert group["stderr_log"] is None


def test_build_summary_normalises_statuses_and_metrics():
    result = build_validation_summary(
        _run_summary(),
        {
            "triage_model": "rule/v1",
            "summary": {"true_positive": 1, "false_positive": 0},
            "findings": [{"cluster_id": "c1"}],
        },
        metadata={"project": "LogosFuzz", "environment": "ec2"},
        generated_at="2026-08-29T00:00:00+00:00",
    )

    assert result["schema_version"] == SUMMARY_SCHEMA_VERSION
    assert result["run"]["groups"][0]["status"] == "passed"
    assert result["run"]["groups"][1]["status"] == "crashed"
    assert result["metrics"] == {
        "groups": 2,
        "passed_groups": 1,
        "failed_groups": 0,
        "timed_out_groups": 0,
        "crashed_groups": 1,
        "crashes": 1,
        "sanitizer_findings": 1,
        "true_positive": 1,
        "false_positive": 0,
        "needs_review": 0,
    }
    assert result["analysis"]["status"] == "completed"


def test_missing_analysis_is_explicitly_not_run():
    result = build_validation_summary(_run_summary())

    assert result["analysis"]["status"] == "not_run"
    assert result["metrics"]["needs_review"] == 0


def test_sanitizer_finding_alone_is_reported_as_crashed():
    """크래시 산출물이 없어도 sanitizer 결함이 있으면 crashed 다.

    스키마 문서의 정의 - "크래시 산출물 또는 sanitizer 오류가 확인됨" - 를 따른다.
    ASAN이 결함을 잡았는데 libFuzzer가 artifact를 남기지 못한 실행이 실제로
    관측된다. 이 경우를 passed 로 보고하면 리포트가 버그를 숨긴다.
    """
    run = _run_summary()
    group = run["groups"][0]
    group["crashed"] = False
    group["crashes"] = []
    group["exit_code"] = 0
    group["sanitizer_findings"] = [{"category": "buffer-overflow"}]

    result = build_validation_summary(run)

    assert result["run"]["groups"][0]["status"] == "crashed"
    assert result["run"]["groups"][0]["sanitizer_count"] == 1
    assert result["run"]["groups"][0]["crash_count"] == 0
    assert result["metrics"]["crashed_groups"] == 2   # 원래 crashed 이던 그룹 포함
    assert result["metrics"]["passed_groups"] == 0


def test_empty_sanitizer_findings_do_not_change_the_status():
    """빈 결함 목록이 정상 실행을 crashed 로 만들지 않는다."""
    run = _run_summary()
    run["groups"][0]["sanitizer_findings"] = []

    result = build_validation_summary(run)

    assert result["run"]["groups"][0]["status"] == "passed"


def test_non_list_sanitizer_findings_are_ignored_in_the_status():
    """손상된 입력이 상태 판정을 흔들지 않는다."""
    run = _run_summary()
    run["groups"][0]["sanitizer_findings"] = "buffer-overflow"

    result = build_validation_summary(run)

    assert result["run"]["groups"][0]["status"] == "passed"
    assert result["run"]["groups"][0]["sanitizer_count"] == 0


def test_timeout_takes_precedence_over_crash():
    run = _run_summary()
    run["groups"][0]["timed_out"] = True
    run["groups"][0]["crashed"] = True

    result = build_validation_summary(run)

    assert result["run"]["groups"][0]["status"] == "timeout"
    assert result["metrics"]["timed_out_groups"] == 1


def test_timeout_still_takes_precedence_over_a_sanitizer_finding():
    """새니타이저 결함이 추가돼도 타임아웃 우선 계약은 유지된다.

    이 우선순위는 스키마 소유자가 정한 것이라 임의로 뒤집지 않는다. 바꾸려면
    팀 합의와 함께 이 테스트를 먼저 고쳐야 한다.
    """
    run = _run_summary()
    group = run["groups"][0]
    group["timed_out"] = True
    group["sanitizer_findings"] = [{"category": "buffer-overflow"}]

    result = build_validation_summary(run)

    assert result["run"]["groups"][0]["status"] == "timeout"
    assert result["run"]["groups"][0]["sanitizer_count"] == 1


def test_write_and_load_round_trip(tmp_path):
    destination = tmp_path / "nested" / "validation-summary.json"
    data = build_validation_summary(_run_summary())

    written = write_validation_summary(destination, data)

    assert written == destination
    assert load_json(destination) == data


def test_validation_rejects_unknown_schema_version():
    data = build_validation_summary(_run_summary())
    data["schema_version"] = "2.0"

    with pytest.raises(ValidationSummaryError, match="schema_version"):
        validate_validation_summary(data)


def test_load_json_rejects_non_object(tmp_path):
    path = tmp_path / "array.json"
    path.write_text(json.dumps([]), encoding="utf-8")

    with pytest.raises(ValidationSummaryError, match="최상위 JSON 객체"):
        load_json(path)


def test_cli_summary_writes_shared_contract(tmp_path, capsys):
    run_path = tmp_path / "fuzz_summary.json"
    output_path = tmp_path / "validation-summary.json"
    run_path.write_text(json.dumps(_run_summary()), encoding="utf-8")

    assert main([
        "summary",
        "--run", str(run_path),
        "--environment", "ec2",
        "--output", str(output_path),
    ]) == 0

    saved = json.loads(output_path.read_text(encoding="utf-8"))
    assert saved["metadata"]["environment"] == "ec2"
    assert saved["metrics"]["crashed_groups"] == 1
    assert "[SUMMARY]" in capsys.readouterr().out


def test_generation_and_selection_are_normalised_into_shared_contract():
    result = build_validation_summary(
        _run_summary(),
        generation_summary={
            "total_groups": 2,
            "passed": 1,
            "failed": 1,
            "failed_groups": ["score"],
            "outcomes": [
                {
                    "group_id": "dlt",
                    "final_status": "validated",
                    "rounds": 1,
                    "log_path": "logs/gen_validation/dlt.json",
                    "reports": [{"failed_step": None, "reason": ""}],
                },
                {
                    "group_id": "score",
                    "final_status": "validation_failed",
                    "rounds": 2,
                    "log_path": "logs/gen_validation/score.json",
                    "reports": [{"failed_step": "mock_trace", "reason": "mock 누락"}],
                },
            ],
        },
        selection_summary={
            "dlt_path_scan": {
                "kb": "dlt-kb.json",
                "apis": 230,
                "groups_count": 21,
                "constraint_coverage": 0.8739,
            }
        },
    )

    assert result["gen"]["status"] == "completed"
    assert result["gen"]["validated_groups"] == 1
    assert result["gen"]["groups"][1]["failed_step"] == "mock_trace"
    assert result["selection"]["targets"][0] == {
        "target": "dlt_path_scan",
        "kb": "dlt-kb.json",
        "groups": None,
        "apis": 230,
        "groups_count": 21,
        "constraint_coverage": 0.8739,
        "notes": "",
    }


def test_cli_summary_accepts_generation_and_selection(tmp_path):
    run_path = tmp_path / "fuzz_summary.json"
    gen_path = tmp_path / "gen_validation_summary.json"
    selection_path = tmp_path / "selection.json"
    output_path = tmp_path / "validation-summary.json"
    run_path.write_text(json.dumps(_run_summary()), encoding="utf-8")
    gen_path.write_text(json.dumps({"total_groups": 0, "passed": 0, "failed": 0}), encoding="utf-8")
    selection_path.write_text(json.dumps({"targets": []}), encoding="utf-8")

    assert main([
        "summary",
        "--run", str(run_path),
        "--gen", str(gen_path),
        "--selection", str(selection_path),
        "--output", str(output_path),
    ]) == 0
    saved = json.loads(output_path.read_text(encoding="utf-8"))
    assert saved["gen"]["status"] == "completed"
    assert saved["selection"]["targets"] == []


def test_compact_generation_record_keeps_attempts_and_marks_gate_unrun():
    result = build_validation_summary(
        _run_summary(),
        generation_summary={
            "real": {
                "dlt": {
                    "generation_attempts": 1,
                    "source": "/work/gen/dlt_generated.c",
                    "binary": "/work/gen/dlt_generated_fuzzer",
                },
                "score": {
                    "generation_attempts": 2,
                    "repair_attempts": 1,
                    "source": "/work/gen/score_generated.cpp",
                    "binary": "/work/gen/score_generated_fuzzer",
                    "repair_note": "size guard applied",
                },
            }
        },
    )

    assert result["gen"]["gate_status"] == "not_run"
    assert result["gen"]["total_groups"] == 2
    score = result["gen"]["groups"][1]
    assert score["status"] == "generated"
    assert score["generation_attempts"] == 2
    assert score["repair_attempts"] == 1
