"""EXE·ANA 결과를 웹과 보고서가 함께 사용하는 JSON으로 정규화한다.

실행기(``fuzz_summary.json``)와 분석기(``analyze`` 출력)는 서로 다른
목적의 산출물이다. 이 모듈은 두 산출물을 보존하면서도, 화면과 보고서가
안정적으로 읽을 수 있는 최소 계약을 제공한다.

계약 원칙
---------
* ``schema_version``으로 형식 변경을 명시한다.
* 실행 결과의 원문 필드는 ``run`` 아래에 보존한다.
* ANA 결과의 원문 필드는 ``analysis`` 아래에 보존한다.
* 화면에 바로 쓸 집계값은 ``metrics``와 ``run.groups``에 둔다.
* 새 필드는 선택적으로 추가할 수 있지만 기존 필드의 의미를 바꾸지 않는다.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


SUMMARY_SCHEMA_VERSION = "1.0"
_VERDICT_KEYS = ("true_positive", "false_positive", "needs_review")
_GROUP_STATUSES = {"passed", "failed", "timeout", "crashed"}


class ValidationSummaryError(ValueError):
    """검증 결과 JSON이 공유 계약을 만족하지 않을 때 발생한다."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_json(path: str | Path) -> dict[str, Any]:
    """UTF-8 JSON 파일을 읽고 최상위 객체인지 확인한다."""
    source = Path(path)
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValidationSummaryError(f"JSON 파일이 없습니다: {source}") from exc
    except json.JSONDecodeError as exc:
        raise ValidationSummaryError(f"JSON 형식이 올바르지 않습니다: {source}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationSummaryError(f"최상위 JSON 객체가 필요합니다: {source}")
    return value


def _number(value: Any, default: int | float = 0) -> int | float:
    if isinstance(value, bool) or value is None:
        return default
    if isinstance(value, (int, float)):
        return value
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _int(value: Any, default: int = 0) -> int:
    number = _number(value, default)
    try:
        return max(0, int(number))
    except (TypeError, ValueError):
        return default


def _float(value: Any, default: float = 0.0) -> float:
    number = _number(value, default)
    try:
        return max(0.0, float(number))
    except (TypeError, ValueError):
        return default


def _status(group: Mapping[str, Any]) -> str:
    """실행 결과를 화면용 상태 하나로 정규화한다.

    우선순위는 ``timeout`` > ``crashed`` > ``failed`` > ``passed`` 다. 타임아웃이
    앞서는 것은 ``test_timeout_takes_precedence_over_crash``가 고정한 계약이므로
    유지한다.

    ``crashed``의 판정 조건은 스키마 문서(``docs/VALIDATION-SUMMARY-SCHEMA.md``)의
    정의 - "크래시 산출물 **또는 sanitizer 오류**가 확인됨" - 를 그대로 따른다.
    새니타이저 결함만 있고 크래시 산출물이 없는 실행이 실제로 나온다(ASAN이
    결함을 잡았지만 libFuzzer가 artifact를 남기지 못한 경우). 이때 결함을
    ``passed``로 보고하면 리포트가 버그를 숨기게 된다.
    """
    if bool(group.get("timed_out")):
        return "timeout"
    findings = group.get("sanitizer_findings")
    if (
        bool(group.get("crashed"))
        or bool(group.get("crashes"))
        or (isinstance(findings, list) and bool(findings))
    ):
        return "crashed"
    exit_code = group.get("exit_code")
    if exit_code not in (None, 0):
        return "failed"
    return "passed"


def _normalise_group(group: Mapping[str, Any], *, stage: str) -> dict[str, Any]:
    name = str(group.get("group") or group.get("target") or "unknown")
    crashes = group.get("crashes")
    findings = group.get("sanitizer_findings")
    crashes = list(crashes) if isinstance(crashes, list) else []
    findings = list(findings) if isinstance(findings, list) else []
    status = _status(group)
    return {
        "stage": stage,
        "target": name,
        "harness_name": str(group.get("harness_name") or name),
        "status": status,
        "exit_code": group.get("exit_code"),
        "timed_out": bool(group.get("timed_out")),
        "crashed": status == "crashed",
        "duration_sec": round(_float(group.get("duration_sec")), 3),
        "execs": _int(group.get("execs")),
        "exec_per_sec": _float(group.get("exec_per_sec")),
        "coverage": _number(group.get("coverage"), 0),
        "crash_count": len(crashes),
        "sanitizer_count": len(findings),
        "compile_error_count": _int(group.get("compile_error_count")),
        "crashes": crashes,
        "sanitizer_findings": findings,
        "coverage_report": group.get("coverage_report"),
        "notes": str(group.get("notes") or ""),
    }


def _normalise_analysis(analysis: Mapping[str, Any] | None) -> dict[str, Any]:
    source = dict(analysis or {})
    raw_summary = source.get("summary")
    raw_summary = raw_summary if isinstance(raw_summary, Mapping) else {}
    verdict_summary = {key: _int(raw_summary.get(key)) for key in _VERDICT_KEYS}
    findings = source.get("findings")
    if not isinstance(findings, list):
        findings = []
    return {
        "status": "completed" if analysis is not None else "not_run",
        "triage_model": str(source.get("triage_model") or ""),
        "summary": verdict_summary,
        "findings": findings,
    }


def _normalise_generation(generation: Mapping[str, Any] | None) -> dict[str, Any]:
    """GEN-03-04 품질 게이트 결과를 화면용 요약으로 정규화한다.

    ``gen_validation_summary.json``은 라운드별 상세 리포트를 포함할 수 있어
    그대로 HTML에 넣으면 결과 파일이 불필요하게 커진다. 최종 상태·라운드 수·
    실패 단계·로그 경로처럼 재현과 보고서에 필요한 정보만 보존한다.
    """
    if generation is None:
        return {
            "status": "not_run",
            "total_groups": 0,
            "validated_groups": 0,
            "failed_groups": 0,
            "groups": [],
        }

    source = dict(generation)
    # 최종 EC2 기록에는 GEN 실행 메타데이터가 ``real.{dlt,score}``로
    # 남아 있을 수 있다. GEN-03-04 파이프라인 산출물(outcomes)이 아직
    # 없다는 사실을 숨기지 않고, 생성/수선 산출물만 별도 상태로 보존한다.
    compact_real = source.get("real")
    if isinstance(compact_real, Mapping) and not isinstance(source.get("outcomes"), list):
        compact_groups: list[dict[str, Any]] = []
        for group_id, item in compact_real.items():
            if not isinstance(item, Mapping):
                continue
            compact_groups.append({
                "group_id": str(group_id),
                "status": "generated",
                "rounds": _int(item.get("generation_attempts")),
                "generation_attempts": _int(item.get("generation_attempts")),
                "repair_attempts": _int(item.get("repair_attempts")),
                "failed_step": None,
                "reason": str(item.get("repair_note") or ""),
                "log_path": None,
                "source": item.get("source"),
                "binary": item.get("binary"),
            })
        return {
            "status": str(source.get("status") or "completed"),
            "gate_status": "not_run",
            "model": str(source.get("model") or compact_real.get("model") or ""),
            "total_groups": len(compact_groups),
            "validated_groups": 0,
            "failed_groups": 0,
            "failed_group_ids": [],
            "started_at": source.get("started_at"),
            "finished_at": source.get("finished_at"),
            "groups": compact_groups,
        }
    outcomes = source.get("outcomes")
    outcomes = outcomes if isinstance(outcomes, list) else []
    groups: list[dict[str, Any]] = []
    for outcome in outcomes:
        if not isinstance(outcome, Mapping):
            continue
        reports = outcome.get("reports")
        reports = reports if isinstance(reports, list) else []
        final_report = reports[-1] if reports and isinstance(reports[-1], Mapping) else {}
        groups.append({
            "group_id": str(outcome.get("group_id") or "unknown"),
            "status": str(outcome.get("final_status") or "unknown"),
            "rounds": _int(outcome.get("rounds")),
            "generation_attempts": _int(outcome.get("generation_attempts")),
            "repair_attempts": _int(outcome.get("repair_attempts")),
            "failed_step": final_report.get("failed_step"),
            "reason": str(final_report.get("reason") or ""),
            "log_path": outcome.get("log_path"),
            "source": outcome.get("source"),
            "binary": outcome.get("binary"),
        })

    total = _int(source.get("total_groups"), len(groups))
    validated = _int(source.get("passed"), sum(g["status"] == "validated" for g in groups))
    failed = _int(source.get("failed"), sum(g["status"] == "validation_failed" for g in groups))
    if total == 0 and groups:
        total = len(groups)
    if validated + failed > total:
        total = validated + failed
    # 파일을 명시적으로 전달했다면 그룹이 0개인 검증도 정상 완료로
    # 기록한다(대상 미생성/빈 입력과 파일 자체 누락을 구분하기 위함).
    status = str(source.get("status") or "completed")
    if status not in {"completed", "not_run", "failed"}:
        status = "completed"
    return {
        "status": status,
        "gate_status": "completed" if outcomes else "not_run",
        "model": str(source.get("model") or ""),
        "total_groups": total,
        "validated_groups": validated,
        "failed_groups": failed,
        "failed_group_ids": [str(x) for x in (source.get("failed_groups") or [])],
        "started_at": source.get("started_at"),
        "finished_at": source.get("finished_at"),
        "groups": groups,
    }


def _normalise_selection(selection: Mapping[str, Any] | None) -> dict[str, Any]:
    """EXT/SCH 대상 선정·제약 조건 결과를 공통 배열로 정규화한다."""
    if selection is None:
        return {"status": "not_run", "targets": []}

    source = dict(selection)
    raw_targets = source.get("targets")
    if isinstance(raw_targets, list):
        candidates = raw_targets
    else:
        # 기존 검증 보고서(ext_sch)의 ``{target_name: result}`` 형식도 수용한다.
        candidates = [
            {"target": name, **value}
            for name, value in source.items()
            if isinstance(value, Mapping)
        ]

    targets: list[dict[str, Any]] = []
    for item in candidates:
        if not isinstance(item, Mapping):
            continue
        target = str(item.get("target") or item.get("name") or item.get("group") or "unknown")
        groups = item.get("groups")
        group_count = item.get("groups_count")
        if group_count is None and isinstance(groups, list):
            group_count = len(groups)
        targets.append({
            "target": target,
            "kb": item.get("kb"),
            "groups": groups if isinstance(groups, (list, str)) else None,
            "apis": _int(item.get("apis")),
            "groups_count": _int(group_count),
            "constraint_coverage": _float(item.get("constraint_coverage")),
            "notes": str(item.get("notes") or ""),
        })

    raw_issues = source.get("known_issues")
    if isinstance(raw_issues, list):
        known_issues = [str(item) for item in raw_issues]
    elif raw_issues:
        known_issues = [str(raw_issues)]
    else:
        known_issues = []
    return {
        "status": str(source.get("status") or "completed"),
        "targets": targets,
        "known_issues": known_issues,
    }


def build_validation_summary(
    run_summary: Mapping[str, Any],
    analysis_summary: Mapping[str, Any] | None = None,
    *,
    metadata: Mapping[str, Any] | None = None,
    stage: str = "exe_ana",
    generated_at: str | None = None,
    generation_summary: Mapping[str, Any] | None = None,
    selection_summary: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """실행 요약과 선택적인 ANA 결과를 표준 검증 결과로 묶는다.

    ``run_summary``는 ``FuzzSession``이 쓰는 ``fuzz_summary.json`` 형식,
    ``analysis_summary``는 ``logosfuzz analyze``의 출력 형식을 받는다.
    누락된 선택 필드는 안전한 기본값으로 채우고 원문 분석 결과는 보존한다.
    """
    if not isinstance(run_summary, Mapping):
        raise ValidationSummaryError("run_summary는 JSON 객체여야 합니다")

    raw_groups = run_summary.get("groups")
    if not isinstance(raw_groups, list):
        raw_groups = []
    groups = [
        _normalise_group(group, stage=stage)
        for group in raw_groups
        if isinstance(group, Mapping)
    ]
    analysis = _normalise_analysis(analysis_summary)
    verdict_summary = analysis["summary"]
    crashes = sum(group["crash_count"] for group in groups)
    sanitizer_findings = sum(group["sanitizer_count"] for group in groups)
    timed_out = sum(1 for group in groups if group["status"] == "timeout")
    failed = sum(1 for group in groups if group["status"] == "failed")
    crashed_groups = sum(1 for group in groups if group["status"] == "crashed")
    passed = sum(1 for group in groups if group["status"] == "passed")

    result: dict[str, Any] = {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "generated_at": generated_at or _now_iso(),
        "metadata": dict(metadata or {}),
        "run": {
            "engine": str(run_summary.get("engine") or "unknown"),
            "timeout_sec": _int(run_summary.get("timeout_sec")),
            "started_at": run_summary.get("started_at"),
            "finished_at": run_summary.get("finished_at"),
            "total_groups": len(groups),
            "total_crashes": crashes,
            "groups": groups,
        },
        "analysis": analysis,
        "gen": _normalise_generation(generation_summary),
        "selection": _normalise_selection(selection_summary),
        "metrics": {
            "groups": len(groups),
            "passed_groups": passed,
            "failed_groups": failed,
            "timed_out_groups": timed_out,
            "crashed_groups": crashed_groups,
            "crashes": crashes,
            "sanitizer_findings": sanitizer_findings,
            "true_positive": verdict_summary["true_positive"],
            "false_positive": verdict_summary["false_positive"],
            "needs_review": verdict_summary["needs_review"],
        },
    }
    validate_validation_summary(result)
    return result


def validate_validation_summary(data: Mapping[str, Any]) -> None:
    """공유 계약의 필수 필드와 기본 타입을 검증한다."""
    if not isinstance(data, Mapping):
        raise ValidationSummaryError("검증 결과는 JSON 객체여야 합니다")
    if data.get("schema_version") != SUMMARY_SCHEMA_VERSION:
        raise ValidationSummaryError(
            f"지원하지 않는 schema_version: {data.get('schema_version')!r}"
        )
    for key in ("generated_at", "metadata", "run", "analysis", "metrics"):
        if key not in data:
            raise ValidationSummaryError(f"필수 필드가 없습니다: {key}")
    run = data["run"]
    if not isinstance(run, Mapping) or not isinstance(run.get("groups"), list):
        raise ValidationSummaryError("run.groups는 배열이어야 합니다")
    analysis = data["analysis"]
    if not isinstance(analysis, Mapping):
        raise ValidationSummaryError("analysis는 객체여야 합니다")
    summary = analysis.get("summary")
    if not isinstance(summary, Mapping):
        raise ValidationSummaryError("analysis.summary는 객체여야 합니다")
    missing_verdicts = [key for key in _VERDICT_KEYS if key not in summary]
    if missing_verdicts:
        raise ValidationSummaryError(
            f"analysis.summary 필드가 없습니다: {', '.join(missing_verdicts)}"
        )
    for index, group in enumerate(run["groups"]):
        if not isinstance(group, Mapping):
            raise ValidationSummaryError(f"run.groups[{index}]는 객체여야 합니다")
        if not group.get("target"):
            raise ValidationSummaryError(f"run.groups[{index}].target가 비어 있습니다")
        if group.get("status") not in _GROUP_STATUSES:
            raise ValidationSummaryError(
                f"run.groups[{index}].status가 올바르지 않습니다: {group.get('status')!r}"
            )


def write_validation_summary(path: str | Path, data: Mapping[str, Any]) -> Path:
    """검증 결과를 UTF-8 JSON으로 원자적으로 저장한다."""
    validate_validation_summary(data)
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(destination)
    return destination
