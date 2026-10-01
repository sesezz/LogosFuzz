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
from typing import Any, Mapping, Sequence


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


def _execs_of(group: Mapping[str, Any]) -> tuple[int, bool]:
    """(총 실행 횟수, 추정 여부).

    EXE 의 ``fuzz_summary.json`` 은 그룹별로 ``exec_per_sec``/``duration_sec`` 만 쓰고 총
    실행 횟수는 기록하지 않는다(화면 출력에만 나온다). ``execs`` 가 없으면 0 으로 채워
    "한 번도 안 돌았다"고 읽히게 하지 말고 ``exec_per_sec × duration_sec`` 로 추정하고
    추정치임을 표시한다. 실측 대비 1% 안팎이었다(743,036회 실측 vs 추정 747,801회).
    """
    execs = group.get("execs")
    if execs is not None:
        return _int(execs), False
    rate, seconds = _float(group.get("exec_per_sec")), _float(group.get("duration_sec"))
    if rate > 0 and seconds > 0:
        return int(round(rate * seconds)), True
    return 0, False


def _normalise_group(group: Mapping[str, Any], *, stage: str,
                     build_lookup: Mapping[str, Mapping[str, Any]] | None = None,
                     ) -> dict[str, Any]:
    name = str(group.get("group") or group.get("target") or "unknown")
    harness_name = str(group.get("harness_name") or name)
    crashes = group.get("crashes")
    findings = group.get("sanitizer_findings")
    crashes = list(crashes) if isinstance(crashes, list) else []
    findings = list(findings) if isinstance(findings, list) else []
    status = _status(group)
    execs, execs_estimated = _execs_of(group)
    return {
        "stage": stage,
        "target": name,
        "harness_name": harness_name,
        **_build_fields(group, build_lookup or {}, name, harness_name),
        "status": status,
        "exit_code": group.get("exit_code"),
        "timed_out": bool(group.get("timed_out")),
        "crashed": status == "crashed",
        "duration_sec": round(_float(group.get("duration_sec")), 3),
        "execs": execs,
        "execs_estimated": execs_estimated,
        "exec_per_sec": _float(group.get("exec_per_sec")),
        "coverage": _number(group.get("coverage"), 0),
        "crash_count": len(crashes),
        "sanitizer_count": len(findings),
        "compile_error_count": _int(group.get("compile_error_count")),
        "crashes": crashes,
        "sanitizer_findings": findings,
        "coverage_report": group.get("coverage_report"),
        "stdout_log": group.get("stdout_log"),
        "stderr_log": group.get("stderr_log"),
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


# ---------------------------------------------------------------------
# 빌드 단위 키 (4주차, B 송서원)
# ---------------------------------------------------------------------
# 3주차부터 Logic Group 경계가 빌드 단위(Bazel 타깃)이고, 하네스도
# "빌드 단위 하위 패키지의 cc_fuzz_test" 로 만들어진다. 그런데 리포트는 여전히
# 그룹 이름으로만 집계돼서 "//score/json:json 을 퍼징한 결과가 어떤가" 를
# 한눈에 볼 수 없었다. 여기서 빌드 단위를 1급 키로 올린다.
#
# 호환성: schema_version 1.0 을 유지한다. 기존 필드(run.groups, metrics)의
# 의미는 그대로이고, 아래 두 가지를 **선택 필드로 추가**만 한다.
#   - run.groups[*].build_target / build_system / fuzz_target / binary
#   - 최상위 build_units  (빌드 단위별 집계)
# 빌드 정보를 모르는 그룹은 UNASSIGNED_BUILD_TARGET 아래로 모은다.

UNASSIGNED_BUILD_TARGET = "(unassigned)"

# 빌드 단위 안에 그룹이 여럿일 때 대표 상태를 고르는 우선순위(앞이 우선).
# 실행 결과는 "무엇이 터졌나" 가 중요하므로 crashed 를 가장 앞에 둔다.
_RUN_STATUS_ORDER = ("crashed", "timeout", "failed", "passed", "not_run")
_BUILD_STATUS_ORDER = ("failed", "repaired", "built", "emitted", "not_built")


def _pick(statuses: Sequence[str], order: Sequence[str]) -> str:
    present = set(statuses)
    for status in order:
        if status in present:
            return status
    return order[-1]


def _build_lookup(build_summary: Mapping[str, Any] | None) -> dict[str, dict[str, Any]]:
    """BUILD 단계 결과(``build_summary.json``)를 그룹 조인용 사전으로 만든다.

    EXE 가 그룹을 어떤 이름으로 기록하느냐는 실행 방식에 따라 다르다 —
    Logic Group 이름, cc_fuzz_test 이름, ``_bin`` 바이너리 이름 중 하나다.
    어느 쪽으로 와도 붙도록 세 이름을 모두 키로 넣는다.
    """
    lookup: dict[str, dict[str, Any]] = {}
    if not isinstance(build_summary, Mapping):
        return lookup
    units = build_summary.get("units")
    for unit in units if isinstance(units, list) else []:
        if not isinstance(unit, Mapping):
            continue
        record = dict(unit)
        keys = [str(unit.get("group") or "")]
        fuzz_target = str(unit.get("fuzz_target") or "")
        if fuzz_target:
            name = fuzz_target.rsplit(":", 1)[-1]
            keys += [name, f"{name}_bin"]
        binary = unit.get("binary")
        if binary:
            keys.append(Path(str(binary)).name)
        for key in keys:
            if key:
                lookup.setdefault(key, record)
    return lookup


def _build_fields(group: Mapping[str, Any], lookup: Mapping[str, Mapping[str, Any]],
                  name: str, harness_name: str) -> dict[str, Any]:
    """그룹에 붙일 빌드 단위 필드. 그룹 자체 값이 BUILD 결과보다 우선한다."""
    raw_binary = group.get("binary")
    unit = (lookup.get(name) or lookup.get(harness_name)
            or (lookup.get(Path(str(raw_binary)).name) if raw_binary else None) or {})
    build_target = str(group.get("build_target") or unit.get("build_target") or "")
    return {
        "build_target": build_target or None,
        "build_system": str(group.get("build_system") or unit.get("build_system") or "") or None,
        "fuzz_target": group.get("fuzz_target") or unit.get("fuzz_target"),
        "binary": group.get("binary") or unit.get("binary"),
    }


def _canonical_group_name(group: Mapping[str, Any],
                          lookup: Mapping[str, Mapping[str, Any]]) -> str:
    """EXE 그룹 이름을 BUILD 결과의 Logic Group 이름으로 통일한다.

    EXE 가 cc_fuzz_test 이름이나 ``_bin`` 바이너리 이름으로 그룹을 기록하면, 같은
    그룹이 build 결과의 이름(Logic Group)과 EXE 이름 두 개로 ``groups`` 에 중복
    등장한다. 조인 사전에서 같은 빌드 결과를 찾아 그 ``group`` 이름으로 합친다.
    (``--groups-out`` 을 쓰면 처음부터 같은 이름이라 이 경로는 폴백이다.)
    """
    binary = group.get("binary")
    record = (lookup.get(group["target"]) or lookup.get(group["harness_name"])
              or (lookup.get(Path(str(binary)).name) if binary else None))
    return str((record or {}).get("group") or group["target"])


def _normalise_build_units(
    groups: Sequence[Mapping[str, Any]],
    build_summary: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """빌드 단위별 집계. 실행 그룹 + BUILD 결과를 build_target 으로 합친다."""
    units: dict[str, dict[str, Any]] = {}

    def unit_for(target: str, build_system: str | None = None) -> dict[str, Any]:
        entry = units.get(target)
        if entry is None:
            entry = units[target] = {
                "build_target": target,
                "build_system": build_system or None,
                "groups": [],
                "fuzz_targets": [],
                "binaries": [],
                "build_statuses": [],
                "rounds_used": 0,
                "run_statuses": [],
                "crashes": 0,
                "sanitizer_findings": 0,
                "execs": 0,
                "execs_estimated": False,
                "duration_sec": 0.0,
                "coverage": 0,
            }
        elif build_system and not entry["build_system"]:
            entry["build_system"] = build_system
        return entry

    def add_unique(values: list, value: Any) -> None:
        if value and value not in values:
            values.append(value)

    source = build_summary if isinstance(build_summary, Mapping) else {}
    lookup = _build_lookup(source)
    raw_units = source.get("units")
    for unit in raw_units if isinstance(raw_units, list) else []:
        if not isinstance(unit, Mapping):
            continue
        target = str(unit.get("build_target") or unit.get("target") or UNASSIGNED_BUILD_TARGET)
        entry = unit_for(target, unit.get("build_system"))
        add_unique(entry["groups"], str(unit.get("group") or ""))
        add_unique(entry["fuzz_targets"], unit.get("fuzz_target"))
        add_unique(entry["binaries"], unit.get("binary"))
        entry["build_statuses"].append(str(unit.get("status") or "not_built"))
        entry["rounds_used"] = max(entry["rounds_used"], _int(unit.get("rounds_used")))

    for group in groups:
        target = str(group.get("build_target") or UNASSIGNED_BUILD_TARGET)
        entry = unit_for(target, group.get("build_system"))
        add_unique(entry["groups"], _canonical_group_name(group, lookup))
        add_unique(entry["fuzz_targets"], group.get("fuzz_target"))
        add_unique(entry["binaries"], group.get("binary"))
        entry["run_statuses"].append(group["status"])
        entry["crashes"] += group["crash_count"]
        entry["sanitizer_findings"] += group["sanitizer_count"]
        entry["execs"] += group["execs"]
        entry["execs_estimated"] = entry["execs_estimated"] or group["execs_estimated"]
        entry["duration_sec"] += group["duration_sec"]
        coverage = group.get("coverage")
        if isinstance(coverage, (int, float)) and coverage > entry["coverage"]:
            entry["coverage"] = coverage

    out_units: list[dict[str, Any]] = []
    for target in sorted(units, key=lambda t: (t == UNASSIGNED_BUILD_TARGET, t)):
        entry = units.pop(target)
        build_statuses = entry.pop("build_statuses")
        run_statuses = entry.pop("run_statuses")
        entry["build_status"] = _pick(build_statuses, _BUILD_STATUS_ORDER)
        entry["run_status"] = _pick(run_statuses, _RUN_STATUS_ORDER)
        entry["run_groups"] = len(run_statuses)
        entry["duration_sec"] = round(entry["duration_sec"], 3)
        out_units.append(entry)

    assigned = [u for u in out_units if u["build_target"] != UNASSIGNED_BUILD_TARGET]
    return {
        "status": "completed" if source else "not_run",
        "build_system": str(source.get("build_system") or "") or None,
        "config": source.get("config"),
        "total_units": len(assigned),
        "built_units": sum(u["build_status"] in ("built", "repaired") for u in assigned),
        "repaired_units": sum(u["build_status"] == "repaired" for u in assigned),
        "failed_units": sum(u["build_status"] == "failed" for u in assigned),
        "crashed_units": sum(u["run_status"] == "crashed" for u in assigned),
        "units": out_units,
    }


def render_build_units_markdown(data: Mapping[str, Any]) -> str:
    """빌드 단위 표를 Markdown 으로 만든다 (최종 리포트·발표자료 붙여넣기용)."""
    section = data.get("build_units")
    section = section if isinstance(section, Mapping) else {}
    units = section.get("units") if isinstance(section.get("units"), list) else []
    lines = [
        "| 빌드 단위 | 그룹 | 빌드 | 라운드 | 실행 | 크래시 | sanitizer | execs | 커버리지 |",
        "|---|---|---|---:|---|---:|---:|---:|---:|",
    ]
    for unit in units:
        lines.append(
            "| `{}` | {} | {} | {} | {} | {} | {} | {} | {} |".format(
                unit.get("build_target"),
                ", ".join(unit.get("groups") or []) or "-",
                unit.get("build_status"),
                unit.get("rounds_used"),
                unit.get("run_status"),
                unit.get("crashes"),
                unit.get("sanitizer_findings"),
                f"~{unit.get('execs')}" if unit.get("execs_estimated") else unit.get("execs"),
                unit.get("coverage"),
            )
        )
    head = (
        f"빌드 단위 {section.get('total_units', 0)}개 · "
        f"빌드 성공 {section.get('built_units', 0)} "
        f"(자가치유 {section.get('repaired_units', 0)}) · "
        f"빌드 실패 {section.get('failed_units', 0)} · "
        f"크래시 발생 {section.get('crashed_units', 0)}"
    )
    return head + "\n\n" + "\n".join(lines) + "\n"


def build_validation_summary(
    run_summary: Mapping[str, Any],
    analysis_summary: Mapping[str, Any] | None = None,
    *,
    metadata: Mapping[str, Any] | None = None,
    stage: str = "exe_ana",
    generated_at: str | None = None,
    generation_summary: Mapping[str, Any] | None = None,
    selection_summary: Mapping[str, Any] | None = None,
    build_summary: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """실행 요약과 선택적인 ANA 결과를 표준 검증 결과로 묶는다.

    ``run_summary``는 ``FuzzSession``이 쓰는 ``fuzz_summary.json`` 형식,
    ``analysis_summary``는 ``logosfuzz analyze``의 출력 형식을 받는다.
    ``build_summary``는 CTR-06-01 BUILD 단계의 ``build_summary.json``이며,
    주면 그룹에 빌드 단위 필드를 붙이고 ``build_units`` 집계를 채운다.
    누락된 선택 필드는 안전한 기본값으로 채우고 원문 분석 결과는 보존한다.
    """
    if not isinstance(run_summary, Mapping):
        raise ValidationSummaryError("run_summary는 JSON 객체여야 합니다")

    raw_groups = run_summary.get("groups")
    if not isinstance(raw_groups, list):
        raw_groups = []
    build_lookup = _build_lookup(build_summary)
    groups = [
        _normalise_group(group, stage=stage, build_lookup=build_lookup)
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
        "build_units": _normalise_build_units(groups, build_summary),
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
    build_units = data.get("build_units")
    if build_units is not None:
        if not isinstance(build_units, Mapping) or not isinstance(build_units.get("units"), list):
            raise ValidationSummaryError("build_units.units는 배열이어야 합니다")
        for index, unit in enumerate(build_units["units"]):
            if not isinstance(unit, Mapping) or not unit.get("build_target"):
                raise ValidationSummaryError(
                    f"build_units.units[{index}].build_target가 비어 있습니다"
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
