"""GEN-03-04 실패 피드백 루프 + 오케스트레이터.

검증 실패 시 실패 사유(`FeedbackPayload`)를 상위 재진입점(GEN-03-01 하네스
재생성 또는 GEN-03-02 컴파일 자가치유 루프 — 어느 쪽으로 라우팅할지는 그
재진입점 자신이 실패 사유를 보고 판단한다)으로 돌려주고 재검증한다.
`--max-round` 횟수를 초과하면 해당 로직 그룹을 "검증 실패"로 최종 처리하고
다음 그룹으로 넘어간다(무한 루프 방지).

`run_validation_pipeline`은 여러 로직 그룹을 순회하며 위 루프를 돌리고,
GEN-03-00("성공/실패 그룹 수 + 실패 로그 경로" 출력)과 EXE-04-01
(`fuzz_session.py`의 `SessionSummary`/`_write_summary` 패턴)의 컨벤션에
맞춘 요약을 콘솔에 출력하고 JSON으로 저장한다.
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from logosfuzz.generate.contracts import FeedbackPayload, HarnessArtifact, RegenerateCallback
from logosfuzz.generate.llm_review import StaticReviewer
from logosfuzz.generate.validation import (
    Runner,
    ValidationConfig,
    ValidationReport,
    _default_runner,
    validate_harness,
)

Logger = Callable[[str], None]


@dataclass
class RetryOutcome:
    group_id: str
    final_status: str  # "validated" | "validation_failed"
    rounds: int
    reports: list  # list[ValidationReport], 라운드 순서대로
    log_path: Optional[Path] = None

    @property
    def passed(self) -> bool:
        return self.final_status == "validated"

    def to_dict(self) -> dict:
        return {
            "group_id": self.group_id,
            "final_status": self.final_status,
            "rounds": self.rounds,
            "log_path": str(self.log_path) if self.log_path else None,
            "reports": [r.to_dict() for r in self.reports],
        }


def _make_feedback(artifact: HarnessArtifact, round_no: int, report: ValidationReport) -> FeedbackPayload:
    return FeedbackPayload(
        group_id=artifact.group_id,
        round_no=round_no,
        failed_steps=report.steps_run,
        reason=report.reason,
        detail={"failed_step": report.failed_step},
    )


def validate_with_retry(
    artifact: HarnessArtifact,
    max_round: int,
    regenerate_fn: Optional[RegenerateCallback] = None,
    config: ValidationConfig = ValidationConfig(),
    runner: Runner = _default_runner,
    static_reviewer: Optional[StaticReviewer] = None,
    log: Optional[Logger] = None,
) -> RetryOutcome:
    """검증 → 실패 시 `regenerate_fn`으로 피드백 → 재검증을, `max_round`까지 반복한다.

    `regenerate_fn`이 주어지지 않았거나 재생성/재컴파일 자체가 예외를 던지면
    그 시점에서 재시도를 중단하고 "검증 실패"로 최종 처리한다(무한 루프 방지는
    `max_round` 상한과 이 중단 처리 두 가지로 보장된다).
    """
    _log = log or (lambda msg: None)
    reports: list = []
    current = artifact

    for round_no in range(max_round + 1):
        current.round_no = round_no
        report = validate_harness(current, config, runner, static_reviewer)
        reports.append(report)

        if report.passed:
            _log(f"  [{current.group_id}] round {round_no}: 검증 통과")
            return RetryOutcome(current.group_id, "validated", round_no + 1, reports)

        _log(f"  [{current.group_id}] round {round_no}: 검증 실패 "
             f"({report.failed_step}: {report.reason})")

        if round_no >= max_round:
            _log(f"  [{current.group_id}] --max-round({max_round}) 초과 — 검증 실패로 최종 처리")
            break

        if regenerate_fn is None:
            _log(f"  [{current.group_id}] 재생성 콜백 미지정 — 재시도 없이 검증 실패로 처리")
            break

        feedback = _make_feedback(current, round_no, report)
        try:
            current = regenerate_fn(current, feedback)
        except Exception as e:  # noqa: BLE001 — 재진입점 실패는 재시도 중단 사유로만 다룬다.
            _log(f"  [{current.group_id}] 재생성/재컴파일 콜백 실패: {e} — 재시도 중단")
            break

    return RetryOutcome(current.group_id, "validation_failed", len(reports), reports)


@dataclass
class GenValidationSummary:
    total_groups: int
    passed_groups: list
    failed_groups: list
    outcomes: list  # list[RetryOutcome]
    started_at: float = 0.0
    finished_at: float = 0.0

    def to_dict(self) -> dict:
        return {
            "total_groups": self.total_groups,
            "passed": len(self.passed_groups),
            "failed": len(self.failed_groups),
            "failed_groups": self.failed_groups,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "outcomes": [o.to_dict() for o in self.outcomes],
        }


def run_validation_pipeline(
    artifacts: list,
    max_round: int,
    output_dir: Path,
    regenerate_fn: Optional[RegenerateCallback] = None,
    config: ValidationConfig = ValidationConfig(),
    runner: Runner = _default_runner,
    static_reviewer: Optional[StaticReviewer] = None,
    stream=sys.stdout,
) -> GenValidationSummary:
    def _log(msg: str) -> None:
        stream.write(msg + "\n")
        stream.flush()

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    logs_dir = output_dir / "logs" / "gen_validation"
    logs_dir.mkdir(parents=True, exist_ok=True)

    started = time.time()
    outcomes: list = []
    passed_groups: list = []
    failed_groups: list = []

    _log(f"=== LogosFuzz GEN-03-04 | 대상 {len(artifacts)}개 그룹, max-round={max_round} ===")
    for i, artifact in enumerate(artifacts, 1):
        _log(f"\n[{i}/{len(artifacts)}] 로직 그룹 '{artifact.group_id}' 검증 시작")
        outcome = validate_with_retry(
            artifact, max_round, regenerate_fn, config, runner, static_reviewer, log=_log,
        )
        log_path = logs_dir / f"{artifact.group_id}.json"
        outcome.log_path = log_path
        log_path.write_text(json.dumps(outcome.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")

        outcomes.append(outcome)
        (passed_groups if outcome.passed else failed_groups).append(artifact.group_id)

    summary = GenValidationSummary(len(artifacts), passed_groups, failed_groups, outcomes, started, time.time())
    summary_path = output_dir / "gen_validation_summary.json"
    summary_path.write_text(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")

    failed_part = f" ({', '.join(failed_groups)})" if failed_groups else ""
    _log(f"\n=== 완료: 성공 {len(passed_groups)}개 / 실패 {len(failed_groups)}개{failed_part} "
         f"→ 실패 로그: {logs_dir} ===")
    return summary
