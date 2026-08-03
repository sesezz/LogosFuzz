"""로직 그룹들을 순차적으로 격리 실행하는 퍼징 세션 오케스트레이터.

설계서 EXE-04-00 흐름:
  - Docker 격리 환경에서 Logic Group별로 퍼징 순차 수행
  - --timeout 도달 시 해당 그룹 종료 후 다음 그룹으로 진행
  - 새 크래시는 강조 출력하고 crashes/ 폴더에 저장
  - 완료 후 다음 기능(analyze)으로 연결될 요약(JSON) 산출
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from logosfuzz.config import CoverageMode, FuzzConfig, LogicGroup
from logosfuzz.execute.crash_collector import CrashCollector
from logosfuzz.execute.docker_runner import DockerIsolationRunner, GroupResult
from logosfuzz.execute.stats import LiveStats, StatsMonitor
from logosfuzz.execute.sanitizer import SanitizerMonitor, write_findings
from logosfuzz.execute.coverage import CoverageCollector, write_coverage


@dataclass
class SessionSummary:
    engine: str
    timeout_sec: int
    groups: list = field(default_factory=list)  # list[GroupResult]
    started_at: float = 0.0
    finished_at: float = 0.0

    @property
    def total_crashes(self) -> int:
        return sum(len(g.crashes) for g in self.groups)

    def to_dict(self) -> dict:
        return {
            "engine": self.engine,
            "timeout_sec": self.timeout_sec,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "total_groups": len(self.groups),
            "total_crashes": self.total_crashes,
            "groups": [
                {
                    "group": g.group,
                    "exit_code": g.exit_code,
                    "timed_out": g.timed_out,
                    "crashed": g.crashed,
                    "duration_sec": round(g.duration_sec, 2),
                    "exec_per_sec": g.stats.exec_per_sec,
                    "coverage": g.stats.coverage,
                    "crashes": [str(p) for p in g.crashes],
                    "sanitizer_findings": [f.to_dict() for f in g.sanitizer_findings],
                    "coverage_report": g.coverage.to_dict()
                    if getattr(g, "coverage", None) is not None else None,
                }
                for g in self.groups
            ],
        }


class FuzzSession:
    def __init__(self, config: FuzzConfig, runner: Optional[DockerIsolationRunner] = None,
                 stream=sys.stdout,
                 coverage_collector: Optional[CoverageCollector] = None):
        self.config = config
        self.runner = runner or DockerIsolationRunner(config)
        self.stream = stream
        self.collector = CrashCollector(config.crashes_dir)
        # EXE-04-04: 커버리지 수집기(테스트에서 주입 가능). NONE이면 사용되지 않음.
        self.coverage_collector = coverage_collector or CoverageCollector(config)

    def _log(self, msg: str) -> None:
        self.stream.write(msg + "\n")
        self.stream.flush()

    def _crash_search_dirs(self, group: LogicGroup) -> list:
        # libFuzzer artifact_prefix(/out/crashes/) 와 AFL++(/out/afl/**/crashes)
        return [
            self.config.crashes_dir,
            self.config.output_dir / "afl",
        ]

    def run(self, groups: list, ensure_image: bool = True) -> SessionSummary:
        self.config.ensure_dirs()
        if self.config.use_docker and ensure_image:
            self.runner.ensure_image()

        summary = SessionSummary(
            engine=self.config.engine.value,
            timeout_sec=self.config.timeout_sec,
            started_at=time.time(),
        )
        self._log(f"=== LogosFuzz EXE-04-01 | engine={self.config.engine.value} "
                  f"timeout={self.config.timeout_sec}s docker={self.config.use_docker} ===")

        for i, group in enumerate(groups, 1):
            self._log(f"\n[{i}/{len(groups)}] 로직 그룹 '{group.name}' 격리 퍼징 시작")
            stats = LiveStats(group=group.name)
            monitor = StatsMonitor(stats, stream=self.stream, live=True)
            sanitizer_monitor = SanitizerMonitor(
                on_finding=lambda finding: self._log(
                    f"  >>> [SANITIZER:{finding.sanitizer}] "
                    f"{finding.category} ({finding.signature})"
                )
            )

            # EXE-04-04: 계측 활성 시 실행 전 그룹별 profraw 디렉토리를 준비한다
            # (컨테이너가 /out 마운트에 profraw를 떨굴 수 있도록).
            if self.config.coverage is not CoverageMode.NONE:
                (self.config.coverage_dir / group.name).mkdir(parents=True, exist_ok=True)

            # 그룹 실행 전 크래시 baseline
            before = set(self.config.crashes_dir.rglob("*"))
            result: GroupResult = self.runner.run_group(
                group, monitor=monitor, sanitizer_monitor=sanitizer_monitor
            )
            result.stats = stats
            if result.sanitizer_findings:
                write_findings(
                    self.config.logs_dir / "sanitizer" / f"{group.name}.jsonl",
                    result.sanitizer_findings,
                )

            # EXE-04-04: 실행 후 커버리지 후처리(profraw→profdata→llvm-cov export).
            if self.config.coverage is not CoverageMode.NONE:
                cov = self.coverage_collector.collect(group)
                result.coverage = cov
                if cov is not None:
                    write_coverage(
                        self.config.coverage_dir / f"{group.name}.summary.json", cov
                    )
                    self._log(
                        f"  >>> [COVERAGE:{cov.mode}] lines "
                        f"{cov.lines.covered}/{cov.lines.count} ({cov.lines.percent}%), "
                        f"functions {cov.functions.covered}/{cov.functions.count} "
                        f"({cov.functions.percent}%)"
                    )
                else:
                    self._log("  - 커버리지 산출물 없음(계측 미빌드 또는 도구 실패), 건너뜀")

            # 크래시 수집 및 강조
            saved = self.collector.collect(group.name, self._crash_search_dirs(group))
            result.crashes = saved
            if saved:
                self._log(f"  >>> [CRASH] '{group.name}'에서 새 크래시 {len(saved)}건 저장: "
                          f"{self.config.crashes_dir / group.name}")
            if result.timed_out:
                self._log(f"  - 타임아웃 도달, 다음 그룹으로 진행")

            summary.groups.append(result)

        summary.finished_at = time.time()
        self._write_summary(summary)
        self._log(f"\n=== 완료: 그룹 {len(summary.groups)}개, "
                  f"총 크래시 {summary.total_crashes}건 → analyze 단계로 전달 ===")
        return summary

    def _write_summary(self, summary: SessionSummary) -> Path:
        path = self.config.output_dir / "fuzz_summary.json"
        path.write_text(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2))
        return path
