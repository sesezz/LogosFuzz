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

from logosfuzz.config import FuzzConfig, LogicGroup
from logosfuzz.execute.crash_collector import CrashCollector
from logosfuzz.execute.docker_runner import DockerIsolationRunner, GroupResult
from logosfuzz.execute.stats import LiveStats, StatsMonitor


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
                }
                for g in self.groups
            ],
        }


class FuzzSession:
    def __init__(self, config: FuzzConfig, runner: Optional[DockerIsolationRunner] = None,
                 stream=sys.stdout):
        self.config = config
        self.runner = runner or DockerIsolationRunner(config)
        self.stream = stream
        self.collector = CrashCollector(config.crashes_dir)

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

            # 그룹 실행 전 크래시 baseline
            before = set(self.config.crashes_dir.rglob("*"))
            result: GroupResult = self.runner.run_group(group, monitor=monitor)
            result.stats = stats

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
