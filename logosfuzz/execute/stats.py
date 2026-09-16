"""퍼징 실시간 통계 파싱/표시.

설계서 EXE-04-00: exec/s, coverage, crash 수를 라이브로 갱신 출력.
EXE-04-01에서는 libFuzzer/AFL++ 표준 출력에서 핵심 지표를 추출하는
경량 파서만 제공한다. 정밀 coverage 계측(EXE-04-04)과 ASAN/TSAN 스트림
정밀 전처리(EXE-04-02)는 이후 주차에서 이 모듈을 확장한다.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass


# libFuzzer 진행 라인 예: "#1024 pulse cov: 231 ft: 512 exec/s: 512 ..."
# 필드가 라인마다 가변적이라 필드별로 독립 검색한다.
_LF_EXECS = re.compile(r"^#(\d+)\s+\w+")
_LF_COV = re.compile(r"\bcov:\s*(\d+)", re.IGNORECASE)
_LF_EPS = re.compile(r"\bexec/s:\s*(\d+)", re.IGNORECASE)
# AFL++ status 라인 일부 예: "corpus count : 120", "exec speed : 900/sec"
_AFL_EXEC_SPEED = re.compile(r"exec speed\s*:\s*([\d.]+)\s*/sec", re.IGNORECASE)
_AFL_PATHS = re.compile(r"(?:paths total|corpus count)\s*:\s*(\d+)", re.IGNORECASE)
_AFL_CRASHES = re.compile(r"(?:uniq crashes|saved crashes)\s*:\s*(\d+)", re.IGNORECASE)


@dataclass
class LiveStats:
    """단일 로직 그룹의 누적 통계."""

    group: str
    execs: int = 0
    exec_per_sec: float = 0.0
    coverage: int = 0
    crashes: int = 0

    def update_from_line(self, line: str) -> bool:
        """엔진 출력 한 줄을 반영. 값이 갱신되면 True."""
        changed = False

        stripped = line.strip()
        m = _LF_EXECS.match(stripped)
        if m:
            self.execs = max(self.execs, int(m.group(1)))
            changed = True
            mc = _LF_COV.search(stripped)
            if mc:
                self.coverage = max(self.coverage, int(mc.group(1)))
            me = _LF_EPS.search(stripped)
            if me:
                self.exec_per_sec = float(me.group(1))

        m = _AFL_EXEC_SPEED.search(line)
        if m:
            self.exec_per_sec = float(m.group(1))
            changed = True
        m = _AFL_PATHS.search(line)
        if m:
            self.coverage = max(self.coverage, int(m.group(1)))
            changed = True
        m = _AFL_CRASHES.search(line)
        if m:
            self.crashes = max(self.crashes, int(m.group(1)))
            changed = True

        return changed

    def render(self) -> str:
        return (
            f"[{self.group}] exec/s={self.exec_per_sec:>8.0f} "
            f"cov={self.coverage:>6d} crashes={self.crashes:>3d} "
            f"execs={self.execs}"
        )


class StatsMonitor:
    """라이브 통계를 한 줄로 갱신 출력하는 경량 모니터.

    stream 인자를 주입할 수 있어 테스트에서 캡처가 가능하다.
    """

    def __init__(self, stats: LiveStats, stream=sys.stdout, live: bool = True):
        self.stats = stats
        self.stream = stream
        self.live = live

    def feed(self, line: str) -> None:
        if self.stats.update_from_line(line) and self.live:
            self.stream.write("\r" + self.stats.render())
            self.stream.flush()

    def finish(self) -> None:
        if self.live:
            self.stream.write("\r" + self.stats.render() + "\n")
            self.stream.flush()
