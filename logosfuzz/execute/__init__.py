"""EXE 파트: Docker 격리 퍼징 실행 및 크래시 수집.

- EXE-04-01: Docker 기반 격리 퍼징 실행 (이 모듈의 현재 구현 범위)
- EXE-04-02: ASAN/TSAN 실시간 모니터링 (2주차, stats/env 훅만 준비)
- EXE-04-04: Coverage Instrumentation (3주차, 훅만 준비)
"""

from logosfuzz.execute.docker_runner import DockerIsolationRunner, GroupResult
from logosfuzz.execute.fuzz_session import FuzzSession, SessionSummary

__all__ = [
    "DockerIsolationRunner",
    "GroupResult",
    "FuzzSession",
    "SessionSummary",
]
"""EXE-04-00 Docker 격리 퍼징 실행 단계.

하위 기능:
  - EXE-04-01 Docker 기반 격리 퍼징 실행 (runner)
  - EXE-04-02 동적 분석 새니타이저(ASAN/TSAN) 실시간 모니터링 (sanitizer_monitor)
  - EXE-04-03 타임아웃 임계치 조정 (timeout_manager)
"""
