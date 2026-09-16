"""EXE-04-00 fuzz 커맨드 실행 루프 및 하위 기능 연동 지점.

``logosfuzz fuzz --engine <libfuzzer|afl++> --timeout <sec> --docker``의 코어 루프.
Logic Group을 우선순위 순으로 순회하며 그룹마다 다음을 수행한다.

  1. EXE-04-03 :class:`TimeoutManager`로 그룹별 :class:`TimeoutPlan` 산정.
  2. EXE-04-02 sanitizer monitor에 입력별 실시간 데드라인을 전달(연결).
  3. EXE-04-01 Docker runner로 격리 퍼징 실행. 캠페인 시간 도달 시 runner가
     해당 그룹을 안전 종료하고 결과를 반환하면, 루프가 다음 그룹으로 이행한다.

runner/monitor의 실제 구현(EXE-04-01/02)은 별도 이슈에서 채워지며, 여기서는
연동 계약(Protocol)만 고정한다. 그래서 EXE-04-03 산정 로직을 Docker 없이도
독립 검증할 수 있다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Protocol, runtime_checkable

from logosfuzz.common.logging import get_logger
from logosfuzz.common.models import LogicGroup
from logosfuzz.execute.timeout_manager import TimeoutManager, TimeoutPlan

_FEATURE = "EXE-04-00"


@dataclass
class GroupRunResult:
    """그룹 1개 퍼징 실행 결과 요약."""

    group_id: str
    plan: TimeoutPlan
    timed_out: bool = False           # 캠페인 시간 도달로 종료되었는지
    crashes: int = 0
    extra: dict = field(default_factory=dict)


@runtime_checkable
class FuzzRunner(Protocol):
    """EXE-04-01 Docker 격리 퍼징 실행기 계약.

    구현체는 ``plan.campaign_timeout_sec`` 도달 시 컨테이너를 안전 종료
    (SIGTERM → grace → SIGKILL)하고, 입력별 제한은 ``plan.libfuzzer_timeout_sec``
    /``plan.afl_timeout_ms``를 엔진 인자로 전달한다.
    """

    def run(self, group: LogicGroup, plan: TimeoutPlan) -> GroupRunResult:
        ...


@runtime_checkable
class SanitizerMonitor(Protocol):
    """EXE-04-02 ASAN/TSAN 실시간 모니터 계약.

    ``per_input_timeout_ms``를 실시간성 위반(hang) 판정 기준으로 사용한다.
    """

    def attach(self, group: LogicGroup, per_input_timeout_ms: int) -> None:
        ...


def run_fuzz_campaign(
    groups: Iterable[LogicGroup],
    *,
    runner: FuzzRunner,
    monitor: SanitizerMonitor | None = None,
    cli_timeout_sec: int | None = None,
    timeout_manager: TimeoutManager | None = None,
) -> list[GroupRunResult]:
    """Logic Group들을 순차 퍼징하고 그룹별 실행 결과를 반환한다.

    Args:
        groups: 퍼징 대상 그룹들(호출자가 우선순위 순으로 전달).
        runner: EXE-04-01 실행기.
        monitor: EXE-04-02 모니터(선택).
        cli_timeout_sec: 사용자 ``--timeout`` 값(초). None이면 그룹별 동적/기본 산정.
        timeout_manager: 주입용 EXE-04-03 산정기(미지정 시 기본 설정으로 생성).

    Returns:
        각 그룹의 :class:`GroupRunResult` 리스트(입력 순서와 동일).
    """
    tm = timeout_manager or TimeoutManager()
    logger = get_logger(_FEATURE)

    results: list[GroupRunResult] = []
    for group in groups:
        plan = tm.resolve(group, cli_timeout_sec)          # EXE-04-03
        if monitor is not None:
            monitor.attach(group, plan.per_input_timeout_ms)  # EXE-04-02 연동
        result = runner.run(group, plan)                   # EXE-04-01 격리 실행
        if result.timed_out:
            logger.info(
                "[%s] group=%s 캠페인 시간(%ss) 도달 → 다음 그룹으로 이행",
                _FEATURE,
                group.group_id,
                plan.campaign_timeout_sec,
            )
        results.append(result)
    return results
