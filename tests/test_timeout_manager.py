"""EXE-04-03 타임아웃 임계치 조정 유닛 테스트.

Docker 없이 순수 산정 로직을 검증한다. 표준 라이브러리 unittest 사용.
실행: ``python -m unittest -v`` (프로젝트 루트에서)
"""

from __future__ import annotations

import logging
import unittest

from logosfuzz.common.models import (
    SIGNAL_CONTROL_LOOP,
    SIGNAL_WATCHDOG,
    LogicGroup,
    RealtimeSignal,
)
from logosfuzz.execute.fuzz import GroupRunResult, run_fuzz_campaign
from logosfuzz.execute.timeout_manager import (
    DEFAULT_CAMPAIGN_SEC,
    DEFAULT_PER_INPUT_MS,
    TimeoutManager,
    TimeoutPlan,
    TimeoutSource,
)


def _silent_logger() -> logging.Logger:
    """테스트 출력을 더럽히지 않도록 조용한 로거를 만든다."""
    logger = logging.getLogger("test.EXE-04-03")
    logger.handlers.clear()
    logger.addHandler(logging.NullHandler())
    logger.setLevel(logging.CRITICAL)
    logger.propagate = False
    return logger


class TimeoutManagerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tm = TimeoutManager(logger=_silent_logger())

    # -- 캠페인 시간 축 -----------------------------------------------------

    def test_cli_override_sets_campaign(self) -> None:
        """--timeout 지정 시 캠페인 시간이 그 값이 되고 출처가 CLI_OVERRIDE."""
        group = LogicGroup(group_id="g1")
        plan = self.tm.resolve(group, cli_timeout_sec=120)
        self.assertEqual(plan.campaign_timeout_sec, 120)
        self.assertEqual(plan.campaign_source, TimeoutSource.CLI_OVERRIDE)

    def test_campaign_defaults_when_no_cli(self) -> None:
        """--timeout 미지정 시 캠페인은 기본값(300s)·DEFAULT."""
        plan = self.tm.resolve(LogicGroup(group_id="g1"), cli_timeout_sec=None)
        self.assertEqual(plan.campaign_timeout_sec, DEFAULT_CAMPAIGN_SEC)
        self.assertEqual(plan.campaign_source, TimeoutSource.DEFAULT)

    def test_invalid_cli_timeout_raises(self) -> None:
        """0 이하 --timeout은 ValueError."""
        with self.assertRaises(ValueError):
            self.tm.resolve(LogicGroup(group_id="g1"), cli_timeout_sec=0)
        with self.assertRaises(ValueError):
            self.tm.resolve(LogicGroup(group_id="g1"), cli_timeout_sec=-5)

    # -- 입력별 실시간 데드라인 축 -----------------------------------------

    def test_dynamic_per_input_from_watchdog(self) -> None:
        """watchdog 200ms × 안전계수 1.5 = 300ms, 출처 DYNAMIC."""
        group = LogicGroup(
            group_id="uds_session",
            realtime_signals=[
                RealtimeSignal(SIGNAL_WATCHDOG, 200.0, source="UDS 규격서")
            ],
        )
        plan = self.tm.resolve(group)
        self.assertEqual(plan.per_input_timeout_ms, 300)
        self.assertEqual(plan.per_input_source, TimeoutSource.DYNAMIC)

    def test_tightest_signal_wins(self) -> None:
        """여러 신호 중 가장 짧은 주기가 데드라인 기준이 된다."""
        group = LogicGroup(
            group_id="mixed",
            realtime_signals=[
                RealtimeSignal(SIGNAL_WATCHDOG, 200.0),
                RealtimeSignal(SIGNAL_CONTROL_LOOP, 100.0),  # 가장 빡빡
            ],
        )
        plan = self.tm.resolve(group)
        self.assertEqual(plan.per_input_timeout_ms, 150)  # 100 × 1.5

    def test_per_input_default_when_no_signal(self) -> None:
        """실시간 신호가 없으면 per-input 기본값(1000ms)·DEFAULT로 폴백."""
        plan = self.tm.resolve(LogicGroup(group_id="plain"))
        self.assertEqual(plan.per_input_timeout_ms, DEFAULT_PER_INPUT_MS)
        self.assertEqual(plan.per_input_source, TimeoutSource.DEFAULT)

    def test_floor_clamp(self) -> None:
        """아주 짧은 주기는 하한(floor 50ms)으로 클램프된다."""
        group = LogicGroup(
            group_id="fast",
            realtime_signals=[RealtimeSignal(SIGNAL_CONTROL_LOOP, 10.0)],
        )
        plan = self.tm.resolve(group)  # 10 × 1.5 = 15 → floor 50
        self.assertEqual(plan.per_input_timeout_ms, 50)
        self.assertIn("클램프", plan.rationale)

    def test_ceil_clamp(self) -> None:
        """아주 긴 주기는 상한(ceil)으로 클램프된다."""
        tm = TimeoutManager(ceil_ms=5000, logger=_silent_logger())
        group = LogicGroup(
            group_id="slow",
            realtime_signals=[RealtimeSignal(SIGNAL_WATCHDOG, 10000.0)],
        )
        plan = tm.resolve(group)  # 10000 × 1.5 = 15000 → ceil 5000
        self.assertEqual(plan.per_input_timeout_ms, 5000)

    # -- 그룹별 상이성 & 근거 로깅 -----------------------------------------

    def test_groups_get_different_values(self) -> None:
        """그룹마다 실시간 특성이 다르면 다른 타임아웃이 나온다."""
        groups = [
            LogicGroup(
                group_id="rt",
                realtime_signals=[RealtimeSignal(SIGNAL_WATCHDOG, 200.0)],
            ),
            LogicGroup(group_id="batch"),  # 신호 없음
        ]
        plans = self.tm.resolve_all(groups)
        self.assertEqual(plans["rt"].per_input_timeout_ms, 300)
        self.assertEqual(plans["batch"].per_input_timeout_ms, DEFAULT_PER_INPUT_MS)
        self.assertNotEqual(
            plans["rt"].per_input_timeout_ms, plans["batch"].per_input_timeout_ms
        )

    def test_rationale_records_basis(self) -> None:
        """산정 근거 문자열에 기능번호·신호종류·'기반 산정'이 포함된다."""
        group = LogicGroup(
            group_id="uds",
            realtime_signals=[RealtimeSignal(SIGNAL_WATCHDOG, 200.0)],
        )
        rationale = self.tm.resolve(group).rationale
        self.assertIn("EXE-04-03", rationale)
        self.assertIn("watchdog", rationale)
        self.assertIn("기반 산정", rationale)

    def test_resolve_emits_log(self) -> None:
        """resolve는 산정 근거를 INFO 레벨로 로깅한다(요구사항)."""
        tm = TimeoutManager(logger=logging.getLogger("test.emit.EXE-04-03"))
        with self.assertLogs("test.emit.EXE-04-03", level="INFO") as cap:
            tm.resolve(LogicGroup(group_id="g1"))
        self.assertTrue(any("EXE-04-03" in line for line in cap.output))

    # -- 엔진 인자 매핑 -----------------------------------------------------

    def test_libfuzzer_timeout_mapping(self) -> None:
        """per_input_ms → libFuzzer 초 단위(올림, 최소 1초)."""
        plan = TimeoutPlan(
            group_id="g",
            campaign_timeout_sec=300,
            per_input_timeout_ms=300,
            campaign_source=TimeoutSource.DEFAULT,
            per_input_source=TimeoutSource.DYNAMIC,
            rationale="",
        )
        self.assertEqual(plan.libfuzzer_timeout_sec, 1)   # ceil(0.3s) → 1
        self.assertEqual(plan.afl_timeout_ms, 300)

        plan2 = TimeoutPlan("g", 300, 1500, TimeoutSource.DEFAULT,
                            TimeoutSource.DYNAMIC, "")
        self.assertEqual(plan2.libfuzzer_timeout_sec, 2)  # ceil(1.5s) → 2

    # -- 데이터 모델 검증 ---------------------------------------------------

    def test_signal_rejects_nonpositive_period(self) -> None:
        with self.assertRaises(ValueError):
            RealtimeSignal(SIGNAL_WATCHDOG, 0.0)


class FuzzIntegrationTest(unittest.TestCase):
    """EXE-04-03이 fuzz 루프에서 EXE-04-01/02와 연동되는지 검증."""

    def test_campaign_loop_uses_plans_and_advances(self) -> None:
        recorded_plans: list[TimeoutPlan] = []
        attached: list[int] = []

        class FakeRunner:
            def run(self, group: LogicGroup, plan: TimeoutPlan) -> GroupRunResult:
                recorded_plans.append(plan)
                # 캠페인 시간 도달로 종료되었다고 가정 → 다음 그룹 이행
                return GroupRunResult(group.group_id, plan, timed_out=True)

        class FakeMonitor:
            def attach(self, group: LogicGroup, per_input_timeout_ms: int) -> None:
                attached.append(per_input_timeout_ms)

        groups = [
            LogicGroup(
                group_id="rt",
                realtime_signals=[RealtimeSignal(SIGNAL_WATCHDOG, 200.0)],
            ),
            LogicGroup(group_id="batch"),
        ]
        results = run_fuzz_campaign(
            groups,
            runner=FakeRunner(),
            monitor=FakeMonitor(),
            cli_timeout_sec=None,
            timeout_manager=TimeoutManager(logger=_silent_logger()),
        )

        # 두 그룹 모두 실행되었고, 각자의 plan을 받았다.
        self.assertEqual([r.group_id for r in results], ["rt", "batch"])
        self.assertEqual(len(recorded_plans), 2)
        # monitor에 그룹별 실시간 데드라인이 전달되었다(EXE-04-02 연동).
        self.assertEqual(attached, [300, DEFAULT_PER_INPUT_MS])
        # runner에는 캠페인 시간이 함께 전달되었다(EXE-04-01 연동).
        self.assertTrue(all(r.plan.campaign_timeout_sec == 300 for r in results))


if __name__ == "__main__":
    unittest.main()
