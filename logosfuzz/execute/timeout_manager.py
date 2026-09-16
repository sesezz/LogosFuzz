"""EXE-04-03 타임아웃 임계치 조정.

EXE-04-00(Docker 격리 퍼징 실행)의 하위 기능. 자동차 오픈소스의 실시간성
특성을 고려하여 Logic Group별 타임아웃 임계치를 산정/조정한다.

타임아웃은 성격이 다른 두 축으로 분리한다.

1. 캠페인 시간 (``campaign_timeout_sec``)
   - EXE-04-00의 ``--timeout <sec>``에 대응. 그룹 퍼징의 총 실행(wall-clock)
     예산이며, 도달 시 해당 그룹을 종료하고 다음 그룹으로 이행하는 트리거.
   - CLI로 지정하면 그 값을, 미지정 시 안전 기본값(기본 300초)을 사용한다.

2. 입력별 실시간 데드라인 (``per_input_timeout_ms``)
   - 워치독 주기·실시간 제어 루프 주기 등에서 동적 산정. 퍼징 엔진의 입력 1건
     실행 제한(libFuzzer ``-timeout`` / AFL++ ``-t``)으로 전달되며, 이 시간을
     넘는 입력은 실시간성 위반(hang)으로 잡혀 ANA 단계의 "워치독 시간 초과 /
     주기 지연" 분류로 연결된다.
   - 그룹에 결합된 실시간 신호가 없으면 안전 기본값으로 폴백한다.

본 모듈은 값 산정만 담당하며 프로세스를 직접 종료하지 않는다(관심사 분리).
실제 종료/이행은 산정 결과(:class:`TimeoutPlan`)를 받은 EXE-04-01 runner가 수행한다.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from logosfuzz.common.logging import get_logger
from logosfuzz.common.models import LogicGroup

_FEATURE = "EXE-04-03"

# 산정 기본 상수
DEFAULT_CAMPAIGN_SEC = 300      # CLI 미지정 시 그룹 캠페인 기본 예산(초)
DEFAULT_PER_INPUT_MS = 1000     # 실시간 신호 부재 시 입력별 데드라인 기본값(ms)
DEFAULT_SAFETY_FACTOR = 1.5     # 실시간 주기 대비 데드라인 여유 계수
DEFAULT_FLOOR_MS = 50           # 입력별 데드라인 하한(ms) — 과도한 오탐 hang 방지
DEFAULT_CEIL_MS = 60_000        # 입력별 데드라인 상한(ms)


class TimeoutSource(str, Enum):
    """타임아웃 값의 산정 출처."""

    CLI_OVERRIDE = "cli_override"  # 사용자가 --timeout으로 직접 지정
    DYNAMIC = "dynamic"            # 실시간 신호 기반 동적 산정
    DEFAULT = "default"            # 안전 기본값 폴백


@dataclass(frozen=True)
class TimeoutPlan:
    """Logic Group 1개에 대한 타임아웃 산정 결과.

    Attributes:
        group_id: 대상 그룹 식별자.
        campaign_timeout_sec: 그룹 캠페인 총 예산(초). 도달 시 그룹 종료.
        per_input_timeout_ms: 입력별 실시간 데드라인(ms).
        campaign_source: 캠페인 시간의 산정 출처.
        per_input_source: 입력별 데드라인의 산정 출처.
        rationale: 로그로 남길 사람이 읽는 산정 근거 문자열.
    """

    group_id: str
    campaign_timeout_sec: int
    per_input_timeout_ms: int
    campaign_source: TimeoutSource
    per_input_source: TimeoutSource
    rationale: str

    @property
    def libfuzzer_timeout_sec(self) -> int:
        """libFuzzer ``-timeout=<sec>`` 값(초, 올림, 최소 1초)."""
        return max(1, math.ceil(self.per_input_timeout_ms / 1000))

    @property
    def afl_timeout_ms(self) -> int:
        """AFL++ ``-t <msec>`` 값(ms)."""
        return self.per_input_timeout_ms


class TimeoutManager:
    """EXE-04-03 타임아웃 임계치 산정기.

    ``fuzz`` 루프가 그룹을 순회하며 :meth:`resolve`로 그룹별 :class:`TimeoutPlan`을
    얻고, 이를 EXE-04-01 runner / EXE-04-02 sanitizer monitor에 전달한다.
    """

    def __init__(
        self,
        *,
        default_campaign_sec: int = DEFAULT_CAMPAIGN_SEC,
        default_per_input_ms: int = DEFAULT_PER_INPUT_MS,
        safety_factor: float = DEFAULT_SAFETY_FACTOR,
        floor_ms: int = DEFAULT_FLOOR_MS,
        ceil_ms: int = DEFAULT_CEIL_MS,
        logger: logging.Logger | None = None,
    ) -> None:
        if default_campaign_sec <= 0:
            raise ValueError("default_campaign_sec must be > 0")
        if default_per_input_ms <= 0:
            raise ValueError("default_per_input_ms must be > 0")
        if safety_factor <= 0:
            raise ValueError("safety_factor must be > 0")
        if floor_ms <= 0 or ceil_ms <= 0:
            raise ValueError("floor_ms and ceil_ms must be > 0")
        if floor_ms > ceil_ms:
            raise ValueError("floor_ms must be <= ceil_ms")

        self._default_campaign_sec = default_campaign_sec
        self._default_per_input_ms = default_per_input_ms
        self._safety_factor = safety_factor
        self._floor_ms = floor_ms
        self._ceil_ms = ceil_ms
        self._logger = logger or get_logger(_FEATURE)

    def resolve(
        self, group: LogicGroup, cli_timeout_sec: int | None = None
    ) -> TimeoutPlan:
        """그룹 1개의 타임아웃을 산정하고 근거를 로깅한 뒤 반환한다.

        Args:
            group: 대상 Logic Group.
            cli_timeout_sec: 사용자가 ``--timeout``으로 지정한 값(초). None이면
                캠페인 시간은 기본값을 사용한다. 0 이하이면 ValueError.

        Returns:
            산정된 :class:`TimeoutPlan`.
        """
        campaign_sec, campaign_src, campaign_reason = self._resolve_campaign(
            cli_timeout_sec
        )
        per_input_ms, per_input_src, per_input_reason = self._resolve_per_input(group)

        rationale = (
            f"[{_FEATURE}] group={group.group_id} "
            f"campaign={campaign_sec}s({campaign_src.value}; {campaign_reason}) "
            f"per_input={per_input_ms}ms({per_input_src.value}; {per_input_reason})"
        )

        plan = TimeoutPlan(
            group_id=group.group_id,
            campaign_timeout_sec=campaign_sec,
            per_input_timeout_ms=per_input_ms,
            campaign_source=campaign_src,
            per_input_source=per_input_src,
            rationale=rationale,
        )
        # 요구사항: 타임아웃 값 산정 근거를 로그로 남긴다.
        self._logger.info(rationale)
        return plan

    def resolve_all(
        self, groups: Iterable[LogicGroup], cli_timeout_sec: int | None = None
    ) -> dict[str, TimeoutPlan]:
        """여러 그룹에 대해 산정 결과를 그룹 ID로 매핑하여 반환한다."""
        return {
            group.group_id: self.resolve(group, cli_timeout_sec) for group in groups
        }

    # -- 내부 산정 로직 -----------------------------------------------------

    def _resolve_campaign(
        self, cli_timeout_sec: int | None
    ) -> tuple[int, TimeoutSource, str]:
        """캠페인 시간(초)을 산정한다. CLI 지정값이 있으면 우선한다."""
        if cli_timeout_sec is not None:
            if cli_timeout_sec <= 0:
                raise ValueError(
                    f"--timeout must be > 0 (got {cli_timeout_sec!r})"
                )
            return cli_timeout_sec, TimeoutSource.CLI_OVERRIDE, "사용자 지정(--timeout)"
        return (
            self._default_campaign_sec,
            TimeoutSource.DEFAULT,
            f"기본값 {self._default_campaign_sec}s",
        )

    def _resolve_per_input(
        self, group: LogicGroup
    ) -> tuple[int, TimeoutSource, str]:
        """입력별 실시간 데드라인(ms)을 동적 산정한다.

        가장 빡빡한(주기가 가장 짧은) 실시간 신호를 데드라인의 기준으로 삼고,
        안전계수를 곱한 뒤 [floor, ceil]로 클램프한다. 신호가 없으면 기본값 폴백.
        """
        signals = [s for s in group.realtime_signals if s.period_ms > 0]
        if not signals:
            return (
                self._default_per_input_ms,
                TimeoutSource.DEFAULT,
                f"실시간 신호 없음 → 기본 {self._default_per_input_ms}ms 사용",
            )

        tightest = min(signals, key=lambda s: s.period_ms)
        raw_ms = tightest.period_ms * self._safety_factor
        clamped_ms = int(round(min(max(raw_ms, self._floor_ms), self._ceil_ms)))

        src = tightest.source or "규격서"
        reason = (
            f"{tightest.kind} 주기 {tightest.period_ms:g}ms "
            f"× 안전계수 {self._safety_factor:g} 기반 산정 → {clamped_ms}ms "
            f"(출처: {src})"
        )
        if clamped_ms != int(round(raw_ms)):
            reason += f" [클램프 {self._floor_ms}~{self._ceil_ms}ms 적용]"
        return clamped_ms, TimeoutSource.DYNAMIC, reason
