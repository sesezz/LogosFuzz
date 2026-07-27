"""파이프라인 공용 데이터 모델.

SCH(Schedule) 단계가 산출한 Logic Group을 EXE(Execute) 단계가 소비한다.
EXE-04-03(타임아웃 임계치 조정)은 그룹에 결합된 실시간 제약 신호를 참조한다.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# 실시간 신호 종류(kind) 상수 — 자동차 오픈소스 도메인 특화
SIGNAL_WATCHDOG = "watchdog"        # 워치독 리셋 주기
SIGNAL_CONTROL_LOOP = "control_loop"  # 실시간 제어 루프 주기
SIGNAL_CAN_CYCLE = "can_cycle"      # CAN 메시지 주기
SIGNAL_UDS_P2 = "uds_p2"           # UDS 서버 응답(P2/P2*) 타이밍


@dataclass(frozen=True)
class RealtimeSignal:
    """Logic Group에 결합된 실시간성 제약 신호 1건.

    EXT-01-02(RAG 파서 기반 문서 제약 조건 추출)가 규격서(CAN/UDS 등)에서
    추출하여 지식베이스에 적재하고, SCH 단계가 그룹에 결합한다.

    Attributes:
        kind: 신호 종류. ``SIGNAL_*`` 상수 중 하나를 권장.
        period_ms: 주기/데드라인 (밀리초). 반드시 양수.
        source: 산정 근거 출처(규격서명·헤더 등). 로그/추적용.
    """

    kind: str
    period_ms: float
    source: str = ""

    def __post_init__(self) -> None:
        if self.period_ms <= 0:
            raise ValueError(
                f"RealtimeSignal.period_ms must be > 0 (kind={self.kind!r}, "
                f"got {self.period_ms!r})"
            )


@dataclass
class LogicGroup:
    """SCH-02-01에서 패키징된 상태 기반 로직 그룹.

    Attributes:
        group_id: 그룹 고유 식별자.
        name: 사람이 읽는 그룹명.
        api_set: 그룹에 속한 대상 API 이름 목록.
        priority: SCH-02-02 시너지 점수 기반 퍼징 우선순위(높을수록 먼저).
        realtime_signals: 그룹에 결합된 실시간성 제약 신호 목록.
            비어 있으면 EXE-04-03이 안전 기본값으로 폴백한다.
    """

    group_id: str
    name: str = ""
    api_set: list[str] = field(default_factory=list)
    priority: float = 0.0
    realtime_signals: list[RealtimeSignal] = field(default_factory=list)
