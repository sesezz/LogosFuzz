# CTR-06-02 · Human-in-the-loop (HITL) 인터페이스 골격

LogosFuzz 자동 퍼징 파이프라인(`EXT → SCH → GEN → EXE → ANA`)에서 **사람의 검토·승인이 필요한 지점**을 표준화된 방식으로 처리하기 위한 제어(CTR) 계층 골격입니다. 이번 커밋은 `CTR-06-02 HITL 골격 착수` 범위로, 배관(데이터 모델·저장소·정책·게이트·CLI·연동 훅)까지 동작하는 스켈레톤을 제공합니다. 각 단계의 심층 로직(하네스 재생성, CVE 리포트 작성 등)은 `TODO`로 표시된 연결점만 남겨 두었습니다.

## 구성

| 파일 | 역할 |
|---|---|
| `models.py` | `Stage`, `Checkpoint`, `DecisionType`, `ReviewStatus` 열거형과 `ReviewItem`·`Decision` 데이터클래스 |
| `store.py` | `ReviewStore` 인터페이스 + `JsonReviewStore`(기본)·`InMemoryReviewStore`(테스트). 향후 SQLite/Vector DB로 교체 가능 |
| `policy.py` | 체크포인트별 `AUTO / MANUAL / CONDITIONAL` 정책. 이 파일만 바꾸면 무인 ↔ 감독 운전 전환 |
| `gate.py` | `HITLManager` — 파이프라인이 호출하는 진입점(`request`), 사람 결정 기록(`decide`), 조회(`pending/stats`) |
| `hooks.py` | GEN·ANA 단계가 게이트를 호출하는 예시 어댑터 |
| `cli.py` | `logosfuzz review` 명령(list/show/approve/reject/skip/stats) |
| `demo.py` | 전체 흐름 시연 (`python -m logosfuzz.control.hitl.demo`) |
| `tests/` | 단위 테스트 11종 |

## 개입 지점(Checkpoint)

| Checkpoint | 단계 | 기본 정책 | 설명 |
|---|---|---|---|
| `COMPAT_CHECK` | CTR | AUTO | CTR-06-01 사전 호환성 체크리스트 확인 |
| `SCHEDULE_REVIEW` | SCH | AUTO | 로직 그룹/퍼징 우선순위 사람 조정 |
| `HARNESS_REVIEW` | GEN | CONDITIONAL | **컴파일 실패한 하네스만** 사람 검토 |
| `CRASH_TRIAGE` | ANA | CONDITIONAL | **판정 신뢰도 < 0.8**인 크래시만 사람 확인 |
| `CVE_DISCLOSURE` | ANA-05-02 | MANUAL | 취약점 공개 전 **항상** 사람 승인 |

## 동작 흐름

```
파이프라인 단계 ──request(checkpoint, target, payload)──▶ HITLManager
                                                          │
                                       정책 판정 (policy) │
                    ┌─────────────────────────────────────┴───────────────┐
              사람 불필요(AUTO)                                   사람 필요(MANUAL/조건충족)
                    │                                                     │
          자동 Decision(APPROVE) 반환                        PENDING 항목을 Store에 저장
                                                                          │
                                              interactive=True ──▶ 콘솔에서 즉시 질의(블로킹)
                                              interactive=False ─▶ DEFER 반환(비동기 대기)
                                                                          │
                                            사람이 나중에 `logosfuzz review approve <id>` 로 처리
```

`request()`가 돌려주는 `Decision.type`에 따라 각 단계가 분기합니다: `APPROVE/EDIT`→진행, `REJECT`→재시도/폐기, `SKIP`→건너뜀, `DEFER`→비동기 검토 대기.

## 사용법

라이브러리:

```python
from logosfuzz.control.hitl import HITLManager, Checkpoint, DecisionType

hitl = HITLManager.create()          # 기본 정책 + JSON 저장소
d = hitl.request(
    Checkpoint.CVE_DISCLOSURE,
    target="CVE-DRAFT-001",
    project="dlt-daemon",
    summary="DLT 파싱 힙 오버플로우",
    payload={"severity": "HIGH"},
)
if d.type == DecisionType.APPROVE:
    ...  # 공개 진행
```

CLI:

```bash
python -m logosfuzz.control.hitl.cli review list          # 대기 항목
python -m logosfuzz.control.hitl.cli review show <id>
python -m logosfuzz.control.hitl.cli review approve <id> -m "검토 완료"
python -m logosfuzz.control.hitl.cli review stats
```

상위 `logosfuzz` CLI에는 `cli.register(subparsers)`로 `review` 서브커맨드를 붙이면 됩니다.

## 테스트 / 데모

```bash
export PYTHONPATH=$(pwd)          # logosfuzz 패키지 루트
python -m logosfuzz.control.hitl.demo
python -m unittest logosfuzz.control.hitl.tests.test_hitl -v
```

## 다음 단계(TODO)

- `gate.py` interactive 프롬프트를 rich TUI 또는 웹 UI로 확장
- `store.py` SQLite/Vector DB 백엔드 구현(ERD 연동)
- `HARNESS_REVIEW` REJECT → GEN-03-02 self-heal 재생성 루프 연결
- `CRASH_TRIAGE` REJECT → ANA-05-03 지식베이스 역피드백 연결
- 리뷰 만료(SLA) 및 알림, 감사 로그(audit trail)
