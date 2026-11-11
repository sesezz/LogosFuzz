"""GEN-03-04가 전제하는 GEN-03-01/02/03 산출물 계약(인터페이스)

GEN-03-01(초안 생성)/GEN-03-02(컴파일 자가치유)/GEN-03-03(CAN/UDS mocking)은
이 저장소에 아직 미구현. GEN-03-04는 이들의 실제 구현을 참조하는
대신, 여기 정의된 계약만 신뢰하고 동작:

  - 입력: `HarnessArtifact` — "컴파일까지 성공한 하네스 1건"을 기술하는 값
    GEN-03-02가 이 형태로 결과물을 넘겨준다고 가정
  - 재시도 훅: `RegenerateCallback` — 검증 실패 시 호출할 단일 재진입점
    실패 사유(`FeedbackPayload`)를 받아 하네스를 다시 생성/수정하고, 재컴파일까지
    마친 새 `HarnessArtifact`를 반환한다고 가정. 이 재진입점 내부가
    GEN-03-01(전면 재생성)인지 GEN-03-02(부분 수정)인지는 GEN-03-04가 알 필요가
    없다 — 호출자가 실패 사유를 보고 어느 쪽으로 라우팅할지 결정

추후 GEN-03-01/02/03이 실제로 구현되면, 이 파일의 dataclass/Protocol 형태에
맞춰 값을 만들어 넘기기만 하면 GEN-03-04 쪽 코드는 수정 불필요
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol


@dataclass
class ApiSignature:
    """EXT 단계 지식베이스(API_METADATA)에서 조회한 원본 API 시그니처 1건

    GEN-03-04의 (선택) 정적 리뷰 단계가 하네스 호출부와 인자 개수/타입을
    비교하는 기준으로 사용
    """

    name: str
    param_types: list[str] = field(default_factory=list)
    return_type: str = "void"
    source: str = ""  # 근거 출처(헤더 파일명 등)


@dataclass
class HarnessArtifact:
    """GEN-03-02까지 통과한(컴파일 성공) 하네스 1건 — GEN-03-04의 입력 계약

    Attributes:
        group_id: SCH가 부여한 로직 그룹 식별자
        harness_path: 컴파일된 실행 파일(libFuzzer 등) 경로
        source_path: 하네스 소스 코드 경로. 정적 리뷰(선택 단계)에만 필요하며,
            없으면 해당 단계 생략
        corpus_dir: 시드 코퍼스 디렉토리. 없으면 빈 코퍼스로 dry-run
        expected_mock_symbols: 하네스에 삽입된 mock 함수 심볼 목록
            **GEN-03-03(Mock 주입)은 제거**(`docs/GEN-03-03.md`) — Bazel 의
            `deps` 가 링크를 책임지므로 stub 이 불필요. 현재 이
            필드를 채우는 곳이 없어 mock 트레이싱 단계가 항상 통과. 모킹이 다시
            필요해질 때를 위해 계약만 유지. 채울 경우, 각 mock 함수는
            호출될 때 자신의 심볼명을 포함한 로그 한 줄(예:
            ``[MOCK-CALL] mock_can_send``)을 stdout/stderr에 남겨야 GEN-03-04가
            호출 여부 판별 가능
        api_signatures: 정적 리뷰에서 비교할 원본 API 시그니처 목록
        gen_model: 하네스를 생성한 LLM 모델명. ANA 단계 추적용으로
            `logosfuzz/analyze/cve_reporting`의 `harness.gen_model` 필드 컨벤션과
            동일하게 전달
        round_no: 현재 재시도 라운드(0부터 시작). `validate_with_retry`가
            갱신하며, 호출자가 직접 설정할 필요 없음
    """

    group_id: str
    harness_path: Path
    source_path: Path | None = None
    corpus_dir: Path | None = None
    expected_mock_symbols: list[str] = field(default_factory=list)
    api_signatures: list[ApiSignature] = field(default_factory=list)
    gen_model: str = ""
    round_no: int = 0

    def __post_init__(self) -> None:
        self.harness_path = Path(self.harness_path)
        if self.source_path is not None:
            self.source_path = Path(self.source_path)
        if self.corpus_dir is not None:
            self.corpus_dir = Path(self.corpus_dir)


@dataclass
class FeedbackPayload:
    """검증 실패 시 상위 재진입점(GEN-03-01/02)으로 되돌려줄 실패 사유"""

    group_id: str
    round_no: int
    failed_steps: list[str]
    reason: str
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "group_id": self.group_id,
            "round_no": self.round_no,
            "failed_steps": self.failed_steps,
            "reason": self.reason,
            "detail": self.detail,
        }


class RegenerateCallback(Protocol):
    """검증 실패 시 호출하는 단일 재진입점(GEN-03-01 또는 GEN-03-02)

    실패 사유를 받아 하네스를 다시 생성/수정하고 재컴파일까지 마친 뒤,
    새로 컴파일된 `HarnessArtifact` 반환 필요. 재컴파일까지 실패하면
    예외를 던진다 — `validate_with_retry`가 이를 재시도 중단 신호로 처리
    """

    def __call__(self, artifact: HarnessArtifact, feedback: FeedbackPayload) -> HarnessArtifact: ...
