"""EXE 파트 실행 설정 모델.

의존성을 최소화하기 위해 표준 라이브러리(dataclass/enum)만 사용한다.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path


class Engine(str, enum.Enum):
    """지원하는 퍼징 엔진."""

    LIBFUZZER = "libfuzzer"
    AFLPP = "afl++"

    @classmethod
    def parse(cls, value: str) -> "Engine":
        from logosfuzz.execute.errors import InvalidEngineError

        norm = value.strip().lower()
        alias = {"aflpp": cls.AFLPP, "afl": cls.AFLPP, "afl++": cls.AFLPP,
                 "libfuzzer": cls.LIBFUZZER, "libf": cls.LIBFUZZER}
        if norm not in alias:
            raise InvalidEngineError(
                f"지원하지 않는 엔진: {value!r} (libfuzzer | afl++)"
            )
        return alias[norm]


@dataclass(frozen=True)
class LogicGroup:
    """SCH 단계가 만든 로직 그룹 단위의 퍼징 대상.

    harness_path: GEN 단계가 생성/컴파일한 퍼징 하네스 실행 파일.
    corpus_dir:   시드 코퍼스 디렉토리(없으면 빈 코퍼스로 시작).
    """

    name: str
    harness_path: Path
    corpus_dir: Path | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "harness_path", Path(self.harness_path))
        if self.corpus_dir is not None:
            object.__setattr__(self, "corpus_dir", Path(self.corpus_dir))


@dataclass
class FuzzConfig:
    """`logosfuzz fuzz` 한 회 실행의 전체 설정.

    설계서 EXE-04-00 화면 명세를 반영:
      logosfuzz fuzz --engine <libfuzzer|afl++> --timeout <sec> --docker
    """

    engine: Engine = Engine.LIBFUZZER
    timeout_sec: int = 60
    use_docker: bool = True

    # 산출물 경로
    workdir: Path = field(default_factory=lambda: Path.cwd())
    harness_dir: Path = field(default_factory=lambda: Path.cwd() / "harnesses")
    output_dir: Path = field(default_factory=lambda: Path.cwd() / "out")

    # 격리 이미지
    image: str = "logosfuzz-exec:latest"
    dockerfile: Path = field(default_factory=lambda: Path("docker/Dockerfile"))

    # 컨테이너 격리/자원 제한 (EXE-04-01 핵심)
    network: str = "none"          # 크래시 유발 코드의 외부 통신 차단
    memory_limit: str = "4g"
    cpus: str = "1.0"
    pids_limit: int = 512
    drop_all_caps: bool = True     # --cap-drop ALL
    no_new_privileges: bool = True

    # Sanitizer 환경 (상세 스트림 파싱은 EXE-04-02에서 확장)
    asan_options: str = "abort_on_error=1:detect_leaks=1:symbolize=1"
    tsan_options: str = "halt_on_error=1:second_deadlock_stack=1"

    @property
    def crashes_dir(self) -> Path:
        return self.output_dir / "crashes"

    @property
    def logs_dir(self) -> Path:
        return self.output_dir / "logs"

    def ensure_dirs(self) -> None:
        for d in (self.output_dir, self.crashes_dir, self.logs_dir):
            d.mkdir(parents=True, exist_ok=True)
