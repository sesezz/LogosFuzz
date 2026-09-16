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


class CoverageMode(str, enum.Enum):
    """EXE-04-04 커버리지 계측 방식.

    - ``NONE``          : 커버리지 후처리 비활성(기본). 기존 EXE-04-01/02 흐름과 동일.
    - ``LLVM_COV``      : clang 소스 기반 커버리지(함수/라인/리전/브랜치, llvm-cov).
    - ``SANITIZER_COV`` : SanitizerCoverage 엣지 계측(제어흐름 단위).
    """

    NONE = "none"
    LLVM_COV = "llvm-cov"
    SANITIZER_COV = "sancov"

    @classmethod
    def parse(cls, value: str) -> "CoverageMode":
        norm = (value or "none").strip().lower()
        alias = {
            "none": cls.NONE, "off": cls.NONE, "": cls.NONE,
            "llvm-cov": cls.LLVM_COV, "llvm": cls.LLVM_COV, "llvmcov": cls.LLVM_COV,
            "source": cls.LLVM_COV, "profdata": cls.LLVM_COV,
            "sancov": cls.SANITIZER_COV, "sanitizer": cls.SANITIZER_COV,
            "sanitizer-coverage": cls.SANITIZER_COV, "edge": cls.SANITIZER_COV,
        }
        if norm not in alias:
            from logosfuzz.execute.errors import ExecuteError

            raise ExecuteError(
                f"지원하지 않는 커버리지 모드: {value!r} (none | llvm-cov | sancov)"
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
    # 컨테이너를 호스트의 실행 사용자(uid:gid)로 돌린다. 이미지 기본 사용자
    # (uid 1000 fuzzer)로 두면, 호스트 사용자의 uid가 다를 때(실측 확인:
    # uid 1003) /out 바인드 마운트에 컨테이너가 쓰기 권한이 없어 크래시
    # artifact가 조용히 저장되지 않는다 - ASAN은 결함을 잡지만
    # crashes/ 가 빈 채로 남고 total_crashes=0 으로 보고된다.
    run_as_host_user: bool = True

    # Sanitizer 환경 (상세 스트림 파싱은 EXE-04-02에서 확장)
    #
    # symbolize=0: ASAN이 크래시 시그널 핸들러 "안에서" llvm-symbolizer를
    # fork/exec하면 WSL2에서 그 자식 프로세스가 응답 없이 멈춘다(실측 확인 -
    # 컨테이너 밖 단독 llvm-symbolizer 호출은 즉시 응답하지만, ASAN이 크래시
    # 시점에 내부적으로 호출하면 무한 대기 → 하드 타임아웃까지 감 →
    # 크래시 산출물 저장 전에 프로세스가 죽어 crashes/ 가 비고, 상태가
    # crashed 대신 timeout 으로 잘못 기록된다). 심볼라이즈를 끄면 즉시
    # SIGABRT로 종료되고 크래시 산출물도 정상 저장된다(실측 확인).
    #
    # 대신 파일:줄 정보를 잃는다. 이건 크래시 발생 "이후" 별도 프로세스로
    # (ASAN 시그널 핸들러 밖에서) `asan_symbolize`/`llvm-symbolizer`를 돌려
    # 복원해야 한다 - ANA 단계의 후속 작업으로 남겨둔다.
    asan_options: str = "abort_on_error=1:detect_leaks=1:symbolize=0"
    tsan_options: str = "halt_on_error=1:second_deadlock_stack=1"

    # 커버리지 계측 (EXE-04-04). 기본 NONE → 기존 동작 불변, 옵트인 시에만 활성.
    coverage: CoverageMode = CoverageMode.NONE
    coverage_subdir: str = "coverage"          # output_dir 하위 profraw/profdata 위치
    coverage_in_docker: bool = True            # llvm 도구를 이미지 안에서 실행할지
    coverage_merge_sparse: bool = True         # llvm-profdata merge -sparse
    coverage_sources: tuple = ()               # llvm-cov export 소스 필터(선택)
    llvm_profdata: str = "llvm-profdata"       # 병합 도구 경로/이름
    llvm_cov: str = "llvm-cov"                 # export 도구 경로/이름

    @property
    def crashes_dir(self) -> Path:
        return self.output_dir / "crashes"

    @property
    def logs_dir(self) -> Path:
        return self.output_dir / "logs"

    @property
    def coverage_dir(self) -> Path:
        return self.output_dir / self.coverage_subdir

    def ensure_dirs(self) -> None:
        dirs = [self.output_dir, self.crashes_dir, self.logs_dir]
        if self.coverage is not CoverageMode.NONE:
            dirs.append(self.coverage_dir)
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)
