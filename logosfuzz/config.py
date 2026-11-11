"""EXE 파트 실행 설정 모델 (표준 라이브러리만 사용)"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path


class Engine(str, enum.Enum):
    """지원 퍼징 엔진 (libFuzzer 만 지원, 실행 이미지에 AFL++ 없음)"""

    LIBFUZZER = "libfuzzer"

    @classmethod
    def parse(cls, value: str) -> "Engine":
        from logosfuzz.execute.errors import InvalidEngineError

        norm = value.strip().lower()
        if norm in ("libfuzzer", "libf"):
            return cls.LIBFUZZER
        if norm in ("afl++", "aflpp", "afl"):
            raise InvalidEngineError(
                "AFL++ 는 지원하지 않는다: 실행 이미지에 AFL++ 가 없다 (libfuzzer 를 쓴다)"
            )
        raise InvalidEngineError(f"지원하지 않는 엔진: {value!r} (libfuzzer)")


class CoverageMode(str, enum.Enum):
    """EXE-04-04 커버리지 계측 방식

    - ``NONE``          : 커버리지 후처리 비활성 (기본)
    - ``LLVM_COV``      : clang 소스 기반 커버리지 (함수/라인/리전/브랜치, llvm-cov)
    - ``SANITIZER_COV`` : SanitizerCoverage 엣지 계측 (제어흐름 단위)
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
    """SCH 단계 로직 그룹 단위 퍼징 대상

    harness_path: GEN 단계에서 생성/컴파일한 퍼징 하네스 실행 파일
    corpus_dir:   시드 코퍼스 디렉토리 (없으면 빈 코퍼스로 시작)
    dict_path:    libFuzzer 딕셔너리 파일 (없으면 ``FuzzConfig.dict_dir`` 의
                  ``<name>.dict``, 하네스 옆 ``<바이너리>.dict`` 순으로 탐색)
    """

    name: str
    harness_path: Path
    corpus_dir: Path | None = None
    dict_path: Path | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "harness_path", Path(self.harness_path))
        if self.corpus_dir is not None:
            object.__setattr__(self, "corpus_dir", Path(self.corpus_dir))
        if self.dict_path is not None:
            object.__setattr__(self, "dict_path", Path(self.dict_path))


@dataclass
class FuzzConfig:
    """`logosfuzz fuzz` 1회 실행 전체 설정

    설계서 EXE-04-00 화면 명세 반영:
      logosfuzz fuzz --engine libfuzzer --timeout <sec> --docker
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

    # 컨테이너 격리/자원 제한
    network: str = "none"          # 크래시 유발 코드의 외부 통신 차단
    memory_limit: str = "4g"
    cpus: str = "1.0"
    pids_limit: int = 512
    drop_all_caps: bool = True     # --cap-drop ALL
    no_new_privileges: bool = True
    # 컨테이너를 호스트 실행 사용자(uid:gid)로 실행
    # 이미지 기본 사용자(uid 1000 fuzzer)로 두면 호스트 uid 가 다를 때(실측 확인:
    # uid 1003) /out 바인드 마운트에 쓰기 권한이 없어 크래시 artifact 가 조용히
    # 유실 — ASAN 은 결함을 잡지만 crashes/ 는 빈 채로 남고 total_crashes=0 으로 보고
    run_as_host_user: bool = True

    # Sanitizer 환경
    #
    # symbolize=0: ASAN 이 크래시 시그널 핸들러 "안에서" llvm-symbolizer 를
    # fork/exec 하면 WSL2 에서 그 자식 프로세스가 무응답 상태로 정지(실측 확인 —
    # 컨테이너 밖 단독 llvm-symbolizer 호출은 즉시 응답, ASAN 내부 호출만 무한
    # 대기 → 하드 타임아웃 → 크래시 산출물 저장 전에 프로세스 종료 → crashes/ 가
    # 비고 상태도 crashed 대신 timeout 으로 오기록). 심볼라이즈를 끄면 즉시
    # SIGABRT 종료, 크래시 산출물도 정상 저장(실측 확인)
    #
    # 대신 파일:줄 정보 손실 — 크래시 발생 "이후" 별도 프로세스로(ASAN 시그널
    # 핸들러 밖에서) `llvm-symbolizer` 를 돌려 복원
    # 담당은 `execute/symbolize.py`, 제어는 아래 세 설정
    asan_options: str = "abort_on_error=1:detect_leaks=1:symbolize=0"
    tsan_options: str = "halt_on_error=1:second_deadlock_stack=1"

    # 크래시 후처리 심볼라이즈 (EXE-04-02). 끄면 sanitizer 결함의 traceback 이
    # 비어 ANA 의 시그니처/정오탐 판별이 근거를 잃는다(모듈 docstring 참조).
    symbolize_crashes: bool = True
    # 심볼라이저는 호스트 실행이 기본 — 퍼징 이미지는 clang/llvm 을 apt 로 깔지
    # 않아(Bazel @llvm_toolchain 이 가져옴) llvm-symbolizer 부재
    # 한쪽에 도구가 없으면 다른 쪽으로 한 번 전환(symbolize.py 참조)
    symbolize_in_docker: bool = False
    llvm_symbolizer: str = "llvm-symbolizer"   # 심볼라이저 경로/이름

    # libFuzzer 실행 옵션
    # per_input_timeout_ms: 입력 1건 실행 제한(-timeout). None 이면 EXE-04-03
    #   TimeoutManager 기본값(DEFAULT_PER_INPUT_MS) 사용
    # rss_limit_mb / malloc_limit_mb: 메모리 상한(-rss_limit_mb / -malloc_limit_mb).
    #   컨테이너 --memory 보다 낮게 두어, 헤더 값만 믿고 거대 할당을 하는 입력이
    #   컨테이너 OOM-kill(원인 불명 종료) 대신 libFuzzer OOM 보고로 남도록 함. 0 이면 생략
    # max_len: 입력 최대 길이(-max_len). 0 이면 생략(libFuzzer 자동 결정)
    # dict_dir: ``<그룹 이름>.dict`` 탐색 디렉토리. 있으면 -dict= 자동 추가
    per_input_timeout_ms: int | None = None
    rss_limit_mb: int = 2048
    malloc_limit_mb: int = 2048
    max_len: int = 0
    dict_dir: Path | None = None
    # fork_jobs: 병렬 퍼징 작업 수(-fork=N). 0 이면 단일 프로세스(기존 동작)
    # ignore_crashes: fork 모드에서 크래시 후 캠페인 지속 여부(-ignore_crashes=1).
    #   끄면 첫 크래시에서 전체 종료
    # Docker --cpus 는 cpus 와 fork_jobs 중 큰 값 적용(effective_cpus)
    # fork_replay_limit: fork 모드 종료 후 스택 확보용 크래시 입력 재실행 최대 건수
    fork_jobs: int = 0
    ignore_crashes: bool = True
    fork_replay_limit: int = 20

    # 캠페인 후 코퍼스 최소화(-merge=1). 같은 커버리지를 내는 최소 입력 집합만 코퍼스에 유지
    minimize_corpus: bool = False

    # 커버리지 계측 (EXE-04-04). 기본 NONE → 기존 동작 불변, 옵트인 시에만 활성.
    coverage: CoverageMode = CoverageMode.NONE
    coverage_subdir: str = "coverage"          # output_dir 하위 profraw/profdata 위치
    coverage_in_docker: bool = True            # llvm 도구 이미지 내 실행 여부
    coverage_merge_sparse: bool = True         # llvm-profdata merge -sparse
    coverage_sources: tuple = ()               # llvm-cov export 소스 필터 (선택)
    llvm_profdata: str = "llvm-profdata"       # 병합 도구 경로/이름
    llvm_cov: str = "llvm-cov"                 # export 도구 경로/이름

    @property
    def effective_cpus(self) -> str:
        """컨테이너 --cpus 값. fork 모드면 작업 수 이상으로 상향"""
        try:
            base = float(self.cpus)
        except ValueError:
            return self.cpus
        if self.fork_jobs > base:
            return f"{float(self.fork_jobs):.1f}"
        return self.cpus

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
