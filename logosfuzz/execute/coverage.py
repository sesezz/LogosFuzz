"""EXE-04-04: 커버리지 계측 (llvm-cov / SanitizerCoverage 연동)

EXE-04-01 실행이 남긴 ``*.profraw`` 후처리 및 함수/라인/리전/브랜치 커버리지 요약 생성

1. 계측(빌드 시): :func:`instrumentation_flags` 로 컴파일 플래그 계약 고정
     * ``llvm-cov`` (소스 기반)   : ``-fprofile-instr-generate -fcoverage-mapping``
     * SanitizerCoverage(엣지)    : ``-fsanitize-coverage=trace-pc-guard``
2. 수집(실행 시): :func:`profile_env` 로 ``LLVM_PROFILE_FILE`` 값 계산
3. 후처리(실행 후): ``llvm-profdata merge`` → ``llvm-cov export`` 결과를 :class:`CoverageSummary` 로 정규화

외부 프로세스 실행은 ``runner`` 콜러블로 주입 가능
"""

from __future__ import annotations

import glob
import json
import shlex
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from logosfuzz.config import CoverageMode, FuzzConfig, LogicGroup

# ---------------------------------------------------------------------------
# 계측 플래그 계약
# ---------------------------------------------------------------------------

_INSTRUMENTATION_FLAGS = {
    # clang 소스 기반 커버리지
    CoverageMode.LLVM_COV: ("-fprofile-instr-generate", "-fcoverage-mapping"),
    # SanitizerCoverage 엣지 단위 계측 (독립 하네스용)
    CoverageMode.SANITIZER_COV: ("-fsanitize-coverage=trace-pc-guard",),
    CoverageMode.NONE: (),
}


def instrumentation_flags(mode: CoverageMode) -> tuple[str, ...]:
    """커버리지 모드별 clang 컴파일 플래그 반환 (비-Bazel 경로용)"""
    return _INSTRUMENTATION_FLAGS.get(CoverageMode(mode), ())


# ---------------------------------------------------------------------------
# Bazel 경로의 계측 config
# ---------------------------------------------------------------------------
# 개별 컴파일 플래그 대신 대상 저장소의 config 사용 (baselibs: llvm_cov)
_BAZEL_COVERAGE_CONFIGS = {
    CoverageMode.LLVM_COV: ("llvm_cov",),
    # 퍼징 config(rules_fuzzing libfuzzer 계측)가 이미 적용하므로 불필요
    CoverageMode.SANITIZER_COV: (),
    CoverageMode.NONE: (),
}


def bazel_coverage_configs(mode: CoverageMode) -> tuple[str, ...]:
    """``bazel coverage`` 전용 config 이름 반환

    * 퍼징 빌드에는 미적용 (퍼징 쪽은 :func:`bazel_fuzz_coverage_build_argv`)
    * baselibs 는 ``coverage:llvm_cov`` 로만 정의하므로 ``bazel build`` 와 조합 불가
    * ``--config=bl-x86_64-linux`` 동시 지정 시 GCC 선택으로 LLVM covmap 미생성
    * 결과 ``_coverage_report.dat`` 는 zip 형식 (:func:`extract_bazel_lcov` 참고)
    """
    return _BAZEL_COVERAGE_CONFIGS.get(CoverageMode(mode), ())


# 퍼징 하네스용 커버리지 빌드
# 퍼징 config 위에 소스 기반 계측만 추가, platform_suffix 로 본 빌드 산출물과 분리
# 퍼징은 비계측 바이너리로 수행, 커버리지는 최종 코퍼스를 -runs=0 으로 재생해 측정
FUZZ_COVERAGE_PLATFORM_SUFFIX = "fuzz_cov"
FUZZ_COVERAGE_FLAGS = (
    "--copt=-fprofile-instr-generate",
    "--copt=-fcoverage-mapping",
    "--linkopt=-fprofile-instr-generate",
)


def bazel_fuzz_coverage_build_argv(
    target: str, *, fuzz_config: str = "fuzz", bazel: str = "bazel"
) -> list[str]:
    """퍼징 하네스 커버리지 계측 빌드 커맨드 생성 (실제 빌드 대상은 ``<name>_bin``)"""
    if not target.endswith("_bin"):
        target = f"{target}_bin"
    return [
        bazel, "build", f"--config={fuzz_config}",
        f"--platform_suffix={FUZZ_COVERAGE_PLATFORM_SUFFIX}",
        *FUZZ_COVERAGE_FLAGS,
        target,
    ]


# 툴체인 llvm 도구 경로
# 시스템 llvm-profdata 는 clang 22 profraw 버전 불일치로 사용 불가
_LLVM_TOOLCHAIN_BIN_GLOB = "external/toolchains_llvm++llvm+llvm_toolchain_llvm/bin"


def bazel_llvm_tool(output_base: "Path | str", tool: str) -> Optional[Path]:
    """``output_base`` 아래 툴체인 llvm 도구 경로 탐색 (없으면 ``None``)"""
    for candidate in sorted(Path(output_base).glob(f"{_LLVM_TOOLCHAIN_BIN_GLOB}/{tool}")):
        if candidate.is_file():
            return candidate
    return None


def extract_bazel_lcov(report: "Path | str", dest: "Path | str") -> Path:
    """``bazel coverage`` 결과물(zip 또는 lcov)에서 lcov 추출"""
    import zipfile

    report, dest = Path(report), Path(dest)
    if zipfile.is_zipfile(report):
        with zipfile.ZipFile(report) as bundle:
            dest.write_bytes(bundle.read("lcov_report/lcov.dat"))
    else:
        dest.write_bytes(report.read_bytes())
    return dest


# ---------------------------------------------------------------------------
# 실행 시 환경변수 (LLVM_PROFILE_FILE) 계산
# ---------------------------------------------------------------------------


def profile_env(group: LogicGroup, cfg: FuzzConfig, *, in_docker: bool) -> dict:
    """그룹 실행용 커버리지 환경변수 생성 (컨테이너/호스트 경로 구분)"""
    if CoverageMode(cfg.coverage) is CoverageMode.NONE:
        return {}
    if in_docker:
        base = f"/out/{cfg.coverage_subdir}/{group.name}"
    else:
        base = (cfg.coverage_dir / group.name).as_posix()
    # %m: 다중 프로세스에서도 충돌 없는 온라인 병합
    return {"LLVM_PROFILE_FILE": f"{base}/%m.profraw"}


# ---------------------------------------------------------------------------
# 커버리지 데이터 모델
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CoverageMetric:
    """단일 커버리지 축(함수/라인/리전/브랜치)의 수치."""

    covered: int = 0
    count: int = 0

    @property
    def percent(self) -> float:
        return round(100.0 * self.covered / self.count, 2) if self.count else 0.0

    @classmethod
    def from_llvm(cls, node: dict) -> "CoverageMetric":
        """llvm-cov export ``summary`` 하위 노드의 covered/count 추출"""
        return cls(covered=int(node.get("covered", 0)),
                   count=int(node.get("count", 0)))

    def to_dict(self) -> dict:
        return {"covered": self.covered, "count": self.count, "percent": self.percent}


@dataclass
class FileCoverage:
    """소스 파일 1개의 라인 커버리지"""

    filename: str
    lines: CoverageMetric = field(default_factory=CoverageMetric)

    def to_dict(self) -> dict:
        return {"filename": self.filename, "lines": self.lines.to_dict()}


@dataclass
class CoverageSummary:
    """그룹 1개의 정규화된 커버리지 요약"""

    group: str
    mode: str
    functions: CoverageMetric = field(default_factory=CoverageMetric)
    lines: CoverageMetric = field(default_factory=CoverageMetric)
    regions: CoverageMetric = field(default_factory=CoverageMetric)
    branches: CoverageMetric = field(default_factory=CoverageMetric)
    files: list[FileCoverage] = field(default_factory=list)
    profdata_path: str = ""
    export_path: str = ""

    def to_dict(self) -> dict:
        return {
            "group": self.group,
            "mode": self.mode,
            "functions": self.functions.to_dict(),
            "lines": self.lines.to_dict(),
            "regions": self.regions.to_dict(),
            "branches": self.branches.to_dict(),
            "file_count": len(self.files),
            "files": [f.to_dict() for f in self.files],
            "profdata_path": self.profdata_path,
            "export_path": self.export_path,
        }


# ---------------------------------------------------------------------------
# llvm-cov export JSON 파서
# ---------------------------------------------------------------------------


def parse_llvm_cov_export(export_json: str, *, group: str, mode: str,
                          include_files: bool = True) -> CoverageSummary:
    """``llvm-cov export`` JSON을 :class:`CoverageSummary` 로 정규화 (파일별은 라인만)"""
    doc = json.loads(export_json)
    data = doc.get("data") or []
    summary = CoverageSummary(group=group, mode=mode)
    if not data:
        return summary
    block = data[0]
    totals = block.get("totals", {})

    def metric(name: str) -> CoverageMetric:
        node = totals.get(name)
        return CoverageMetric.from_llvm(node) if isinstance(node, dict) else CoverageMetric()

    summary.functions = metric("functions")
    summary.lines = metric("lines")
    summary.regions = metric("regions")
    summary.branches = metric("branches")

    if include_files:
        for f in block.get("files", []):
            fsum = (f.get("summary") or {}).get("lines")
            summary.files.append(FileCoverage(
                filename=f.get("filename", ""),
                lines=CoverageMetric.from_llvm(fsum) if isinstance(fsum, dict) else CoverageMetric(),
            ))
    return summary


# ---------------------------------------------------------------------------
# 외부 명령 실행 추상화
# ---------------------------------------------------------------------------


@dataclass
class CmdResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


CommandRunner = Callable[[list], CmdResult]


def _default_runner(argv: list) -> CmdResult:
    """subprocess 기반 기본 실행기"""
    proc = subprocess.run(argv, capture_output=True, text=True)
    return CmdResult(proc.returncode, proc.stdout, proc.stderr)


# ---------------------------------------------------------------------------
# 하네스 바이너리 위치
# ---------------------------------------------------------------------------
# 빌드 어댑터가 cquery로 얻은 실제 경로(LogicGroup.harness_path) 그대로 사용
# bazel-bin 심링크는 직전 빌드 config에 따라 바뀌므로 경로 조립 금지


def harness_binary_path(group: LogicGroup, cfg: FuzzConfig) -> Path:
    """하네스 바이너리의 호스트 경로 (이름만 있으면 ``harness_dir`` 기준)"""
    p = Path(group.harness_path)
    if p.parent != Path("."):
        return p.resolve()
    return (cfg.harness_dir / p.name).resolve()


# ---------------------------------------------------------------------------
# 커버리지 수집 오케스트레이터
# ---------------------------------------------------------------------------


class CoverageCollector:
    """profraw → profdata → llvm-cov export → :class:`CoverageSummary` 파이프라인

    ``use_docker`` 와 ``cfg.coverage_in_docker`` 가 모두 참이면 컨테이너 내 도구 사용
    """

    def __init__(self, cfg: FuzzConfig, runner: Optional[CommandRunner] = None,
                 docker_bin: str = "docker", use_docker: Optional[bool] = None):
        self.cfg = cfg
        self.runner = runner or _default_runner
        self.docker_bin = docker_bin
        self.use_docker = cfg.use_docker if use_docker is None else use_docker

    # ---- 경로 헬퍼 ----------------------------------------------------
    def profraw_dir(self, group: LogicGroup) -> Path:
        return self.cfg.coverage_dir / group.name

    def profdata_path(self, group: LogicGroup) -> Path:
        return self.cfg.coverage_dir / f"{group.name}.profdata"

    def export_path(self, group: LogicGroup) -> Path:
        return self.cfg.coverage_dir / f"{group.name}.coverage.json"

    def has_profraw(self, group: LogicGroup) -> bool:
        return bool(glob.glob(str(self.profraw_dir(group) / "*.profraw")))

    def _harness_binary_host_path(self, group: LogicGroup) -> Path:
        """llvm-cov export 심볼 소스 바이너리의 호스트 경로"""
        return harness_binary_path(group, self.cfg)

    # ---- 컨테이너 내부 도구 사용 여부 --------------------------------
    def _in_docker(self) -> bool:
        return self.use_docker and self.cfg.coverage_in_docker

    # ---- argv 구성 ----------------------------------------------------
    def build_merge_argv(self, group: LogicGroup) -> list:
        """profraw 병합용 ``llvm-profdata merge`` argv"""
        sparse = ["-sparse"] if self.cfg.coverage_merge_sparse else []
        if self._in_docker():
            g = group.name
            inner = " ".join([
                shlex.quote(self.cfg.llvm_profdata), "merge", *sparse,
                f"/out/{self.cfg.coverage_subdir}/{g}/*.profraw",
                "-o", f"/out/{self.cfg.coverage_subdir}/{g}.profdata",
            ])
            return self._docker_prefix() + ["bash", "-lc", inner]
        # 호스트: glob 결과를 명시적 파일 목록으로 전달
        raws = sorted(glob.glob(str(self.profraw_dir(group) / "*.profraw")))
        return [self.cfg.llvm_profdata, "merge", *sparse, *raws,
                "-o", str(self.profdata_path(group))]

    def build_export_argv(self, group: LogicGroup) -> list:
        """커버리지 JSON 생성용 ``llvm-cov export`` argv

        컨테이너 경로는 ``/harness`` 마운트 규약 유지, 호스트 경로만 bazel-bin 인식
        """
        sources = list(self.cfg.coverage_sources)
        if self._in_docker():
            g = group.name
            harness = f"/harness/{group.harness_path.name}"
            parts = [
                shlex.quote(self.cfg.llvm_cov), "export", "-format=text",
                f"-instr-profile=/out/{self.cfg.coverage_subdir}/{g}.profdata",
                shlex.quote(harness),
            ]
            parts += [shlex.quote(s) for s in sources]
            return self._docker_prefix() + ["bash", "-lc", " ".join(parts)]
        harness = str(self._harness_binary_host_path(group))
        argv = [self.cfg.llvm_cov, "export", "-format=text",
                f"-instr-profile={self.profdata_path(group)}", harness]
        argv += sources
        return argv

    def _docker_prefix(self) -> list:
        c = self.cfg
        return [
            self.docker_bin, "run", "--rm", "--network", "none",
            "-v", f"{c.harness_dir.resolve()}:/harness:ro",
            "-v", f"{c.output_dir.resolve()}:/out",
            c.image,
        ]

    # ---- 실행 단계 ----------------------------------------------------
    def merge(self, group: LogicGroup) -> CmdResult:
        return self.runner(self.build_merge_argv(group))

    def export(self, group: LogicGroup) -> CmdResult:
        return self.runner(self.build_export_argv(group))

    def collect(self, group: LogicGroup) -> Optional[CoverageSummary]:
        """그룹 실행 후 커버리지 수집 (미계측·NONE·도구 실패 시 예외 없이 ``None``)"""
        if CoverageMode(self.cfg.coverage) is CoverageMode.NONE:
            return None
        if not self.has_profraw(group):
            return None

        merged = self.merge(group)
        if merged.returncode != 0:
            return None
        exported = self.export(group)
        if exported.returncode != 0:
            return None

        summary = parse_llvm_cov_export(
            exported.stdout, group=group.name, mode=str(CoverageMode(self.cfg.coverage).value)
        )
        summary.profdata_path = str(self.profdata_path(group))
        # 재검증용 export 원문 보존
        try:
            self.export_path(group).parent.mkdir(parents=True, exist_ok=True)
            self.export_path(group).write_text(exported.stdout, encoding="utf-8")
            summary.export_path = str(self.export_path(group))
        except OSError:
            pass
        return summary


# ---------------------------------------------------------------------------
# 비-Bazel 경로: 커버리지 빌드 바이너리로 최종 코퍼스 재생 (GENERIC)
# ---------------------------------------------------------------------------
#
# CMake/prebuilt 대상은 퍼징 바이너리(ASan+UBSan+libFuzzer)와 커버리지 바이너리
# (같은 하네스를 ``-fprofile-instr-generate -fcoverage-mapping`` 으로 한 번 더 빌드,
# ``CMakeAdapter(coverage=True)`` 의 ``bin-cov/``)가 따로 있다. 퍼징이 끝난 뒤
# 최종 코퍼스를 커버리지 바이너리로 한 번씩 돌려 profraw 를 만들고, 그걸 병합해
# 요약한다. 퍼징 중에 profraw 를 쓰지 않으므로 퍼징 속도에 영향이 없다.
#
#   1. 재생   : LLVM_PROFILE_FILE=<dir>/%m.profraw <cov-bin> -runs=0 <corpus...>
#   2. 병합   : llvm-profdata merge -sparse <dir>/*.profraw -o <group>.profdata
#   3. 요약   : llvm-cov export -summary-only -ignore-filename-regex=<re> \
#                 -instr-profile=<group>.profdata <cov-bin>
#
# Bazel 경로(bazel_coverage_configs, bazel_fuzz_coverage_build_argv)는 건드리지 않는다.

# 하네스 자신과 퍼징 전용 소스는 대상 커버리지에서 뺀다. 하네스 파일은
# out/.../harness/ 아래에 생기고, 이름에 _fuzzer 가 붙거나 fuzz/ 디렉터리에 있다.
DEFAULT_IGNORE_FILENAME_REGEX = r"(harness|_fuzzer|/fuzz/)"

# 재생 중 크래시/누수로 프로세스가 죽으면 profraw 가 써지지 않는다. 그때는 입력을
# 하나씩 돌려 살아남은 입력의 커버리지라도 모은다. 너무 큰 코퍼스는 여기서 자른다.
_MAX_SINGLE_REPLAY_INPUTS = 5000


def replay_corpus_argv(binary: Path | str, corpus_dirs: list, *,
                       profile_file: str, asan_options: str = "detect_leaks=0") -> list:
    """커버리지 바이너리로 코퍼스를 한 번씩 실행하는 argv (``env`` 프리픽스 포함).

    ``-runs=0`` 은 libFuzzer 가 코퍼스를 읽어 각 입력을 한 번 실행하고 끝내게 한다.
    """
    return ["env", f"LLVM_PROFILE_FILE={profile_file}", f"ASAN_OPTIONS={asan_options}",
            str(binary), "-runs=0", *[str(d) for d in corpus_dirs]]


def merge_profraw_argv(profraws: list, profdata: Path | str, *,
                       llvm_profdata: str = "llvm-profdata") -> list:
    return [llvm_profdata, "merge", "-sparse", *[str(p) for p in profraws],
            "-o", str(profdata)]


def export_summary_argv(binary: Path | str, profdata: Path | str, *,
                        llvm_cov: str = "llvm-cov",
                        ignore_filename_regex: str = DEFAULT_IGNORE_FILENAME_REGEX) -> list:
    argv = [llvm_cov, "export", "-summary-only", f"-instr-profile={profdata}"]
    if ignore_filename_regex:
        argv.append(f"-ignore-filename-regex={ignore_filename_regex}")
    argv.append(str(binary))
    return argv


def _corpus_files(corpus_dirs: list) -> list:
    files: list = []
    for d in corpus_dirs:
        p = Path(d)
        if p.is_file():
            files.append(p)
        elif p.is_dir():
            files.extend(sorted(f for f in p.rglob("*") if f.is_file()))
    return files


def collect_corpus_coverage(
    binary: Path | str,
    corpus_dirs: list,
    out_dir: Path | str,
    *,
    group: str,
    runner: Optional[CommandRunner] = None,
    llvm_profdata: str = "llvm-profdata",
    llvm_cov: str = "llvm-cov",
    ignore_filename_regex: str = DEFAULT_IGNORE_FILENAME_REGEX,
) -> Optional[CoverageSummary]:
    """비-Bazel 대상: 커버리지 빌드 바이너리로 최종 코퍼스를 재생해 커버리지를 요약한다.

    Args:
        binary: ``-fprofile-instr-generate -fcoverage-mapping`` 으로 빌드한 하네스 실행 파일.
        corpus_dirs: 재생할 코퍼스 디렉터리(또는 파일) 목록. 퍼징이 끝난 최종 코퍼스.
        out_dir: ``<group>/*.profraw``, ``<group>.profdata``, ``<group>.coverage.json`` 위치.
        group: 로직 그룹 이름(파일 이름과 요약의 ``group``).
        runner: 외부 명령 실행기(테스트 주입용).
        ignore_filename_regex: llvm-cov 에서 뺄 파일 경로 정규식(기본: 하네스·퍼징 소스).

    Returns:
        :class:`CoverageSummary`. 코퍼스가 비었거나 profraw 가 하나도 안 생기거나
        도구가 실패하면 ``None`` (세션을 멈추지 않는다).
    """
    base_run = runner or _default_runner

    def run(argv: list) -> CmdResult:
        try:
            return base_run(argv)
        except OSError as exc:  # llvm 도구가 없을 때
            return CmdResult(127, "", str(exc))

    out = Path(out_dir)
    raw_dir = out / group
    raw_dir.mkdir(parents=True, exist_ok=True)
    for stale in raw_dir.glob("*.profraw"):
        stale.unlink()

    inputs = _corpus_files(corpus_dirs)
    if not inputs:
        return None

    pattern = (raw_dir / "%m.profraw").as_posix()
    run(replay_corpus_argv(binary, [str(d) for d in corpus_dirs], profile_file=pattern))
    profraws = sorted(raw_dir.glob("*.profraw"))
    if not profraws:
        # 재생 도중 죽었다(크래시 입력이 섞였거나 누수). 입력을 하나씩 돌린다.
        # %m 은 바이너리별 병합 풀이라 프로세스가 여러 번 떠도 같은 파일에 누적된다.
        for item in inputs[:_MAX_SINGLE_REPLAY_INPUTS]:
            run(replay_corpus_argv(binary, [str(item)], profile_file=pattern))
        profraws = sorted(raw_dir.glob("*.profraw"))
    if not profraws:
        return None

    profdata = out / f"{group}.profdata"
    if run(merge_profraw_argv(profraws, profdata, llvm_profdata=llvm_profdata)).returncode != 0:
        return None
    exported = run(export_summary_argv(binary, profdata, llvm_cov=llvm_cov,
                                       ignore_filename_regex=ignore_filename_regex))
    if exported.returncode != 0:
        return None

    summary = parse_llvm_cov_export(exported.stdout, group=group,
                                    mode=CoverageMode.LLVM_COV.value)
    summary.profdata_path = str(profdata)
    export_path = out / f"{group}.coverage.json"
    try:
        export_path.write_text(exported.stdout, encoding="utf-8")
        summary.export_path = str(export_path)
    except OSError:
        pass
    return summary


def write_coverage(path: Path, summary: CoverageSummary) -> None:
    """그룹 커버리지 요약 JSON 기록"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2),
                    encoding="utf-8")
