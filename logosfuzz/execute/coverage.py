"""EXE-04-04: Coverage Instrumentation (llvm-cov / SanitizerCoverage 연동).

퍼징이 "얼마나 많이 실행됐는가"(exec/s)를 넘어 "코드의 어디까지 도달했는가"를
정밀하게 측정한다. EXE-04-01(격리 실행)이 남긴 계측 산출물(``*.profraw``)을
후처리하여 함수/라인/리전/브랜치 커버리지 요약을 만들고, 세션 요약과
SCH-02-03(미탐색 경로 가중치) 단계가 소비할 수 있는 형태로 보존한다.

설계 개요
--------
1. **계측(빌드 시)** — 하네스를 커버리지 플래그로 컴파일한다. 이 빌드는 GEN/빌드
   규약의 책임이며, 본 모듈은 :func:`instrumentation_flags` 로 그 계약(플래그)만
   고정한다.
     * ``llvm-cov`` (소스 기반)   : ``-fprofile-instr-generate -fcoverage-mapping``
     * SanitizerCoverage(엣지)    : ``-fsanitize-coverage=trace-pc-guard``
2. **수집(실행 시)** — 실행 프로세스에 ``LLVM_PROFILE_FILE`` 환경변수를 주입해
   각 그룹의 ``*.profraw`` 를 ``/out/coverage/<group>/`` 로 떨군다. 환경변수
   주입은 :class:`~logosfuzz.execute.docker_runner.DockerIsolationRunner` 가 담당하며
   본 모듈은 :func:`profile_env` 로 그 값을 계산한다.
3. **후처리(실행 후)** — ``llvm-profdata merge`` → ``llvm-cov export`` 로 커버리지
   JSON을 얻고, 그 ``totals`` 를 :class:`CoverageSummary` 로 정규화한다.

의존성 최소화 원칙(프로젝트 공통)에 따라 표준 라이브러리만 사용하고, 외부
프로세스 실행은 ``runner`` 콜러블로 주입할 수 있어 실제 llvm 도구 없이도 단위
테스트가 가능하다(``docker_runner`` 의 ``executor`` 주입 패턴과 동일).
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
# 계측 플래그 계약 (GEN/빌드 규약이 지켜야 하는 컴파일 옵션)
# ---------------------------------------------------------------------------

_INSTRUMENTATION_FLAGS = {
    # clang 소스 기반 커버리지: 함수/라인/리전/브랜치 매핑을 심볼에 포함한다.
    CoverageMode.LLVM_COV: ("-fprofile-instr-generate", "-fcoverage-mapping"),
    # SanitizerCoverage: 엣지(제어흐름) 단위 계측. libFuzzer는 자동 링크되지만
    # 독립 하네스는 아래 플래그가 필요하다.
    CoverageMode.SANITIZER_COV: ("-fsanitize-coverage=trace-pc-guard",),
    CoverageMode.NONE: (),
}


def instrumentation_flags(mode: CoverageMode) -> tuple[str, ...]:
    """지정한 커버리지 모드에 필요한 clang 컴파일 플래그를 돌려준다.

    GEN 단계/빌드 스크립트가 하네스를 이 플래그로 빌드해야 실행 시 커버리지가
    수집된다. 계측되지 않은 바이너리는 ``*.profraw`` 를 생성하지 않으므로
    :meth:`CoverageCollector.collect` 가 ``None`` 을 반환한다.
    """
    return _INSTRUMENTATION_FLAGS.get(CoverageMode(mode), ())


# ---------------------------------------------------------------------------
# 실행 시 환경변수 (LLVM_PROFILE_FILE) 계산
# ---------------------------------------------------------------------------


def profile_env(group: LogicGroup, cfg: FuzzConfig, *, in_docker: bool) -> dict:
    """그룹 실행에 주입할 커버리지 환경변수 map을 만든다.

    ``LLVM_PROFILE_FILE`` 의 ``%m`` 패턴은 clang 프로파일 런타임의 "온라인 병합"
    모드로, 같은 그룹을 여러 프로세스(AFL++ fork 모델 등)로 실행해도 profraw가
    안전하게 병합되도록 한다. 컨테이너 경로(``/out``)와 호스트 경로를 구분한다.
    """
    if CoverageMode(cfg.coverage) is CoverageMode.NONE:
        return {}
    if in_docker:
        base = f"/out/{cfg.coverage_subdir}/{group.name}"
    else:
        base = (cfg.coverage_dir / group.name).as_posix()
    # %m: 프로세스별 온라인 병합 풀. libFuzzer(단일 프로세스)·AFL++(다중 프로세스)
    # 모두에서 profraw 충돌 없이 수집된다.
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
        """llvm-cov export ``summary`` 하위 노드에서 covered/count를 읽는다."""
        return cls(covered=int(node.get("covered", 0)),
                   count=int(node.get("count", 0)))

    def to_dict(self) -> dict:
        return {"covered": self.covered, "count": self.count, "percent": self.percent}


@dataclass
class FileCoverage:
    """소스 파일 1개의 라인 커버리지(요약용, 상세는 export 원문에 보존)."""

    filename: str
    lines: CoverageMetric = field(default_factory=CoverageMetric)

    def to_dict(self) -> dict:
        return {"filename": self.filename, "lines": self.lines.to_dict()}


@dataclass
class CoverageSummary:
    """그룹 1개의 정규화된 커버리지 요약(ANA/SCH 소비용)."""

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
# llvm-cov export JSON 파서 (순수 함수 — 단위 테스트 대상)
# ---------------------------------------------------------------------------


def parse_llvm_cov_export(export_json: str, *, group: str, mode: str,
                          include_files: bool = True) -> CoverageSummary:
    """``llvm-cov export -format=text`` 출력(JSON)을 :class:`CoverageSummary` 로 정규화.

    llvm-cov export는 ``data[0].totals`` 에 프로그램 전체 합계를, ``data[0].files``
    에 파일별 요약을 담는다. 합계를 우선 사용하고, 파일 목록은 요약용으로 라인
    커버리지만 뽑아 둔다(리전/브랜치 상세는 export 원문 파일에 보존).
    """
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
# 외부 명령 실행 추상화 (테스트 주입 가능)
# ---------------------------------------------------------------------------


@dataclass
class CmdResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


CommandRunner = Callable[[list], CmdResult]


def _default_runner(argv: list) -> CmdResult:
    """subprocess 기반 기본 실행기(표준출력을 문자열로 캡처)."""
    proc = subprocess.run(argv, capture_output=True, text=True)
    return CmdResult(proc.returncode, proc.stdout, proc.stderr)


# ---------------------------------------------------------------------------
# 커버리지 수집 오케스트레이터
# ---------------------------------------------------------------------------


class CoverageCollector:
    """profraw → profdata → llvm-cov export → :class:`CoverageSummary` 파이프라인.

    실제 llvm 도구 실행은 ``runner`` 콜러블로 주입해 테스트에서 대체할 수 있다.
    ``use_docker`` 이고 ``cfg.coverage_in_docker`` 이면 이미지 안의 llvm 도구를
    ``/out`` 마운트에 대해 실행하고, 아니면 호스트의 llvm 도구를 사용한다.
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

    # ---- 컨테이너 내부에서 도구를 돌릴지 여부 ------------------------
    def _in_docker(self) -> bool:
        return self.use_docker and self.cfg.coverage_in_docker

    # ---- argv 구성 ----------------------------------------------------
    def build_merge_argv(self, group: LogicGroup) -> list:
        """``llvm-profdata merge`` argv. profraw들을 하나의 profdata로 병합."""
        sparse = ["-sparse"] if self.cfg.coverage_merge_sparse else []
        if self._in_docker():
            g = group.name
            inner = " ".join([
                shlex.quote(self.cfg.llvm_profdata), "merge", *sparse,
                f"/out/{self.cfg.coverage_subdir}/{g}/*.profraw",
                "-o", f"/out/{self.cfg.coverage_subdir}/{g}.profdata",
            ])
            return self._docker_prefix() + ["bash", "-lc", inner]
        # 호스트: 파이썬에서 glob을 펼쳐 명시적 파일 목록을 넘긴다.
        raws = sorted(glob.glob(str(self.profraw_dir(group) / "*.profraw")))
        return [self.cfg.llvm_profdata, "merge", *sparse, *raws,
                "-o", str(self.profdata_path(group))]

    def build_export_argv(self, group: LogicGroup) -> list:
        """``llvm-cov export`` argv. profdata + 하네스 바이너리로 커버리지 JSON 생성."""
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
        harness = str((self.cfg.harness_dir / group.harness_path.name).resolve())
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
        """그룹 실행 후 커버리지를 수집한다.

        계측되지 않았거나(profraw 없음) 모드가 NONE이면 ``None`` 을 반환해
        호출부가 조용히 건너뛸 수 있게 한다. 도구 실행이 실패하면 그 사실을
        요약 없이 ``None`` 으로 알리되, 예외로 세션을 중단시키지 않는다.
        """
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
        # export 원문(리전/브랜치 상세 포함)을 보존해 이후 단계가 재검증 가능.
        try:
            self.export_path(group).parent.mkdir(parents=True, exist_ok=True)
            self.export_path(group).write_text(exported.stdout, encoding="utf-8")
            summary.export_path = str(self.export_path(group))
        except OSError:
            pass
        return summary


def write_coverage(path: Path, summary: CoverageSummary) -> None:
    """그룹 커버리지 요약을 JSON으로 기록(ANA/리포트 소비용)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2),
                    encoding="utf-8")
