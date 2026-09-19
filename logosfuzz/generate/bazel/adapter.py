"""
GEN-03 빌드 어댑터 - Bazel 구현
================================

파이프라인의 공통 계약은 빌드 시스템이 아니라 **산출물**이다.

    어느 타깃이든 최종 산출물 =
        clang + libFuzzer + sanitizer 로 빌드된,
        LLVMFuzzerTestOneInput 을 export 하는 실행 파일 1개

그 파일만 나오면 그 아래(EXE 실행 / ANA 트리아지 / 커버리지)는 타깃이 Bazel 이든
CMake 든 동일하다. 그래서 `build()` 는 **바이너리 경로**를 돌려준다.
`bazel run` 이 아니라 `<name>_bin` 을 직접 실행하게 하려는 것이고, 1주차에
확정한 팀 결정사항 ④ 이기도 하다.
"""
from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Protocol, Sequence

from .build_file import FuzzTargetSpec, render_build_file

# 1주차에 오버레이로 추가한 config. bl-x86_64-linux(GCC) 와 절대 병용 금지 —
# 마지막 --extra_toolchains 가 이겨서 clang 이 밀려나고, GCC 에는
# -fsanitize=fuzzer 가 없어 링크에서 죽는다.
DEFAULT_FUZZ_CONFIG = "fuzz"

# 오버레이가 손대지 않은 원래 빌드가 여전히 도는지 보는 회귀 게이트.
REGRESSION_CONFIG = "bl-x86_64-linux"


@dataclass
class BuildResult:
    """빌드 1회 시도의 결과."""

    ok: bool
    target: str
    log: str = ""
    binary: Optional[Path] = None
    duration_s: float = 0.0
    command: Sequence[str] = field(default_factory=tuple)

    @property
    def short_log(self) -> str:
        lines = [ln for ln in self.log.splitlines() if ln.startswith("ERROR")]
        return "\n".join(lines[:5]) or self.log[-500:]


class BuildAdapter(Protocol):
    """빌드 시스템 1종을 감싸는 어댑터."""

    def emit_build_definition(self, spec: FuzzTargetSpec, harness_source: str) -> Path:
        """BUILD 정의와 하네스 소스를 워크스페이스에 쓴다. BUILD 파일 경로 반환."""
        ...

    def build(self, spec: FuzzTargetSpec) -> BuildResult:
        """퍼저 바이너리를 만든다."""
        ...

    def remove(self, spec: FuzzTargetSpec) -> None:
        """생성한 것을 되돌린다."""
        ...


class BazelAdapter:
    """S-CORE(baselibs) 같은 Bazel 워크스페이스용 어댑터."""

    def __init__(
        self,
        workspace_root: Path | str,
        *,
        config: str = DEFAULT_FUZZ_CONFIG,
        bazel: str = "bazel",
        extra_args: Sequence[str] = (),
        timeout_s: Optional[float] = None,
    ) -> None:
        self.workspace_root = Path(workspace_root).expanduser().resolve()
        self.config = config
        self.bazel = bazel
        self.extra_args = tuple(extra_args)
        self.timeout_s = timeout_s

    # ------------------------------------------------------------------ #
    # 생성
    # ------------------------------------------------------------------ #
    def package_dir(self, spec: FuzzTargetSpec) -> Path:
        return self.workspace_root / spec.package

    def emit_build_definition(self, spec: FuzzTargetSpec, harness_source: str) -> Path:
        pkg = self.package_dir(spec)
        pkg.mkdir(parents=True, exist_ok=True)

        if len(spec.srcs) != 1:
            raise ValueError(
                f"하네스 소스는 1개여야 한다(현재 {len(spec.srcs)}개): {spec.srcs}"
            )
        (pkg / spec.srcs[0]).write_text(harness_source, encoding="utf-8")

        build_path = pkg / "BUILD.bazel"
        build_path.write_text(render_build_file(spec), encoding="utf-8")
        return build_path

    def remove(self, spec: FuzzTargetSpec) -> None:
        pkg = self.package_dir(spec)
        if pkg.exists():
            shutil.rmtree(pkg)

    # ------------------------------------------------------------------ #
    # 빌드
    # ------------------------------------------------------------------ #
    def _run(self, args: Sequence[str]) -> tuple[int, str, str, float]:
        """(returncode, stdout, stderr, elapsed).

        stdout 과 stderr 를 분리해 둔다 — cquery 결과는 stdout 으로만 나오는데
        bazel 은 INFO/Loading 진행 표시를 stderr 로 찍는다. 합쳐서 파싱하면
        경로 목록에 진행 표시가 섞인다.
        """
        started = time.monotonic()
        proc = subprocess.run(
            list(args),
            cwd=self.workspace_root,
            capture_output=True,
            text=True,
            timeout=self.timeout_s,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or "", time.monotonic() - started

    def build(self, spec: FuzzTargetSpec) -> BuildResult:
        """`<name>_bin` 을 빌드한다.

        cc_fuzz_test 가 만드는 타깃 중 `_bin` 이 계측된 퍼저 바이너리이고,
        EXE 계층이 직접 실행할 대상이다(`_run` 은 bazel run 전용 런처라
        libFuzzer 인자를 그대로 못 넘긴다 - 1주차 실측).
        """
        target = spec.bin_label
        cmd = [self.bazel, "build", f"--config={self.config}", *self.extra_args, target]
        try:
            code, out, err, elapsed = self._run(cmd)
            log = out + err
        except subprocess.TimeoutExpired as exc:
            return BuildResult(
                ok=False,
                target=target,
                log=f"빌드 타임아웃({self.timeout_s}s): {exc}",
                command=cmd,
            )
        except FileNotFoundError:
            return BuildResult(
                ok=False,
                target=target,
                log=f"bazel 실행 파일을 찾을 수 없다: {self.bazel}",
                command=cmd,
            )

        binary = self._binary_path(spec) if code == 0 else None
        return BuildResult(
            ok=code == 0,
            target=target,
            log=log,
            binary=binary,
            duration_s=elapsed,
            command=cmd,
        )

    def _binary_path(self, spec: FuzzTargetSpec) -> Optional[Path]:
        """설정에 고정된 퍼저 바이너리 경로를 돌려준다.

        `bazel-bin` 은 **직전 빌드 설정**을 가리키는 편의 심링크다. 다른 config
        로 빌드가 한 번만 돌아도 이 경로가 무효가 된다 — 회귀 게이트
        (--config=bl-x86_64-linux) 를 돌린 직후 퍼저 바이너리가 사라진 것처럼
        보이는 현상을 실측으로 확인했다. --platform_suffix=fuzz 로 출력 트리를
        분리해 둔 터라 더 잘 어긋난다.

        EXE 계층이 이 경로를 받아 퍼저를 직접 실행하므로, 심링크 추측이 아니라
        cquery 로 설정에 맞는 실제 경로를 질의한다. 질의가 안 되는 환경에서는
        기존 방식으로 폴백한다.
        """
        expected_name = f"{spec.name}_bin"
        cmd = [
            self.bazel,
            "cquery",
            f"--config={self.config}",
            "--output=files",
            spec.bin_label,
        ]
        try:
            code, out, _err, _elapsed = self._run(cmd)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            code, out = 1, ""

        if code == 0:
            candidates = []
            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                path = Path(line)
                if not path.is_absolute():
                    path = self.workspace_root / path
                if path.exists():
                    candidates.append(path)
            for path in candidates:
                if path.name == expected_name:
                    return path
            if candidates:
                return candidates[0]

        fallback = self.workspace_root / "bazel-bin" / spec.package / expected_name
        return fallback if fallback.exists() else None

    # ------------------------------------------------------------------ #
    # 회귀 게이트
    # ------------------------------------------------------------------ #
    def regression_build(self, target: str) -> BuildResult:
        """오버레이가 기존 GCC 빌드를 깨지 않았는지 확인한다.

        퍼징 타깃에 tags=["manual"] 을 붙여 두었으므로 //... 전체 빌드에
        딸려 들어가지 않아야 정상이다.
        """
        cmd = [self.bazel, "build", f"--config={REGRESSION_CONFIG}", target]
        code, out, err, elapsed = self._run(cmd)
        return BuildResult(
            ok=code == 0, target=target, log=out + err, duration_s=elapsed, command=cmd
        )
