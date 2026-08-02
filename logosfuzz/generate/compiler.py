"""
GEN-03 하네스 생성 - 컴파일러 추상화
====================================

자가 치유 루프가 사용하는 컴파일 백엔드.

- Compiler          : 인터페이스
- SubprocessCompiler: clang/gcc를 subprocess로 호출하는 실제 구현(컴파일 검증용 -c 기본)
- FakeCompiler      : 테스트/데모용. 소스에 특정 마커가 있으면 성공/실패를 흉내냄
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional

from .models import CompileResult, HarnessDraft


class Compiler(ABC):
    """하네스 소스를 컴파일하고 결과를 반환하는 인터페이스."""

    @abstractmethod
    def compile(self, draft: HarnessDraft, source: Optional[str] = None) -> CompileResult:
        """source가 주어지면 그 소스를, 아니면 draft.source를 컴파일한다."""
        raise NotImplementedError


class SubprocessCompiler(Compiler):
    """
    실제 컴파일러(clang/gcc)를 호출한다.

    기본은 `-c`(오브젝트만 생성)로 '컴파일 가능 여부'만 검증한다.
    libFuzzer 링크까지 하려면 link=True 및 fuzzer_flags를 지정.
    """

    def __init__(
        self,
        cc: str = "clang",
        *,
        std: Optional[str] = None,             # 예: "c11", "c++17"
        include_dirs: Optional[List[str]] = None,
        defines: Optional[List[str]] = None,
        extra_flags: Optional[List[str]] = None,
        sanitizers: str = "address",           # ASAN 기본
        link_fuzzer: bool = False,             # True면 -fsanitize=fuzzer 링크
        timeout_sec: int = 120,
        workdir: Optional[str] = None,
    ) -> None:
        self.cc = cc
        self.std = std
        self.include_dirs = include_dirs or []
        self.defines = defines or []
        self.extra_flags = extra_flags or []
        self.sanitizers = sanitizers
        self.link_fuzzer = link_fuzzer
        self.timeout_sec = timeout_sec
        self.workdir = workdir

    def available(self) -> bool:
        return shutil.which(self.cc) is not None

    def _build_argv(self, src_path: Path, out_path: Path) -> List[str]:
        argv = [self.cc]
        if self.std:
            argv.append(f"-std={self.std}")
        san = self.sanitizers
        if self.link_fuzzer:
            san = f"fuzzer,{san}" if san else "fuzzer"
        else:
            argv.append("-c")  # 컴파일만(링크 안 함)
        if san:
            argv.append(f"-fsanitize={san}")
        argv += [f"-I{d}" for d in self.include_dirs]
        argv += [f"-D{d}" for d in self.defines]
        argv += self.extra_flags
        argv += [str(src_path), "-o", str(out_path)]
        return argv

    def compile(self, draft: HarnessDraft, source: Optional[str] = None) -> CompileResult:
        code = source if source is not None else draft.source
        suffix = ".cpp" if draft.language in ("cpp", "c++", "cxx") else ".c"
        if not self.available():
            return CompileResult(
                ok=False, returncode=127,
                stderr=f"컴파일러를 찾을 수 없음: {self.cc} (PATH 확인 필요)",
            )
        base = Path(self.workdir) if self.workdir else Path(tempfile.mkdtemp(prefix="logosfuzz_gen_"))
        base.mkdir(parents=True, exist_ok=True)
        src_path = base / f"{draft.logic_group}{suffix}"
        out_path = base / f"{draft.logic_group}.out"
        src_path.write_text(code, encoding="utf-8")
        argv = self._build_argv(src_path, out_path)

        start = time.monotonic()
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=self.timeout_sec
            )
            dur = time.monotonic() - start
            return CompileResult(
                ok=(proc.returncode == 0),
                returncode=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                artifact_path=str(out_path) if proc.returncode == 0 else None,
                duration_sec=dur,
            )
        except subprocess.TimeoutExpired as e:
            return CompileResult(
                ok=False, returncode=124,
                stderr=f"컴파일 타임아웃({self.timeout_sec}s): {e}",
                duration_sec=time.monotonic() - start,
            )
        except OSError as e:
            return CompileResult(ok=False, returncode=1, stderr=f"컴파일 실행 오류: {e}")


class FakeCompiler(Compiler):
    """
    테스트/데모용 가짜 컴파일러.

    규칙:
      - 소스에 `success_marker`(기본 "// COMPILE_OK")가 포함되면 성공.
      - 아니면 `error_template`을 렌더링한 실패 로그를 반환.
    이렇게 하면 LLM 스텁이 마커를 추가하는 것으로 '수정'을 흉내낼 수 있다.
    """

    def __init__(
        self,
        success_marker: str = "// COMPILE_OK",
        error_template: str = "{group}.c:{line}: error: {msg}",
        error_message: str = "expected ';' before '}' token",
        error_line: int = 42,
    ) -> None:
        self.success_marker = success_marker
        self.error_template = error_template
        self.error_message = error_message
        self.error_line = error_line

    def compile(self, draft: HarnessDraft, source: Optional[str] = None) -> CompileResult:
        code = source if source is not None else draft.source
        if self.success_marker in code:
            return CompileResult(ok=True, returncode=0, stdout="", duration_sec=0.001,
                                 artifact_path=f"/tmp/{draft.logic_group}.o")
        log = self.error_template.format(
            group=draft.logic_group, line=self.error_line, msg=self.error_message
        )
        return CompileResult(ok=False, returncode=1, stderr=log, duration_sec=0.001)
