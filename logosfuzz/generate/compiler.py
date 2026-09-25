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
from typing import Callable, List, Optional

from .models import CompileResult, HarnessDraft

# link_fuzzer(하네스가 libFuzzer 링크까지 요구하는지)를 받아 "-fsanitize=..."
# 인자 목록(0개 이상)을 돌려주는 콜백.
#
# BuildAdapter(logosfuzz/generate/bazel/adapter.py)가 나온 뒤 확인한 것:
# 그 어댑터는 이 콜백을 구현하지 않는다. 그리고 그게 맞다. 두 경로의 역할이
# 다르기 때문이다.
#
#   BazelAdapter  : BUILD 룰을 쓰고 `bazel build --config=fuzz` 로 퍼저
#                   바이너리를 만든다. 새니타이저/libFuzzer 설정은 개별
#                   -fsanitize 플래그가 아니라 config(build:fuzz) 가 통째로
#                   공급하므로, 어댑터가 플래그를 돌려줄 일이 없다.
#   이 컴파일러    : 자가치유 루프가 "이 하네스 소스가 컴파일은 되는가"를
#                   빠르게 확인하는 용도다. 전체 Bazel 빌드(의존 클로저 전체
#                   재컴파일, 실측 7분대)를 매 수정마다 돌릴 수 없어서
#                   clang -c 로 짧게 끊는 경로가 따로 필요하다.
#
# 그래서 이 훅은 "Bazel 어댑터를 꽂는 자리"가 아니라, 빠른 컴파일 검증에
# 쓸 플래그를 호출부가 바꿔 끼우는 자리로 남는다(예: 대상 프로젝트가
# UBSan까지 요구하는 경우). 기본값이면 지금까지의 동작 그대로다.
SanitizeFlagsProvider = Callable[[bool], List[str]]


# C 에서 **경고에 그치지만 하네스를 실행 불가로 만드는** 진단들.
#
# 왜 필요한가 — 2단계 검증에서 하네스 두 개가 첫 입력에 SEGV 로 죽었다. 원인은
# `dlt_print_char_string` 의 실제 시그니처가 `char **text` 인데 `char *` 를
# 넘긴 것이었다. C 에서 이건 **에러가 아니라 경고**라 빌드가 "성공"하고, 파이프
# 라인은 `returncode == 0` 이고 로그에 `error:` 가 없으니 성공으로 집계한다.
#
# 즉 이 게이트가 없으면 "하네스 컴파일 성공률" 은 "링크까지 통과했다" 는 뜻이지
# "실행 가능한 하네스" 라는 뜻이 아니다. 아래 네 가지는 전부 LLM 이 생성한
# 하네스에서 흔하고, 전부 런타임에 죽거나 조용히 틀린 동작을 만든다.
#
#   incompatible-pointer-types  : char* <-> char** 등 포인터 층위 불일치
#   implicit-function-declaration: 선언 없이 호출 -> 잘못된 시그니처로 링크
#   int-conversion              : 정수를 포인터 자리에 전달
#   return-type                 : LLVMFuzzerTestOneInput 이 int 를 안 돌려줌
#
# C++ 에서는 이미 전부 에러이므로 C 컴파일에만 붙인다.
STRICT_C_WARNINGS = (
    "-Werror=incompatible-pointer-types",
    "-Werror=implicit-function-declaration",
    "-Werror=int-conversion",
    "-Werror=return-type",
)

_CPP_LANGUAGES = ("cpp", "c++", "cxx")


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
        strict_warnings: bool = True,          # 실행 불가를 만드는 C 경고를 에러로
        sanitize_flags_provider: Optional[SanitizeFlagsProvider] = None,
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
        self.strict_warnings = strict_warnings
        # None(기본값)이면 아래 _default_sanitize_flags로 지금까지의 동작을
        # 그대로 유지한다 - 기존 직접 주입 로직은 지우지 않는다. 어댑터가
        # 생기면 이 자리에 그 메서드를 넘기면 된다.
        self._sanitize_flags = sanitize_flags_provider or self._default_sanitize_flags

    def available(self) -> bool:
        return shutil.which(self.cc) is not None

    def _default_sanitize_flags(self, link_fuzzer: bool) -> List[str]:
        """지금까지의 기본 동작: self.sanitizers를 그대로 -fsanitize=로 넘긴다."""
        san = self.sanitizers
        if link_fuzzer:
            san = f"fuzzer,{san}" if san else "fuzzer"
        return [f"-fsanitize={san}"] if san else []

    def _build_argv(self, src_path: Path, out_path: Path,
                    language: str = "c") -> List[str]:
        argv = [self.cc]
        if self.std:
            argv.append(f"-std={self.std}")
        # C++ 에서는 이 진단들이 이미 에러라 붙이지 않는다(미지원 플래그 경고만 난다).
        if self.strict_warnings and language not in _CPP_LANGUAGES:
            argv += list(STRICT_C_WARNINGS)
        if not self.link_fuzzer:
            argv.append("-c")  # 컴파일만(링크 안 함)
        argv += self._sanitize_flags(self.link_fuzzer)
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
        argv = self._build_argv(src_path, out_path, draft.language)

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
