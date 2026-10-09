"""CMake 가 생성한 ``compile_commands.json`` 에서 파싱용 플래그를 뽑는다.

비-Bazel(cmake/prebuilt) 대상에서 ast_analyzer·constraint_extractor 가 호스트
clang/libclang 으로 소스를 파싱하려면 파일별 ``-I``/``-isystem``/``-D``/``-std``
가 필요하다. 이 모듈은 그 값을 빌드 시스템이 직접 남긴 산출물에서 읽는다.

bear 폐기 결정(README "빌드 정보 수급: bear → Bazel")과의 관계:
    이 모듈은 컴파일러 호출을 **가로채지 않는다**. ``bear`` 처럼 빌드를 감싸서
    명령을 기록하는 대신, CMake 가 ``-DCMAKE_EXPORT_COMPILE_COMMANDS=ON`` 으로
    스스로 생성한 ``compile_commands.json`` 만 읽는다. 빌드 정보의 정답은 여전히
    빌드 시스템이 소유하며(Bazel 대상은 계속 ``bazel_query``), 이 파일은 그
    빌드 시스템의 공식 산출물이다.

크로스컴파일(임베디드) 대상은 ``-mcpu=*``, ``-mthumb``, ``--specs=*`` 같은
타깃 전용 플래그 때문에 호스트 clang 이 파싱을 거부한다. 프로필의
``embedded.strip_flags`` (glob) 에 걸리는 토큰은 추출 전에 제거한다.

Example::

    python -m logosfuzz.extract.compile_db --profile targets/libsndfile.json
    python -m logosfuzz.extract.compile_db \
        --compile-db third_party/libsndfile/build-fuzz/compile_commands.json \
        --strip-flag='-mcpu=*' --merged
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import shlex
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Dict, Iterable, List, Optional, Sequence

if TYPE_CHECKING:  # pragma: no cover
    from logosfuzz.common.target_profile import TargetProfile


class CompileDbError(RuntimeError):
    """compile_commands.json 이 없거나 형식이 맞지 않을 때."""


@dataclass(frozen=True)
class CompileEntry:
    """compile_commands.json 의 항목 1개(인자는 토큰 배열로 정규화)."""

    file: str
    directory: str
    arguments: tuple


@dataclass
class CompileFlags:
    """호스트 clang 파싱에 필요한 플래그만 추린 결과.

    include 경로는 모두 절대경로이며, 순서는 원래 명령 순서를 유지한다
    (같은 값이 반복되면 처음 것만 남긴다).
    """

    include_dirs: List[str] = field(default_factory=list)
    system_include_dirs: List[str] = field(default_factory=list)
    defines: List[str] = field(default_factory=list)
    std: str = ""

    def clang_args(self) -> List[str]:
        """libclang ``parse(args=...)`` 에 그대로 넘길 인자 목록."""
        args: List[str] = [f"-I{d}" for d in self.include_dirs]
        for d in self.system_include_dirs:
            args.extend(["-isystem", d])
        args.extend(f"-D{d}" for d in self.defines)
        if self.std:
            args.append(f"-std={self.std}")
        return args

    def merge(self, other: "CompileFlags") -> None:
        _extend_unique(self.include_dirs, other.include_dirs)
        _extend_unique(self.system_include_dirs, other.system_include_dirs)
        _extend_unique(self.defines, other.defines)
        if not self.std:
            self.std = other.std

    def to_dict(self) -> dict:
        data = asdict(self)
        data["clang_args"] = self.clang_args()
        return data


def _extend_unique(dst: List[str], values: Iterable[str]) -> None:
    for value in values:
        if value not in dst:
            dst.append(value)


# ---------------------------------------------------------------------
# 로드
# ---------------------------------------------------------------------

def _split_command(command: str) -> List[str]:
    # CMake(Ninja/Makefile)는 POSIX 셸 인용으로 command 를 쓴다.
    return shlex.split(command, posix=True)


def load_compile_db(path) -> List[CompileEntry]:
    """compile_commands.json 을 읽어 :class:`CompileEntry` 목록으로.

    ``arguments`` 배열과 ``command`` 문자열 형식을 모두 받는다.
    ``file`` 이 상대경로면 ``directory`` 기준으로 절대화한다.
    """
    p = Path(path)
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CompileDbError(f"compile_commands.json 을 읽을 수 없다: {p} ({exc})") from exc
    except json.JSONDecodeError as exc:
        raise CompileDbError(f"compile_commands.json 파싱 실패: {p} ({exc})") from exc
    if not isinstance(raw, list):
        raise CompileDbError(f"{p}: 최상위는 배열이어야 한다")

    entries: List[CompileEntry] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict) or "file" not in item or "directory" not in item:
            raise CompileDbError(f"{p}[{index}]: file/directory 가 없는 항목")
        if isinstance(item.get("arguments"), list):
            args = [str(a) for a in item["arguments"]]
        elif isinstance(item.get("command"), str):
            args = _split_command(item["command"])
        else:
            raise CompileDbError(f"{p}[{index}]: arguments 또는 command 가 필요하다")
        directory = str(item["directory"])
        file_path = Path(item["file"])
        if not file_path.is_absolute():
            file_path = Path(directory) / file_path
        entries.append(CompileEntry(
            file=os.path.normpath(str(file_path)),
            directory=directory,
            arguments=tuple(args),
        ))
    return entries


# ---------------------------------------------------------------------
# 플래그 추출
# ---------------------------------------------------------------------

def strip_args(args: Sequence[str], patterns: Sequence[str]) -> List[str]:
    """glob 패턴(대소문자 구분)에 걸리는 토큰을 제거한다."""
    if not patterns:
        return list(args)
    return [a for a in args if not any(fnmatch.fnmatchcase(a, pat) for pat in patterns)]


def _abs_dir(value: str, directory: str) -> str:
    if os.path.isabs(value):
        return os.path.normpath(value)
    return os.path.normpath(os.path.join(directory, value))


def extract_flags(args: Sequence[str], directory: str, strip_flags: Sequence[str] = ()) -> CompileFlags:
    """컴파일러 인자 토큰에서 -I/-isystem/-D/-std 만 추린다.

    ``-I dir``/``-Idir``, ``-isystem dir``/``-isystemdir``, ``-D X``/``-DX``,
    ``-std=...`` 를 지원한다. 상대 include 경로는 ``directory`` 기준 절대화.
    첫 토큰(컴파일러 경로)과 그 밖의 플래그는 무시한다.
    """
    tokens = strip_args(list(args)[1:], strip_flags)
    flags = CompileFlags()
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        nxt = tokens[i + 1] if i + 1 < len(tokens) else None
        if tok == "-I" and nxt is not None:
            _extend_unique(flags.include_dirs, [_abs_dir(nxt, directory)])
            i += 2
            continue
        if tok.startswith("-I") and len(tok) > 2:
            _extend_unique(flags.include_dirs, [_abs_dir(tok[2:], directory)])
        elif tok == "-isystem" and nxt is not None:
            _extend_unique(flags.system_include_dirs, [_abs_dir(nxt, directory)])
            i += 2
            continue
        elif tok.startswith("-isystem") and len(tok) > len("-isystem"):
            _extend_unique(flags.system_include_dirs, [_abs_dir(tok[len("-isystem"):], directory)])
        elif tok == "-D" and nxt is not None:
            _extend_unique(flags.defines, [nxt])
            i += 2
            continue
        elif tok.startswith("-D") and len(tok) > 2:
            _extend_unique(flags.defines, [tok[2:]])
        elif tok.startswith("-std="):
            # 여러 번 나오면 컴파일러처럼 마지막 값이 이긴다.
            flags.std = tok[len("-std="):]
        i += 1
    return flags


def flags_by_file(path, strip_flags: Sequence[str] = ()) -> Dict[str, CompileFlags]:
    """소스 파일(절대경로) → :class:`CompileFlags`.

    같은 파일이 여러 번 나오면(다중 구성) 플래그를 합친다.
    """
    result: Dict[str, CompileFlags] = {}
    for entry in load_compile_db(path):
        flags = extract_flags(entry.arguments, entry.directory, strip_flags)
        if entry.file in result:
            result[entry.file].merge(flags)
        else:
            result[entry.file] = flags
    return result


def merged_flags(path, strip_flags: Sequence[str] = ()) -> CompileFlags:
    """프로젝트 전체 플래그의 합집합(헤더처럼 항목이 없는 파일 파싱용)."""
    merged = CompileFlags()
    for flags in flags_by_file(path, strip_flags).values():
        merged.merge(flags)
    return merged


def compile_db_path(profile: "TargetProfile") -> Path:
    """프로필의 ``build.compile_commands`` 절대경로. 지정이 없으면 CompileDbError."""
    if not profile.build.compile_commands:
        raise CompileDbError(f"{profile.name}: build.compile_commands 가 지정되지 않았다")
    return profile.abs(profile.build.compile_commands)


def flags_for_profile(profile: "TargetProfile") -> Dict[str, CompileFlags]:
    """프로필의 compile_commands.json 을 strip_flags 를 적용해 읽는다."""
    return flags_by_file(compile_db_path(profile), profile.embedded.strip_flags)


def merged_flags_for_profile(profile: "TargetProfile") -> CompileFlags:
    return merged_flags(compile_db_path(profile), profile.embedded.strip_flags)


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="compile_commands.json 플래그 추출")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--profile", help="targets/*.json (compile_commands·strip_flags 사용)")
    src.add_argument("--compile-db", help="compile_commands.json 경로")
    parser.add_argument("--strip-flag", action="append", default=[],
                        help="--compile-db 와 함께: 제거할 플래그 glob (반복 가능, '--strip-flag=-mcpu=*' 형식)")
    parser.add_argument("--merged", action="store_true", help="파일별 대신 전체 합집합만 출력")
    parser.add_argument("--output", help="결과 JSON 경로 (기본: stdout)")
    args = parser.parse_args(argv)

    try:
        if args.profile:
            from logosfuzz.common.target_profile import ProfileError, load_profile
            try:
                profile = load_profile(args.profile)
            except ProfileError as exc:
                print(f"[ERROR] {exc}", file=sys.stderr)
                return 1
            db, strip = compile_db_path(profile), profile.embedded.strip_flags
        else:
            db, strip = Path(args.compile_db), tuple(args.strip_flag)
        if args.merged:
            data = merged_flags(db, strip).to_dict()
        else:
            data = {f: fl.to_dict() for f, fl in sorted(flags_by_file(db, strip).items())}
    except CompileDbError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    text = json.dumps(data, indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
