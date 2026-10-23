"""퍼징 대상 프로필(TargetProfile) 계약

대상별 빌드·API·에러계약 정보를 ``targets/*.json`` 한 파일로 통합
EXT/KB, GEN 빌드 어댑터, EXE, ANA 공용 (:func:`load_profile`), 필드 변경 시 네 파트 동시 반영 필요

스키마 요약::

    {
      "name": "libsndfile", "version": "1.2.2",
      "language": "c" | "cpp",
      "domain": "generic" | "embedded" | "automotive",
      "build": {
        "system": "bazel" | "cmake" | "prebuilt",
        "source_root": "third_party/libsndfile",
        "build_dir": "build-fuzz",
        "configure_args": [...], "libraries": [...],
        "include_dirs": [...], "link_flags": [...],
        "compile_commands": "build-fuzz/compile_commands.json",
        "bazel": {"workspace": ".", "target": "//pkg:lib"} | null
      },
      "apis": [...],
      "error_contract": "none" | "c_return_code" | "score_result",
      "embedded": {"strip_flags": [...], "stub_undefined": false, "stub_allowlist": [...]},
      "seeds": [...]
    }

경로 규칙:
    * ``build.source_root`` 상대경로는 ``load_profile(path, base_dir=...)`` 의
      ``base_dir``(기본: 현재 작업 디렉터리 = 저장소 루트) 기준 해석
    * 나머지 ``build.*`` 경로(build_dir, libraries, include_dirs, compile_commands,
      bazel.workspace)와 ``seeds`` 는 source_root 기준 상대경로,
      :meth:`TargetProfile.abs` 로 절대경로 획득

``_`` 로 시작하는 키는 주석으로 무시, 그 밖의 미지 키는 :class:`ProfileError`
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional, Tuple, Union

LANGUAGES = ("c", "cpp")
DOMAINS = ("generic", "embedded", "automotive")
BUILD_SYSTEMS = ("bazel", "cmake", "prebuilt")
ERROR_CONTRACTS = ("none", "c_return_code", "score_result")

_TOP_KEYS = {
    "name", "version", "language", "domain", "build", "apis",
    "error_contract", "embedded", "seeds",
}
_BUILD_KEYS = {
    "system", "source_root", "build_dir", "configure_args", "libraries",
    "include_dirs", "link_flags", "compile_commands", "bazel",
}
_BAZEL_KEYS = {"workspace", "target"}
_EMBEDDED_KEYS = {"strip_flags", "stub_undefined", "stub_allowlist"}

PathLike = Union[str, "os.PathLike[str]"]


class ProfileError(ValueError):
    """프로필 JSON 부재·손상·스키마 위반 시 발생"""


@dataclass(frozen=True)
class BazelSpec:
    """``build.system == "bazel"`` 일 때만 존재하는 Bazel 위치 정보"""

    workspace: str
    target: str


@dataclass(frozen=True)
class BuildSpec:
    """대상 라이브러리 빌드·링크 방식"""

    system: str
    source_root: str
    build_dir: str = ""
    configure_args: Tuple[str, ...] = ()
    libraries: Tuple[str, ...] = ()
    include_dirs: Tuple[str, ...] = ()
    link_flags: Tuple[str, ...] = ()
    compile_commands: str = ""
    bazel: Optional[BazelSpec] = None


@dataclass(frozen=True)
class EmbeddedSpec:
    """크로스컴파일 대상의 호스트 분석·퍼징 설정

    Attributes:
        strip_flags: 호스트 clang 전달 전 제거할 플래그 glob
            (예: ``-mcpu=*``, ``-mthumb``, ``--specs=*``)
        stub_undefined: 링크 시 미정의 심볼 스텁 자동 생성 여부
        stub_allowlist: 스텁 생성 허용 심볼 glob (비어 있으면 제한 없음)
    """

    strip_flags: Tuple[str, ...] = ()
    stub_undefined: bool = False
    stub_allowlist: Tuple[str, ...] = ()


@dataclass(frozen=True)
class TargetProfile:
    """``targets/*.json`` 하나를 검증해 고정한 값 객체"""

    name: str
    language: str
    domain: str
    build: BuildSpec
    error_contract: str
    version: str = ""
    apis: Tuple[str, ...] = ()
    embedded: EmbeddedSpec = field(default_factory=EmbeddedSpec)
    seeds: Tuple[str, ...] = ()
    # source_root 해석 절대경로 (abs() 기준점)
    root: Path = field(default=Path("."), compare=False)
    # 프로필 파일 경로 (로그/리포트용, 직접 생성 시 None)
    path: Optional[Path] = field(default=None, compare=False)

    @property
    def is_bazel(self) -> bool:
        return self.build.system == "bazel"

    @property
    def is_automotive(self) -> bool:
        return self.domain == "automotive"

    def abs(self, path: PathLike) -> Path:
        """source_root 기준 상대경로의 절대경로 변환 (절대경로는 그대로)"""
        p = Path(path)
        if p.is_absolute():
            return p
        return (self.root / p).resolve()

    def to_dict(self) -> dict:
        """JSON 재기록 가능한 원래 스키마 형태"""
        build = self.build
        return {
            "name": self.name,
            "version": self.version,
            "language": self.language,
            "domain": self.domain,
            "build": {
                "system": build.system,
                "source_root": build.source_root,
                "build_dir": build.build_dir,
                "configure_args": list(build.configure_args),
                "libraries": list(build.libraries),
                "include_dirs": list(build.include_dirs),
                "link_flags": list(build.link_flags),
                "compile_commands": build.compile_commands,
                "bazel": (
                    {"workspace": build.bazel.workspace, "target": build.bazel.target}
                    if build.bazel else None
                ),
            },
            "apis": list(self.apis),
            "error_contract": self.error_contract,
            "embedded": {
                "strip_flags": list(self.embedded.strip_flags),
                "stub_undefined": self.embedded.stub_undefined,
                "stub_allowlist": list(self.embedded.stub_allowlist),
            },
            "seeds": list(self.seeds),
        }


# ---------------------------------------------------------------------
# 검증 헬퍼
# ---------------------------------------------------------------------

def _check_keys(data: Mapping[str, Any], allowed: set, where: str) -> None:
    unknown = sorted(k for k in data if k not in allowed and not str(k).startswith("_"))
    if unknown:
        raise ProfileError(f"{where}: 알 수 없는 키 {unknown} (허용: {sorted(allowed)})")


def _require_str(data: Mapping[str, Any], key: str, where: str) -> str:
    if key not in data:
        raise ProfileError(f"{where}.{key} 가 없다")
    value = data[key]
    if not isinstance(value, str) or not value.strip():
        raise ProfileError(f"{where}.{key} 는 비어 있지 않은 문자열이어야 한다 (got {value!r})")
    return value


def _opt_str(data: Mapping[str, Any], key: str, where: str) -> str:
    value = data.get(key)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ProfileError(f"{where}.{key} 는 문자열이어야 한다 (got {value!r})")
    return value


def _enum(data: Mapping[str, Any], key: str, choices: Tuple[str, ...], where: str) -> str:
    value = _require_str(data, key, where)
    if value not in choices:
        raise ProfileError(f"{where}.{key}={value!r} 는 허용값 {list(choices)} 중 하나여야 한다")
    return value


def _str_list(
    data: Mapping[str, Any], key: str, where: str, *, allow_single: bool = False
) -> Tuple[str, ...]:
    value = data.get(key)
    if value is None:
        return ()
    if allow_single and isinstance(value, str):
        # seeds 처럼 디렉터리 하나만 적는 경우 허용
        return (value,)
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ProfileError(f"{where}.{key} 는 문자열 배열이어야 한다 (got {value!r})")
    return tuple(value)


def _mapping(data: Mapping[str, Any], key: str, where: str, *, required: bool) -> Optional[Mapping[str, Any]]:
    value = data.get(key)
    if value is None:
        if required:
            raise ProfileError(f"{where}.{key} 가 없다")
        return None
    if not isinstance(value, dict):
        raise ProfileError(f"{where}.{key} 는 객체여야 한다 (got {type(value).__name__})")
    return value


def _parse_build(data: Mapping[str, Any]) -> BuildSpec:
    where = "build"
    _check_keys(data, _BUILD_KEYS, where)
    system = _enum(data, "system", BUILD_SYSTEMS, where)

    bazel_raw = _mapping(data, "bazel", where, required=False)
    bazel: Optional[BazelSpec] = None
    if system == "bazel":
        if bazel_raw is None:
            raise ProfileError("build.system=bazel 이면 build.bazel{workspace,target} 이 필요하다")
        _check_keys(bazel_raw, _BAZEL_KEYS, "build.bazel")
        target = _require_str(bazel_raw, "target", "build.bazel")
        if not target.startswith(("//", "@")):
            raise ProfileError(f"build.bazel.target={target!r} 는 Bazel 라벨(// 또는 @)이어야 한다")
        bazel = BazelSpec(
            workspace=_require_str(bazel_raw, "workspace", "build.bazel"),
            target=target,
        )
    elif bazel_raw is not None:
        raise ProfileError(f"build.bazel 은 system=bazel 일 때만 쓸 수 있다 (system={system!r})")

    return BuildSpec(
        system=system,
        source_root=_require_str(data, "source_root", where),
        build_dir=_opt_str(data, "build_dir", where),
        configure_args=_str_list(data, "configure_args", where),
        libraries=_str_list(data, "libraries", where),
        include_dirs=_str_list(data, "include_dirs", where),
        link_flags=_str_list(data, "link_flags", where),
        compile_commands=_opt_str(data, "compile_commands", where),
        bazel=bazel,
    )


def _parse_embedded(data: Optional[Mapping[str, Any]]) -> EmbeddedSpec:
    if data is None:
        return EmbeddedSpec()
    where = "embedded"
    _check_keys(data, _EMBEDDED_KEYS, where)
    stub_undefined = data.get("stub_undefined", False)
    if not isinstance(stub_undefined, bool):
        raise ProfileError(f"embedded.stub_undefined 는 bool 이어야 한다 (got {stub_undefined!r})")
    return EmbeddedSpec(
        strip_flags=_str_list(data, "strip_flags", where),
        stub_undefined=stub_undefined,
        stub_allowlist=_str_list(data, "stub_allowlist", where),
    )


def parse_profile(
    data: Mapping[str, Any],
    *,
    base_dir: Optional[PathLike] = None,
    path: Optional[Path] = None,
) -> TargetProfile:
    """읽은 dict 검증 후 :class:`TargetProfile` 생성"""
    if not isinstance(data, dict):
        raise ProfileError(f"프로필 최상위는 객체여야 한다 (got {type(data).__name__})")
    _check_keys(data, _TOP_KEYS, "profile")

    build = _parse_build(_mapping(data, "build", "profile", required=True))
    base = Path(base_dir) if base_dir is not None else Path.cwd()
    root = Path(build.source_root)
    if not root.is_absolute():
        root = base / root

    version = data.get("version", "")
    if not isinstance(version, (str, int, float)) or isinstance(version, bool):
        raise ProfileError(f"profile.version 은 문자열이어야 한다 (got {version!r})")

    apis = _str_list(data, "apis", "profile")
    if len(set(apis)) != len(apis):
        raise ProfileError(f"profile.apis 에 중복이 있다: {list(apis)}")

    return TargetProfile(
        name=_require_str(data, "name", "profile"),
        version=str(version),
        language=_enum(data, "language", LANGUAGES, "profile"),
        domain=_enum(data, "domain", DOMAINS, "profile"),
        build=build,
        apis=apis,
        error_contract=_enum(data, "error_contract", ERROR_CONTRACTS, "profile"),
        embedded=_parse_embedded(_mapping(data, "embedded", "profile", required=False)),
        seeds=_str_list(data, "seeds", "profile", allow_single=True),
        root=root.resolve(),
        path=path,
    )


def load_profile(path: PathLike, *, base_dir: Optional[PathLike] = None) -> TargetProfile:
    """``targets/*.json`` 로드 및 검증

    Args:
        path: 프로필 JSON 경로
        base_dir: 상대 ``build.source_root`` 기준 디렉터리 (기본: 현재 작업 디렉터리)

    Raises:
        ProfileError: 파일 부재, JSON 손상, 스키마 위반
    """
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise ProfileError(f"프로필을 읽을 수 없다: {p} ({exc})") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ProfileError(f"프로필 JSON 파싱 실패: {p}:{exc.lineno}:{exc.colno} {exc.msg}") from exc
    try:
        return parse_profile(data, base_dir=base_dir, path=p.resolve())
    except ProfileError as exc:
        raise ProfileError(f"{p}: {exc}") from None
