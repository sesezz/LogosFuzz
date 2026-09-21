"""
GEN-03 Bazel 어댑터 - BUILD.bazel 렌더러
=========================================

`cc_fuzz_test` 룰 하나를 담은 BUILD.bazel 텍스트를 만든다.

정답 형태는 1주차에 손으로 써서 실제로 빌드·퍼징까지 통과시킨
`overlay/score/json/fuzz/BUILD.bazel` 이다. 이 모듈의 출력이 그 파일과
같은 모양이어야 하고, 그걸 테스트로 못박는다.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Sequence, Tuple

# S-CORE 저장소 규약. BUILD 파일에 이 블록이 없으면 lint 가 잡는다.
LICENSE_HEADER = """\
# *******************************************************************************
# Copyright (c) 2025 Contributors to the Eclipse Foundation
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
# *******************************************************************************
"""

LOAD_STATEMENT = 'load("@rules_fuzzing//fuzzing:cc_defs.bzl", "cc_fuzz_test")'

# 라벨 파서: @repo//package/path:target  /  //package/path:target  /  //package/path
_LABEL_RE = re.compile(
    r"^(?:@(?P<repo>[A-Za-z0-9_.\-+]+))?//(?P<package>[^:]*)(?::(?P<target>.+))?$"
)


@dataclass(frozen=True)
class Label:
    repo: str
    package: str
    target: str

    @property
    def text(self) -> str:
        prefix = f"@{self.repo}" if self.repo else ""
        return f"{prefix}//{self.package}:{self.target}"


def parse_label(label: str) -> Label:
    m = _LABEL_RE.match(label.strip())
    if not m:
        raise ValueError(f"Bazel 라벨 형식이 아니다: {label!r}")
    package = m.group("package") or ""
    # //score/json 처럼 타깃이 생략되면 패키지 마지막 조각이 타깃이다.
    target = m.group("target") or (package.rsplit("/", 1)[-1] if package else "")
    return Label(repo=m.group("repo") or "", package=package, target=target)


def fuzz_package_for(target_label: str) -> str:
    """퍼징 패키지 경로를 정한다.

    대상 패키지의 **하위** 패키지로 둔다. 1주차에 확인한 이유:
    선언 헤더를 가진 타깃의 visibility 가 `//<pkg>:__subpackages__` 인 경우가
    많아, 트리 밖 패키지(//fuzz/json 등)에서는 직접 의존할 수 없다. :json 이
    public 이라 전이 헤더로 끌어 쓸 수는 있지만 layering_check 가 켜진
    툴체인에서는 "직접 의존이 아닌 헤더 include" 가 에러가 된다.

        @score_baselibs//score/json  ->  score/json/fuzz
    """
    return f"{parse_label(target_label).package}/fuzz"


def default_test_name(target_label: str) -> str:
    """cc_fuzz_test 이름. 타깃 이름에서 규칙적으로 만든다."""
    return f"{parse_label(target_label).target}_fuzz_test"


@dataclass(frozen=True)
class FuzzTargetSpec:
    """생성할 cc_fuzz_test 한 개의 명세."""

    name: str
    package: str                                   # 워크스페이스 기준 상대 경로
    srcs: Tuple[str, ...]
    deps: Tuple[str, ...]
    # //... 전체 빌드에 딸려 들어가면 --config=bl-x86_64-linux(GCC) 회귀 빌드가
    # libFuzzer 링크에서 깨진다. 1주차에 실측으로 확인했다.
    tags: Tuple[str, ...] = ("manual",)
    corpus: Tuple[str, ...] = ()
    dicts: Tuple[str, ...] = ()
    size: str = ""
    license_header: bool = True
    notes: Tuple[str, ...] = field(default_factory=tuple)

    @property
    def label(self) -> str:
        return f"//{self.package}:{self.name}"

    @property
    def bin_label(self) -> str:
        """EXE 계층이 직접 실행할 계측된 퍼저 바이너리 타깃."""
        return f"//{self.package}:{self.name}_bin"

    def with_deps(self, deps: Sequence[str]) -> "FuzzTargetSpec":
        return FuzzTargetSpec(**{**self.__dict__, "deps": tuple(deps)})


def _string_list(name: str, values: Sequence[str], indent: str = "    ") -> str:
    if not values:
        return ""
    if len(values) == 1:
        return f'{indent}{name} = ["{values[0]}"],\n'
    body = "".join(f'{indent}    "{v}",\n' for v in values)
    return f"{indent}{name} = [\n{body}{indent}],\n"


def render_build_file(spec: FuzzTargetSpec) -> str:
    """FuzzTargetSpec 을 BUILD.bazel 텍스트로 렌더링한다."""
    parts: list[str] = []
    if spec.license_header:
        parts.append(LICENSE_HEADER)
    parts.append(LOAD_STATEMENT + "\n\n")

    for note in spec.notes:
        for line in note.splitlines():
            parts.append(f"# {line}\n" if line else "#\n")
        parts.append("\n")

    parts.append("cc_fuzz_test(\n")
    parts.append(f'    name = "{spec.name}",\n')
    parts.append(_string_list("srcs", spec.srcs))
    if spec.corpus:
        parts.append(_string_list("corpus", spec.corpus))
    if spec.dicts:
        parts.append(_string_list("dicts", spec.dicts))
    if spec.size:
        parts.append(f'    size = "{spec.size}",\n')
    parts.append(_string_list("tags", spec.tags))
    parts.append(_string_list("deps", spec.deps))
    parts.append(")\n")
    return "".join(parts)
