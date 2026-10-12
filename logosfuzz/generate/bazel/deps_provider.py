"""
GEN-03 Bazel 어댑터 - deps 공급자
==================================

`build_file_generator` 가 BUILD 룰을 쓰려면 대상 타깃의 deps 를 알아야 한다.
그 deps 를 **어디서 알아내는지**는 생성기의 관심사가 아니므로 여기서 분리한다.

왜 분리하나 — 계획상 deps 는 A 파트의 `extract/bazel_query.py` 에서 수급하는데,
그게 아직 없다. 생성기가 bazel_query 를 직접 호출하면 A 가 끝날 때까지 B 가
멈춘다. 공급자를 주입받는 구조면 지금은 StaticDepsProvider 로 진행하고,
bazel_query 가 나오면 생성기 코드를 한 줄도 안 고치고 교체할 수 있다.

    generator = BuildFileGenerator(deps_provider=StaticDepsProvider({...}))
    generator = BuildFileGenerator(deps_provider=BazelQueryDepsProvider(query))
"""
from __future__ import annotations

from typing import Callable, Dict, Iterable, Mapping, Optional, Protocol, Sequence, Tuple

from .build_file import parse_label


class DepsProvider(Protocol):
    """퍼징 대상 타깃이 필요로 하는 Bazel deps 를 돌려준다."""

    def deps_for(self, target_label: str) -> Sequence[str]:
        """`target_label` 하네스가 의존해야 할 라벨 목록. 순서는 보존한다."""
        ...


class StaticDepsProvider:
    """미리 정해둔 매핑에서 deps 를 읽는다.

    1주차에 손으로 검증한 조합을 그대로 쓰기 위한 공급자다. A 파트의
    bazel_query 가 없어도 2주차 생성기를 끝까지 돌릴 수 있게 해 준다.

    fallback 은 "매핑에 없는 타깃" 을 만났을 때 쓸 기본 deps 다. 대상 타깃
    자기 자신만 넣는 게 보통 맞다 — 링크는 되지만 헤더 가시성에서 깨질 수
    있고, 그건 자가치유가 붙잡을 몫이다.
    """

    def __init__(
        self,
        mapping: Mapping[str, Iterable[str]] | None = None,
        *,
        fallback_to_self: bool = True,
    ) -> None:
        self._mapping: Dict[str, Tuple[str, ...]] = {
            k: tuple(v) for k, v in (mapping or {}).items()
        }
        self._fallback_to_self = fallback_to_self

    @staticmethod
    def _identity(label: str) -> Optional[Tuple[str, str]]:
        """repo 접두사를 뗀 (package, target). 라벨 형식이 아니면 None."""
        try:
            parsed = parse_label(label)
        except ValueError:
            return None
        return parsed.package, parsed.target

    def _lookup(self, target_label: str) -> Optional[Tuple[str, ...]]:
        if target_label in self._mapping:
            return self._mapping[target_label]
        # 같은 대상이 `@repo//pkg` 와 `//pkg:pkg` 로 달리 표기되는 경우를 잇는다.
        # (KB 는 `//score/json:json`, 1주차 검증 표는 `@score_baselibs//score/json`)
        want = self._identity(target_label)
        if want is None:
            return None
        for key, deps in self._mapping.items():
            if self._identity(key) == want:
                return deps
        return None

    def deps_for(self, target_label: str) -> Sequence[str]:
        found = self._lookup(target_label)
        if found is not None:
            return found
        if self._fallback_to_self:
            return (target_label,)
        return ()

    def learn(self, target_label: str, deps: Iterable[str]) -> None:
        """자가치유가 찾아낸 deps 를 되먹인다(같은 타깃 재생성 시 재사용)."""
        self._mapping[target_label] = tuple(deps)


class BazelQueryDepsProvider:
    """A 파트의 `extract/bazel_query.py` 를 감싸는 공급자.

    bazel_query 모듈을 import 하지 않고 **호출 가능한 객체를 주입**받는다.
    아직 없는 모듈에 대한 import 의존을 만들지 않기 위해서다. A 가 완성되면
    호출부에서 이렇게 연결하면 된다:

        from logosfuzz.extract.bazel_query import deps_of
        provider = BazelQueryDepsProvider(deps_of)
    """

    def __init__(self, query: Callable[[str], Sequence[str]]) -> None:
        self._query = query

    def deps_for(self, target_label: str) -> Sequence[str]:
        return tuple(self._query(target_label))


# 1주차에 실제로 빌드·퍼징까지 검증한 조합.
# score/json/fuzz 패키지에서 cc_fuzz_test 가 통과한 deps 다.
VERIFIED_SCORE_JSON_DEPS: Dict[str, Tuple[str, ...]] = {
    "@score_baselibs//score/json": (
        # 구현 링크 (visibility = public)
        "@score_baselibs//score/json",
        # JsonParser / IJsonParser 선언 헤더 (subpackages 가시성)
        "@score_baselibs//score/json:parser_interface",
    ),
}
