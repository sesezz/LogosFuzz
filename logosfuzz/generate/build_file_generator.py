"""
GEN-03 빌드 정의 자동 생성 (2주차)
===================================

`BUILD.bazel` + `cc_fuzz_test` 를 자동 생성하고, 빌드가 실패하면 에러를 보고
**BUILD 룰 수준에서** 고쳐 다시 시도한다.

1주차에 손으로 써서 실제 빌드·퍼징까지 통과시킨
`generate/bazel/overlay/score/json/fuzz/BUILD.bazel` 이 이 생성기의 정답이다.

책임 경계
---------
- 여기         : BUILD 룰 생성 + deps 수준 자가치유 + 라운드 로그
- selfheal.py  : 하네스 소스(.cc) 자체의 자가치유 (기존 루프, 손대지 않는다)
- build_errors : 에러 분류기 본체 (D 파트). 주입해서 쓴다

deps 는 `DepsProvider` 로 주입받는다. A 파트의 `extract/bazel_query.py` 가
없어도 StaticDepsProvider 로 끝까지 돌고, 나오면 한 줄 교체로 갈아끼운다.

사용
----
    from logosfuzz.generate.bazel.adapter import BazelAdapter
    from logosfuzz.generate.bazel.deps_provider import (
        StaticDepsProvider, VERIFIED_SCORE_JSON_DEPS,
    )
    from logosfuzz.generate.build_file_generator import BuildFileGenerator

    gen = BuildFileGenerator(
        adapter=BazelAdapter("~/baselibs"),
        deps_provider=StaticDepsProvider(VERIFIED_SCORE_JSON_DEPS),
    )
    report = gen.generate("@score_baselibs//score/json", harness_source)
    print(report.summary())
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .bazel.adapter import BuildAdapter, BuildResult
from .bazel.build_file import (
    FuzzTargetSpec,
    default_test_name,
    fuzz_package_for,
    parse_label,
    render_build_file,
)
from .bazel.deps_provider import DepsProvider, StaticDepsProvider
from .bazel.repair import BuildFileRepairer, BuildFix

DEFAULT_MAX_ROUNDS = 3


@dataclass
class Round:
    """빌드 1회 시도와 그에 대한 처방."""

    index: int
    spec: FuzzTargetSpec
    build: BuildResult
    fix: Optional[BuildFix] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "round": self.index,
            "target": self.build.target,
            "ok": self.build.ok,
            "deps": list(self.spec.deps),
            "duration_s": round(self.build.duration_s, 2),
            "fix": None if self.fix is None else {
                "kind": self.fix.kind,
                "detail": self.fix.detail,
                "add": list(self.fix.add),
                "remove": list(self.fix.remove),
                "repairable": self.fix.repairable,
            },
            "error_excerpt": "" if self.build.ok else self.build.short_log,
        }


@dataclass
class GenerateReport:
    """생성 -> 빌드 -> (자가치유) 전 과정의 기록."""

    target_label: str
    spec: FuzzTargetSpec
    rounds: List[Round] = field(default_factory=list)
    binary: Optional[Path] = None

    @property
    def ok(self) -> bool:
        return bool(self.rounds) and self.rounds[-1].build.ok

    @property
    def repaired(self) -> bool:
        """자가치유가 1회 이상 실제로 복구했는가 (2주차 완료 기준)."""
        return self.ok and len(self.rounds) > 1

    @property
    def rounds_used(self) -> int:
        return len(self.rounds)

    def summary(self) -> str:
        head = "성공" if self.ok else "실패"
        if self.repaired:
            head += f" (자가치유 {self.rounds_used - 1}회 복구)"
        lines = [f"{self.target_label} -> {self.spec.label}: {head}"]
        for r in self.rounds:
            mark = "OK " if r.build.ok else "FAIL"
            lines.append(f"  [{r.index}] {mark} deps={len(r.spec.deps)}")
            if r.fix is not None:
                lines.append(f"       -> {r.fix}")
            elif not r.build.ok:
                lines.append(f"       -> 분류 실패: {r.build.short_log.splitlines()[:1]}")
        if self.binary:
            lines.append(f"  바이너리: {self.binary}")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target_label,
            "fuzz_target": self.spec.label,
            "bin_target": self.spec.bin_label,
            "ok": self.ok,
            "repaired": self.repaired,
            "rounds_used": self.rounds_used,
            "binary": str(self.binary) if self.binary else None,
            "rounds": [r.to_dict() for r in self.rounds],
        }


class BuildFileGenerator:
    """대상 타깃 하나에 대해 BUILD 정의를 만들고 빌드까지 끌고 간다."""

    def __init__(
        self,
        adapter: BuildAdapter,
        deps_provider: Optional[DepsProvider] = None,
        repairer: Optional[BuildFileRepairer] = None,
        *,
        max_rounds: int = DEFAULT_MAX_ROUNDS,
    ) -> None:
        self.adapter = adapter
        self.deps_provider = deps_provider or StaticDepsProvider()
        self.repairer = repairer or BuildFileRepairer()
        self.max_rounds = max(1, max_rounds)

    # ------------------------------------------------------------------ #
    def make_spec(
        self,
        target_label: str,
        *,
        harness_filename: str = "",
        name: str = "",
        package: str = "",
    ) -> FuzzTargetSpec:
        """대상 라벨에서 cc_fuzz_test 명세를 만든다."""
        test_name = name or default_test_name(target_label)
        src = harness_filename or f"{parse_label(target_label).target}_fuzz.cc"
        return FuzzTargetSpec(
            name=test_name,
            package=package or fuzz_package_for(target_label),
            srcs=(src,),
            deps=tuple(self.deps_provider.deps_for(target_label)),
            notes=(
                f"LogosFuzz GEN-03 자동 생성 - 대상 {target_label}",
                "",
                "tags = [\"manual\"] : //... 전체 빌드에 딸려 들어가면",
                "--config=bl-x86_64-linux(GCC) 회귀 빌드가 libFuzzer 링크에서 깨진다.",
            ),
        )

    def render(self, spec: FuzzTargetSpec) -> str:
        """빌드하지 않고 BUILD.bazel 텍스트만 본다(미리보기·테스트용)."""
        return render_build_file(spec)

    # ------------------------------------------------------------------ #
    def generate(
        self,
        target_label: str,
        harness_source: str,
        *,
        spec: Optional[FuzzTargetSpec] = None,
    ) -> GenerateReport:
        """BUILD 를 쓰고 빌드하고, 실패하면 고쳐서 다시 시도한다."""
        current = spec or self.make_spec(target_label)
        report = GenerateReport(target_label=target_label, spec=current)

        for index in range(1, self.max_rounds + 1):
            self.adapter.emit_build_definition(current, harness_source)
            result = self.adapter.build(current)

            if result.ok:
                report.rounds.append(Round(index=index, spec=current, build=result))
                report.spec = current
                report.binary = result.binary
                # 마지막에 통한 deps 를 공급자에 되먹여 다음 생성에서 재사용한다.
                learn = getattr(self.deps_provider, "learn", None)
                if callable(learn):
                    learn(target_label, current.deps)
                return report

            repaired, fix = self.repairer.repair(current, result.log)
            report.rounds.append(Round(index=index, spec=current, build=result, fix=fix))
            if repaired is None:
                break
            current = repaired

        report.spec = current
        return report
