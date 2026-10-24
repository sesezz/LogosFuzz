"""GENERIC-C 자가치유 ↔ 빌드 어댑터 ↔ 스텁 연결 테스트

GENERIC-B 빌드 어댑터(``generate/build`` 의 ``adapter_for``)가 없어도 돌도록 가짜 어댑터를
``adapter_factory`` 로 주입. 가짜 어댑터는 링크 입력(``build.link_flags``)에 들어온
스텁 파일을 실제로 읽어서, 정의되지 않은 심볼을 GNU ld 원문 형식으로 보고
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pytest

from logosfuzz.common.target_profile import load_profile
from logosfuzz.generate.adapter_compiler import (
    AdapterCompiler,
    classifier_for,
    compiler_for,
    heal_loop_for,
)
from logosfuzz.generate.bazel_errors import classify as bazel_classify
from logosfuzz.generate.contracts import FeedbackPayload, HarnessArtifact
from logosfuzz.generate.errors import classify_toolchain_log
from logosfuzz.generate.feedback_loop import (
    RebuildFailedError,
    artifact_from_report,
    selfheal_regenerate_fn,
)
from logosfuzz.generate.llm import ScriptedLLMClient
from logosfuzz.generate.models import HarnessDraft, HealOutcome
from logosfuzz.generate.selfheal import SelfHealLoop
from logosfuzz.generate.stubs import StubPolicy

REPO = Path(__file__).resolve().parents[3]


@dataclass
class FakeBuildResult:
    ok: bool
    target: str
    log: str = ""
    binary: Optional[Path] = None
    duration_s: float = 0.01


class FakeAdapter:
    """``BuildAdapter`` 계약만 모사. 외부 심볼 정의는 스텁 파일에서만 제공"""

    def __init__(self, profile, work_dir: Path, required, extra_log: str = "") -> None:
        self.profile = profile
        self.work_dir = work_dir
        self.required = list(required)
        self.extra_log = extra_log
        self.builds = 0

    def emit_build_definition(self, spec, harness_source: str) -> Path:
        path = self.work_dir / "harness" / spec.srcs[0]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(harness_source, encoding="utf-8")
        return path

    def _defined(self) -> set:
        names = set()
        for flag in self.profile.build.link_flags:
            p = Path(flag)
            if p.suffix == ".c" and p.is_file():
                names |= set(re.findall(r"\b(\w+)\(", p.read_text()))
        return names

    def build(self, spec) -> FakeBuildResult:
        self.builds += 1
        missing = [s for s in self.required if s not in self._defined()]
        if missing or self.extra_log:
            lines = ["/usr/bin/ld: build-fuzz/libproto.a(proto_parser.c.o): "
                     "in function `proto_parse':"]
            lines += [f"/src/proto_parser.c:{49 + i}:(.text.proto_parse+0x3b): "
                      f"undefined reference to `{s}'" for i, s in enumerate(missing)]
            if self.extra_log:
                lines.append(self.extra_log)
            lines.append("clang: error: linker command failed with exit code 1 "
                         "(use -v to see invocation)")
            return FakeBuildResult(ok=False, target=spec.name, log="\n".join(lines))
        binary = self.work_dir / "bin" / spec.name
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_text("ELF")
        return FakeBuildResult(ok=True, target=spec.name, binary=binary)

    def remove(self, spec) -> None:
        pass


class Factory:
    def __init__(self, work_dir: Path, required, extra_log: str = "") -> None:
        self.work_dir = work_dir
        self.required = required
        self.extra_log = extra_log
        self.adapters = []

    def __call__(self, profile):
        adapter = FakeAdapter(profile, self.work_dir, self.required, self.extra_log)
        self.adapters.append(adapter)
        return adapter


@pytest.fixture
def embedded_profile():
    return load_profile(REPO / "targets" / "embedded-sample.json", base_dir=REPO)


def _draft() -> HarnessDraft:
    return HarnessDraft(logic_group="fuzz_proto", source="int LLVMFuzzerTestOneInput(){return 0;}",
                        project="embedded-sample", language="c")


def _loop(profile, tmp_path, required, llm=None, extra_log=""):
    factory = Factory(tmp_path, required, extra_log)
    llm = llm or ScriptedLLMClient([])
    loop = heal_loop_for(profile, llm, max_round=2, adapter_factory=factory, work_dir=tmp_path)
    return loop, factory, llm


# --------------------------------------------------------------------------- #
# 링크 실패 → 스텁 → 재빌드 (LLM 없이)
# --------------------------------------------------------------------------- #
def test_link_failure_is_fixed_by_stubs_without_llm(embedded_profile, tmp_path):
    loop, factory, llm = _loop(embedded_profile, tmp_path, ["HAL_GetTick", "HAL_UART_Transmit"])
    report = loop.run(_draft())

    assert report.outcome is HealOutcome.SUCCESS
    assert llm.calls == []
    assert report.rounds_used == 0
    assert report.stubbed_symbols == ["HAL_GetTick", "HAL_UART_Transmit"]
    assert [r.ok for r in report.rounds] == [False, True]
    assert report.rounds[0].diagnosis == "undefined_symbol/resolve_symbol"
    # 실행 파일 경로는 어댑터의 BuildResult.binary 그대로
    assert report.last_compile.artifact_path == str(tmp_path / "bin" / "fuzz_proto")
    stub = (tmp_path / "stubs" / "embedded-sample_stubs.c").read_text()
    assert "__attribute__((weak)) int HAL_GetTick()" in stub
    data = report.to_dict()
    assert data["stubbed_symbols"] == ["HAL_GetTick", "HAL_UART_Transmit"]
    assert data["rounds"][1]["stubbed_symbols"] == ["HAL_GetTick", "HAL_UART_Transmit"]


def test_only_non_allowlisted_symbols_escalate(embedded_profile, tmp_path):
    loop, _, llm = _loop(embedded_profile, tmp_path, ["vendor_crc32"])
    report = loop.run(_draft())
    assert report.outcome is HealOutcome.ESCALATED
    assert llm.calls == []
    assert report.stubbed_symbols == []


def test_mixed_symbols_stub_allowed_then_escalate_rest(embedded_profile, tmp_path):
    loop, _, llm = _loop(embedded_profile, tmp_path, ["HAL_GetTick", "vendor_crc32"])
    report = loop.run(_draft())
    assert report.outcome is HealOutcome.ESCALATED
    assert report.stubbed_symbols == ["HAL_GetTick"]
    assert llm.calls == []


def test_escalation_reaches_hitl_with_reason(embedded_profile, tmp_path):
    class FakeHITL:
        def __init__(self):
            self.requests = []

        def request(self, checkpoint, **kwargs):
            self.requests.append(kwargs)

            class D:
                class type:
                    value = "pending"
            return D()

        def pending(self, project=None):
            return []

    hitl = FakeHITL()
    factory = Factory(tmp_path, ["vendor_crc32"])
    loop = heal_loop_for(embedded_profile, ScriptedLLMClient([]), adapter_factory=factory,
                         work_dir=tmp_path, hitl=hitl)
    loop.run(_draft())
    assert "vendor_crc32" in hitl.requests[0]["payload"]["stop_reason"]


def test_other_errors_with_rejected_symbols_go_to_llm(embedded_profile, tmp_path):
    """허용목록 밖 심볼과 다른 에러가 섞여 있으면 에스컬레이션하지 않고 LLM 에 위임"""
    fixed = "```c\nint LLVMFuzzerTestOneInput(){return 1;}\n```"
    loop, _, llm = _loop(embedded_profile, tmp_path, ["vendor_crc32"],
                         llm=ScriptedLLMClient([fixed]),
                         extra_log="h.c:3:5: error: use of undeclared identifier 'x'")
    report = loop.run(_draft())
    assert len(llm.calls) >= 1
    assert report.outcome is not HealOutcome.SUCCESS


def test_stub_policy_disabled_keeps_old_behaviour(embedded_profile, tmp_path):
    """stub_undefined=false 면 기존처럼 LLM 수정 루프로 진행"""
    factory = Factory(tmp_path, ["HAL_GetTick"])
    compiler = AdapterCompiler(embedded_profile, adapter_factory=factory, work_dir=tmp_path)
    llm = ScriptedLLMClient([])
    loop = SelfHealLoop(compiler, llm, max_round=1, classifier=classify_toolchain_log,
                        stub_policy=StubPolicy(enabled=False))
    report = loop.run(_draft())
    assert report.stubbed_symbols == []
    assert report.outcome is HealOutcome.STAGNATED
    assert len(llm.calls) == 1
    assert "undefined_symbol" in llm.calls[0]


def test_subprocess_compiler_ignores_stub_policy(tmp_path):
    """apply_stubs 가 없는 기존 컴파일러는 스텁 정책이 있어도 동작 동일"""
    from logosfuzz.generate.compiler import FakeCompiler

    loop = SelfHealLoop(FakeCompiler(), ScriptedLLMClient(["```c\n// COMPILE_OK\n```"]),
                        max_round=1, stub_policy=StubPolicy(enabled=True))
    assert loop.run(_draft()).outcome is HealOutcome.SUCCESS


# --------------------------------------------------------------------------- #
# compiler_for / classifier_for
# --------------------------------------------------------------------------- #
def test_compiler_for_rejects_bazel_and_picks_classifier(embedded_profile):
    auto = load_profile(REPO / "targets" / "automotive.json", base_dir=REPO)
    with pytest.raises(ValueError, match="BazelCompiler"):
        compiler_for(auto)
    assert classifier_for(auto) is bazel_classify
    assert classifier_for(embedded_profile) is classify_toolchain_log


def test_adapter_compiler_rebuilds_adapter_with_stub_link_input(embedded_profile, tmp_path):
    factory = Factory(tmp_path, ["HAL_GetTick"])
    compiler = AdapterCompiler(embedded_profile, adapter_factory=factory, work_dir=tmp_path)
    assert not compiler.compile(_draft()).ok
    assert compiler.effective_profile.build.link_flags == ()
    compiler.apply_stubs(["HAL_GetTick"])
    assert compiler.effective_profile.build.link_flags == (str(compiler.stub_path),)
    result = compiler.compile(_draft())
    assert result.ok
    assert len(factory.adapters) == 2
    # 원래 프로필은 frozen 그대로 유지
    assert embedded_profile.build.link_flags == ()


def test_default_factory_uses_generic_build_adapter(embedded_profile, tmp_path):
    """빌드 어댑터 머지 후에는 adapter_for 가 CMakeAdapter 반환"""
    build = pytest.importorskip("logosfuzz.generate.build")
    compiler = AdapterCompiler(embedded_profile, work_dir=tmp_path)
    adapter = compiler.adapter
    assert type(adapter).__name__ == "CMakeAdapter"
    assert hasattr(build, "adapter_for")


# --------------------------------------------------------------------------- #
# feedback_loop 연결
# --------------------------------------------------------------------------- #
def test_selfheal_regenerate_fn_returns_adapter_binary(embedded_profile, tmp_path):
    loop, _, _ = _loop(embedded_profile, tmp_path, ["HAL_GetTick"])
    seen = []

    def draft_for(artifact, feedback):
        seen.append(feedback.reason)
        return _draft()

    regenerate = selfheal_regenerate_fn(loop, draft_for)
    old = HarnessArtifact(group_id="fuzz_proto", harness_path=tmp_path / "old",
                          source_path=tmp_path / "src" / "fuzz_proto.c", round_no=1)
    fb = FeedbackPayload(group_id="fuzz_proto", round_no=1, failed_steps=["smoke"],
                         reason="crash on start")
    new = regenerate(old, fb)
    assert seen == ["crash on start"]
    assert new.harness_path == tmp_path / "bin" / "fuzz_proto"
    assert new.round_no == 1
    assert (tmp_path / "src" / "fuzz_proto.c").read_text().startswith("int LLVMFuzzerTestOneInput")


def test_artifact_from_failed_report_raises(embedded_profile, tmp_path):
    loop, _, _ = _loop(embedded_profile, tmp_path, ["vendor_crc32"])
    report = loop.run(_draft())
    with pytest.raises(RebuildFailedError):
        artifact_from_report("fuzz_proto", report)
