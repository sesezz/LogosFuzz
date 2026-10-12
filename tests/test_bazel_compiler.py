"""GEN-03-02 Bazel 빌드 백엔드 테스트.

두 층으로 나뉜다.

- 단위 테스트: 실행기를 주입해 bazel 없이 돈다(CI 에 툴체인이 필요 없다).
- 통합 테스트: **실제 `bazel build`** 로 자가치유가 실패 -> 복구하는 것을 증명한다.
  bazel 이 PATH 에 없으면 통째로 skip 한다.

통합 테스트가 왜 필요한가 - 2주차 분류기와 3주차 프롬프트 주입은 **Bazel 로그를
전제**한다. 그런데 지금까지 루프를 돌린 컴파일러는 clang(`SubprocessCompiler`)과
스텁(`FakeCompiler`)뿐이라, 루프 전체가 진짜 Bazel 빌드를 한 번도 겪은 적이 없었다.
여기서 처음으로 끝까지 통과시킨다.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from logosfuzz.generate.bazel_compiler import (
    BazelCompiler,
    BazelRunResult,
    bazel_available,
)
from logosfuzz.generate.errors import BazelErrorKind
from logosfuzz.generate.llm import ScriptedLLMClient
from logosfuzz.generate.models import HarnessDraft, HealOutcome
from logosfuzz.generate.selfheal import SelfHealLoop

REPRO = Path(__file__).parent / "fixtures" / "bazel_repro"
TARGET = "//harness:json_fuzzer"
HARNESS_REL = "harness/json_fuzzer.cc"


def _workspace(tmp_path: Path) -> Path:
    """재현 워크스페이스를 복사한다(파손 오버레이는 뺀다)."""
    work = tmp_path / "workspace"
    shutil.copytree(REPRO, work)
    shutil.rmtree(work / "breaks", ignore_errors=True)
    return work


def _fake_runner(returncode: int, stdout: str = "", stderr: str = ""):
    calls = []

    def run(argv, cwd, timeout):
        calls.append({"argv": list(argv), "cwd": cwd, "timeout": timeout})
        return BazelRunResult(returncode, stdout, stderr)

    run.calls = calls
    return run


# --------------------------------------------------------------------------- #
# 단위 - 명령 구성
# --------------------------------------------------------------------------- #
def test_argv_has_no_config_flag_by_default(tmp_path: Path) -> None:
    compiler = BazelCompiler(_workspace(tmp_path), TARGET, HARNESS_REL)
    assert compiler.argv() == ["bazel", "build", TARGET]


def test_argv_includes_config_and_extra_args(tmp_path: Path) -> None:
    compiler = BazelCompiler(
        _workspace(tmp_path), TARGET, HARNESS_REL,
        config="asan_ubsan_lsan", extra_args=["--keep_going"],
    )
    assert compiler.argv() == [
        "bazel", "build", "--config=asan_ubsan_lsan", "--keep_going", TARGET,
    ]


def test_requested_target_is_exposed_for_the_classifier(tmp_path: Path) -> None:
    """루프가 이 값을 분류기에 넘겨 '자기 타깃 vs 의존 대상'을 가른다(발견 A)."""
    compiler = BazelCompiler(_workspace(tmp_path), TARGET, HARNESS_REL)
    assert compiler.requested_target == TARGET


# --------------------------------------------------------------------------- #
# 단위 - 소스 기록과 결과 변환
# --------------------------------------------------------------------------- #
def test_source_is_written_into_the_workspace(tmp_path: Path) -> None:
    work = _workspace(tmp_path)
    compiler = BazelCompiler(work, TARGET, HARNESS_REL, runner=_fake_runner(0))
    compiler.compile(HarnessDraft("g", "원본"), "// 새 하네스")

    assert (work / HARNESS_REL).read_text(encoding="utf-8") == "// 새 하네스"


def test_build_runs_in_the_workspace_directory(tmp_path: Path) -> None:
    """Bazel 은 워크스페이스 안에서 실행돼야 한다."""
    work = _workspace(tmp_path)
    runner = _fake_runner(0)
    BazelCompiler(work, TARGET, HARNESS_REL, runner=runner).compile(
        HarnessDraft("g", "x")
    )
    assert runner.calls[0]["cwd"] == str(work)


def test_failure_keeps_the_whole_log(tmp_path: Path) -> None:
    """3주차 항목이 '로그 전문 투입'이다. 여기서 자르면 분류기가 원인을 잃는다."""
    stderr = (REPRO.parent / "bazel_errors" / "not_visible.txt").read_text(
        encoding="utf-8", errors="replace"
    )
    compiler = BazelCompiler(
        _workspace(tmp_path), TARGET, HARNESS_REL,
        runner=_fake_runner(1, stderr=stderr),
    )
    result = compiler.compile(HarnessDraft("g", "x"))

    assert not result.ok
    assert result.returncode == 1
    # 앞·가운데·끝이 모두 살아 있어야 '전문'이다. 길이로 재면 CompileResult.log 의
    # strip() 때문에 어긋나므로 내용으로 확인한다.
    assert "Visibility error:" in result.log            # 앞
    assert "is not visible from" in result.log          # 가운데(ERROR 줄 다음 줄)
    assert "Build did NOT complete successfully" in result.log  # 끝
    assert result.log.count("\n") >= stderr.strip().count("\n")


def test_success_is_reported(tmp_path: Path) -> None:
    compiler = BazelCompiler(
        _workspace(tmp_path), TARGET, HARNESS_REL,
        runner=_fake_runner(0, stdout="INFO: Build completed successfully"),
    )
    result = compiler.compile(HarnessDraft("g", "x"))
    assert result.ok
    assert result.returncode == 0


# --------------------------------------------------------------------------- #
# 단위 - 환경 문제를 조용히 넘기지 않는가
# --------------------------------------------------------------------------- #
def test_non_workspace_directory_fails_loudly(tmp_path: Path) -> None:
    """MODULE.bazel 이 없는 곳에서 빌드하면 원인을 분명히 말해야 한다."""
    compiler = BazelCompiler(tmp_path, TARGET, HARNESS_REL, runner=_fake_runner(0))
    result = compiler.compile(HarnessDraft("g", "x"))

    assert not result.ok
    assert "MODULE.bazel" in result.log


def test_missing_bazel_executable_is_reported(tmp_path: Path) -> None:
    """실행기를 주입하지 않고 실제 실행 경로를 탄다(기본 실행기의 OSError 처리)."""
    compiler = BazelCompiler(
        _workspace(tmp_path), TARGET, HARNESS_REL,
        executable="존재하지-않는-bazel-실행파일",
    )
    result = compiler.compile(HarnessDraft("g", "x"))

    assert not result.ok
    assert result.returncode == 127
    assert "찾을 수 없거나" in result.log


def test_loop_survives_a_broken_backend(tmp_path: Path) -> None:
    """백엔드가 실패해도 루프가 예외로 터지지 않고 리포트를 돌려줘야 한다."""
    compiler = BazelCompiler(tmp_path, TARGET, HARNESS_REL, runner=_fake_runner(0))
    loop = SelfHealLoop(compiler, ScriptedLLMClient([]), max_round=1)
    report = loop.run(HarnessDraft("g", "x"))

    assert not report.success


# --------------------------------------------------------------------------- #
# 통합 - 실제 bazel build 로 실패 -> 복구
# --------------------------------------------------------------------------- #
pytestmark_integration = pytest.mark.skipif(
    not bazel_available(),
    reason="bazel(bazelisk)이 PATH 에 없다. WSL/컨테이너에서 실행할 것.",
)


@pytestmark_integration
def test_self_healing_recovers_a_real_bazel_build(tmp_path: Path) -> None:
    """2주차 완료 기준 '실패 시 자가치유가 1회 이상 복구'를 실제 툴체인으로 증명한다.

    시나리오: 하네스가 정의 없는 심볼(`score::json::ParseStrict`)을 부른다.
    -> 진짜 `bazel build` 가 링크에서 실패
    -> 분류기가 undefined_symbol / resolve_symbol 로 판정(소스로 고칠 수 있는 결함)
    -> LLM 이 고친 소스를 돌려줌
    -> 재빌드 성공
    """
    work = _workspace(tmp_path)
    broken = (REPRO / "breaks" / "link_undefined" / HARNESS_REL).read_text(
        encoding="utf-8"
    )
    fixed = (REPRO / HARNESS_REL).read_text(encoding="utf-8")

    compiler = BazelCompiler(work, TARGET, HARNESS_REL, config="fuzzer")
    llm = ScriptedLLMClient([f"정의 없는 호출을 제거했다.\n```c\n{fixed}\n```"])
    loop = SelfHealLoop(compiler, llm, max_round=2)

    report = loop.run(HarnessDraft("json_fuzzer", broken, language="cpp"))

    assert report.outcome is HealOutcome.SUCCESS, (
        f"복구 실패({report.outcome.value}). 마지막 로그:\n"
        f"{report.rounds[-1].compile_result.log[-2000:]}"
    )
    assert report.rounds_used == 1

    # 라운드 0 은 실패였고, 분류기가 소스로 고칠 수 있는 결함으로 판정했어야 한다.
    first = report.rounds[0]
    assert not first.ok
    assert first.classification is not None
    assert first.classification.primary.kind is BazelErrorKind.UNDEFINED_SYMBOL

    # 마지막 라운드는 실제로 빌드에 성공했고 산출물이 생겼다.
    last = report.rounds[-1].compile_result
    assert last.ok
    assert last.artifact_path is not None
    assert Path(last.artifact_path).exists()


@pytestmark_integration
def test_real_build_of_the_pristine_workspace_succeeds(tmp_path: Path) -> None:
    """대조군 - 멀쩡한 하네스는 첫 빌드에 통과해야 한다(오탐 게이트)."""
    work = _workspace(tmp_path)
    source = (REPRO / HARNESS_REL).read_text(encoding="utf-8")

    compiler = BazelCompiler(work, TARGET, HARNESS_REL, config="fuzzer")
    report = SelfHealLoop(compiler, ScriptedLLMClient([]), max_round=2).run(
        HarnessDraft("json_fuzzer", source, language="cpp")
    )

    assert report.outcome is HealOutcome.SUCCESS
    assert report.rounds_used == 0


@pytestmark_integration
def test_real_visibility_failure_escalates_without_burning_rounds(tmp_path: Path) -> None:
    """BUILD 를 고쳐야 하는 결함은 실제 빌드에서도 LLM 을 부르지 않고 끊어야 한다."""
    work = _workspace(tmp_path)
    shutil.copy(
        REPRO / "breaks" / "not_visible" / "harness" / "BUILD.bazel",
        work / "harness" / "BUILD.bazel",
    )
    source = (REPRO / HARNESS_REL).read_text(encoding="utf-8")

    llm = ScriptedLLMClient(["```c\n// 고쳐보겠다\n```"])
    compiler = BazelCompiler(work, TARGET, HARNESS_REL, config="fuzzer")
    report = SelfHealLoop(compiler, llm, max_round=3).run(
        HarnessDraft("json_fuzzer", source, language="cpp")
    )

    assert report.outcome is HealOutcome.ESCALATED
    assert llm.calls == []
    assert report.rounds[0].classification.primary.kind is BazelErrorKind.NOT_VISIBLE
