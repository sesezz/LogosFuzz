"""CTR-06-01 BUILD 단계 테스트 (3주차). bazel 없이 가짜 어댑터로 돈다."""
from __future__ import annotations

import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from logosfuzz.control.ctr_06_01_controller import (
    HealUnavailable,
    save_generation_artifacts,
    is_source_error,
    BUILD_STATUS_BUILT,
    BUILD_STATUS_EMITTED,
    BUILD_STATUS_FAILED,
    BUILD_STATUS_REPAIRED,
    BuildStage,
    BuildStageResult,
    RegressionTester,
    main,
)
from logosfuzz.generate.bazel.adapter import BuildResult
from logosfuzz.generate.bazel.build_file import render_build_file
from logosfuzz.generate.bazel.deps_provider import StaticDepsProvider
from logosfuzz.generate.bazel.repair import (
    BuildFix,
    apply_fix,
    classify,
    classify_with_bazel_errors,
    default_classifier,
    fix_from_report,
)
from logosfuzz.generate.gen_03_01_harness_generator import (
    demo_pair,
    make_pair_spec,
    pair_driver,
    write_pairs,
)
from logosfuzz.generate.llm_harness_generator import FuzzDriver, LANG_CPP

SCORE_JSON = "@score_baselibs//score/json"

LOG_MISSING_HEADER = (
    "ERROR: <WORKSPACE>/harness/BUILD.bazel:3:10: Compiling harness/json_fuzzer.cc failed\n"
    "harness/json_fuzzer.cc:7:10: fatal error: 'score/json/json.h' file not found\n"
    "1 error generated.\n"
)
LOG_UNKNOWN = "ERROR: something nobody can classify\n"

CC = 'extern "C" int LLVMFuzzerTestOneInput(const uint8_t* d, size_t n) { return 0; }\n'


class FakeAdapter:
    """패키지별로 정해 둔 실패 로그를 차례로 내고, 다 쓰면 성공한다."""

    def __init__(self, workspace: Path, fail_logs: dict[str, list[str]] | None = None,
                 regression_ok: bool = True):
        self.workspace = workspace
        self.fail_logs = {k: list(v) for k, v in (fail_logs or {}).items()}
        self.regression_ok = regression_ok
        self.emitted = []
        self.regressed = []

    def emit_build_definition(self, spec, harness_source):
        pkg = self.workspace / spec.package
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / spec.srcs[0]).write_text(harness_source, encoding="utf-8")
        path = pkg / "BUILD.bazel"
        path.write_text(render_build_file(spec), encoding="utf-8")
        self.emitted.append(spec)
        return path

    def build(self, spec):
        logs = self.fail_logs.get(spec.package) or []
        if logs:
            return BuildResult(ok=False, target=spec.bin_label, log=logs.pop(0))
        binary = self.workspace / "bazel-bin" / spec.package / f"{spec.name}_bin"
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_text("", encoding="utf-8")
        return BuildResult(ok=True, target=spec.bin_label, binary=binary)

    def remove(self, spec):
        pass

    def binary_path(self, spec):
        """cquery 기반 재조회 흉내 — 빌드가 통과한 뒤에만 경로가 있다."""
        binary = self.workspace / "bazel-bin" / spec.package / f"{spec.name}_bin"
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_text("", encoding="utf-8")
        return binary

    def regression_build(self, target):
        self.regressed.append(target)
        return BuildResult(ok=self.regression_ok, target=target,
                           log="" if self.regression_ok else "ERROR: gcc broke\n")


def _pair(group, deps=None):
    provider = StaticDepsProvider({SCORE_JSON: deps} if deps else None)
    driver = FuzzDriver(group_name=group, code=CC, language=LANG_CPP)
    return pair_driver(driver, SCORE_JSON, provider)


def _stage(tmp_path, adapter, **kw):
    return BuildStage(tmp_path, adapter=adapter, stream=io.StringIO(), **kw)


def test_build_stage_statuses(tmp_path):
    ok = _pair("ok_group")
    repaired = _pair("fix_group", deps=["@score_baselibs//score/other"])
    broken = _pair("bad_group")
    adapter = FakeAdapter(tmp_path, {
        repaired.spec.package: [LOG_MISSING_HEADER],
        broken.spec.package: [LOG_UNKNOWN],
    })

    result = _stage(tmp_path, adapter).run([ok, repaired, broken], skipped=["ghost"])
    by_group = {u["group"]: u for u in result.units}

    assert by_group["ok_group"]["status"] == BUILD_STATUS_BUILT
    assert by_group["fix_group"]["status"] == BUILD_STATUS_REPAIRED
    assert by_group["bad_group"]["status"] == BUILD_STATUS_FAILED
    assert result.total == 3 and result.built == 2 and result.failed == 1
    assert result.ok is False
    assert set(result.binaries()) == {"ok_group", "fix_group"}

    unit = by_group["ok_group"]
    assert unit["build_target"] == SCORE_JSON
    assert unit["build_system"] == "bazel"
    assert unit["bin_target"] == ok.spec.bin_label
    assert "target" not in unit  # build_target 과 중복 키는 뺀다

    data = result.to_dict()
    assert data["built_units"] == 2 and data["repaired_units"] == 1
    assert data["skipped_groups"] == ["ghost"]


def test_build_stage_emit_only_does_not_build(tmp_path):
    adapter = FakeAdapter(tmp_path, {"never": ["x"]})
    pair = demo_pair()
    result = _stage(tmp_path, adapter, emit_only=True).run([pair], regression=True)

    assert [u["status"] for u in result.units] == [BUILD_STATUS_EMITTED]
    assert result.ok is True
    assert adapter.regressed == []
    assert (tmp_path / pair.build_relpath).is_file()
    assert (tmp_path / pair.source_relpath).is_file()


def test_build_stage_regression_gate(tmp_path):
    adapter = FakeAdapter(tmp_path, regression_ok=False)
    result = _stage(tmp_path, adapter).run([_pair("a"), _pair("b")], regression=True)

    # 같은 빌드 단위는 한 번만 회귀 빌드한다
    assert adapter.regressed == [SCORE_JSON]
    assert result.regression[0]["ok"] is False
    assert result.ok is False


def test_build_summary_is_written(tmp_path):
    result = _stage(tmp_path, FakeAdapter(tmp_path)).run([_pair("a")])
    path = BuildStage.write(result, tmp_path / "out" / "build_summary.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["schema_version"] == "1.0"
    assert data["units"][0]["group"] == "a"


def test_build_regression_baseline(tmp_path):
    baseline = tmp_path / "baseline.json"
    tester = RegressionTester()

    good = _stage(tmp_path, FakeAdapter(tmp_path)).run([_pair("a")])
    tester.save_build_baseline(good, str(baseline))
    assert tester.compare_build(good, str(baseline)).passed

    bad_pair = _pair("a")
    bad = _stage(tmp_path, FakeAdapter(tmp_path, {bad_pair.spec.package: [LOG_UNKNOWN]})).run([bad_pair])
    reg = tester.compare_build(bad, str(baseline))
    assert reg.passed is False
    assert SCORE_JSON in reg.message


def test_cli_bazel_emit_only_with_single_harness(tmp_path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    harness = tmp_path / "my_fuzz.cc"
    harness.write_text(CC, encoding="utf-8")
    summary = tmp_path / "build_summary.json"

    code = main([
        "--mode", "bazel", "--skip-check", "--emit-only",
        "--workspace", str(workspace),
        "--harness", str(harness),
        "--build-target", SCORE_JSON,
        "--group", "lg_cli",
        "--build-summary", str(summary),
    ])

    assert code == 0
    data = json.loads(summary.read_text(encoding="utf-8"))
    assert data["emitted_units"] == 1
    assert (workspace / "score/json/fuzz/lg_cli/BUILD.bazel").is_file()
    assert (workspace / "score/json/fuzz/lg_cli/lg_cli_fuzz.cc").is_file()


def test_cli_bazel_emit_only_from_manifest(tmp_path):
    manifest = write_pairs([demo_pair()], tmp_path / "stage")
    workspace = tmp_path / "ws"
    workspace.mkdir()
    code = main([
        "--mode", "bazel", "--skip-check", "--emit-only",
        "--workspace", str(workspace),
        "--pairs", str(manifest),
        "--build-summary", str(tmp_path / "bs.json"),
    ])
    assert code == 0
    assert (workspace / "score/json/fuzz/lg_json_parser/BUILD.bazel").is_file()


def test_cli_bazel_requires_workspace(capsys):
    assert main(["--mode", "bazel", "--skip-check"]) == 2


# --------------------------------------------------------------------------- #
# D 분류기(bazel_errors) -> BuildFix 변환.  D 모듈 없이 가짜 report 로 검증한다.
# --------------------------------------------------------------------------- #
def _report(kind, action, detail=None, summary=""):
    primary = SimpleNamespace(
        kind=SimpleNamespace(value=kind), action=SimpleNamespace(value=action),
        detail=detail or {}, summary=summary,
    )
    return SimpleNamespace(primary=primary)


def _spec_with_deps(*deps):
    return make_pair_spec("g", SCORE_JSON, StaticDepsProvider({SCORE_JSON: deps}))


def test_fix_from_report_missing_dep_adds_dep_with_repo_prefix():
    spec = _spec_with_deps("@score_baselibs//score/other")
    fix = fix_from_report(
        _report("missing_dep", "add_deps", {"header": "score/json/json.h"}), spec)
    assert fix.kind == "add_dep" and fix.repairable
    assert fix.add == ("@score_baselibs//score/json",)


def test_fix_from_report_missing_dep_already_present_or_unknown_falls_back():
    spec = _spec_with_deps("@score_baselibs//score/json")
    assert fix_from_report(
        _report("missing_dep", "add_deps", {"header": "score/json/json.h"}), spec) is None
    assert fix_from_report(_report("missing_dep", "add_deps", {"header": "json.h"}), spec) is None


@pytest.mark.parametrize("kind,action", [
    ("no_such_target", "fix_dep_label"),
    ("no_such_target", "add_deps"),
    ("unknown", "fix_dep_label"),
])
def test_fix_from_report_rename_dep_with_suggestion(kind, action):
    spec = _spec_with_deps("@score_baselibs//score/json:jsonn")
    fix = fix_from_report(_report(kind, action, {
        "label": "//score/json:jsonn", "suggestion": "json"}), spec)
    assert fix.kind == "rename_dep"
    assert fix.add == ("@score_baselibs//score/json:json",)       # repo 접두사 보존
    assert fix.remove == ("@score_baselibs//score/json:jsonn",)


def test_fix_from_report_no_suggestion_is_left_to_fallback():
    spec = _spec_with_deps("@score_baselibs//score/json:jsonn")
    assert fix_from_report(_report("no_such_target", "fix_dep_label",
                                   {"label": "//score/json:jsonn"}), spec) is None


@pytest.mark.parametrize("kind,action,expected_kind", [
    ("not_visible", "expand_visibility", "not_visible"),
    ("unknown", "expand_visibility", "not_visible"),
    ("dep_cycle", "escalate", "escalate"),
])
def test_fix_from_report_unrepairable_kinds(kind, action, expected_kind):
    fix = fix_from_report(_report(kind, action, {"label": "//a:b"}), _spec_with_deps("//a:b"))
    assert fix.kind == expected_kind and fix.repairable is False


# --------------------------------------------------------------------------- #
# 안 보이는 의존(visibility)은 추측으로 넣은 것이면 뺀다
# (실사례: KB deps 에 섞인 private json_builder 때문에 nlohmann_parser 빌드가 분석 단계에서 막혔다)
# --------------------------------------------------------------------------- #
PRIVATE_HELPER = "@score_baselibs//score/private:helper"
PRIVATE_OTHER = "@score_baselibs//score/private:other"
PUBLIC_OK = "@score_baselibs//score/ok:ok"

LOG_PRIVATE_NOT_VISIBLE = (
    "ERROR: /ws/score/x/BUILD.bazel:24:13: in cc_binary rule //score/x:t_raw_: Visibility error:\n"
    "target '//score/private:helper' is not visible from target '//score/x:t_raw_'\n"
    "Type 'bazel help info visibility' for help on how to set visibility.\n"
)


def _vis_report(*labels):
    diagnostics = [SimpleNamespace(kind=SimpleNamespace(value="not_visible"), detail={"label": label})
                   for label in labels]
    primary = SimpleNamespace(
        kind=SimpleNamespace(value="not_visible"), action=SimpleNamespace(value="expand_visibility"),
        detail={"label": labels[0]}, summary="")
    return SimpleNamespace(primary=primary, diagnostics=diagnostics)


def test_fix_from_report_drops_invisible_speculative_deps():
    spec = _spec_with_deps(SCORE_JSON, PRIVATE_HELPER, PRIVATE_OTHER, PUBLIC_OK)
    fix = fix_from_report(_vis_report("//score/private:helper", "//score/private:other"), spec)

    assert fix.kind == "drop_dep" and fix.repairable and fix.add == ()
    assert fix.remove == (PRIVATE_HELPER, PRIVATE_OTHER)       # Bazel 이 찍은 repo 없는 라벨을 deps 표기로 잇는다
    assert apply_fix(spec, fix).deps == (SCORE_JSON, PUBLIC_OK)


def test_fix_from_report_keeps_unrepairable_visibility_cases():
    spec = _spec_with_deps(SCORE_JSON, PRIVATE_HELPER)
    # 대상 단위(deps[0]) 자신이 안 보이면 위치 문제라 뺄 수 없다
    unit = fix_from_report(_vis_report("//score/json:json"), spec)
    assert unit.kind == "not_visible" and unit.repairable is False
    # 우리 deps 에 없는 대상(헤더가 끌어오는 전이 의존)은 여기서 고칠 수 없다
    outside = fix_from_report(_vis_report("//score/elsewhere:x"), spec)
    assert outside.kind == "not_visible" and outside.repairable is False
    # 하나라도 못 빼면 전부 수리 불가 — 일부만 빼고 다시 돌리지 않는다
    mixed = fix_from_report(_vis_report("//score/private:helper", "//score/elsewhere:x"), spec)
    assert mixed.repairable is False


def test_builtin_classifier_drops_every_invisible_dep_in_the_log():
    spec = _spec_with_deps(SCORE_JSON, PRIVATE_HELPER, PRIVATE_OTHER, PUBLIC_OK)
    log = LOG_PRIVATE_NOT_VISIBLE + LOG_PRIVATE_NOT_VISIBLE.replace("helper", "other")

    fix = classify(log, spec)
    assert fix.kind == "drop_dep" and fix.remove == (PRIVATE_HELPER, PRIVATE_OTHER)

    # 안 보이는 것이 deps 에 없으면 기존처럼 수리 불가
    assert classify(LOG_PRIVATE_NOT_VISIBLE, _spec_with_deps(SCORE_JSON)).repairable is False


def test_build_stage_repairs_by_dropping_invisible_dep(tmp_path):
    pair = _pair("vis_group", deps=[SCORE_JSON, PRIVATE_HELPER])
    adapter = FakeAdapter(tmp_path, {pair.spec.package: [LOG_PRIVATE_NOT_VISIBLE]})

    unit = _stage(tmp_path, adapter).run([pair]).units[0]

    assert unit["status"] == BUILD_STATUS_REPAIRED and unit["rounds_used"] == 2
    assert unit["deps"] == [SCORE_JSON]                          # 안 보이던 의존이 빠졌다
    assert unit["rounds"][0]["fix"]["kind"] == "drop_dep"
    assert unit["rounds"][0]["fix"]["remove"] == [PRIVATE_HELPER]


def test_fix_from_report_other_kinds_and_empty_report_are_none():
    spec = _spec_with_deps("//a:b")
    assert fix_from_report(_report("undefined_symbol", "resolve_symbol"), spec) is None
    assert fix_from_report(_report("missing_load", "add_load"), spec) is None
    assert fix_from_report(SimpleNamespace(primary=None), spec) is None


def test_default_classifier_prefers_primary_and_falls_back_to_builtin():
    spec = _spec_with_deps("@score_baselibs//score/other")
    mine = BuildFix(kind="add_dep", detail="D", add=("//d:d",))

    assert default_classifier(lambda log, spec: mine)("anything", spec) is mine
    # D 가 못 분류하면 내장 분류기 (헤더 없음 -> add_dep)
    fallback = default_classifier(lambda log, spec: None)(LOG_MISSING_HEADER, spec)
    assert fallback.kind == "add_dep" and "@score_baselibs//score/json" in fallback.add


def test_classify_with_bazel_errors_is_none_without_d_module(monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "logosfuzz.generate.bazel_errors", None)
    assert classify_with_bazel_errors(LOG_MISSING_HEADER, _spec_with_deps("//a:b")) is None


# --------------------------------------------------------------------------- #
# 소스(.cc) 컴파일 에러 자가치유 연결 (D 의 SelfHealLoop 자리에 가짜 루프 주입)
# --------------------------------------------------------------------------- #
LOG_SOURCE_ERROR = (
    "ERROR: <WORKSPACE>/harness/BUILD.bazel:3:10: Compiling harness/json_fuzzer.cc failed\n"
    "harness/json_fuzzer.cc:12:5: error: use of undeclared identifier 'fdp'\n"
    "1 error generated.\n"
)
LOG_NOT_VISIBLE = (
    "ERROR: <WORKSPACE>/x/BUILD.bazel:1:1: in cc_fuzz_test rule //x:t: "
    "target '//score/internal:helper' is not visible from target '//x:t'\n"
)


class FakeLoop:
    def __init__(self, success=True, final_source="FIXED", outcome="success", rounds_used=1):
        self.result = SimpleNamespace(
            success=success, final_source=final_source, rounds_used=rounds_used,
            outcome=SimpleNamespace(value=outcome), hitl_decision=None)
        self.drafts = []

    def run(self, draft):
        self.drafts.append(draft)
        return self.result


def _heal_stage(tmp_path, adapter, loop=None, factory=None, **kw):
    calls = []

    def default_factory(pair, spec):
        calls.append((pair.group_name, spec.bin_label))
        return loop

    stage = _stage(tmp_path, adapter, heal_rounds=2,
                   heal_loop_factory=factory or default_factory, **kw)
    return stage, calls


def test_is_source_error_uses_classifier_action_then_log():
    def classify_as(action):
        return lambda log, label: _report("x", action)

    assert is_source_error("anything", "//a:b_bin", classify_as("add_deps")) is False
    assert is_source_error("anything", "//a:b_bin", classify_as("escalate")) is False
    assert is_source_error("anything", "//a:b_bin", classify_as("resolve_symbol")) is True
    # 분류기가 못 잡으면 로그 문구로 판단한다
    none = lambda log, label: None
    assert is_source_error(LOG_SOURCE_ERROR, "//a:b_bin", none) is True
    assert is_source_error(LOG_UNKNOWN, "//a:b_bin", none) is False
    assert is_source_error(LOG_NOT_VISIBLE, "//a:b_bin", none) is False
    assert is_source_error(LOG_MISSING_HEADER, "//a:b_bin", none) is False


def test_source_error_is_healed_and_binary_is_requeried(tmp_path):
    pair = _pair("src_group")
    adapter = FakeAdapter(tmp_path, {pair.spec.package: [LOG_SOURCE_ERROR]})
    loop = FakeLoop(final_source="FIXED SOURCE", rounds_used=2)
    stage, calls = _heal_stage(tmp_path, adapter, loop, classify_errors=lambda log, label: None)

    result = stage.run([pair])
    unit = result.units[0]

    assert calls == [("src_group", pair.spec.bin_label)]
    assert unit["status"] == BUILD_STATUS_REPAIRED and unit["ok"] is True
    assert unit["heal"]["ok"] and unit["heal"]["rounds_used"] == 2
    assert unit["binary"] == unit["heal"]["binary"] and unit["binary"]
    assert pair.source == "FIXED SOURCE"                # 후속 산출물이 고친 소스를 가리킨다
    assert loop.drafts[0].logic_group == "src_group"
    assert loop.drafts[0].context["bazel_target"] == pair.spec.bin_label
    assert result.healed == 1 and result.ok is True
    assert result.to_dict()["healed_units"] == 1
    assert set(result.binaries()) == {"src_group"}


def test_build_file_causes_are_not_sent_to_source_heal(tmp_path):
    pair = _pair("vis_group")
    adapter = FakeAdapter(tmp_path, {pair.spec.package: [LOG_NOT_VISIBLE]})

    def factory(pair, spec):
        raise AssertionError("BUILD 원인은 소스 자가치유 대상이 아니다")

    stage, _ = _heal_stage(tmp_path, adapter, factory=factory,
                           classify_errors=lambda log, label: None)
    unit = stage.run([pair]).units[0]
    assert unit["status"] == BUILD_STATUS_FAILED and "heal" not in unit


def test_source_heal_is_off_by_default(tmp_path):
    pair = _pair("src_group")
    adapter = FakeAdapter(tmp_path, {pair.spec.package: [LOG_SOURCE_ERROR]})

    def factory(pair, spec):
        raise AssertionError("heal_rounds=0 이면 호출하면 안 된다")

    unit = _stage(tmp_path, adapter, heal_loop_factory=factory).run([pair]).units[0]
    assert unit["status"] == BUILD_STATUS_FAILED and "heal" not in unit


def test_failed_heal_keeps_unit_failed_and_records_why(tmp_path):
    pair = _pair("src_group")
    adapter = FakeAdapter(tmp_path, {pair.spec.package: [LOG_SOURCE_ERROR]})
    loop = FakeLoop(success=False, outcome="exhausted", rounds_used=2)
    stage, _ = _heal_stage(tmp_path, adapter, loop, classify_errors=lambda log, label: None)

    unit = stage.run([pair]).units[0]
    assert unit["status"] == BUILD_STATUS_FAILED
    assert unit["heal"]["ok"] is False and unit["heal"]["outcome"] == "exhausted"
    assert unit["binary"] is None


def test_failed_heal_records_error_digest_and_rounds(tmp_path):
    """exhausted 라는 결과만으로는 원인을 알 수 없다 — 마지막 에러와 라운드 기록을 남긴다."""
    pair = _pair("src_group")
    adapter = FakeAdapter(tmp_path, {pair.spec.package: [LOG_SOURCE_ERROR]})
    loop = FakeLoop(success=False, outcome="exhausted", rounds_used=2)
    loop.result.last_compile = SimpleNamespace(
        error_digest=lambda: "x.cc:12:5: error: no member named 'StringArray'")
    loop.result.rounds = [
        SimpleNamespace(index=0, ok=False, diagnosis="", llm_note=""),
        SimpleNamespace(index=1, ok=False, diagnosis="unknown/retry_raw", llm_note="API 이름 수정"),
    ]
    stream = io.StringIO()
    stage = BuildStage(tmp_path, adapter=adapter, stream=stream, heal_rounds=2,
                       heal_loop_factory=lambda pair, spec: loop,
                       classify_errors=lambda log, label: None)

    heal = stage.run([pair]).units[0]["heal"]

    assert "StringArray" in heal["error_digest"]
    assert [r["index"] for r in heal["rounds"]] == [0, 1]
    assert heal["rounds"][1]["diagnosis"] == "unknown/retry_raw"
    assert heal["rounds"][1]["note"] == "API 이름 수정"
    assert "exhausted" in stream.getvalue() and "StringArray" in stream.getvalue()


def test_short_log_includes_compiler_diagnostics():
    log = (
        "ERROR: /ws/BUILD.bazel:24:13: Compiling x_fuzz.cc failed: (Exit 1): cc_wrapper.sh failed\n"
        "score/x/x_fuzz.cc:12:5: error: no member named 'StringArray' in 'JsonParser'\n"
        "score/x/x_fuzz.cc:3:10: \x1b[0m\x1b[0;1;31mfatal error: \x1b[0m'a/b.h' file not found\n"
        "score/x/x_fuzz.cc:9:1: warning: unused variable\n"
        "ERROR: Build did NOT complete successfully\n"
    )
    short = BuildResult(ok=False, target="//x:y", log=log).short_log
    assert "Compiling x_fuzz.cc failed" in short
    assert "no member named 'StringArray'" in short
    assert "file not found" in short
    assert "unused variable" not in short            # 경고는 싣지 않는다
    assert short.splitlines()[0].startswith("ERROR")  # 기존 첫 줄 동작 유지


def test_heal_without_d_modules_is_skipped_not_fatal(tmp_path):
    pair = _pair("src_group")
    adapter = FakeAdapter(tmp_path, {pair.spec.package: [LOG_SOURCE_ERROR]})

    def factory(pair, spec):
        raise HealUnavailable("D 모듈 없음")

    stage, _ = _heal_stage(tmp_path, adapter, factory=factory,
                           classify_errors=lambda log, label: None)
    unit = stage.run([pair]).units[0]
    assert unit["status"] == BUILD_STATUS_FAILED
    assert unit["heal"]["attempted"] is False and "D 모듈" in unit["heal"]["reason"]


def test_heal_success_without_binary_is_failed(tmp_path):
    pair = _pair("src_group")
    adapter = FakeAdapter(tmp_path, {pair.spec.package: [LOG_SOURCE_ERROR]})
    adapter.binary_path = lambda spec: None              # cquery 도 폴백도 실패한 경우
    stage, _ = _heal_stage(tmp_path, adapter, FakeLoop(), classify_errors=lambda log, label: None)

    unit = stage.run([pair]).units[0]
    assert unit["status"] == BUILD_STATUS_FAILED
    assert "바이너리" in unit["heal"]["reason"]


# --------------------------------------------------------------------------- #
# 후속 파트로 넘기는 산출물: EXE groups JSON, D 검증 게이트 artifact
# --------------------------------------------------------------------------- #
def _built_result(tmp_path, *groups):
    pairs = [_pair(g) for g in groups]
    return _stage(tmp_path, FakeAdapter(tmp_path)).run(pairs)


def test_groups_json_matches_exe_discover_groups_format(tmp_path):
    from logosfuzz.cli import discover_groups

    result = _built_result(tmp_path, "lg_a", "lg_b")
    corpus_root = tmp_path / "corpus"
    (corpus_root / "lg_a").mkdir(parents=True)              # lg_b 는 코퍼스 폴더 없음

    path = BuildStage.write_groups(result, tmp_path / "out" / "groups.json", corpus_root)
    data = json.loads(path.read_text(encoding="utf-8"))

    # name 은 Logic Group 이름 — 4주차 리포트의 조인 키
    assert [g["name"] for g in data] == ["lg_a", "lg_b"]
    assert all(Path(g["harness"]).is_absolute() for g in data)
    assert data[0]["corpus"] == str((corpus_root / "lg_a").resolve()) and "corpus" not in data[1]

    groups = discover_groups(tmp_path, path)
    assert [g.name for g in groups] == ["lg_a", "lg_b"]
    assert groups[0].corpus_dir is not None and groups[1].corpus_dir is None


def test_groups_json_resolves_bin_symlink_for_docker_runner(tmp_path):
    """`_bin` 은 bazel-out 의 심볼릭 링크다. groups 는 **실제 파일 경로**를 준다.

    docker_runner 는 resolve() 한 폴더를 마운트하고 컨테이너 안에서는 harness_path.name 으로
    실행한다. 링크 경로를 주면 이름(`..._bin`)이 마운트된 폴더(`..._raw_` 가 있다)와 어긋난다.
    """
    real = tmp_path / "execroot" / "lg_a_fuzz_test_raw_"
    real.parent.mkdir()
    real.write_text("", encoding="utf-8")
    link = tmp_path / "bazel-out" / "lg_a_fuzz_test_bin"
    link.parent.mkdir()
    link.symlink_to(real)

    result = BuildStageResult(workspace=str(tmp_path), config="fuzz", started_at="",
                              units=[{"group": "lg_a", "binary": str(link)}])
    [entry] = result.groups()

    assert entry == {"name": "lg_a", "harness": str(real.resolve())}
    assert Path(entry["harness"]).name == real.name              # 마운트 폴더 안의 실제 파일 이름
    assert result.units[0]["binary"] == str(link)                # build_summary 쪽 경로는 그대로


def test_groups_json_skips_groups_without_binary(tmp_path):
    broken = _pair("bad")
    adapter = FakeAdapter(tmp_path, {broken.spec.package: [LOG_UNKNOWN]})
    result = _stage(tmp_path, adapter).run([broken, _pair("good")])
    assert [g["name"] for g in result.groups()] == ["good"]


def test_build_artifacts_follow_harness_artifact_contract(tmp_path):
    from logosfuzz.generate.contracts import ApiSignature, HarnessArtifact

    result = _built_result(tmp_path, "lg_a", "lg_b")
    plan = SimpleNamespace(api_signature=lambda: ApiSignature(
        name="parse", param_types=["const char*"], return_type="int", source="json.h"))

    artifacts = BuildStage.build_artifacts(result, {"lg_a": [plan]}, gen_model="gpt-x")
    by_group = {a.group_id: a for a in artifacts}

    assert all(isinstance(a, HarnessArtifact) for a in artifacts)
    a = by_group["lg_a"]
    unit = result.units[0]
    assert a.harness_path == Path(unit["binary"])
    assert a.source_path == Path(result.workspace) / unit["source"]
    assert a.gen_model == "gpt-x"
    assert [g.name for g in a.api_signatures] == ["parse"]
    assert by_group["lg_b"].api_signatures == []             # 계획이 없으면 빈 목록

    path = BuildStage.write_artifacts(artifacts, tmp_path / "artifacts.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["schema_version"] == "1.0"
    first = data["artifacts"][0]
    assert first["group_id"] == "lg_a" and first["gen_model"] == "gpt-x"
    assert first["api_signatures"][0] == {
        "name": "parse", "param_types": ["const char*"], "return_type": "int", "source": "json.h"}
    assert first["corpus_dir"] is None


# --------------------------------------------------------------------------- #
# CLI 옵션 배선
# --------------------------------------------------------------------------- #
def test_cli_writes_groups_and_artifacts_outputs(tmp_path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    manifest = write_pairs([demo_pair()], tmp_path / "stage")
    groups_out, artifacts_out = tmp_path / "groups.json", tmp_path / "artifacts.json"

    code = main([
        "--mode", "bazel", "--skip-check", "--emit-only",
        "--workspace", str(workspace), "--pairs", str(manifest),
        "--heal-rounds", "2",
        "--groups-out", str(groups_out), "--artifacts-out", str(artifacts_out),
        "--corpus-dir", str(tmp_path / "corpus"), "--gen-model", "gpt-x",
        "--build-summary", str(tmp_path / "bs.json"),
    ])

    assert code == 0
    # emit-only 는 바이너리가 없으므로 목록은 비지만 파일은 만들어진다
    assert json.loads(groups_out.read_text(encoding="utf-8")) == []
    assert json.loads(artifacts_out.read_text(encoding="utf-8"))["artifacts"] == []


def test_cli_deps_kb_without_kb_is_a_clear_error(tmp_path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    harness = tmp_path / "my_fuzz.cc"
    harness.write_text(CC, encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        main(["--mode", "bazel", "--skip-check", "--emit-only",
              "--workspace", str(workspace), "--harness", str(harness),
              "--build-target", SCORE_JSON, "--deps", "kb"])
    assert "KB" in str(exc.value)


def test_cli_invalid_only_pattern_fails_before_any_llm_call(tmp_path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    with pytest.raises(SystemExit) as exc:
        main(["--mode", "bazel", "--skip-check", "--workspace", str(workspace),
              "--kb", str(tmp_path / "nonexistent-kb.json"), "--only", "("])
    assert "--only" in str(exc.value)


def test_source_heal_loop_gets_api_declarations_as_knowledge(tmp_path):
    """생성 때 프롬프트에 넣은 헤더 선언을 자가치유 힌트로도 준다 (D 모듈이 있을 때만)."""
    pytest.importorskip("logosfuzz.generate.bazel_compiler")
    pytest.importorskip("logosfuzz.generate.selfheal")
    from logosfuzz.generate.llm import ScriptedLLMClient

    pair = _pair("lg_v")
    declarations = "// x.h:9 (member of VajsonParser)\nstatic auto FromBuffer(std::string_view) -> Result;"

    def stage(meta):
        return _stage(tmp_path, FakeAdapter(tmp_path), heal_rounds=2,
                      llm=ScriptedLLMClient([]), group_meta=meta)

    loop = stage({"lg_v": {"header_content": declarations}})._make_heal_loop(pair, pair.spec)
    assert loop.max_round == 2
    assert "member of VajsonParser" in loop.knowledge["api_declarations"]
    assert loop.compiler.target == pair.spec.bin_label

    bare = stage({})._make_heal_loop(pair, pair.spec)
    assert "api_declarations" not in (bare.knowledge or {})


def test_generation_artifacts_keep_prompt_and_first_draft(tmp_path):
    """자가치유가 소스를 덮어쓰기 전의 첫 초안과 LLM 이 받은 프롬프트를 남긴다."""
    generated = _pair("lg_gen")
    generated.prompt_used = "PROMPT TEXT"
    generated.source = "FIRST DRAFT"
    from_manifest = _pair("lg_manifest")                 # 프롬프트 기록이 없다(--pairs 로 읽은 쌍)

    written = save_generation_artifacts([generated, from_manifest], tmp_path / "prompts")

    assert sorted(p.name for p in written) == ["lg_gen.draft.cc", "lg_gen.prompt.txt"]
    assert (tmp_path / "prompts" / "lg_gen.prompt.txt").read_text(encoding="utf-8") == "PROMPT TEXT"
    assert (tmp_path / "prompts" / "lg_gen.draft.cc").read_text(encoding="utf-8") == "FIRST DRAFT"
    assert not (tmp_path / "prompts" / "lg_manifest.draft.cc").exists()
    assert save_generation_artifacts([from_manifest], tmp_path / "none") == []
    assert not (tmp_path / "none").exists()              # 쓸 게 없으면 폴더도 만들지 않는다
