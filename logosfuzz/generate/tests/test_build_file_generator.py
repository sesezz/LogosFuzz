"""GEN-03 빌드 정의 자동 생성 테스트 (2주차)."""
from __future__ import annotations

from pathlib import Path

import pytest

from logosfuzz.generate.bazel.adapter import BuildResult
from logosfuzz.generate.bazel.build_file import (
    FuzzTargetSpec,
    default_test_name,
    fuzz_package_for,
    parse_label,
    render_build_file,
)
from logosfuzz.generate.bazel.deps_provider import (
    VERIFIED_SCORE_JSON_DEPS,
    BazelQueryDepsProvider,
    StaticDepsProvider,
)
from logosfuzz.generate.bazel.repair import BuildFileRepairer, apply_fix, classify
from logosfuzz.generate.build_file_generator import BuildFileGenerator

SCORE_JSON = "@score_baselibs//score/json"

# D 파트가 tests/fixtures/bazel_errors/ 에 수집한 실제 Bazel 출력에서 발췌.
# 픽스처 디렉터리가 있으면 원본으로 한 번 더 검증한다(아래 fixture 테스트).
LOG_NO_SUCH_TARGET = (
    "ERROR: <WORKSPACE>/harness/BUILD.bazel:3:10: no such target "
    "'//score/json:jsonn': target 'jsonn' not declared in package 'score/json' "
    "defined by <WORKSPACE>/score/json/BUILD.bazel (did you mean json?) "
    "and referenced by '//harness:json_fuzzer'\n"
)
LOG_MISSING_HEADER = (
    "ERROR: <WORKSPACE>/harness/BUILD.bazel:3:10: Compiling harness/json_fuzzer.cc failed\n"
    "harness/json_fuzzer.cc:7:10: fatal error: 'score/json/json.h' file not found\n"
    "1 error generated.\n"
)
LOG_NOT_VISIBLE = (
    "ERROR: <WORKSPACE>/harness/BUILD.bazel:3:10: in cc_binary rule "
    "//harness:json_fuzzer: Visibility error:\n"
    "target '//score/internal:helper' is not visible from\n"
    "target '//harness:json_fuzzer'\n"
)

FIXTURE_DIR = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "bazel_errors"


# --------------------------------------------------------------------------- #
# 라벨 / 패키지 규칙
# --------------------------------------------------------------------------- #
def test_parse_label_without_explicit_target():
    lbl = parse_label(SCORE_JSON)
    assert (lbl.repo, lbl.package, lbl.target) == ("score_baselibs", "score/json", "json")


def test_fuzz_package_is_subpackage_of_target():
    # 대상의 하위 패키지여야 __subpackages__ 가시성에 걸리지 않는다(1주차 실측).
    assert fuzz_package_for(SCORE_JSON) == "score/json/fuzz"


def test_default_test_name():
    assert default_test_name(SCORE_JSON) == "json_fuzz_test"


# --------------------------------------------------------------------------- #
# 렌더러 - 1주차 수동 작성본과 같은 모양이어야 한다
# --------------------------------------------------------------------------- #
def _score_json_spec() -> FuzzTargetSpec:
    return FuzzTargetSpec(
        name="json_parser_fuzz_test",
        package="score/json/fuzz",
        srcs=("json_parser_fuzz.cc",),
        deps=VERIFIED_SCORE_JSON_DEPS[SCORE_JSON],
    )


def test_render_matches_week1_shape():
    text = render_build_file(_score_json_spec())
    assert "SPDX-License-Identifier: Apache-2.0" in text
    assert 'load("@rules_fuzzing//fuzzing:cc_defs.bzl", "cc_fuzz_test")' in text
    assert "cc_fuzz_test(" in text
    assert 'name = "json_parser_fuzz_test",' in text
    assert 'srcs = ["json_parser_fuzz.cc"],' in text
    assert 'tags = ["manual"],' in text
    assert '"@score_baselibs//score/json",' in text
    assert '"@score_baselibs//score/json:parser_interface",' in text


def test_render_matches_overlay_file_byte_for_byte_rule_block():
    """1주차 오버레이 파일의 cc_fuzz_test 블록과 같은 내용을 만들어야 한다."""
    overlay = (
        Path(__file__).resolve().parents[1]
        / "bazel" / "overlay" / "score" / "json" / "fuzz" / "BUILD.bazel"
    )
    if not overlay.exists():
        pytest.skip("오버레이 원본이 없다")
    want = overlay.read_text(encoding="utf-8")
    got = render_build_file(_score_json_spec())

    def rule_block(text: str) -> list[str]:
        lines = text.splitlines()
        start = next(i for i, ln in enumerate(lines) if ln.startswith("cc_fuzz_test("))
        end = next(i for i in range(start, len(lines)) if lines[i] == ")")
        # 주석 줄은 비교에서 뺀다(설명문은 자유롭게 달라질 수 있다).
        return [ln for ln in lines[start:end + 1] if not ln.strip().startswith("#")]

    assert rule_block(got) == rule_block(want)


def test_bin_label_is_the_exe_entrypoint():
    spec = _score_json_spec()
    assert spec.bin_label == "//score/json/fuzz:json_parser_fuzz_test_bin"


# --------------------------------------------------------------------------- #
# deps 공급자 - A 파트(bazel_query) 없이도 돌아야 한다
# --------------------------------------------------------------------------- #
def test_static_provider_returns_verified_deps():
    provider = StaticDepsProvider(VERIFIED_SCORE_JSON_DEPS)
    assert provider.deps_for(SCORE_JSON) == VERIFIED_SCORE_JSON_DEPS[SCORE_JSON]


def test_static_provider_falls_back_to_self():
    assert StaticDepsProvider().deps_for(SCORE_JSON) == (SCORE_JSON,)


def test_bazel_query_provider_is_injectable():
    # A 의 bazel_query 가 나오면 import 없이 주입만으로 갈아끼운다.
    provider = BazelQueryDepsProvider(lambda label: ["//a:b", "//c:d"])
    assert provider.deps_for(SCORE_JSON) == ("//a:b", "//c:d")


# --------------------------------------------------------------------------- #
# 분류 / 수리
# --------------------------------------------------------------------------- #
def test_classify_no_such_target_uses_bazel_suggestion():
    spec = _score_json_spec().with_deps(["@score_baselibs//score/json:jsonn"])
    fix = classify(LOG_NO_SUCH_TARGET, spec)
    assert fix is not None and fix.kind == "rename_dep" and fix.repairable
    fixed = apply_fix(spec, fix)
    assert "@score_baselibs//score/json:json" in fixed.deps
    assert "@score_baselibs//score/json:jsonn" not in fixed.deps


def test_classify_missing_header_adds_dep():
    spec = _score_json_spec().with_deps(["@score_baselibs//score/other"])
    fix = classify(LOG_MISSING_HEADER, spec)
    assert fix is not None and fix.kind == "add_dep"
    assert "@score_baselibs//score/json" in apply_fix(spec, fix).deps


def test_classify_not_visible_is_not_auto_repairable():
    # deps 를 더해서 풀리는 문제가 아니다. 사람이 볼 일로 넘긴다.
    fix = classify(LOG_NOT_VISIBLE, _score_json_spec())
    assert fix is not None and fix.kind == "not_visible" and not fix.repairable


def test_classify_clean_log_returns_none():
    assert classify("INFO: Build completed successfully", _score_json_spec()) is None


def test_repairer_accepts_injected_classifier():
    """D 파트의 build_errors.py 가 나오면 이렇게 주입한다."""
    calls = []

    def fake(log, spec):
        calls.append(spec.label)
        return None

    BuildFileRepairer(classifier=fake).repair(_score_json_spec(), "whatever")
    assert calls == ["//score/json/fuzz:json_parser_fuzz_test"]


@pytest.mark.parametrize("case", ["no_such_target", "missing_dep", "not_visible"])
def test_classify_against_collected_fixtures(case):
    """D 가 수집한 실제 Bazel 출력으로도 분류가 되는가."""
    path = FIXTURE_DIR / f"{case}.txt"
    if not path.exists():
        pytest.skip("tests/fixtures/bazel_errors 가 아직 이 브랜치에 없다")
    fix = classify(path.read_text(encoding="utf-8"), _score_json_spec())
    assert fix is not None, f"{case} 를 분류하지 못했다"


# --------------------------------------------------------------------------- #
# 생성 -> 빌드 -> 자가치유 루프 (2주차 완료 기준)
# --------------------------------------------------------------------------- #
class FakeAdapter:
    """지정한 로그로 실패하다가 N번째에 성공하는 어댑터."""

    def __init__(self, fail_logs: list[str], workspace: Path):
        self.fail_logs = list(fail_logs)
        self.workspace = workspace
        self.emitted: list[FuzzTargetSpec] = []

    def emit_build_definition(self, spec, harness_source):
        pkg = self.workspace / spec.package
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / spec.srcs[0]).write_text(harness_source, encoding="utf-8")
        path = pkg / "BUILD.bazel"
        path.write_text(render_build_file(spec), encoding="utf-8")
        self.emitted.append(spec)
        return path

    def build(self, spec):
        if self.fail_logs:
            return BuildResult(ok=False, target=spec.bin_label, log=self.fail_logs.pop(0))
        binary = self.workspace / "bazel-bin" / spec.package / f"{spec.name}_bin"
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_text("", encoding="utf-8")
        return BuildResult(ok=True, target=spec.bin_label, binary=binary)

    def remove(self, spec):
        pass


def test_generate_succeeds_first_round(tmp_path):
    gen = BuildFileGenerator(
        adapter=FakeAdapter([], tmp_path),
        deps_provider=StaticDepsProvider(VERIFIED_SCORE_JSON_DEPS),
    )
    report = gen.generate(SCORE_JSON, "int LLVMFuzzerTestOneInput(){return 0;}")
    assert report.ok
    assert report.rounds_used == 1
    assert report.repaired is False
    assert report.binary is not None


def test_generate_repairs_missing_dep_and_succeeds(tmp_path):
    """2주차 완료 기준: 실패 시 자가치유가 1회 이상 복구한다."""
    adapter = FakeAdapter([LOG_MISSING_HEADER], tmp_path)
    gen = BuildFileGenerator(
        adapter=adapter,
        # 일부러 틀린 deps 로 시작한다.
        deps_provider=StaticDepsProvider({SCORE_JSON: ["@score_baselibs//score/other"]}),
    )
    report = gen.generate(SCORE_JSON, "int LLVMFuzzerTestOneInput(){return 0;}")

    assert report.ok
    assert report.repaired is True
    assert report.rounds_used == 2
    assert report.rounds[0].fix is not None
    assert report.rounds[0].fix.kind == "add_dep"
    # 수리된 deps 로 BUILD 를 다시 썼는가
    assert "@score_baselibs//score/json" in adapter.emitted[-1].deps
    # 라운드 로그가 남는가
    assert [r["ok"] for r in report.to_dict()["rounds"]] == [False, True]


def test_generate_gives_up_on_unrepairable_error(tmp_path):
    gen = BuildFileGenerator(
        adapter=FakeAdapter([LOG_NOT_VISIBLE, LOG_NOT_VISIBLE], tmp_path),
        deps_provider=StaticDepsProvider(VERIFIED_SCORE_JSON_DEPS),
    )
    report = gen.generate(SCORE_JSON, "src")
    assert not report.ok
    assert report.rounds_used == 1        # 못 고치는 건 재시도하지 않는다
    assert report.rounds[0].fix.kind == "not_visible"


def test_generate_respects_max_rounds(tmp_path):
    logs = [LOG_MISSING_HEADER.replace("score/json", f"score/p{i}") for i in range(5)]
    gen = BuildFileGenerator(
        adapter=FakeAdapter(logs, tmp_path),
        deps_provider=StaticDepsProvider({SCORE_JSON: ["@score_baselibs//score/other"]}),
        max_rounds=3,
    )
    report = gen.generate(SCORE_JSON, "src")
    assert not report.ok
    assert report.rounds_used == 3


def test_successful_deps_are_learned_back(tmp_path):
    provider = StaticDepsProvider({SCORE_JSON: ["@score_baselibs//score/other"]})
    gen = BuildFileGenerator(adapter=FakeAdapter([LOG_MISSING_HEADER], tmp_path), deps_provider=provider)
    gen.generate(SCORE_JSON, "src")
    # 다음 생성에서는 고쳐진 deps 로 바로 시작한다.
    assert "@score_baselibs//score/json" in provider.deps_for(SCORE_JSON)


# --------------------------------------------------------------------------- #
# 바이너리 경로 해석 - bazel-bin 심링크에 기대면 안 된다
# --------------------------------------------------------------------------- #
def _adapter_with_fake_run(tmp_path, *, code, stdout):
    """_run 만 가짜로 바꾼 BazelAdapter."""
    from logosfuzz.generate.bazel.adapter import BazelAdapter

    adapter = BazelAdapter(tmp_path)
    adapter._run = lambda args: (code, stdout, "", 0.0)  # noqa: SLF001
    return adapter


def _spec_for_binary_tests() -> FuzzTargetSpec:
    return FuzzTargetSpec(
        name="json_fuzz_test",
        package="score/json/fuzz",
        srcs=("json_fuzz.cc",),
        deps=(SCORE_JSON,),
    )


def test_binary_path_uses_cquery_result(tmp_path):
    spec = _spec_for_binary_tests()
    real = tmp_path / "bazel-out/k8-fastbuild-ST-abc/bin/score/json/fuzz/json_fuzz_test_bin"
    real.parent.mkdir(parents=True)
    real.write_text("", encoding="utf-8")

    adapter = _adapter_with_fake_run(tmp_path, code=0, stdout=f"{real}\n")
    assert adapter._binary_path(spec) == real  # noqa: SLF001


def test_binary_path_picks_the_bin_target_among_several(tmp_path):
    spec = _spec_for_binary_tests()
    out_dir = tmp_path / "bazel-out/k8-fastbuild-ST-abc/bin/score/json/fuzz"
    out_dir.mkdir(parents=True)
    other = out_dir / "json_fuzz_test.runfiles_manifest"
    want = out_dir / "json_fuzz_test_bin"
    for f in (other, want):
        f.write_text("", encoding="utf-8")

    adapter = _adapter_with_fake_run(tmp_path, code=0, stdout=f"{other}\n{want}\n")
    assert adapter._binary_path(spec) == want  # noqa: SLF001


def test_binary_path_falls_back_when_cquery_unavailable(tmp_path):
    spec = _spec_for_binary_tests()
    legacy = tmp_path / "bazel-bin/score/json/fuzz/json_fuzz_test_bin"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("", encoding="utf-8")

    adapter = _adapter_with_fake_run(tmp_path, code=1, stdout="")
    assert adapter._binary_path(spec) == legacy  # noqa: SLF001


def test_binary_path_ignores_stale_cquery_paths(tmp_path):
    """회귀 빌드로 트리가 바뀌어 경로가 사라진 경우 None 을 돌려준다."""
    spec = _spec_for_binary_tests()
    adapter = _adapter_with_fake_run(
        tmp_path, code=0, stdout=str(tmp_path / "gone/json_fuzz_test_bin") + "\n"
    )
    assert adapter._binary_path(spec) is None  # noqa: SLF001
