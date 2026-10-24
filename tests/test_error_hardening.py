import json
import sys
from pathlib import Path

import pytest

from logosfuzz.common.redact import redact_error
from logosfuzz.control.ctr_06_01_controller import (
    AutoPipeline,
    BuildStageResult,
    PipelineResult,
    RegressionTester,
)
from logosfuzz.execute.exe_04_05_corpus_manager import SeedEntry
from logosfuzz.execute.regression import RegressionRunner, _execute
from logosfuzz.generate.bazel.adapter import BazelAdapter
from logosfuzz.generate.bazel.build_file import FuzzTargetSpec
from logosfuzz.generate.build.base import DEFAULT_BUILD_TIMEOUT_S
from logosfuzz.generate.gen_03_01_harness_generator import HarnessPair, write_pairs
from logosfuzz.common.safe_path import UnsafePathError


# --------------------------------------------------------------------------- #
# redact_error
# --------------------------------------------------------------------------- #
def test_redact_error_replaces_home_and_shortens_absolute_paths():
    home = str(Path.home())
    out = redact_error(f"open failed: {home}/work/secret/a.c and /opt/tools/clang/bin/clang")
    assert home not in out
    assert "/work/secret" not in out and "/opt/tools" not in out
    assert "a.c" in out and "clang" in out


def test_redact_error_keeps_the_tail_and_limits_size():
    text = "\n".join(f"line {i}" for i in range(100))
    out = redact_error(text, max_lines=3)
    assert out.splitlines() == ["line 97", "line 98", "line 99"]
    assert len(redact_error("x" * 5000, max_chars=50)) <= 53


def test_redact_error_accepts_exceptions_and_none():
    assert "boom" in redact_error(RuntimeError("boom"))
    assert redact_error(None) == ""


def test_redact_error_leaves_urls_and_relative_paths_alone():
    assert redact_error("see https://example.com/a/b and src/x.c:3") == "see https://example.com/a/b and src/x.c:3"


# --------------------------------------------------------------------------- #
# 저장되는 오류에 절대경로가 남지 않는다
# --------------------------------------------------------------------------- #
def test_regression_execute_error_hides_the_missing_path(tmp_path):
    result = _execute(["/nonexistent_dir_xyz/tool"], tmp_path, 2.0, {})
    assert result.error
    assert "/nonexistent_dir_xyz" not in result.error


def test_auto_pipeline_stores_redacted_stderr(tmp_path):
    script = tmp_path / "fake_pipeline.py"
    script.write_text(
        "import sys\n"
        "sys.stderr.write('Traceback...\\nFileNotFoundError: /home/someone/private/src/a.c\\n')\n"
        "sys.exit(1)\n", encoding="utf-8")
    result = AutoPipeline(str(script)).run(str(tmp_path / "a.c"), str(tmp_path / "out.c"), budget=30)
    assert result.success is False
    assert "/home/someone" not in result.error
    assert "a.c" in result.error


# --------------------------------------------------------------------------- #
# exists() 확인 없이도 파일이 없을 때 같은 결과를 낸다
# --------------------------------------------------------------------------- #
def test_failed_only_without_previous_summary_reruns_nothing(tmp_path):
    """이전 요약이 없으면 다시 돌릴 실패 케이스가 없다(기존 동작 유지, 예외 없음)."""
    manifest = tmp_path / "m.json"
    manifest.write_text(json.dumps({"cases": [
        {"name": "a", "expected_status": "passed", "run": ["a"]}]}), encoding="utf-8")
    from logosfuzz.execute.regression import CommandResult
    summary = RegressionRunner(tmp_path / "out", lambda *x: CommandResult(0, False)).run_manifest(
        manifest, failed_only=True)
    assert summary["total"] == 0


def test_compare_reports_missing_baseline(tmp_path):
    tester = RegressionTester()
    missing = str(tmp_path / "none.json")
    cur = PipelineResult("r", "s", "o", "t", harness_count=2)
    reg = tester.compare(cur, missing)
    assert reg.passed is False and "Baseline not found" in reg.message
    build_reg = tester.compare_build(
        BuildStageResult(workspace=str(tmp_path), config="fuzz", started_at="t"), missing)
    assert build_reg.passed is False and "Baseline not found" in build_reg.message


# --------------------------------------------------------------------------- #
# 빌드 명령 기본 제한 시간
# --------------------------------------------------------------------------- #
def test_bazel_adapter_has_a_default_timeout_but_accepts_override(tmp_path):
    assert BazelAdapter(tmp_path).timeout_s == DEFAULT_BUILD_TIMEOUT_S
    assert BazelAdapter(tmp_path, timeout_s=None).timeout_s == DEFAULT_BUILD_TIMEOUT_S
    assert BazelAdapter(tmp_path, timeout_s=12.5).timeout_s == 12.5


# --------------------------------------------------------------------------- #
# 시드 체크섬
# --------------------------------------------------------------------------- #
def test_seed_checksum_is_sha256():
    import hashlib
    entry = SeedEntry("s", "g", b"abc", "initial")
    assert entry.checksum == hashlib.sha256(b"abc").hexdigest()


# --------------------------------------------------------------------------- #
# write_pairs: package·파일명이 out_root 밖으로 나가지 못한다
# --------------------------------------------------------------------------- #
def _pair(package, src="h.cc"):
    spec = FuzzTargetSpec(name="x_fuzz_test", package=package, srcs=(src,), deps=())
    return HarnessPair(group_name="x", target_label="//a:b", spec=spec, source="int x;\n")


@pytest.mark.parametrize("pair", [_pair("../../escape"), _pair("pkg", "../../evil.cc"), _pair("")])
def test_write_pairs_refuses_paths_outside_out_root(tmp_path, pair):
    out = tmp_path / "work" / "out"
    out.mkdir(parents=True)
    with pytest.raises(UnsafePathError):
        write_pairs([pair], out)
    assert not (tmp_path / "escape").exists()
    assert not (tmp_path / "evil.cc").exists()


def test_write_pairs_refuses_manifest_name_outside_out_root(tmp_path):
    out = tmp_path / "out"
    with pytest.raises(UnsafePathError):
        write_pairs([_pair("pkg")], out, manifest_name="../manifest.json")
    assert not (tmp_path / "manifest.json").exists()


def test_write_pairs_still_writes_a_normal_pair(tmp_path):
    manifest = write_pairs([_pair("score/x/fuzz/x")], tmp_path)
    assert manifest.exists()
    assert (tmp_path / "score/x/fuzz/x/h.cc").read_text(encoding="utf-8") == "int x;\n"
