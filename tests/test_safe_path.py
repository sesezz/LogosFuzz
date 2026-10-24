import json
import os

import pytest

from logosfuzz.common.safe_path import UnsafePathError, resolve_within, safe_component
from logosfuzz.execute.exe_04_05_corpus_manager import CorpusManager, SeedEntry, SeedManager
from logosfuzz.execute.regression import CommandResult, RegressionRunner
from logosfuzz.generate.bazel.adapter import BazelAdapter
from logosfuzz.generate.bazel.build_file import FuzzTargetSpec


# --------------------------------------------------------------------------- #
# safe_component
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name", ["lg_1", "asan-buffer-overflow", "a.b_c", "그룹_1"])
def test_safe_component_keeps_already_safe_names(name):
    assert safe_component(name) == name


@pytest.mark.parametrize("name", ["../../etc/passwd", "/abs/path", "a/b", "..", ".", "",
                                  "x\x00y", "a\\b", "//score/json:json"])
def test_safe_component_never_yields_a_path_separator_or_dot_segment(name):
    out = safe_component(name)
    assert out not in ("", ".", "..")
    assert "/" not in out and "\\" not in out and "\x00" not in out
    assert not out.startswith(".")


def test_safe_component_distinguishes_inputs_that_clean_to_the_same_text():
    assert safe_component("a/b") != safe_component("a?b")
    assert safe_component("a/b") == safe_component("a/b")


def test_safe_component_limits_length():
    assert len(safe_component("x" * 1000)) <= 120


# --------------------------------------------------------------------------- #
# resolve_within
# --------------------------------------------------------------------------- #
def test_resolve_within_accepts_nested_relative_paths(tmp_path):
    assert resolve_within(tmp_path, "score/x/fuzz", "a.cc") == tmp_path / "score/x/fuzz/a.cc"


@pytest.mark.parametrize("parts", [("..",), ("a/../../x",), ("/etc/passwd",), ("",), (".",), ("a", "..")])
def test_resolve_within_rejects_escape_and_base_itself(tmp_path, parts):
    with pytest.raises(UnsafePathError):
        resolve_within(tmp_path, *parts)


def test_resolve_within_allows_base_only_when_asked(tmp_path):
    assert resolve_within(tmp_path, ".", allow_base=True) == tmp_path


def test_resolve_within_does_not_follow_symlink_out_of_the_base(tmp_path):
    """bazel-bin 처럼 밖을 가리키는 링크 아래의 정상 경로는 허용한다."""
    outside = tmp_path / "outside"
    outside.mkdir()
    base = tmp_path / "ws"
    base.mkdir()
    os.symlink(outside, base / "bazel-bin")
    assert resolve_within(base, "bazel-bin", "pkg", "bin") == base / "bazel-bin" / "pkg" / "bin"


# --------------------------------------------------------------------------- #
# BazelAdapter: package 가 작업 영역을 벗어나면 지우거나 쓰지 않는다
# --------------------------------------------------------------------------- #
def _spec(package, srcs=("h.cc",)):
    return FuzzTargetSpec(name="t_fuzz_test", package=package, srcs=srcs, deps=())


@pytest.mark.parametrize("package", ["../victim", "a/../../victim", "", "."])
def test_bazel_remove_refuses_package_outside_workspace(tmp_path, package):
    ws = tmp_path / "ws"
    ws.mkdir()
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "keep.txt").write_text("keep", encoding="utf-8")
    (ws / "keep.txt").write_text("keep", encoding="utf-8")

    with pytest.raises(UnsafePathError):
        BazelAdapter(ws).remove(_spec(package))

    assert (victim / "keep.txt").exists()
    assert (ws / "keep.txt").exists()


def test_bazel_remove_still_deletes_a_normal_package_and_tolerates_missing(tmp_path):
    adapter = BazelAdapter(tmp_path)
    spec = _spec("score/x/fuzz/lg_x")
    adapter.emit_build_definition(spec, "int x;\n")
    assert (tmp_path / "score/x/fuzz/lg_x/BUILD.bazel").exists()
    adapter.remove(spec)
    assert not (tmp_path / "score/x/fuzz/lg_x").exists()
    adapter.remove(spec)   # 이미 없어도 오류 없음


def test_bazel_emit_refuses_source_name_that_escapes_the_package(tmp_path):
    with pytest.raises(UnsafePathError):
        BazelAdapter(tmp_path).emit_build_definition(_spec("pkg", ("../../evil.cc",)), "x")
    assert not (tmp_path / "evil.cc").exists()


# --------------------------------------------------------------------------- #
# RegressionRunner: manifest 의 케이스 이름이 로그 위치를 정하지 못한다
# --------------------------------------------------------------------------- #
def test_regression_case_name_cannot_escape_the_logs_dir(tmp_path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"cases": [
        {"name": "../../escape", "expected_status": "passed", "run": ["ok"]},
    ]}), encoding="utf-8")
    out = tmp_path / "work" / "out"

    summary = RegressionRunner(out, lambda *a: CommandResult(0, False, "hi", "")).run_manifest(manifest)

    assert summary["matched"] == 1
    assert not (tmp_path / "escape").exists()
    assert not (tmp_path / "work" / "escape").exists()
    assert all(str(p).startswith(str(out)) for p in out.rglob("*"))


# --------------------------------------------------------------------------- #
# 코퍼스 매니저: 그룹명·시드 ID 가 base_dir 밖으로 쓰지 못한다
# --------------------------------------------------------------------------- #
def test_corpus_manager_keeps_files_under_base_dir(tmp_path):
    base = tmp_path / "corpus"
    entry = SeedEntry(seed_id="../../evil", group_name="../../esc", data=b"x", source="initial")
    SeedManager(str(base)).save_seeds([entry])
    crash = SeedEntry(seed_id="../c", group_name="../../esc", data=b"y", source="crash")
    assert CorpusManager(str(base)).add(crash) is True

    written = [p for p in tmp_path.rglob("*") if p.is_file()]
    assert len(written) == 2
    assert all(base in p.parents for p in written)


def test_corpus_manager_round_trips_a_normal_group(tmp_path):
    base = str(tmp_path / "corpus")
    SeedManager(base).save_seeds([SeedEntry("lg_1_a", "lg_1", b"abc", "initial")])
    loaded = SeedManager(base).load_seeds("lg_1")
    assert [e.data for e in loaded] == [b"abc"]
    assert (tmp_path / "corpus" / "lg_1" / "seeds" / "lg_1_a.bin").exists()
