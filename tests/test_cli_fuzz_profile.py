"""``logosfuzz fuzz --profile``: 프로필에서 하네스 위치·빌드 시스템·시드를 읽는다."""

import json
from pathlib import Path

import pytest

from logosfuzz import cli
from logosfuzz.config import LogicGroup
from logosfuzz.execute.seeds import copy_seeds, seed_group_corpora


def _profile(tmp_path, *, seeds=("seeds",), system="cmake"):
    root = tmp_path / "src"
    (root / "seeds").mkdir(parents=True)
    (root / "seeds" / "a.bin").write_bytes(b"A")
    (root / "seeds" / "b.bin").write_bytes(b"B")
    build = {"system": system, "source_root": str(root)}
    if system == "bazel":
        build["bazel"] = {"workspace": ".", "target": "//x:y"}
    data = {"name": "demo", "language": "c", "domain": "generic", "build": build,
            "error_contract": "none", "seeds": list(seeds)}
    path = tmp_path / "demo.json"
    path.write_text(json.dumps(data))
    return path


class FakeSession:
    instances = []

    def __init__(self, config):
        self.config = config
        self.groups = None
        FakeSession.instances.append(self)

    def run(self, groups, ensure_image=True):
        self.groups = groups

        class S:
            total_crashes = 0
            failed_groups = []
        return S()


@pytest.fixture
def fake_session(monkeypatch):
    FakeSession.instances = []
    monkeypatch.setattr(cli, "FuzzSession", FakeSession)
    return FakeSession


def test_profile_sets_harness_dir_image_and_seeds(tmp_path, monkeypatch, fake_session):
    monkeypatch.chdir(tmp_path)
    profile = _profile(tmp_path)
    bin_dir = tmp_path / "out" / "generic" / "demo" / "bin"
    bin_dir.mkdir(parents=True)
    (bin_dir / "g1").write_text("bin")

    rc = cli.main(["fuzz", "--profile", str(profile), "--no-docker", "-o", str(tmp_path / "run")])

    assert rc == 0
    session = fake_session.instances[0]
    assert session.config.harness_dir == Path("out/generic/demo/bin")
    assert session.config.image == "logosfuzz-exec:generic"
    assert session.config.dockerfile == Path("docker/Dockerfile.generic")
    [group] = session.groups
    assert group.corpus_dir == tmp_path / "run" / "corpus" / "g1"
    assert sorted(p.name for p in group.corpus_dir.iterdir()) == ["a.bin", "b.bin"]


def test_explicit_harness_dir_wins_over_profile(tmp_path, fake_session):
    profile = _profile(tmp_path)
    harness = tmp_path / "h"
    harness.mkdir()
    (harness / "g2").write_text("bin")
    rc = cli.main(["fuzz", "--profile", str(profile), "--harness-dir", str(harness),
                   "-o", str(tmp_path / "run")])
    assert rc == 0
    assert fake_session.instances[0].config.harness_dir == harness


def test_bazel_profile_keeps_bazel_image(tmp_path, fake_session):
    profile = _profile(tmp_path, system="bazel")
    harness = tmp_path / "h"
    harness.mkdir()
    (harness / "g").write_text("bin")
    cli.main(["fuzz", "--profile", str(profile), "--harness-dir", str(harness),
              "-o", str(tmp_path / "run")])
    config = fake_session.instances[0].config
    assert config.image == "logosfuzz-exec:latest"
    assert config.dockerfile == Path("docker/Dockerfile")


def test_without_profile_behaviour_is_unchanged(tmp_path, monkeypatch, fake_session):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "harnesses").mkdir()
    (tmp_path / "harnesses" / "g").write_text("bin")
    cli.main(["fuzz", "-o", str(tmp_path / "run")])
    session = fake_session.instances[0]
    assert session.config.harness_dir == Path("harnesses")
    assert session.config.image == "logosfuzz-exec:latest"
    assert session.groups[0].corpus_dir is None


def test_bad_profile_is_reported(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    assert cli.main(["fuzz", "--profile", str(bad)]) == 1
    assert "프로필 오류" in capsys.readouterr().err


def test_aflpp_engine_is_rejected(tmp_path, capsys):
    (tmp_path / "h").mkdir()
    assert cli.main(["fuzz", "--engine", "afl++", "--harness-dir", str(tmp_path / "h")]) == 1
    assert "AFL++" in capsys.readouterr().err


def test_seed_copy_keeps_user_seeds_untouched_and_merges_existing_corpus(tmp_path):
    seeds = tmp_path / "seeds"
    seeds.mkdir()
    (seeds / "x").write_bytes(b"1")
    old = tmp_path / "old"
    old.mkdir()
    (old / "x").write_bytes(b"2")  # 같은 이름, 다른 내용
    [group] = seed_group_corpora([LogicGroup("g", Path("/bin/g"), corpus_dir=old)],
                                 [seeds], tmp_path / "corpus")
    names = sorted(p.name for p in group.corpus_dir.iterdir())
    assert names[0] == "x" and names[1].startswith("x-") and len(names) == 2
    assert copy_seeds([seeds], group.corpus_dir) == 0   # 같은 내용은 다시 복사하지 않는다
    assert sorted(p.name for p in seeds.iterdir()) == ["x"]
