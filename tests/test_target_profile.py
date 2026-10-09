import copy
import dataclasses
import json
from pathlib import Path

import pytest

from logosfuzz.common.target_profile import (
    ProfileError,
    TargetProfile,
    load_profile,
    parse_profile,
)


REPO_ROOT = Path(__file__).resolve().parents[1]

CMAKE_PROFILE = {
    "name": "demo",
    "version": "1.0",
    "language": "c",
    "domain": "generic",
    "build": {
        "system": "cmake",
        "source_root": "src/demo",
        "build_dir": "build",
        "configure_args": ["-DBUILD_SHARED_LIBS=OFF"],
        "libraries": ["build/libdemo.a"],
        "include_dirs": ["include"],
        "link_flags": ["-lm"],
        "compile_commands": "build/compile_commands.json",
        "bazel": None,
    },
    "apis": ["demo_open", "demo_close"],
    "error_contract": "c_return_code",
    "embedded": {
        "strip_flags": ["-mcpu=*", "-mthumb"],
        "stub_undefined": True,
        "stub_allowlist": ["HAL_*"],
    },
    "seeds": ["seeds"],
}


def _write(tmp_path, data, name="profile.json"):
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _mutated(**changes):
    data = copy.deepcopy(CMAKE_PROFILE)
    for dotted, value in changes.items():
        node = data
        keys = dotted.split("__")
        for key in keys[:-1]:
            node = node[key]
        if value is _DELETE:
            del node[keys[-1]]
        else:
            node[keys[-1]] = value
    return data


_DELETE = object()


# ---------------------------------------------------------------------
# 정상 로드
# ---------------------------------------------------------------------

def test_load_cmake_profile(tmp_path):
    profile = load_profile(_write(tmp_path, CMAKE_PROFILE), base_dir=tmp_path)

    assert isinstance(profile, TargetProfile)
    assert profile.name == "demo"
    assert profile.language == "c"
    assert profile.build.system == "cmake"
    assert profile.build.bazel is None
    assert profile.build.libraries == ("build/libdemo.a",)
    assert profile.apis == ("demo_open", "demo_close")
    assert profile.embedded.strip_flags == ("-mcpu=*", "-mthumb")
    assert profile.embedded.stub_undefined is True
    assert profile.seeds == ("seeds",)
    assert not profile.is_bazel and not profile.is_automotive


def test_profile_is_frozen(tmp_path):
    profile = load_profile(_write(tmp_path, CMAKE_PROFILE), base_dir=tmp_path)
    with pytest.raises(dataclasses.FrozenInstanceError):
        profile.name = "other"
    with pytest.raises(dataclasses.FrozenInstanceError):
        profile.build.system = "bazel"


def test_abs_resolves_against_source_root(tmp_path):
    profile = load_profile(_write(tmp_path, CMAKE_PROFILE), base_dir=tmp_path)
    root = (tmp_path / "src" / "demo").resolve()

    assert profile.root == root
    assert profile.abs("build/libdemo.a") == root / "build" / "libdemo.a"
    assert profile.abs(profile.build.compile_commands) == root / "build" / "compile_commands.json"
    absolute = (tmp_path / "elsewhere").resolve()
    assert profile.abs(absolute) == absolute


def test_absolute_source_root_ignores_base_dir(tmp_path):
    data = _mutated(build__source_root=str(tmp_path / "abs_root"))
    profile = parse_profile(data, base_dir="/nonexistent")
    assert profile.root == (tmp_path / "abs_root").resolve()


def test_optional_sections_default(tmp_path):
    data = _mutated(embedded=_DELETE, seeds=_DELETE, apis=_DELETE, version=_DELETE)
    del data["build"]["bazel"]
    profile = parse_profile(data, base_dir=tmp_path)

    assert profile.embedded.strip_flags == ()
    assert profile.embedded.stub_undefined is False
    assert profile.apis == ()
    assert profile.seeds == ()
    assert profile.version == ""


def test_seeds_accepts_single_string(tmp_path):
    profile = parse_profile(_mutated(seeds="corpus"), base_dir=tmp_path)
    assert profile.seeds == ("corpus",)


def test_comment_keys_are_ignored(tmp_path):
    data = _mutated(_comment="메모")
    data["build"]["_note"] = "메모"
    assert parse_profile(data, base_dir=tmp_path).name == "demo"


def test_bazel_profile(tmp_path):
    data = _mutated(
        language="cpp",
        domain="automotive",
        error_contract="score_result",
        build__system="bazel",
        build__bazel={"workspace": ".", "target": "//score/json:json"},
    )
    profile = parse_profile(data, base_dir=tmp_path)

    assert profile.is_bazel and profile.is_automotive
    assert profile.build.bazel.target == "//score/json:json"
    assert profile.abs(profile.build.bazel.workspace) == profile.root


def test_to_dict_round_trip(tmp_path):
    profile = parse_profile(CMAKE_PROFILE, base_dir=tmp_path)
    again = parse_profile(profile.to_dict(), base_dir=tmp_path)
    assert again == profile


@pytest.mark.parametrize("name", ["libsndfile.json", "automotive.json"])
def test_repo_target_profiles_load(name):
    profile = load_profile(REPO_ROOT / "targets" / name, base_dir=REPO_ROOT)
    assert profile.name


def test_repo_libsndfile_profile_contents():
    profile = load_profile(REPO_ROOT / "targets" / "libsndfile.json", base_dir=REPO_ROOT)
    assert profile.version == "1.2.2"
    assert profile.domain == "generic"
    assert profile.build.system == "cmake"
    assert profile.error_contract == "c_return_code"
    assert profile.build.libraries == ("build-fuzz/libsndfile.a",)
    assert profile.build.include_dirs == ("include",)
    assert profile.build.compile_commands == "build-fuzz/compile_commands.json"
    assert profile.apis == (
        "sf_open", "sf_open_virtual", "sf_read_short", "sf_readf_float",
        "sf_seek", "sf_command", "sf_get_string", "sf_close",
    )
    for arg in ("-DBUILD_SHARED_LIBS=OFF", "-DBUILD_PROGRAMS=OFF", "-DBUILD_EXAMPLES=OFF",
                "-DBUILD_TESTING=OFF", "-DENABLE_EXTERNAL_LIBS=OFF"):
        assert arg in profile.build.configure_args


def test_repo_automotive_profile_contents():
    profile = load_profile(REPO_ROOT / "targets" / "automotive.json", base_dir=REPO_ROOT)
    assert profile.domain == "automotive"
    assert profile.build.system == "bazel"
    assert profile.error_contract == "score_result"
    assert profile.build.bazel.target == "//score/json:json"


# ---------------------------------------------------------------------
# 오류 케이스
# ---------------------------------------------------------------------

@pytest.mark.parametrize(
    "changes, message",
    [
        ({"language": "rust"}, "language"),
        ({"domain": "aerospace"}, "domain"),
        ({"error_contract": "exceptions"}, "error_contract"),
        ({"build__system": "make"}, "system"),
        ({"name": _DELETE}, "name"),
        ({"name": ""}, "name"),
        ({"language": _DELETE}, "language"),
        ({"build": _DELETE}, "build"),
        ({"build__source_root": _DELETE}, "source_root"),
        ({"build__system": "bazel"}, "bazel"),
        ({"build__system": "bazel", "build__bazel": {"workspace": "."}}, "target"),
        ({"build__system": "bazel", "build__bazel": {"workspace": ".", "target": "score/json"}}, "라벨"),
        ({"build__bazel": {"workspace": ".", "target": "//a:b"}}, "system=bazel"),
        ({"build__libraries": "build/libdemo.a"}, "libraries"),
        ({"build__include_dirs": [1, 2]}, "include_dirs"),
        ({"apis": ["a", "a"]}, "중복"),
        ({"embedded__stub_undefined": "yes"}, "stub_undefined"),
        ({"embedded": ["-mthumb"]}, "embedded"),
        ({"unknown_field": 1}, "unknown_field"),
        ({"build__cmake_args": []}, "cmake_args"),
        ({"embedded__strip": []}, "strip"),
    ],
)
def test_invalid_profiles_raise(tmp_path, changes, message):
    with pytest.raises(ProfileError, match=message):
        load_profile(_write(tmp_path, _mutated(**changes)), base_dir=tmp_path)


def test_missing_file_raises(tmp_path):
    with pytest.raises(ProfileError, match="읽을 수 없다"):
        load_profile(tmp_path / "nope.json")


def test_broken_json_raises(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{ not json", encoding="utf-8")
    with pytest.raises(ProfileError, match="JSON"):
        load_profile(path)


def test_top_level_must_be_object(tmp_path):
    path = tmp_path / "list.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(ProfileError, match="객체"):
        load_profile(path)


def test_profile_error_is_value_error():
    assert issubclass(ProfileError, ValueError)
