import json
import os
from pathlib import Path

import pytest

from logosfuzz.common.target_profile import parse_profile
from logosfuzz.extract import compile_db
from logosfuzz.extract.compile_db import (
    CompileDbError,
    extract_flags,
    flags_by_file,
    flags_for_profile,
    load_compile_db,
    merged_flags,
    strip_args,
)


FIXTURE = Path(__file__).parent / "fixtures" / "compile_db" / "compile_commands.json"
EMBEDDED_STRIP = ("-mcpu=*", "-mthumb", "-mfloat-abi=*", "--specs=*")


def _n(*parts):
    return os.path.normpath(os.path.join(*parts))


@pytest.fixture
def root(tmp_path):
    return tmp_path.resolve()


@pytest.fixture
def db(root):
    # fixture 의 @ROOT@ 를 실제 임시 경로로 바꿔 OS 에 맞는 절대경로를 만든다.
    text = FIXTURE.read_text(encoding="utf-8").replace("@ROOT@", root.as_posix())
    path = root / "build-fuzz" / "compile_commands.json"
    path.parent.mkdir(parents=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_load_accepts_command_and_arguments(db, root):
    entries = load_compile_db(db)

    assert len(entries) == 3
    assert entries[0].arguments[0] == "/usr/bin/cc"
    assert "-DHAVE_CONFIG_H" in entries[0].arguments
    assert entries[1].arguments[0] == "arm-none-eabi-gcc"
    # 상대 file 은 directory 기준으로 절대화
    assert entries[1].file == _n(str(root), "src", "hal.c")


def test_command_string_flags(db, root):
    flags = flags_by_file(db)[_n(str(root), "src", "sndfile.c")]

    assert flags.include_dirs[:3] == [
        _n(str(root), "build-fuzz", "src"),
        _n(str(root), "include"),          # -I../include → directory 기준
        _n(str(root), "src"),              # -I <dir> 분리형
    ]
    assert flags.system_include_dirs == [_n("/opt/sysroot/include")]
    assert flags.defines[:2] == ["HAVE_CONFIG_H", 'PACKAGE_NAME="libsndfile"']
    assert "-O2" not in flags.clang_args()


def test_duplicate_file_entries_are_merged(db, root):
    flags = flags_by_file(db)[_n(str(root), "src", "sndfile.c")]

    assert "EXTRA=1" in flags.defines
    # ../include 는 두 항목에 모두 있지만 한 번만
    assert flags.include_dirs.count(_n(str(root), "include")) == 1
    # 첫 항목의 std 가 유지된다
    assert flags.std == "gnu99"


def test_last_std_wins_within_one_command(root):
    flags = extract_flags(["cc", "-std=c99", "-std=c11", "-c", "a.c"], str(root))
    assert flags.std == "c11"


def test_arguments_array_relative_isystem(db, root):
    flags = flags_by_file(db)[_n(str(root), "src", "hal.c")]

    assert flags.include_dirs == [_n(str(root), "build-fuzz", "include")]
    assert flags.system_include_dirs == [_n(str(root), "third_party", "cmsis")]
    assert flags.defines == ["STM32F4"]
    assert flags.std == "c11"


def test_strip_flags_remove_cross_compile_tokens():
    args = ["-mcpu=cortex-m4", "-mthumb", "--specs=nano.specs", "-DX", "-mthumb-interwork"]
    assert strip_args(args, EMBEDDED_STRIP) == ["-DX", "-mthumb-interwork"]
    assert strip_args(args, ()) == args


def test_clang_args_after_strip(db, root):
    flags = flags_by_file(db, EMBEDDED_STRIP)[_n(str(root), "src", "hal.c")]
    args = flags.clang_args()

    assert not any(a.startswith(("-mcpu", "--specs")) or a == "-mthumb" for a in args)
    assert args == [
        "-I" + _n(str(root), "build-fuzz", "include"),
        "-isystem", _n(str(root), "third_party", "cmsis"),
        "-DSTM32F4",
        "-std=c11",
    ]


def test_strip_can_drop_defines_too(root):
    flags = extract_flags(["cc", "-DARM_MATH_CM4", "-DKEEP", "-c", "a.c"], str(root), ("-DARM_*",))
    assert flags.defines == ["KEEP"]


def test_merged_flags_union(db, root):
    merged = merged_flags(db, EMBEDDED_STRIP)

    assert _n(str(root), "include") in merged.include_dirs
    assert _n(str(root), "build-fuzz", "include") in merged.include_dirs
    assert set(merged.defines) >= {"HAVE_CONFIG_H", "STM32F4", "EXTRA=1"}
    assert merged.std == "gnu99"


def test_flags_for_profile_uses_compile_commands_and_strip(db, root):
    profile = parse_profile({
        "name": "demo",
        "language": "c",
        "domain": "embedded",
        "error_contract": "c_return_code",
        "build": {
            "system": "cmake",
            "source_root": str(root),
            "compile_commands": "build-fuzz/compile_commands.json",
        },
        "embedded": {"strip_flags": list(EMBEDDED_STRIP)},
    })
    flags = flags_for_profile(profile)[_n(str(root), "src", "hal.c")]
    assert "-mthumb" not in flags.clang_args()
    assert flags.defines == ["STM32F4"]


def test_profile_without_compile_commands_raises(root):
    profile = parse_profile({
        "name": "demo", "language": "c", "domain": "generic", "error_contract": "none",
        "build": {"system": "prebuilt", "source_root": str(root)},
    })
    with pytest.raises(CompileDbError, match="compile_commands"):
        flags_for_profile(profile)


@pytest.mark.parametrize(
    "content, message",
    [
        ("{}", "배열"),
        ("not json", "파싱"),
        ('[{"file": "a.c"}]', "directory"),
        ('[{"file": "a.c", "directory": "/w"}]', "arguments"),
    ],
)
def test_invalid_db_raises(tmp_path, content, message):
    path = tmp_path / "compile_commands.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(CompileDbError, match=message):
        load_compile_db(path)


def test_missing_db_raises(tmp_path):
    with pytest.raises(CompileDbError, match="읽을 수 없다"):
        load_compile_db(tmp_path / "nope.json")


def test_cli_merged_output(db, tmp_path, capsys):
    out = tmp_path / "out" / "flags.json"
    rc = compile_db.main(["--compile-db", str(db), "--strip-flag=-mcpu=*", "--merged",
                          "--output", str(out)])
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert "STM32F4" in data["defines"]
    assert all(not a.startswith("-mcpu") for a in data["clang_args"])


def test_cli_missing_db_returns_error(tmp_path, capsys):
    assert compile_db.main(["--compile-db", str(tmp_path / "nope.json")]) == 1
    assert "ERROR" in capsys.readouterr().err
