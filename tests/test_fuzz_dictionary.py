"""프로필 libFuzzer 사전 형식 검사·그룹별 배치"""

from pathlib import Path
from types import SimpleNamespace

import pytest

from logosfuzz.execute.dictionary import (
    install_profile_dictionary, parse_entry, validate_dictionary,
)


def _profile(root: Path, dictionary: str):
    # profile.abs 와 같은 source_root 기준 해석만 흉내낸 대역 생성
    return SimpleNamespace(
        dictionary=dictionary,
        abs=lambda p: Path(p) if Path(p).is_absolute() else (root / p).resolve(),
    )


@pytest.mark.parametrize("line, value", [
    (b'"RIFF"', b"RIFF"),
    (b'kw1="fmt "', b"fmt "),
    (b'  name="ID3\\x02"  ', b"ID3\x02"),
    (b'"a\\"b\\\\c"', b'a"b\\c'),
    (b'"X"\r', b"X"),
])
def test_parse_entry_accepts_libfuzzer_syntax(line, value):
    assert parse_entry(line) == value


@pytest.mark.parametrize("line", [
    b'RIFF', b'""', b'"abc', b'"\\q"', b'"\\x4"', b'"\x01"', '"한글"'.encode(),
])
def test_parse_entry_rejects_invalid_lines(line):
    assert parse_entry(line) is None


def test_validate_dictionary_counts_entries_and_skips_comments(tmp_path):
    path = tmp_path / "a.dict"
    path.write_bytes('# 주석\n\n  # 들여쓴 주석\nkw1="RIFF"\r\n"WAVE"\n'.encode())
    assert validate_dictionary(path) == (2, "")


def test_validate_dictionary_reports_bad_line(tmp_path):
    path = tmp_path / "a.dict"
    path.write_bytes(b'"RIFF"\nWAVE\n')
    count, reason = validate_dictionary(path)
    assert ":2 " in reason


def test_validate_dictionary_rejects_empty_and_missing(tmp_path):
    empty = tmp_path / "empty.dict"
    empty.write_bytes(b"# only comment\n")
    assert validate_dictionary(empty)[1]
    assert validate_dictionary(tmp_path / "missing.dict")[1]


def test_install_copies_for_every_group_without_overwriting(tmp_path):
    src = tmp_path / "targets" / "dicts" / "demo.dict"
    src.parent.mkdir(parents=True)
    src.write_bytes(b'"RIFF"\n')
    dict_dir = tmp_path / "out" / "dict"
    dict_dir.mkdir(parents=True)
    (dict_dir / "lg_b.dict").write_bytes(b'"USER"\n')       # 사용자 지정 사전
    root = tmp_path / "third_party" / "demo"
    logs = []

    installed = install_profile_dictionary(
        _profile(root, "../../targets/dicts/demo.dict"), ["lg_a", "lg_b"], dict_dir, log=logs.append)

    assert set(installed) == {"lg_a", "lg_b"}
    assert (dict_dir / "lg_a.dict").read_bytes() == b'"RIFF"\n'
    assert (dict_dir / "lg_b.dict").read_bytes() == b'"USER"\n'
    assert any("[DICT]" in m for m in logs)


@pytest.mark.parametrize("content", [None, b"not a dict\n"])
def test_install_warns_and_skips_missing_or_invalid(tmp_path, content):
    src = tmp_path / "demo.dict"
    if content is not None:
        src.write_bytes(content)
    logs = []
    installed = install_profile_dictionary(
        _profile(tmp_path, str(src)), ["lg_a"], tmp_path / "dict", log=logs.append)
    assert installed == {}
    assert not (tmp_path / "dict").exists()
    assert any("[WARN]" in m for m in logs)


def test_install_without_profile_dictionary_is_noop(tmp_path):
    logs = []
    assert install_profile_dictionary(SimpleNamespace(seeds=()), ["lg_a"], tmp_path / "dict",
                                      log=logs.append) == {}
    assert logs == [] and not (tmp_path / "dict").exists()
