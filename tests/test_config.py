import pytest

from logosfuzz.config import Engine, FuzzConfig
from logosfuzz.execute.errors import InvalidEngineError


def test_engine_parse_aliases():
    assert Engine.parse("libfuzzer") is Engine.LIBFUZZER
    assert Engine.parse("afl++") is Engine.AFLPP
    assert Engine.parse("AFL") is Engine.AFLPP


def test_engine_parse_invalid():
    with pytest.raises(InvalidEngineError):
        Engine.parse("honggfuzz")


def test_config_derived_dirs(tmp_path):
    c = FuzzConfig(output_dir=tmp_path / "out")
    assert c.crashes_dir == tmp_path / "out" / "crashes"
    c.ensure_dirs()
    assert c.crashes_dir.exists() and c.logs_dir.exists()
