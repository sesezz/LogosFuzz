import pytest

from logosfuzz.config import Engine, FuzzConfig
from logosfuzz.execute.errors import InvalidEngineError


def test_engine_parse_aliases():
    assert Engine.parse("libfuzzer") is Engine.LIBFUZZER
    assert Engine.parse("LibFuzzer") is Engine.LIBFUZZER


@pytest.mark.parametrize("name", ["afl++", "AFL", "aflpp"])
def test_engine_parse_rejects_aflpp_not_in_image(name):
    # 실행 이미지(docker/Dockerfile*)에 AFL++ 가 없으므로 받지 않는다.
    with pytest.raises(InvalidEngineError, match="AFL"):
        Engine.parse(name)


def test_engine_parse_invalid():
    with pytest.raises(InvalidEngineError):
        Engine.parse("honggfuzz")


def test_config_derived_dirs(tmp_path):
    c = FuzzConfig(output_dir=tmp_path / "out")
    assert c.crashes_dir == tmp_path / "out" / "crashes"
    c.ensure_dirs()
    assert c.crashes_dir.exists() and c.logs_dir.exists()
