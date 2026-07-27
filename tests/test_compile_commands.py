import json
from pathlib import Path

from src.compile_commands import load_compile_commands, list_sources


def test_load_compile_commands(tmp_path):
    path = tmp_path / "compile_commands.json"
    data = [
        {"directory": str(tmp_path), "command": "gcc -c sample.c", "file": "sample.c"}
    ]
    path.write_text(json.dumps(data), encoding="utf-8")

    loaded = load_compile_commands(str(path))
    assert loaded == data
    assert list_sources(str(path)) == ["sample.c"]
