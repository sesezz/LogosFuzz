import json
from pathlib import Path

from src.compile_db_analyzer import analyze_compile_commands


def test_analyze_compile_commands(tmp_path, monkeypatch):
    compile_commands = [
        {
            "directory": str(tmp_path),
            "command": "gcc -Iinclude -DTEST -std=c11 -c sample.c -o sample.o",
            "file": "sample.c",
        }
    ]
    (tmp_path / "compile_commands.json").write_text(json.dumps(compile_commands), encoding="utf-8")
    (tmp_path / "sample.c").write_text("int main(void) { return 0; }", encoding="utf-8")

    result = analyze_compile_commands(str(tmp_path / "compile_commands.json"), output_path=str(tmp_path / "out.json"))

    assert result[0]["file"].endswith("sample.c")
    assert result[0]["analysis"]["file"].endswith("sample.c")
    assert (tmp_path / "out.json").exists()
