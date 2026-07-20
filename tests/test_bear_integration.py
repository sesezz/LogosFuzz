import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from src.bear_integration import run_bear_build


def test_run_bear_build_creates_compile_commands(tmp_path, monkeypatch):
    output_path = tmp_path / "compile_commands.json"
    expected = [{"directory": str(tmp_path), "command": "gcc -c sample.c", "file": "sample.c"}]

    def fake_run(cmd, cwd=None, capture_output=False, text=False, check=False):
        output_path.write_text(json.dumps(expected), encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, stdout="ok", stderr="")

    monkeypatch.setattr("src.bear_integration.shutil.which", lambda name: "/usr/bin/bear")
    monkeypatch.setattr("src.bear_integration.subprocess.run", fake_run)

    result = run_bear_build("gcc -c sample.c", output_path=str(output_path), cwd=str(tmp_path))

    assert result["status"] == "ok"
    assert output_path.exists()
    assert json.loads(output_path.read_text(encoding="utf-8")) == expected


def test_run_bear_build_requires_bear_binary(monkeypatch):
    monkeypatch.setattr("src.bear_integration.shutil.which", lambda name: None)

    with pytest.raises(FileNotFoundError):
        run_bear_build("gcc -c sample.c", output_path="compile_commands.json")
