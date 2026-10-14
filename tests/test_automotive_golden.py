"""자동차(Bazel) 모드 골든 회귀 - 범용화 작업이 --mode bazel 산출물을 바꾸지 않았는지."""

import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_automotive_golden.py"


def _load():
    spec = importlib.util.spec_from_file_location("check_automotive_golden", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_bazel_emit_only_matches_golden(tmp_path):
    diff = _load().check(tmp_path / "ws")
    assert diff == [], "\n".join(diff)
