"""logosfuzz regression CLI 서브커맨드 배선 검증."""
from __future__ import annotations

import json

from logosfuzz.cli import _build_parser, main


def test_regression_parser_defaults():
    args = _build_parser().parse_args(["regression", "--manifest", "m.json"])
    assert args.manifest == "m.json" or str(args.manifest) == "m.json"
    assert str(args.output) == "out"
    assert args.failed_only is False


def test_regression_cli_runs_manifest_and_writes_summary(tmp_path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"suite": "cli-smoke", "cases": [
        {"name": "ok", "expected_status": "passed", "run": ["true"]},
    ]}), encoding="utf-8")
    output = tmp_path / "out"

    exit_code = main(["regression", "--manifest", str(manifest), "--output", str(output)])

    assert exit_code == 0
    summary = json.loads((output / "regression-summary.json").read_text(encoding="utf-8"))
    assert summary["matched"] == 1
    assert summary["failed"] == 0


def test_regression_cli_returns_nonzero_on_mismatch(tmp_path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"cases": [
        {"name": "bad", "expected_status": "passed", "run": ["false"]},
    ]}), encoding="utf-8")
    output = tmp_path / "out"

    exit_code = main(["regression", "--manifest", str(manifest), "--output", str(output)])

    assert exit_code == 1
