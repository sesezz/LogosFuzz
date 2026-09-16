"""logosfuzz regression CLI 서브커맨드 배선 검증."""
from __future__ import annotations

import json
import sys

from logosfuzz.cli import _build_parser, main

# `true` / `false` 는 유닉스 실행 파일이라 Windows 에는 없다. 러너가 argv 리스트를
# 그대로 subprocess.run 에 넘기므로 셸 빌트인으로도 대체되지 않는다. 현재
# 인터프리터를 쓰면 어느 플랫폼에서든 같은 종료 코드를 얻는다.
EXIT_OK = [sys.executable, "-c", "raise SystemExit(0)"]
EXIT_FAIL = [sys.executable, "-c", "raise SystemExit(1)"]


def test_regression_parser_defaults():
    args = _build_parser().parse_args(["regression", "--manifest", "m.json"])
    assert args.manifest == "m.json" or str(args.manifest) == "m.json"
    assert str(args.output) == "out"
    assert args.failed_only is False


def test_regression_cli_runs_manifest_and_writes_summary(tmp_path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"suite": "cli-smoke", "cases": [
        {"name": "ok", "expected_status": "passed", "run": EXIT_OK},
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
        {"name": "bad", "expected_status": "passed", "run": EXIT_FAIL},
    ]}), encoding="utf-8")
    output = tmp_path / "out"

    exit_code = main(["regression", "--manifest", str(manifest), "--output", str(output)])

    assert exit_code == 1
