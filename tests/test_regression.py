import json

from logosfuzz.execute.regression import CommandResult, RegressionRunner


def test_regression_classifies_all_required_outcomes(tmp_path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"cases": [
        {"name": "ok", "expected_status": "passed", "run": ["ok"]},
        {"name": "compile", "expected_status": "compile_failed",
         "compile": ["bad-cc"], "run": ["never"]},
        {"name": "timeout", "expected_status": "timeout", "run": ["timeout"]},
        {"name": "crash", "expected_status": "crashed", "run": ["crash"]},
        {"name": "asan", "expected_status": "sanitizer_error", "run": ["asan"]},
        {"name": "exec-fail", "expected_status": "execution_failed", "run": ["fail"]},
    ]}), encoding="utf-8")

    def execute(argv, cwd, timeout, env):
        outcomes = {
            "ok": CommandResult(0, False, "hello", ""),
            "bad-cc": CommandResult(1, False, "", "compile error"),
            "timeout": CommandResult(None, True),
            "crash": CommandResult(-11, False),
            "asan": CommandResult(1, False, "", "ERROR: AddressSanitizer: heap-buffer-overflow"),
            "fail": CommandResult(2, False, "", "bad arguments"),
        }
        return outcomes[argv[0]]

    summary = RegressionRunner(tmp_path / "out", execute).run_manifest(manifest)
    assert summary["matched"] == 6
    assert summary["failed"] == 0
    assert {item["status"] for item in summary["groups"]} == {
        "passed", "compile_failed", "timeout", "crashed",
        "sanitizer_error", "execution_failed",
    }
    assert (tmp_path / "out" / "regression-summary.json").exists()


def test_failed_only_reruns_only_previous_mismatches(tmp_path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"cases": [
        {"name": "good", "expected_status": "passed", "run": ["good"]},
        {"name": "flaky", "expected_status": "passed", "run": ["flaky"]},
    ]}), encoding="utf-8")
    calls = []

    def first(argv, cwd, timeout, env):
        return CommandResult(0 if argv[0] == "good" else 1, False)

    runner = RegressionRunner(tmp_path / "out", first)
    runner.run_manifest(manifest)

    def second(argv, cwd, timeout, env):
        calls.append(argv[0])
        return CommandResult(0, False)

    runner.executor = second
    summary = runner.run_manifest(manifest, failed_only=True)
    assert calls == ["flaky"]
    assert summary["matched"] == 1
