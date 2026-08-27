"""
CTR-06-01 : Compatibility Checklist + Auto-run Pipeline + Regression Test

Responsibilities
----------------
1. CompatibilityChecker : Pre-run checklist (Python version, tools, env vars, paths)
2. AutoPipeline         : Run EXT -> SCH -> GEN -> EXE -> ANA in sequence
3. RegressionTester     : Compare current run results against baseline to detect regression

Usage
-----
python ctr_06_01_controller.py --source test_target.c --output harness_output.c
python ctr_06_01_controller.py --regression --baseline baseline.json
"""

from __future__ import annotations
import os
import sys
import json
import shutil
import argparse
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()  # cwd부터 상위로 .env 자동 탐색 (팀원 환경마다 경로가 다르므로 하드코딩 금지)


# ---------------------------------------------------------------------
# 1. Compatibility Checker
# ---------------------------------------------------------------------

@dataclass
class CheckResult:
    name: str
    passed: bool
    message: str


class CompatibilityChecker:
    """
    Pre-run checklist.
    Verifies environment before starting the pipeline.
    """

    def __init__(self):
        self.results: list[CheckResult] = []

    def _check(self, name: str, condition: bool, ok_msg: str, fail_msg: str):
        self.results.append(CheckResult(name, condition, ok_msg if condition else fail_msg))

    def run_all(self) -> bool:
        """Run all checks. Returns True if all pass."""
        self.results.clear()

        # Python version
        major, minor = sys.version_info[:2]
        self._check(
            "Python version",
            major == 3 and minor >= 9,
            f"Python {major}.{minor} OK",
            f"Python {major}.{minor} - requires 3.9+"
        )

        # Required tools
        for tool in ["clang", "clang++", "bear"]:
            found = shutil.which(tool) is not None
            self._check(f"Tool: {tool}", found, f"{tool} found", f"{tool} not found in PATH")

        # OpenAI API key
        api_key = os.environ.get("OPENAI_API_KEY", "")
        self._check(
            "OPENAI_API_KEY",
            bool(api_key),
            "OPENAI_API_KEY set",
            "OPENAI_API_KEY not set"
        )

        # Required Python packages
        for pkg in ["openai", "dotenv", "clang"]:
            try:
                __import__(pkg)
                self._check(f"Package: {pkg}", True, f"{pkg} installed", "")
            except ImportError:
                self._check(f"Package: {pkg}", False, "", f"{pkg} not installed - run pip install {pkg}")

        # Print results
        print("\n=== CTR-06-01 Compatibility Checklist ===")
        all_passed = True
        for r in self.results:
            status = "✅" if r.passed else "❌"
            print(f"  {status} {r.name}: {r.message}")
            if not r.passed:
                all_passed = False

        print(f"\n  Result: {'ALL PASSED' if all_passed else 'SOME CHECKS FAILED'}\n")
        return all_passed


# ---------------------------------------------------------------------
# 2. Auto Pipeline
# ---------------------------------------------------------------------

@dataclass
class PipelineResult:
    """Result of a single pipeline run."""
    run_id: str
    source: str
    output: str
    started_at: str
    finished_at: str = ""
    success: bool = False
    harness_count: int = 0
    error: str = ""


class AutoPipeline:
    """
    Runs the full EXT -> SCH -> GEN pipeline automatically.
    Wraps pipeline.py as a subprocess for isolation.
    """

    def __init__(self, pipeline_script: str = "pipeline.py"):
        self.pipeline_script = pipeline_script

    def run(self, source: str, output: str, budget: int = 3600) -> PipelineResult:
        run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        result = PipelineResult(
            run_id=run_id,
            source=source,
            output=output,
            started_at=datetime.now().isoformat(),
        )

        print(f"\n[PIPELINE] Starting run {run_id}...")
        print(f"  Source : {source}")
        print(f"  Output : {output}")
        print(f"  Budget : {budget}s")

        try:
            proc = subprocess.run(
                [sys.executable, self.pipeline_script,
                 "--source", source,
                 "--output", output,
                 "--budget", str(budget)],
                capture_output=True, text=True, timeout=budget + 60
            )

            result.finished_at = datetime.now().isoformat()

            if proc.returncode == 0:
                result.success = True
                # Count generated harness groups
                out_path = Path(output)
                if out_path.exists():
                    content = out_path.read_text(encoding="utf-8")
                    result.harness_count = content.count("// ===")
                print(f"  [DONE] Pipeline completed. {result.harness_count} harness(es) generated.")
            else:
                result.success = False
                result.error = proc.stderr
                print(f"  [FAIL] Pipeline failed:\n{proc.stderr}")

        except subprocess.TimeoutExpired:
            result.success = False
            result.error = "Pipeline timed out"
            print(f"  [TIMEOUT] Pipeline exceeded budget {budget}s")

        except Exception as e:
            result.success = False
            result.error = str(e)
            print(f"  [ERROR] {e}")

        return result


# ---------------------------------------------------------------------
# 3. Regression Tester
# ---------------------------------------------------------------------

@dataclass
class RegressionResult:
    passed: bool
    baseline_count: int
    current_count: int
    message: str


class RegressionTester:
    """
    Compares current pipeline output against a saved baseline.
    Detects regression in harness count or structure.
    """

    def save_baseline(self, pipeline_result: PipelineResult, baseline_path: str):
        """Save current run as baseline."""
        baseline = {
            "run_id": pipeline_result.run_id,
            "source": pipeline_result.source,
            "harness_count": pipeline_result.harness_count,
            "success": pipeline_result.success,
            "saved_at": datetime.now().isoformat(),
        }
        Path(baseline_path).write_text(json.dumps(baseline, indent=2), encoding="utf-8")
        print(f"\n[BASELINE] Saved to {baseline_path}")

    def compare(self, current: PipelineResult, baseline_path: str) -> RegressionResult:
        """Compare current result against baseline."""
        if not Path(baseline_path).exists():
            return RegressionResult(
                passed=False,
                baseline_count=0,
                current_count=current.harness_count,
                message=f"Baseline not found: {baseline_path}"
            )

        baseline = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
        baseline_count = baseline.get("harness_count", 0)
        current_count = current.harness_count

        passed = current_count >= baseline_count

        print(f"\n=== Regression Test ===")
        print(f"  Baseline harness count : {baseline_count}")
        print(f"  Current  harness count : {current_count}")
        print(f"  Result : {'PASS ✅' if passed else 'REGRESSION DETECTED ❌'}")

        return RegressionResult(
            passed=passed,
            baseline_count=baseline_count,
            current_count=current_count,
            message="OK" if passed else f"Regression: harness count dropped {baseline_count} -> {current_count}"
        )


# ---------------------------------------------------------------------
# 4. Main
# ---------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CTR-06-01 Controller")
    parser.add_argument("--source", default="test_target.c", help="Target C/C++ source file")
    parser.add_argument("--output", default="harness_output.c", help="Output harness file")
    parser.add_argument("--budget", type=int, default=3600, help="Fuzzing budget (seconds)")
    parser.add_argument("--baseline", default="baseline.json", help="Baseline JSON path")
    parser.add_argument("--save-baseline", action="store_true", help="Save current run as baseline")
    parser.add_argument("--regression", action="store_true", help="Run regression test")
    parser.add_argument("--skip-check", action="store_true", help="Skip compatibility check")
    args = parser.parse_args()

    # Step 1: Compatibility check
    if not args.skip_check:
        checker = CompatibilityChecker()
        passed = checker.run_all()
        if not passed:
            print("[WARN] Some checks failed. Continuing anyway...\n")

    # Step 2: Run pipeline
    pipeline = AutoPipeline()
    result = pipeline.run(args.source, args.output, args.budget)

    # Step 3: Save baseline or run regression test
    tester = RegressionTester()
    if args.save_baseline:
        tester.save_baseline(result, args.baseline)
    elif args.regression:
        reg = tester.compare(result, args.baseline)
        if not reg.passed:
            sys.exit(1)

    print("\n=== CTR-06-01 Complete ===")
