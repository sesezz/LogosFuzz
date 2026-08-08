"""
Performance Evaluation : Coverage & Seed Efficiency
기존 퍼저(libFuzzer 단독) 대비 LogosFuzz 성능 비교실험

Metrics
-------
1. Coverage Rate     : 탐색된 브랜치 수 / 전체 브랜치 수
2. Seed Efficiency   : 유효 Corpus 수 / 전체 Seed 수
3. Crash Rate        : 발견된 크래시 수 / 실행 횟수
4. Harness Success   : 컴파일 성공 하네스 수 / 전체 생성 시도 수

Usage
-----
python performance_eval.py
python performance_eval.py --output report.json
"""

from __future__ import annotations
import json
import argparse
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------
# 1. Data Models
# ---------------------------------------------------------------------

@dataclass
class FuzzerMetrics:
    """단일 퍼저 실행 결과 메트릭."""
    fuzzer_name: str
    total_branches: int
    covered_branches: int
    total_seeds: int
    valid_corpus: int
    total_executions: int
    crashes_found: int
    harness_attempts: int
    harness_success: int
    elapsed_sec: int

    @property
    def coverage_rate(self) -> float:
        if self.total_branches == 0:
            return 0.0
        return round(self.covered_branches / self.total_branches * 100, 2)

    @property
    def seed_efficiency(self) -> float:
        if self.total_seeds == 0:
            return 0.0
        return round(self.valid_corpus / self.total_seeds * 100, 2)

    @property
    def crash_rate(self) -> float:
        if self.total_executions == 0:
            return 0.0
        return round(self.crashes_found / self.total_executions * 100, 4)

    @property
    def harness_success_rate(self) -> float:
        if self.harness_attempts == 0:
            return 0.0
        return round(self.harness_success / self.harness_attempts * 100, 2)


@dataclass
class ComparisonResult:
    """두 퍼저 비교 결과."""
    baseline: FuzzerMetrics
    proposed: FuzzerMetrics
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())

    @property
    def coverage_improvement(self) -> float:
        return round(self.proposed.coverage_rate - self.baseline.coverage_rate, 2)

    @property
    def seed_efficiency_improvement(self) -> float:
        return round(self.proposed.seed_efficiency - self.baseline.seed_efficiency, 2)

    @property
    def crash_rate_improvement(self) -> float:
        return round(self.proposed.crash_rate - self.baseline.crash_rate, 4)

    @property
    def harness_success_improvement(self) -> float:
        return round(self.proposed.harness_success_rate - self.baseline.harness_success_rate, 2)


# ---------------------------------------------------------------------
# 2. Performance Evaluator
# ---------------------------------------------------------------------

class PerformanceEvaluator:

    def compare(self, baseline: FuzzerMetrics,
                proposed: FuzzerMetrics) -> ComparisonResult:
        return ComparisonResult(baseline=baseline, proposed=proposed)

    def print_report(self, result: ComparisonResult) -> None:
        b = result.baseline
        p = result.proposed

        print("\n" + "=" * 60)
        print("  Coverage & Seed Efficiency Performance Report")
        print("=" * 60)

        print(f"\n{'Metric':<30} {'Baseline':>12} {'LogosFuzz':>12} {'Diff':>10}")
        print("-" * 66)

        rows = [
            ("Coverage Rate (%)",
             b.coverage_rate, p.coverage_rate, result.coverage_improvement),
            ("Seed Efficiency (%)",
             b.seed_efficiency, p.seed_efficiency, result.seed_efficiency_improvement),
            ("Crash Rate (%)",
             b.crash_rate, p.crash_rate, result.crash_rate_improvement),
            ("Harness Success Rate (%)",
             b.harness_success_rate, p.harness_success_rate, result.harness_success_improvement),
        ]

        for name, bv, pv, diff in rows:
            sign = "+" if diff >= 0 else ""
            diff_str = f"{sign}{diff}"
            print(f"  {name:<28} {bv:>12} {pv:>12} {diff_str:>10}")

        print("-" * 66)
        print(f"\n  {'Coverage':<28} {b.covered_branches}/{b.total_branches}"
              f"  ->  {p.covered_branches}/{p.total_branches}")
        print(f"  {'Crashes Found':<28} {b.crashes_found}"
              f"  ->  {p.crashes_found}")
        print(f"  {'Elapsed Time (s)':<28} {b.elapsed_sec}"
              f"  ->  {p.elapsed_sec}")
        print("\n" + "=" * 60)

        # Overall verdict
        wins = sum([
            result.coverage_improvement > 0,
            result.seed_efficiency_improvement > 0,
            result.crash_rate_improvement > 0,
            result.harness_success_improvement > 0,
        ])
        print(f"\n  LogosFuzz wins {wins}/4 metrics vs {b.fuzzer_name}")
        if wins >= 3:
            print("  ✅ LogosFuzz outperforms baseline")
        elif wins == 2:
            print("  ⚠️  LogosFuzz comparable to baseline")
        else:
            print("  ❌ LogosFuzz underperforms baseline")
        print()

    def save_report(self, result: ComparisonResult, output_path: str) -> None:
        report = {
            "generated_at": result.generated_at,
            "baseline": {
                "name": result.baseline.fuzzer_name,
                "coverage_rate": result.baseline.coverage_rate,
                "seed_efficiency": result.baseline.seed_efficiency,
                "crash_rate": result.baseline.crash_rate,
                "harness_success_rate": result.baseline.harness_success_rate,
            },
            "proposed": {
                "name": result.proposed.fuzzer_name,
                "coverage_rate": result.proposed.coverage_rate,
                "seed_efficiency": result.proposed.seed_efficiency,
                "crash_rate": result.proposed.crash_rate,
                "harness_success_rate": result.proposed.harness_success_rate,
            },
            "improvements": {
                "coverage": result.coverage_improvement,
                "seed_efficiency": result.seed_efficiency_improvement,
                "crash_rate": result.crash_rate_improvement,
                "harness_success": result.harness_success_improvement,
            }
        }
        Path(output_path).write_text(
            json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"  [SAVED] Report saved to {output_path}")


# ---------------------------------------------------------------------
# 3. Mock Run (목업 실험 데이터)
# ---------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="performance_report.json")
    args = parser.parse_args()

    # 기존 퍼저 (libFuzzer 단독) 목업 실험 결과
    baseline = FuzzerMetrics(
        fuzzer_name="libFuzzer (baseline)",
        total_branches=1000,
        covered_branches=320,       # 32% coverage
        total_seeds=8,
        valid_corpus=12,
        total_executions=100000,
        crashes_found=2,
        harness_attempts=10,
        harness_success=6,          # 60% success (수동 작성)
        elapsed_sec=3600,
    )

    # LogosFuzz 목업 실험 결과
    proposed = FuzzerMetrics(
        fuzzer_name="LogosFuzz",
        total_branches=1000,
        covered_branches=610,       # 61% coverage (+29%)
        total_seeds=8,
        valid_corpus=25,
        total_executions=100000,
        crashes_found=5,
        harness_attempts=10,
        harness_success=9,          # 90% success (LLM 자동 생성)
        elapsed_sec=3600,
    )

    evaluator = PerformanceEvaluator()
    result = evaluator.compare(baseline, proposed)
    evaluator.print_report(result)
    evaluator.save_report(result, args.output)
