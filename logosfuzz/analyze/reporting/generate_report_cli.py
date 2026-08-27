"""
ANA-05-02 리포트 생성 CLI

사용법:
    python3 -m logosfuzz.analyze.reporting.generate_report_cli logosfuzz/analyze/reporting/samples/sample_crash_1.json --seq 1
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .render import render_json, render_markdown
from .report_generator import build_cve_report


def main() -> None:
    parser = argparse.ArgumentParser(description="ANA-05-02 CVE 리포트 생성")
    parser.add_argument("input_path", help="crash 데이터 묶음 JSON 파일 경로")
    parser.add_argument("--seq", type=int, default=1, help="report_id 시퀀스 번호")
    parser.add_argument("--outdir", default="output", help="결과 저장 디렉토리")
    args = parser.parse_args()

    data = json.loads(Path(args.input_path).read_text(encoding="utf-8"))

    report = build_cve_report(
        crash_report=data["crash_report"],
        api_metadata=data["api_metadata"],
        harness=data["harness"],
        triage_result=data["triage_result"],
        poc_input_path=data.get("poc_input_path"),
        sequence=args.seq,
    )

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    json_path = outdir / f"{report.report_id}.json"
    md_path = outdir / f"{report.report_id}.md"

    json_path.write_text(render_json(report), encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")

    print(f"[OK] {report.report_id} 생성 완료")
    print(f"  - JSON: {json_path}")
    print(f"  - Markdown: {md_path}")
    print(f"  - CWE: {report.cwe.id} ({report.cwe.name})")
    print(f"  - CVSS: {report.cvss.base_score} ({report.cvss.severity}, 추정치 여부={report.cvss.is_estimated})")


if __name__ == "__main__":
    main()
