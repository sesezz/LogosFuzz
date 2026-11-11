#!/usr/bin/env python3
"""``logosfuzz run`` 의 run_summary.json 을 검증 문서용 Markdown 표로 변환

docs/VERIFY-GENERIC-libsndfile.md 첨부용 실측값만 추출

    python3 scripts/render_run_report.py out/libsndfile/run_summary.json [--env env.txt] [-o report.md]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _pct(m: dict | None) -> str:
    if not m:
        return "-"
    return f"{m['covered']}/{m['count']} ({m['percent']}%)"


def render(summary: dict, env_text: str = "") -> str:
    lines = [f"## 실측: {summary['target']} {summary.get('version', '')} "
             f"(`logosfuzz run`, {summary['started_at'][:19]})", ""]
    if env_text.strip():
        lines += ["환경:", "", "```", env_text.strip(), "```", ""]
    lines += [
        f"- 명령: `logosfuzz run --profile {summary['profile']} --budget {summary['budget_sec']} "
        f"--max-round {summary['max_round']}{'' if summary['docker'] else ' --no-docker'}`",
        f"- 결과: {'완료' if summary['ok'] else '중단'}",
        "",
        "### 단계 (모두 자동, 사람 개입 없음)",
        "",
        "| 단계 | 결과 | 시간(초) | 비고 |",
        "| --- | --- | --- | --- |",
    ]
    for st in summary["stages"]:
        note = {k: v for k, v in st.items()
                if k not in ("stage", "ok", "automatic", "duration_s", "groups", "prompts",
                             "kb", "summary", "output")}
        lines.append(f"| {st['stage']} | {'성공' if st['ok'] else '실패'} | {st['duration_s']} | "
                     f"{json.dumps(note, ensure_ascii=False) if note else ''} |")
    lines += ["", "### 그룹 (하네스는 LLM 자동 생성)", "",
              "| 그룹 | API | 자가치유 | LLM 수정 | 스텁 | 퍼징(초) | 실행 수 | 크래시 | 라인 커버리지 | 브랜치 커버리지 |",
              "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for g in summary["groups"]:
        cov = g.get("coverage") or {}
        lines.append(
            f"| {g['group']} | {', '.join(g['apis'])} | {g['outcome']} | {g['llm_rounds']} | "
            f"{', '.join(g['stubbed_symbols']) or '-'} | {g.get('fuzz_sec', '-')} | "
            f"{g.get('execs', '-')} | {g.get('crashes', '-')} | {_pct(cov.get('lines'))} | "
            f"{_pct(cov.get('branches'))} |")
    t = summary["totals"]
    lines += ["", f"합계: 하네스 {t['harness_built']}/{t['groups']}개 빌드 "
                  f"(LLM 수정으로 살린 것 {t['llm_repaired']}개), 크래시 {t['crashes']}건"
                  + (f", ANA 정탐 {t.get('true_positive', 0)} · 오탐 {t.get('false_positive', 0)}"
                     f" · 검토필요 {t.get('needs_review', 0)}" if "needs_review" in t else ""), ""]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("summary", type=Path)
    parser.add_argument("--env", type=Path, default=None, help="환경 정보 텍스트 파일")
    parser.add_argument("-o", "--output", type=Path, default=None)
    args = parser.parse_args()
    summary = json.loads(args.summary.read_text(encoding="utf-8"))
    env = args.env.read_text(encoding="utf-8") if args.env and args.env.exists() else ""
    text = render(summary, env)
    if args.output:
        args.output.write_text(text, encoding="utf-8")
        print(f"-> {args.output}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
