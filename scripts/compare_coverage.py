#!/usr/bin/env python3
"""유닛테스트 커버리지와 퍼징 커버리지를 라인 단위로 비교한다 (C 파트 4주차).

왜 총합 비교로는 부족한가
-------------------------
"퍼징 62% vs 유닛테스트 71%" 같은 총합만 내면 퍼징이 진 것처럼 보인다.
하지만 둘은 성격이 다르다. 유닛테스트는 API 표면을 **넓게** 훑고, 퍼징은 입력
파싱 경로를 **깊게** 판다. 총합이 낮아도 유닛테스트가 전혀 밟지 않은 분기를
퍼징이 밟고 있을 수 있고, 그게 바로 퍼징을 돌리는 이유다.

그래서 이 스크립트는 네 가지를 나눠서 센다.

    둘 다 밟음        - 중복 구간
    퍼징만 밟음       <- **핵심 수치.** 퍼징이 벌어준 것
    유닛테스트만 밟음 - 퍼징 하네스가 아직 못 닿는 API 표면
    둘 다 못 밟음     - 남은 미탐색 영역

사용:
    python3 scripts/compare_coverage.py \\
        --unit-lcov unit.lcov --fuzz-lcov fuzz.lcov \\
        --out comparison.json --markdown comparison.md
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path


def parse_lcov(path: Path) -> dict:
    """lcov 트레이스 파일을 ``{소스파일: {행번호: 실행횟수}}`` 로 읽는다.

    lcov 의 최소 문법만 본다.
        SF:<소스 경로>     레코드 시작
        DA:<행>,<횟수>     행 단위 실행 횟수
        end_of_record      레코드 끝

    같은 파일이 여러 레코드로 쪼개져 나오는 경우가 있어(타깃별 측정 등)
    횟수는 누적한다.
    """
    files: dict = defaultdict(dict)
    current = None
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if line.startswith("SF:"):
            current = line[3:]
        elif line.startswith("DA:") and current is not None:
            body = line[3:]
            number, _, count = body.partition(",")
            try:
                lineno = int(number)
                hits = int(count.split(",")[0])
            except ValueError:
                continue
            files[current][lineno] = files[current].get(lineno, 0) + hits
        elif line == "end_of_record":
            current = None
    return dict(files)


def normalize_path(path: str) -> str:
    """빌드 환경마다 다른 경로 접두사를 걷어낸다.

    유닛테스트는 bazel coverage 가, 퍼징은 llvm-cov 가 경로를 찍는데 둘의
    접두사가 다르다. 정규화하지 않으면 같은 파일이 서로 다른 파일로 잡혀
    교집합이 통째로 0 이 된다.
    """
    text = path.replace("\\", "/")
    for marker in ("/execroot/_main/", "/proc/self/cwd/", "/execroot/"):
        idx = text.find(marker)
        if idx != -1:
            text = text[idx + len(marker):]
    return text.lstrip("./")


def covered_lines(lcov: dict) -> dict:
    """``{정규화 경로: {실제로 실행된 행 번호}}``."""
    result: dict = defaultdict(set)
    for path, lines in lcov.items():
        key = normalize_path(path)
        for lineno, hits in lines.items():
            if hits > 0:
                result[key].add(lineno)
    return dict(result)


def all_known_lines(*lcovs: dict) -> dict:
    """측정 대상이 된 전체 행(실행 여부 무관). 미탐색 영역 계산용."""
    result: dict = defaultdict(set)
    for lcov in lcovs:
        for path, lines in lcov.items():
            result[normalize_path(path)].update(lines.keys())
    return dict(result)


def compare(unit_lcov: dict, fuzz_lcov: dict) -> dict:
    unit = covered_lines(unit_lcov)
    fuzz = covered_lines(fuzz_lcov)
    known = all_known_lines(unit_lcov, fuzz_lcov)

    per_file = []
    totals = {"both": 0, "fuzz_only": 0, "unit_only": 0, "neither": 0, "known": 0}

    for path in sorted(known):
        u = unit.get(path, set())
        f = fuzz.get(path, set())
        k = known.get(path, set())
        both = u & f
        fuzz_only = f - u
        unit_only = u - f
        neither = k - (u | f)
        entry = {
            "file": path,
            "known_lines": len(k),
            "both": len(both),
            "fuzz_only": len(fuzz_only),
            "unit_only": len(unit_only),
            "neither": len(neither),
            "unit_covered": len(u),
            "fuzz_covered": len(f),
            # 퍼징이 새로 연 라인은 실제 번호까지 남긴다. 발표에서 "이 분기를
            # 유닛테스트는 안 밟는다" 를 코드로 보여줄 수 있어야 한다.
            "fuzz_only_lines": sorted(fuzz_only)[:50],
        }
        per_file.append(entry)
        for key in ("both", "fuzz_only", "unit_only", "neither"):
            totals[key] += entry[key]
        totals["known"] += entry["known_lines"]

    totals["unit_covered"] = totals["both"] + totals["unit_only"]
    totals["fuzz_covered"] = totals["both"] + totals["fuzz_only"]

    def pct(part: int) -> float:
        return round(100.0 * part / totals["known"], 2) if totals["known"] else 0.0

    totals["unit_percent"] = pct(totals["unit_covered"])
    totals["fuzz_percent"] = pct(totals["fuzz_covered"])
    totals["fuzz_only_percent"] = pct(totals["fuzz_only"])
    totals["union_percent"] = pct(totals["both"] + totals["fuzz_only"] + totals["unit_only"])

    return {"totals": totals, "files": per_file}


def to_markdown(report: dict, top_n: int = 15) -> str:
    t = report["totals"]
    lines = [
        "# 유닛테스트 vs 퍼징 커버리지 비교",
        "",
        "## 총합",
        "",
        "| 구분 | 라인 수 | 비율 |",
        "| --- | ---: | ---: |",
        f"| 유닛테스트 커버 | {t['unit_covered']:,} | {t['unit_percent']}% |",
        f"| 퍼징 커버 | {t['fuzz_covered']:,} | {t['fuzz_percent']}% |",
        f"| **퍼징만 커버** | **{t['fuzz_only']:,}** | **{t['fuzz_only_percent']}%** |",
        f"| 유닛테스트만 커버 | {t['unit_only']:,} | - |",
        f"| 둘 다 커버 | {t['both']:,} | - |",
        f"| 둘 다 미도달 | {t['neither']:,} | - |",
        f"| 합집합 | {t['both'] + t['fuzz_only'] + t['unit_only']:,} | {t['union_percent']}% |",
        "",
        "`퍼징만 커버` 가 이 실험의 핵심 수치다. 유닛테스트가 전혀 밟지 않는",
        "라인을 퍼징이 몇 줄 열었는지를 뜻한다.",
        "",
        f"## 퍼징이 가장 많이 벌어준 파일 (상위 {top_n})",
        "",
        "| 파일 | 퍼징만 | 유닛만 | 둘 다 | 미도달 |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    ranked = sorted(report["files"], key=lambda e: e["fuzz_only"], reverse=True)
    for entry in ranked[:top_n]:
        if entry["fuzz_only"] == 0 and entry["unit_only"] == 0:
            continue
        lines.append(
            f"| `{entry['file']}` | {entry['fuzz_only']} | {entry['unit_only']} "
            f"| {entry['both']} | {entry['neither']} |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--unit-lcov", required=True, type=Path)
    ap.add_argument("--fuzz-lcov", required=True, type=Path)
    ap.add_argument("--out", type=Path, help="비교 결과 JSON 경로")
    ap.add_argument("--markdown", type=Path, help="발표용 표 마크다운 경로")
    args = ap.parse_args()

    for path in (args.unit_lcov, args.fuzz_lcov):
        if not path.exists():
            ap.error(f"lcov 파일이 없다: {path}")

    report = compare(parse_lcov(args.unit_lcov), parse_lcov(args.fuzz_lcov))

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2),
                            encoding="utf-8")
    markdown = to_markdown(report)
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(markdown, encoding="utf-8")

    print(markdown)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
