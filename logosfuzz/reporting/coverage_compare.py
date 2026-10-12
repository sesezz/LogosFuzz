"""유닛테스트 vs 퍼징 커버리지 비교 (4주차, B 송서원)
====================================================

같은 코드를 **기존 유닛테스트(`*_test.cc`)** 가 얼마나 덮고, **퍼징**이 얼마나 덮는지
빌드 단위(Bazel 타깃) 기준으로 나란히 놓는다. 발표·최종 리포트에 넣을 비교표가 목적이다.

입력
----
- 유닛테스트 : ``bazel coverage`` 가 만드는 lcov (``_coverage_report.dat`` 등)
- 퍼징       : ``llvm-cov export -format=lcov`` 결과(줄 단위 비교 가능) 또는
               C 파트 ``coverage.py`` 가 남기는 llvm-cov export JSON /
               ``<group>.summary.json`` (파일·지표 단위 비교만 가능)
- build_summary.json(선택) : 파일을 빌드 단위로 묶는 기준. 각 단위의 패키지 경로
  (``//score/json:json`` -> ``score/json/``) 아래 파일이 그 단위에 속한다.

출력
----
``compare_coverage()`` 가 돌려주는 dict(JSON 저장용)와 ``render_coverage_comparison_markdown()``.

읽을 때 주의할 점(리포트에도 그대로 실린다)
-----------------------------------------
- **줄 단위 합집합·"퍼징만/유닛테스트만"은 양쪽이 lcov 일 때만** 계산된다. llvm-cov JSON 은
  파일별 요약 수치만 있어서 어떤 줄이 덮였는지 모른다.
- 함수·브랜치는 합집합을 알 수 없다. 여러 입력을 합칠 때는 **최댓값(하한)** 을 쓴다.
- 한쪽 리포트에 없는 파일은 "도달 못 함"으로 보고 0% 로 계산한다(분모는 다른 쪽 값).
- 두 리포트의 분모는 도구마다 조금 다를 수 있다. 같은 clang/llvm-cov 로 뽑으면 가장 가깝다.
- 비교 범위에서 테스트·퍼저 하네스·외부 의존성 파일은 기본으로 뺀다(``DEFAULT_EXCLUDE``).
  유닛테스트 리포트에는 테스트 코드 자신이 100% 로 섞여 들어와 결과를 부풀리기 때문이다.

사용
----
    # 퍼징 쪽 lcov (C 파트 수집 결과의 profdata 와 같은 바이너리로)
    llvm-cov export -format=lcov -instr-profile=merged.profdata <fuzz binary> > out/fuzz.lcov

    python -m logosfuzz.reporting.coverage_compare \\
        --unit-test out/unit.lcov --fuzz out/fuzz.lcov \\
        --build out/build_summary.json --workspace ~/baselibs \\
        -o out/coverage_compare.json --markdown out/coverage_compare.md
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

COVERAGE_COMPARE_SCHEMA_VERSION = "1.0"
UNASSIGNED_UNIT = "(unassigned)"
ALL_UNIT = "(all)"

# 비교 범위에서 뺄 경로 조각. 경로 앞에 "/" 를 붙여 검사하므로 "/fuzz/" 는 최상위
# fuzz/ 폴더도 잡는다.
DEFAULT_EXCLUDE = (
    "_test.cc", "_test.cpp", "_test.h", "_fuzz.cc",
    "/fuzz/", "/test/", "external/",
)

_LABEL_PACKAGE_RE = re.compile(r"^(?:@[^/]+)?//(?P<package>[^:]*)(?::.*)?$")

_METRICS = ("lines", "functions", "branches")


class CoverageCompareError(ValueError):
    """입력 커버리지 파일을 읽거나 해석할 수 없을 때."""


# ---------------------------------------------------------------------
# 1. 데이터 모델
# ---------------------------------------------------------------------

@dataclass(frozen=True)
class Metric:
    """덮인 수 / 전체 수. count 가 0 이면 "모름"(예: 요약 JSON 에 없는 지표)이다."""

    covered: int = 0
    count: int = 0

    @property
    def percent(self) -> float | None:
        return round(100.0 * self.covered / self.count, 2) if self.count else None

    def __add__(self, other: "Metric") -> "Metric":
        return Metric(self.covered + other.covered, self.count + other.count)

    def to_dict(self) -> dict[str, Any]:
        return {"covered": self.covered, "count": self.count, "percent": self.percent}


@dataclass
class FileCoverage:
    """소스 파일 1개의 커버리지."""

    path: str
    lines: Metric = field(default_factory=Metric)
    functions: Metric = field(default_factory=Metric)
    branches: Metric = field(default_factory=Metric)
    # 줄 번호 -> 실행 횟수. lcov 에서만 채워진다(줄 단위 합집합 계산용).
    line_hits: dict[int, int] | None = None

    def metric(self, name: str) -> Metric:
        return getattr(self, name)


# ---------------------------------------------------------------------
# 2. 파서
# ---------------------------------------------------------------------

@dataclass
class _LcovAcc:
    lines: dict[int, int] = field(default_factory=dict)
    fn_names: set = field(default_factory=set)
    fn_hits: dict[str, int] = field(default_factory=dict)
    branches: dict[tuple, int] = field(default_factory=dict)
    totals: dict[str, int] = field(default_factory=dict)


def _to_int(text: str) -> int:
    try:
        return int(text)
    except ValueError:
        return 0


def parse_lcov(text: str) -> dict[str, FileCoverage]:
    """lcov tracefile -> {SF 경로: FileCoverage}.

    같은 파일(SF)이 여러 번 나오면(테스트별 기록을 이어 붙인 경우) 실행 횟수를 더해
    합친다. 상세 기록(DA/FN/BRDA)이 없으면 요약 줄(LF/LH, FNF/FNH, BRF/BRH)을 쓴다.
    """
    acc: dict[str, _LcovAcc] = {}
    cur: _LcovAcc | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("SF:"):
            cur = acc.setdefault(line[3:], _LcovAcc())
            continue
        if line == "end_of_record":
            cur = None
            continue
        if cur is None or ":" not in line:
            continue
        tag, _, rest = line.partition(":")
        if tag == "DA":
            parts = rest.split(",")
            if len(parts) >= 2:
                number = _to_int(parts[0])
                cur.lines[number] = cur.lines.get(number, 0) + _to_int(parts[1])
        elif tag == "FN":
            parts = rest.split(",")
            # lcov 1.x: line,name / lcov 2.x: start,end,name
            name = ",".join(parts[2:]) if len(parts) >= 3 and parts[1].isdigit() \
                else ",".join(parts[1:])
            if name:
                cur.fn_names.add(name)
        elif tag == "FNDA":
            hits, _, name = rest.partition(",")
            if name:
                cur.fn_hits[name] = cur.fn_hits.get(name, 0) + _to_int(hits)
        elif tag == "BRDA":
            parts = rest.split(",")
            if len(parts) >= 4:
                key = (_to_int(parts[0]), parts[1], parts[2])
                taken = 0 if parts[3] == "-" else _to_int(parts[3])
                cur.branches[key] = cur.branches.get(key, 0) + taken
        elif tag in ("LF", "LH", "FNF", "FNH", "BRF", "BRH"):
            cur.totals[tag] = cur.totals.get(tag, 0) + _to_int(rest)

    files: dict[str, FileCoverage] = {}
    for path, a in acc.items():
        if a.lines:
            lines = Metric(sum(1 for h in a.lines.values() if h > 0), len(a.lines))
        else:
            lines = Metric(a.totals.get("LH", 0), a.totals.get("LF", 0))
        names = a.fn_names | set(a.fn_hits)
        if names:
            functions = Metric(sum(1 for n in names if a.fn_hits.get(n, 0) > 0), len(names))
        else:
            functions = Metric(a.totals.get("FNH", 0), a.totals.get("FNF", 0))
        if a.branches:
            branches = Metric(sum(1 for h in a.branches.values() if h > 0), len(a.branches))
        else:
            branches = Metric(a.totals.get("BRH", 0), a.totals.get("BRF", 0))
        files[path] = FileCoverage(
            path=path, lines=lines, functions=functions, branches=branches,
            line_hits=dict(a.lines) if a.lines else None,
        )
    return files


def _metric_from(node: Any) -> Metric:
    if isinstance(node, Mapping):
        return Metric(int(node.get("covered", 0) or 0), int(node.get("count", 0) or 0))
    return Metric()


def parse_coverage_json(doc: Mapping[str, Any]) -> dict[str, FileCoverage]:
    """C 파트 커버리지 JSON -> {파일: FileCoverage}. 줄 단위 상세는 없다.

    - ``llvm-cov export`` 원문(``data[*].files[*].summary``)
    - ``coverage.py`` 의 ``CoverageSummary.to_dict()`` (``files[*].lines`` 만 있음 —
      함수·브랜치는 "모름"으로 남는다)
    """
    files: dict[str, FileCoverage] = {}
    if "data" in doc:
        for entry in doc.get("data") or []:
            for item in entry.get("files") or []:
                summary = item.get("summary") or {}
                name = str(item.get("filename") or "")
                if not name:
                    continue
                files[name] = FileCoverage(
                    path=name,
                    lines=_metric_from(summary.get("lines")),
                    functions=_metric_from(summary.get("functions")),
                    branches=_metric_from(summary.get("branches")),
                )
        return files
    if "files" in doc:
        for item in doc.get("files") or []:
            name = str(item.get("filename") or "")
            if name:
                files[name] = FileCoverage(path=name, lines=_metric_from(item.get("lines")))
        return files
    raise CoverageCompareError(
        "알 수 없는 커버리지 JSON 형식 (llvm-cov export 또는 CoverageSummary 여야 한다)")


# ---------------------------------------------------------------------
# 3. 경로 정규화 / 합치기
# ---------------------------------------------------------------------

def normalize_path(path: str, workspace: str | Path | None = None,
                   strip_prefixes: Iterable[str] = ()) -> str:
    """두 도구가 다르게 찍은 경로를 워크스페이스 기준 상대 경로로 맞춘다.

    lcov(bazel coverage)는 ``score/json/x.cc`` 처럼 상대 경로를, llvm-cov 는 절대 경로
    (``<execroot>/_main/score/json/x.cc`` 또는 워크스페이스 절대 경로)를 찍는다.
    """
    p = path.replace("\\", "/")
    if "/execroot/" in p:                       # bazel execroot: .../execroot/_main/<상대경로>
        rest = p.split("/execroot/", 1)[1]
        p = rest.split("/", 1)[1] if "/" in rest else rest
    if workspace:
        ws = str(Path(workspace).expanduser()).replace("\\", "/").rstrip("/") + "/"
        real = str(Path(workspace).expanduser().resolve()).replace("\\", "/").rstrip("/") + "/"
        for prefix in (ws, real):
            if p.startswith(prefix):
                p = p[len(prefix):]
                break
    for prefix in strip_prefixes:
        prefix = prefix.replace("\\", "/")
        if prefix and p.startswith(prefix):
            p = p[len(prefix):]
            break
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def _merge_file(a: FileCoverage, b: FileCoverage) -> FileCoverage:
    """같은 파일의 두 기록을 합친다. 줄은 합집합, 함수·브랜치는 최댓값(하한)."""
    if a.line_hits is not None and b.line_hits is not None:
        hits = dict(a.line_hits)
        for number, count in b.line_hits.items():
            hits[number] = hits.get(number, 0) + count
        lines = Metric(sum(1 for h in hits.values() if h > 0), len(hits))
    else:
        hits = None
        lines = a.lines if a.lines.covered >= b.lines.covered else b.lines
    return FileCoverage(
        path=a.path,
        lines=lines,
        functions=a.functions if a.functions.covered >= b.functions.covered else b.functions,
        branches=a.branches if a.branches.covered >= b.branches.covered else b.branches,
        line_hits=hits,
    )


def merge_coverage(maps: Iterable[Mapping[str, FileCoverage]]) -> dict[str, FileCoverage]:
    merged: dict[str, FileCoverage] = {}
    for files in maps:
        for path, item in files.items():
            merged[path] = _merge_file(merged[path], item) if path in merged else item
    return merged


def load_coverage(paths: Sequence[str | Path], *, workspace: str | Path | None = None,
                  strip_prefixes: Iterable[str] = ()) -> dict[str, FileCoverage]:
    """커버리지 파일(lcov 또는 JSON) 여러 개를 읽어 경로를 맞추고 합친다."""
    if not paths:
        raise CoverageCompareError("커버리지 입력 파일이 없다")
    strip = tuple(strip_prefixes)
    maps = []
    for raw_path in paths:
        path = Path(raw_path).expanduser()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise CoverageCompareError(f"커버리지 파일을 읽을 수 없다: {path} ({exc})") from exc
        if text.lstrip().startswith("{"):
            try:
                raw = parse_coverage_json(json.loads(text))
            except json.JSONDecodeError as exc:
                raise CoverageCompareError(f"JSON 이 아니다: {path} ({exc})") from exc
        else:
            raw = parse_lcov(text)
        if not raw:
            raise CoverageCompareError(f"커버리지 기록이 하나도 없다: {path}")
        normalised = merge_coverage(
            {normalize_path(name, workspace, strip): FileCoverage(
                path=normalize_path(name, workspace, strip),
                lines=item.lines, functions=item.functions,
                branches=item.branches, line_hits=item.line_hits,
            )} for name, item in raw.items()
        )
        maps.append(normalised)
    return merge_coverage(maps)


# ---------------------------------------------------------------------
# 4. 범위·빌드 단위
# ---------------------------------------------------------------------

def in_scope(path: str, include: Sequence[str] = (),
             exclude: Sequence[str] = DEFAULT_EXCLUDE) -> bool:
    """비교 대상 파일인가. ``include`` 는 경로 접두사, ``exclude`` 는 경로 조각."""
    probe = "/" + path
    if any(part in probe for part in exclude):
        return False
    return not include or any(path.startswith(prefix.lstrip("/")) for prefix in include)


def units_from_build_summary(build_summary: Mapping[str, Any] | None) -> dict[str, str]:
    """build_summary.json -> {build_target: 패키지 경로 접두사}.

    ``@repo//score/json:json`` -> ``score/json/``. 퍼징 패키지(``score/json/fuzz/...``)는
    같은 접두사 아래지만 ``DEFAULT_EXCLUDE`` 의 ``/fuzz/`` 로 이미 빠진다.
    """
    units: dict[str, str] = {}
    raw = (build_summary or {}).get("units")
    for unit in raw if isinstance(raw, list) else []:
        if not isinstance(unit, Mapping):
            continue
        target = str(unit.get("build_target") or "")
        match = _LABEL_PACKAGE_RE.match(target)
        if not match:
            continue
        package = match.group("package")
        units.setdefault(target, f"{package}/" if package else "")
    return units


def _unit_of(path: str, units: Mapping[str, str]) -> str:
    """가장 긴 접두사가 맞는 빌드 단위. 없으면 (unassigned)."""
    best, best_len = UNASSIGNED_UNIT, -1
    for target, prefix in units.items():
        if path.startswith(prefix) and len(prefix) > best_len:
            best, best_len = target, len(prefix)
    return best


# ---------------------------------------------------------------------
# 5. 비교
# ---------------------------------------------------------------------

def _sum_metrics(rows: Iterable[FileCoverage], name: str) -> Metric:
    total = Metric()
    for row in rows:
        total = total + row.metric(name)
    return total


def _missing_like(other: FileCoverage) -> FileCoverage:
    """한쪽에 없는 파일: 덮인 것 0, 분모는 다른 쪽 값."""
    return FileCoverage(
        path=other.path,
        lines=Metric(0, other.lines.count),
        functions=Metric(0, other.functions.count),
        branches=Metric(0, other.branches.count),
        line_hits={} if other.line_hits is not None else None,
    )


def _side(row: FileCoverage) -> dict[str, Any]:
    return {name: row.metric(name).to_dict() for name in _METRICS}


def _line_overlap(test: FileCoverage, fuzz: FileCoverage) -> dict[str, int] | None:
    """줄 단위 겹침. 양쪽 모두 줄 상세(lcov)가 있을 때만 계산된다."""
    if test.line_hits is None or fuzz.line_hits is None:
        return None
    test_cov = {n for n, h in test.line_hits.items() if h > 0}
    fuzz_cov = {n for n, h in fuzz.line_hits.items() if h > 0}
    universe = set(test.line_hits) | set(fuzz.line_hits)
    return {
        "both": len(test_cov & fuzz_cov),
        "test_only": len(test_cov - fuzz_cov),
        "fuzz_only": len(fuzz_cov - test_cov),
        "union": len(test_cov | fuzz_cov),
        "count": len(universe),
    }


def _summarise(paths: Sequence[str], test: Mapping[str, FileCoverage],
               fuzz: Mapping[str, FileCoverage]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """파일 묶음 하나의 합계(+파일별 행)."""
    test_rows, fuzz_rows, per_file = [], [], []
    overlaps: list[dict[str, int] | None] = []
    for path in paths:
        t, f = test.get(path), fuzz.get(path)
        t = t or _missing_like(f)            # 둘 다 None 일 수는 없다(paths 는 합집합)
        f = f or _missing_like(t)
        test_rows.append(t)
        fuzz_rows.append(f)
        overlap = _line_overlap(t, f)
        overlaps.append(overlap)
        per_file.append({"path": path, "unit_test": _side(t), "fuzz": _side(f),
                         "lines": overlap})

    lines_total: dict[str, int] | None = None
    if overlaps and all(o is not None for o in overlaps):
        lines_total = {key: sum(o[key] for o in overlaps) for key in
                       ("both", "test_only", "fuzz_only", "union", "count")}
    summary = {
        "files": len(paths),
        "unit_test": {n: _sum_metrics(test_rows, n).to_dict() for n in _METRICS},
        "fuzz": {n: _sum_metrics(fuzz_rows, n).to_dict() for n in _METRICS},
        "lines": lines_total,
    }
    return summary, per_file


def compare_coverage(
    unit_test: Mapping[str, FileCoverage],
    fuzz: Mapping[str, FileCoverage],
    *,
    units: Mapping[str, str] | None = None,
    include: Sequence[str] = (),
    exclude: Sequence[str] = DEFAULT_EXCLUDE,
    inputs: Mapping[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """유닛테스트·퍼징 커버리지를 빌드 단위로 비교한다.

    ``unit_test``/``fuzz`` 는 ``load_coverage`` 가 돌려준(경로가 정규화된) 사전이다.
    ``units`` 를 안 주면 범위 안의 모든 파일을 ``(all)`` 한 단위로 본다.
    """
    paths = sorted(p for p in set(unit_test) | set(fuzz) if in_scope(p, include, exclude))
    groups: dict[str, list[str]] = {}
    for path in paths:
        groups.setdefault(_unit_of(path, units) if units else ALL_UNIT, []).append(path)

    out_units = []
    for target in sorted(groups, key=lambda t: (t in (UNASSIGNED_UNIT, ALL_UNIT), t)):
        summary, per_file = _summarise(groups[target], unit_test, fuzz)
        package = (units or {}).get(target, "")
        out_units.append({"build_target": target, "package": package,
                          **summary, "per_file": per_file})

    totals, _ = _summarise(paths, unit_test, fuzz)
    return {
        "schema_version": COVERAGE_COMPARE_SCHEMA_VERSION,
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(),
        "inputs": dict(inputs or {}),
        "scope": {"include": list(include), "exclude": list(exclude)},
        "units": out_units,
        "totals": totals,
        "notes": _notes(totals),
    }


def _notes(totals: Mapping[str, Any]) -> list[str]:
    notes = [
        "한쪽 리포트에 없는 파일은 도달하지 못한 것으로 보고 0% 로 계산했다.",
        "함수·브랜치는 합집합을 알 수 없어 여러 입력을 합칠 때 최댓값(하한)을 썼다.",
        "테스트·퍼저 하네스·외부 의존성 파일은 비교 범위에서 뺐다.",
    ]
    if totals.get("lines") is None:
        notes.insert(0, "줄 단위 합집합과 '퍼징만/유닛테스트만' 은 양쪽이 lcov 일 때만 계산된다 "
                        "(지금 입력에는 줄 상세가 없다).")
    return notes


# ---------------------------------------------------------------------
# 6. 출력
# ---------------------------------------------------------------------

def _pct(metric: Mapping[str, Any]) -> str:
    if not metric.get("count"):
        return "-"
    return f"{metric['percent']:.1f}% ({metric['covered']}/{metric['count']})"


def render_coverage_comparison_markdown(result: Mapping[str, Any]) -> str:
    """빌드 단위 비교표를 Markdown 으로 만든다 (최종 리포트·발표자료 붙여넣기용)."""
    lines = [
        "| 빌드 단위 | 파일 | 라인 유닛테스트 | 라인 퍼징 | 라인 합집합 | 퍼징만 | 유닛테스트만 "
        "| 함수 UT/퍼징 | 브랜치 UT/퍼징 |",
        "|---|---:|---|---|---|---:|---:|---|---|",
    ]
    rows = list(result.get("units") or [])
    if len(rows) > 1:
        rows.append({**(result.get("totals") or {}), "build_target": "**합계**"})
    for unit in rows:
        overlap = unit.get("lines")
        union = "-"
        if overlap and overlap["count"]:
            union = f"{100.0 * overlap['union'] / overlap['count']:.1f}% " \
                    f"({overlap['union']}/{overlap['count']})"
        test, fuzz = unit.get("unit_test") or {}, unit.get("fuzz") or {}
        lines.append("| {} | {} | {} | {} | {} | {} | {} | {} / {} | {} / {} |".format(
            f"`{unit.get('build_target')}`" if not str(unit.get("build_target")).startswith("**")
            else unit.get("build_target"),
            unit.get("files", 0),
            _pct(test.get("lines", {})), _pct(fuzz.get("lines", {})), union,
            overlap["fuzz_only"] if overlap else "-",
            overlap["test_only"] if overlap else "-",
            _pct(test.get("functions", {})), _pct(fuzz.get("functions", {})),
            _pct(test.get("branches", {})), _pct(fuzz.get("branches", {})),
        ))
    notes = "\n".join(f"- {note}" for note in result.get("notes") or [])
    return "\n".join(lines) + "\n\n" + (f"해석 시 주의:\n{notes}\n" if notes else "")


def write_coverage_comparison(path: str | Path, result: Mapping[str, Any]) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8")
    return destination


# ---------------------------------------------------------------------
# 7. CLI
# ---------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="유닛테스트 vs 퍼징 커버리지를 빌드 단위로 비교한다")
    p.add_argument("--unit-test", nargs="+", required=True, metavar="FILE",
                   help="유닛테스트 커버리지(lcov). 여러 개면 합친다")
    p.add_argument("--fuzz", nargs="+", required=True, metavar="FILE",
                   help="퍼징 커버리지(lcov 또는 llvm-cov export JSON / summary.json)")
    p.add_argument("--build", type=Path, default=None,
                   help="build_summary.json — 파일을 빌드 단위로 묶는 기준")
    p.add_argument("--workspace", type=Path, default=None,
                   help="Bazel 워크스페이스 루트(절대 경로를 상대 경로로 맞춘다)")
    p.add_argument("--strip-prefix", action="append", default=[], metavar="PREFIX",
                   help="경로 앞에서 떼어 낼 접두사(반복 가능)")
    p.add_argument("--include", action="append", default=[], metavar="PREFIX",
                   help="이 접두사 아래 파일만 비교(반복 가능, 기본 전체)")
    p.add_argument("--exclude", action="append", default=[], metavar="PART",
                   help="제외할 경로 조각을 기본 목록에 더한다(반복 가능)")
    p.add_argument("--no-default-exclude", action="store_true",
                   help="기본 제외 목록(테스트·하네스·external)을 쓰지 않는다")
    p.add_argument("--output", "-o", type=Path, required=True, help="비교 결과 JSON 경로")
    p.add_argument("--markdown", type=Path, default=None, help="비교표 Markdown 경로")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        test = load_coverage(args.unit_test, workspace=args.workspace,
                             strip_prefixes=args.strip_prefix)
        fuzz = load_coverage(args.fuzz, workspace=args.workspace,
                             strip_prefixes=args.strip_prefix)
        units = None
        if args.build:
            units = units_from_build_summary(json.loads(args.build.read_text(encoding="utf-8")))
    except (CoverageCompareError, OSError, json.JSONDecodeError) as exc:
        print(f"[COVERAGE 오류] {exc}", file=sys.stderr)
        return 1

    exclude = tuple(args.exclude) if args.no_default_exclude \
        else DEFAULT_EXCLUDE + tuple(args.exclude)
    result = compare_coverage(
        test, fuzz, units=units, include=args.include, exclude=exclude,
        inputs={"unit_test": [str(p) for p in args.unit_test],
                "fuzz": [str(p) for p in args.fuzz],
                "build_summary": str(args.build) if args.build else None},
    )
    write_coverage_comparison(args.output, result)
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(render_coverage_comparison_markdown(result), encoding="utf-8")

    totals = result["totals"]
    print(f"[COVERAGE] 파일 {totals['files']}개 | 라인 유닛테스트 {_pct(totals['unit_test']['lines'])}"
          f" | 퍼징 {_pct(totals['fuzz']['lines'])}")
    if totals["lines"]:
        overlap = totals["lines"]
        print(f"  합집합 {overlap['union']}/{overlap['count']} | 퍼징만 {overlap['fuzz_only']}"
              f" | 유닛테스트만 {overlap['test_only']} | 둘 다 {overlap['both']}")
    print(f"  -> {args.output}")
    if args.markdown:
        print(f"  -> {args.markdown}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
