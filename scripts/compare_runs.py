#!/usr/bin/env python3
"""개선 전/후 측정 런(rep1..N) 비교표와 커버리지 타임라인 생성

입력 디렉터리 구조 (logosfuzz run 측정 래퍼 출력)
    <dir>/rep1/timeline.log           "<경과초>\\t<로그>" 형식 실행 로그
    <dir>/rep1/out/run_summary.json   그룹별 커버리지·execs·크래시·스모크
    <dir>/rep1/out/fuzz_summary.json  그룹별 퍼징 소요 시간·상태
    <dir>/rep1/out/coverage/*.coverage.json  llvm-cov export (파일별 요약)

출력
    comparison.md          지표별 rep 값, 평균 [최소–최대], 후/전 비율
    metrics.csv            같은 지표의 CSV
    coverage_timeline.csv  진행 로그의 cov(엣지) 시계열
    coverage_timeline.png  matplotlib 존재 시 / 없으면 coverage_timeline.svg

사용:
    python3 scripts/compare_runs.py --before runs/baseline --after runs/v2 -o cmp/
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
from pathlib import Path

NA = "측정값 없음"

# 래퍼 진행 로그: 한 줄에 여러 개가 개행 없이 이어질 수 있음
PROGRESS_RE = re.compile(
    r"\[(?P<slug>[^\]\s]+)\]\s*exec/s=\s*(?P<eps>\d+)\s+cov=\s*(?P<cov>\d+)"
    r"\s+crashes=\s*(?P<crashes>\d+)\s+execs=\s*(?P<execs>\d+)"
)
# libFuzzer 원본 진행 로그 (#N INITED/NEW/REDUCE/pulse/DONE cov: X ... exec/s: Y)
LIBFUZZER_RE = re.compile(
    r"#(?P<execs>\d+)\s+(?:INITED|NEW|REDUCE|pulse|DONE)\s+cov:\s*(?P<cov>\d+)"
    r".*?exec/s:\s*(?P<eps>\d+)"
)
TIMELINE_RE = re.compile(r"^\s*(?P<t>\d+(?:\.\d+)?)\t(?P<msg>.*)$", re.S)
GROUP_START_RE = re.compile(r"로직 그룹 '(?P<slug>[^']+)' 격리 퍼징 시작")
COV_LINE_RE = re.compile(
    r"^\s*(?P<slug>\S+): lines (?P<lc>\d+)/(?P<ln>\d+) .*?branches (?P<bc>\d+)/(?P<bn>\d+)"
)
HEADER_RE = re.compile(r"(\w+)=(\S+)")


# --- 파싱 -------------------------------------------------------------------
def _load_json(path: Path):
    """JSON 로드, 없거나 깨진 경우 None 반환"""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def parse_timeline(text: str) -> dict:
    """timeline.log 에서 헤더·EXE 시작 시각·그룹 시작 시각·진행 포인트·COV 줄 추출

    진행 포인트: {slug, logged_s, exec_per_s, cov, crashes, execs}
    logged_s 는 로그가 기록된 시각 (버퍼링으로 그룹 종료 시점에 몰릴 수 있음)
    """
    header: dict = {}
    exe_start = None
    group_start: dict = {}
    points: list = []
    cov_lines: dict = {}
    current = None
    # 진행 로그는 '\r' 로 덮어쓰기 출력 → splitlines() 금지, '\n' 기준 분리
    for raw in text.split("\n"):
        m = TIMELINE_RE.match(raw.rstrip("\r"))
        if not m:
            continue
        t, msg = float(m.group("t")), m.group("msg")
        if not header and "label=" in msg:
            header = dict(HEADER_RE.findall(msg))
        if msg.startswith("[EXE] 시작") and exe_start is None:
            exe_start = t
        g = GROUP_START_RE.search(msg)
        if g:
            current = g.group("slug")
            group_start.setdefault(current, t)
        for p in PROGRESS_RE.finditer(msg):
            points.append({
                "slug": p.group("slug"), "logged_s": t,
                "exec_per_s": int(p.group("eps")), "cov": int(p.group("cov")),
                "crashes": int(p.group("crashes")), "execs": int(p.group("execs")),
            })
        if current:
            for p in LIBFUZZER_RE.finditer(msg):
                points.append({
                    "slug": current, "logged_s": t,
                    "exec_per_s": int(p.group("eps")), "cov": int(p.group("cov")),
                    "crashes": 0, "execs": int(p.group("execs")),
                })
        c = COV_LINE_RE.match(msg)
        if c:
            cov_lines[c.group("slug")] = {
                "lines": (int(c.group("lc")), int(c.group("ln"))),
                "branches": (int(c.group("bc")), int(c.group("bn"))),
            }
    return {"header": header, "exe_start": exe_start, "group_start": group_start,
            "points": points, "cov_lines": cov_lines}


def estimate_times(points: list, group_start: dict, durations: dict) -> list:
    """진행 포인트별 그룹 내 경과초 추정 (execs / exec_s)

    로그 기록 시각은 버퍼링으로 신뢰 불가 → execs/exec_s 로 추정
    exec_s=0 이면 직전 값 유지, 단조 증가 보정, 그룹 소요 시간 상한 적용
    """
    out = []
    last: dict = {}
    for p in points:
        slug = p["slug"]
        prev = last.get(slug, 0.0)
        est = p["execs"] / p["exec_per_s"] if p["exec_per_s"] > 0 else prev
        est = max(prev, est)
        cap = durations.get(slug)
        if cap is not None:
            est = min(est, cap)
        last[slug] = est
        start = group_start.get(slug)
        out.append({**p, "group_elapsed_s": round(est, 3),
                    "run_elapsed_s": round(start + est, 3) if start is not None else None})
    return out


def _cov_pair(cov: dict | None, key: str):
    """coverage 딕셔너리에서 (covered, count) 반환, 없으면 None"""
    if not cov or key not in cov:
        return None
    d = cov[key]
    return int(d.get("covered", 0)), int(d.get("count", 0))


def union_lower_bound(cov_dir: Path) -> dict:
    """그룹별 llvm-cov export 의 파일별 최대 covered 합산 (합집합 하한)

    라인 단위 데이터 부재 → 파일별 max(covered) 합 = 정확한 합집합 이하
    반환: {"lines": (covered, count), "branches": (...)}, 데이터 없으면 빈 딕셔너리
    """
    per_file: dict = {}
    found = False
    for path in sorted(cov_dir.glob("*.coverage.json")) if cov_dir.is_dir() else []:
        data = _load_json(path)
        if not data or not data.get("data"):
            continue
        for f in data["data"][0].get("files", []):
            found = True
            slot = per_file.setdefault(f.get("filename", ""), {})
            for key in ("lines", "branches"):
                s = f.get("summary", {}).get(key) or {}
                cv, cn = int(s.get("covered", 0)), int(s.get("count", 0))
                pc, pn = slot.get(key, (0, 0))
                slot[key] = (max(pc, cv), max(pn, cn))
    if not found:
        return {}
    res = {}
    for key in ("lines", "branches"):
        res[key] = (sum(v[key][0] for v in per_file.values() if key in v),
                    sum(v[key][1] for v in per_file.values() if key in v))
    return res


def load_run(rep_dir: Path, immediate_sec: float = 10.0) -> dict:
    """rep 디렉터리 1개의 지표 딕셔너리 생성"""
    out = rep_dir / "out"
    summary = _load_json(out / "run_summary.json") or {}
    fuzz = _load_json(out / "fuzz_summary.json") or {}
    tl_path = rep_dir / "timeline.log"
    text = ""
    if tl_path.is_file():
        # newline="" : 텍스트 모드의 '\r'→'\n' 변환 차단
        with open(tl_path, encoding="utf-8", errors="replace", newline="") as f:
            text = f.read()
    tl = parse_timeline(text)

    fz = {g.get("group"): g for g in fuzz.get("groups", [])}
    durations = {k: g.get("duration_sec") for k, g in fz.items()
                 if g.get("duration_sec") is not None}

    groups: dict = {}
    for g in summary.get("groups", []):
        slug = g.get("slug") or str(g.get("group", "")).lower()
        cov = g.get("coverage")
        lines, branches = _cov_pair(cov, "lines"), _cov_pair(cov, "branches")
        if lines is None and slug in tl["cov_lines"]:
            lines = tl["cov_lines"][slug]["lines"]
            branches = tl["cov_lines"][slug]["branches"]
        smoke = g.get("smoke")
        groups[slug] = {
            "lines": lines, "branches": branches,
            "execs": g.get("execs"), "crashes": g.get("crashes"),
            "failed_to_start": bool(g.get("failed_to_start")),
            "built": g.get("outcome") == "success",
            "smoke_passed": smoke.get("passed") if isinstance(smoke, dict) else None,
        }
    # run_summary 부재 시 timeline COV 줄로 보완
    for slug, c in tl["cov_lines"].items():
        groups.setdefault(slug, {"lines": c["lines"], "branches": c["branches"],
                                 "execs": None, "crashes": None, "failed_to_start": False,
                                 "built": None, "smoke_passed": None})

    # 크래시 타이밍: fuzz_summary 의 그룹 소요 시간 기준
    crash_in_group, crash_from_exe, immediate = [], [], 0
    for slug, g in fz.items():
        if not g.get("crashed"):
            continue
        dur = g.get("duration_sec")
        if dur is None:
            continue
        crash_in_group.append(dur)
        start, exe = tl["group_start"].get(slug), tl["exe_start"]
        if start is not None and exe is not None:
            crash_from_exe.append(start - exe + dur)
        if dur < immediate_sec:
            immediate += 1

    stage = {s.get("stage"): s for s in summary.get("stages", [])}
    smoke = stage.get("SMOKE")
    totals = summary.get("totals", {})
    union = union_lower_bound(out / "coverage")
    if not union:
        # coverage.json 부재 시 그룹 최대값으로 대체 (역시 하한)
        for key in ("lines", "branches"):
            pairs = [g[key] for g in groups.values() if g[key] and g[key][1] > 0]
            if pairs:
                union[key] = max(pairs)

    execs = [g["execs"] for g in groups.values() if g["execs"] is not None]
    return {
        "name": rep_dir.name,
        "header": tl["header"],
        "groups": groups,
        "union": union,
        "total_execs": sum(execs) if execs else None,
        "crashes": totals.get("crashes", fuzz.get("total_crashes")),
        "harness_built": totals.get("harness_built"),
        "harness_total": totals.get("groups", len(groups) or None),
        "failed_to_start": sum(1 for g in groups.values() if g["failed_to_start"]),
        "immediate_crash": immediate if fz else None,
        "ttfc_group_s": min(crash_in_group) if crash_in_group else None,
        "ttfc_exe_s": min(crash_from_exe) if crash_from_exe else None,
        "smoke": (smoke.get("passed"), smoke.get("total")) if smoke else None,
        "exe_duration_s": stage.get("EXE", {}).get("duration_s"),
        "timeline": estimate_times(tl["points"], tl["group_start"], durations),
    }


def load_side(path: Path, immediate_sec: float = 10.0) -> list:
    """rep* 하위 디렉터리 전체 로드 (rep 번호 순)"""
    reps = [p for p in path.iterdir() if p.is_dir() and p.name.startswith("rep")]
    reps.sort(key=lambda p: int(re.sub(r"\D", "", p.name) or 0))
    return [load_run(p, immediate_sec) for p in reps]


# --- 지표 계산 ---------------------------------------------------------------
def pct(pair) -> float | None:
    """(covered, count) → 백분율, 분모 0 이면 None"""
    if not pair or not pair[1]:
        return None
    return 100.0 * pair[0] / pair[1]


def metric_rows(before: list, after: list) -> list:
    """비교표 행 정의 [(라벨, 값추출함수, 소수자리, 비율표시여부)] 생성"""
    slugs = sorted({s for r in before + after for s in r["groups"]})
    rows = [
        ("라인 커버리지 % (런 전체, 합집합 하한)", lambda r: pct(r["union"].get("lines")), 3, True),
        ("브랜치 커버리지 % (런 전체, 합집합 하한)", lambda r: pct(r["union"].get("branches")), 3, True),
    ]
    for s in slugs:
        rows.append((f"라인 커버리지 % — {s}",
                     lambda r, s=s: pct(r["groups"].get(s, {}).get("lines")), 3, True))
        rows.append((f"브랜치 커버리지 % — {s}",
                     lambda r, s=s: pct(r["groups"].get(s, {}).get("branches")), 3, True))
    rows += [
        ("총 execs", lambda r: r["total_execs"], 0, False),
        ("크래시 수", lambda r: r["crashes"], 0, False),
        (f"즉시 크래시 하네스 수", lambda r: r["immediate_crash"], 0, False),
        ("시작 실패 하네스 수", lambda r: r["failed_to_start"], 0, False),
        ("하네스 빌드 성공 수", lambda r: r["harness_built"], 0, False),
        ("첫 크래시까지 (그룹 퍼징 시작 기준, s)", lambda r: r["ttfc_group_s"], 1, False),
        ("첫 크래시까지 (EXE 시작 기준, s)", lambda r: r["ttfc_exe_s"], 1, False),
        ("스모크 통과율 %", lambda r: pct(r["smoke"]), 1, False),
        ("EXE 단계 소요 (s)", lambda r: r["exe_duration_s"], 1, False),
    ]
    return rows


def fmt(v, digits: int) -> str:
    """수치 문자열 변환, None 은 '측정값 없음'"""
    if v is None:
        return NA
    if digits == 0:
        return f"{int(round(v)):,}"
    return f"{v:.{digits}f}"


def aggregate(values: list) -> dict | None:
    """None 제외 평균·최소·최대·표본 수, 유효값 없으면 None"""
    vals = [v for v in values if v is not None]
    if not vals:
        return None
    return {"mean": sum(vals) / len(vals), "min": min(vals), "max": max(vals), "n": len(vals)}


def fmt_agg(agg: dict | None, digits: int, total: int) -> str:
    """'평균 [최소–최대]' 문자열, 일부 결측 시 (n=k) 표기"""
    if agg is None:
        return NA
    d = max(digits, 1) if digits == 0 and agg["mean"] < 100 else digits
    s = f"{fmt(agg['mean'], d)} [{fmt(agg['min'], digits)}–{fmt(agg['max'], digits)}]"
    if agg["n"] < total:
        s += f" (n={agg['n']})"
    return s


def build_table(before: list, after: list) -> tuple:
    """마크다운 표 문자열과 CSV 행 목록 반환"""
    head = (["지표"] + [f"전 {r['name']}" for r in before] + ["전 평균 [최소–최대]"]
            + [f"후 {r['name']}" for r in after] + ["후 평균 [최소–최대]", "후/전 (평균)"])
    md = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    csv_rows = [["metric", "side", "rep", "value"]]
    for label, fn, digits, ratio in metric_rows(before, after):
        bv, av = [fn(r) for r in before], [fn(r) for r in after]
        ba, aa = aggregate(bv), aggregate(av)
        rt = "-"
        if ratio:
            if ba and aa and ba["mean"] > 0:
                rt = f"{aa['mean'] / ba['mean']:.2f}x"
            elif aa and ba and ba["mean"] == 0:
                rt = "전 0 → 비율 없음"
            else:
                rt = NA
        cells = ([label] + [fmt(v, digits) for v in bv] + [fmt_agg(ba, digits, len(bv))]
                 + [fmt(v, digits) for v in av] + [fmt_agg(aa, digits, len(av)), rt])
        md.append("| " + " | ".join(cells) + " |")
        for side, runs, vals in (("before", before, bv), ("after", after, av)):
            for r, v in zip(runs, vals):
                csv_rows.append([label, side, r["name"], "" if v is None else v])
    return "\n".join(md), csv_rows


def render_markdown(before: list, after: list, args) -> str:
    """comparison.md 본문 생성"""
    table, _ = build_table(before, after)

    def meta(side, runs):
        out = []
        for r in runs:
            h = r["header"]
            out.append(f"- {side} {r['name']}: label={h.get('label', '?')} "
                       f"commit={h.get('commit', '?')[:8]} budget={h.get('budget', '?')}s "
                       f"start={h.get('start', '?')}")
        return out

    lines = [
        "# 측정 런 비교", "",
        f"- 전: `{args.before}` ({len(before)} reps)",
        f"- 후: `{args.after}` ({len(after)} reps)", "",
        *meta("전", before), *meta("후", after), "",
        table, "",
        "## 지표 정의", "",
        "- 커버리지 분모: 라이브러리 전체 (llvm-cov export, run_summary.json `groups[].coverage`)",
        "- 런 전체 커버리지: 그룹별 `out/coverage/*.coverage.json` 파일별 covered 최대값 합"
        " → 실제 합집합 이하 (하한)",
        "- 그룹 커버리지 분모 0 (0/0): 측정 실패로 간주, `측정값 없음` 표기·평균 제외",
        f"- 즉시 크래시: fuzz_summary.json 에서 crashed 이고 duration_sec < {args.immediate_sec:g}s 인 그룹",
        "- 첫 크래시까지: 크래시 그룹 중 최소 duration_sec (그룹 기준),"
        " 그룹 시작 시각 − EXE 시작 시각 + duration_sec (EXE 기준, 그룹은 순차 실행)",
        "- 스모크 통과율: run_summary.json SMOKE 단계 passed/total (단계 없으면 측정값 없음)",
        "- 후/전: 평균값 비율 (커버리지 행만)", "",
    ]
    return "\n".join(lines)


# --- 타임라인 ----------------------------------------------------------------
def timeline_rows(side: str, runs: list) -> list:
    """타임라인 CSV 행 생성"""
    rows = []
    for r in runs:
        for p in r["timeline"]:
            rows.append({"side": side, "rep": r["name"], "group": p["slug"],
                         "run_elapsed_s": p["run_elapsed_s"],
                         "group_elapsed_s": p["group_elapsed_s"], "execs": p["execs"],
                         "exec_per_s": p["exec_per_s"], "cov": p["cov"]})
    return rows


AFTER_COLORS = ["#1f77b4", "#d62728", "#2ca02c", "#9467bd", "#ff7f0e", "#17becf"]
BEFORE_COLOR = "#9e9e9e"


def _series(rows: list) -> dict:
    """(group, side, rep) 별 (x, y) 목록 묶음"""
    out: dict = {}
    for r in rows:
        out.setdefault(r["group"], {}).setdefault((r["side"], r["rep"]), []).append(
            (r["group_elapsed_s"], r["cov"]))
    return out


def plot_png(rows: list, path: Path) -> bool:
    """matplotlib PNG 출력, 모듈 부재 시 False 반환"""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return False
    series = _series(rows)
    groups = sorted(series)
    fig, axes = plt.subplots(1, max(len(groups), 1), figsize=(6 * max(len(groups), 1), 4),
                             squeeze=False)
    for ax, g in zip(axes[0], groups):
        ai = 0
        for (side, rep), pts in sorted(series[g].items()):
            xs, ys = zip(*pts)
            if side == "before":
                ax.step(xs, ys, where="post", color=BEFORE_COLOR, alpha=0.8, label=f"전 {rep}")
            else:
                ax.step(xs, ys, where="post", color=AFTER_COLORS[ai % len(AFTER_COLORS)],
                        label=f"후 {rep}")
                ai += 1
        ax.set_xscale("symlog", linthresh=1)
        ax.set_title(g)
        ax.set_xlabel("그룹 퍼징 경과 (s, 추정)")
        ax.set_ylabel("edge cov")
        ax.grid(alpha=0.3)
        ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)
    return True


def plot_svg(rows: list, path: Path) -> None:
    """matplotlib 부재 시 표준 라이브러리만으로 단순 SVG 출력 (x 축 log10(1+s))"""
    series = _series(rows)
    groups = sorted(series)
    w, h, pad = 460, 300, 50
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w * max(len(groups), 1)}" '
             f'height="{h}" font-family="sans-serif" font-size="11">',
             f'<rect width="100%" height="100%" fill="white"/>']
    for i, g in enumerate(groups):
        ox = i * w
        pts_all = [p for s in series[g].values() for p in s]
        xmax = max(math.log10(1 + x) for x, _ in pts_all) or 1
        ymin = min(y for _, y in pts_all)
        ymax = max(y for _, y in pts_all)
        ymin, ymax = (ymin - 1, ymax + 1) if ymin == ymax else (ymin, ymax)

        def sx(x):
            return ox + pad + (w - 2 * pad) * math.log10(1 + x) / xmax

        def sy(y):
            return h - pad - (h - 2 * pad) * (y - ymin) / (ymax - ymin)

        parts.append(f'<text x="{ox + w / 2}" y="20" text-anchor="middle">{g}</text>')
        parts.append(f'<line x1="{ox + pad}" y1="{h - pad}" x2="{ox + w - pad}" y2="{h - pad}" stroke="#333"/>')
        parts.append(f'<line x1="{ox + pad}" y1="{pad}" x2="{ox + pad}" y2="{h - pad}" stroke="#333"/>')
        parts.append(f'<text x="{ox + pad - 5}" y="{h - pad}" text-anchor="end">{ymin}</text>')
        parts.append(f'<text x="{ox + pad - 5}" y="{pad + 4}" text-anchor="end">{ymax}</text>')
        parts.append(f'<text x="{ox + w - pad}" y="{h - pad + 15}" text-anchor="end">'
                     f'{10 ** xmax - 1:.0f}s (log)</text>')
        ai, ly = 0, pad
        for (side, rep), pts in sorted(series[g].items()):
            if side == "before":
                color, label = BEFORE_COLOR, f"전 {rep}"
            else:
                color, label = AFTER_COLORS[ai % len(AFTER_COLORS)], f"후 {rep}"
                ai += 1
            coords, prev_y = [], None
            for x, y in pts:
                if prev_y is not None:
                    coords.append(f"{sx(x):.1f},{sy(prev_y):.1f}")
                coords.append(f"{sx(x):.1f},{sy(y):.1f}")
                prev_y = y
            parts.append(f'<polyline fill="none" stroke="{color}" stroke-width="1.5" '
                         f'points="{" ".join(coords)}"/>')
            parts.append(f'<text x="{ox + w - pad + 2}" y="{ly}" fill="{color}" '
                         f'font-size="9">{label}</text>')
            ly += 12
    parts.append("</svg>")
    path.write_text("\n".join(parts), encoding="utf-8")


# --- 진입점 ------------------------------------------------------------------
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="개선 전/후 측정 런 비교")
    ap.add_argument("--before", required=True, type=Path)
    ap.add_argument("--after", required=True, type=Path)
    ap.add_argument("-o", "--outdir", required=True, type=Path)
    ap.add_argument("--immediate-sec", type=float, default=10.0,
                    help="즉시 크래시 판정 기준 초 (기본 10)")
    args = ap.parse_args(argv)

    before = load_side(args.before, args.immediate_sec)
    after = load_side(args.after, args.immediate_sec)
    if not before or not after:
        ap.error("rep* 하위 디렉터리 없음")
    args.outdir.mkdir(parents=True, exist_ok=True)

    md = render_markdown(before, after, args)
    (args.outdir / "comparison.md").write_text(md, encoding="utf-8")
    _, csv_rows = build_table(before, after)
    with open(args.outdir / "metrics.csv", "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerows(csv_rows)

    rows = timeline_rows("before", before) + timeline_rows("after", after)
    with open(args.outdir / "coverage_timeline.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["side", "rep", "group", "run_elapsed_s",
                                          "group_elapsed_s", "execs", "exec_per_s", "cov"])
        w.writeheader()
        w.writerows(rows)
    if rows:
        if plot_png(rows, args.outdir / "coverage_timeline.png"):
            print("coverage_timeline.png 생성")
        else:
            plot_svg(rows, args.outdir / "coverage_timeline.svg")
            print("matplotlib 없음 → PNG 생략, coverage_timeline.svg 대체 생성")
    print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
