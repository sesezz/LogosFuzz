#!/usr/bin/env python3
"""자동차(Bazel) 모드 회귀: tests/golden/automotive 골든 비교

범용화 작업의 ``ctr_06_01_controller --mode bazel`` 경로 영향 확인 (``--emit-only``, Bazel·LLM 불필요)
비교 규칙은 tests/golden/automotive/README.md 와 동일 (실행마다 다른 필드 제외)

    python3 scripts/check_automotive_golden.py            # 임시 워크스페이스
    python3 scripts/check_automotive_golden.py --workspace ~/baselibs

종료 코드: 0 일치, 1 불일치
"""
from __future__ import annotations

import argparse
import difflib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
GOLDEN = REPO / "tests" / "golden" / "automotive"
HARNESS = 'extern "C" int LLVMFuzzerTestOneInput(const unsigned char* d, unsigned long n){return 0;}\n'
VOLATILE = ("started_at", "finished_at", "workspace")


def normalise(summary: dict) -> str:
    data = {k: v for k, v in summary.items() if k not in VOLATILE}
    data["units"] = [{k: v for k, v in u.items() if k != "rounds"} for u in data.get("units", [])]
    return json.dumps(data, indent=1, sort_keys=True, ensure_ascii=False)


def run_emit(workspace: Path, work: Path) -> tuple[dict, str]:
    harness = work / "h.cc"
    harness.write_text(HARNESS, encoding="utf-8")
    summary_path = work / "after.json"
    cmd = [sys.executable, "-m", "logosfuzz.control.ctr_06_01_controller", "--mode", "bazel",
           "--workspace", str(workspace), "--harness", str(harness),
           "--build-target", "//score/json:json", "--group", "ar_probe",
           "--emit-only", "--skip-check", "--build-summary", str(summary_path)]
    subprocess.run(cmd, cwd=REPO, check=True, capture_output=True, text=True)
    build_file = workspace / "score" / "json" / "fuzz" / "ar_probe" / "BUILD.bazel"
    return json.loads(summary_path.read_text(encoding="utf-8")), build_file.read_text(encoding="utf-8")


def check(workspace: Path | None = None) -> list[str]:
    """차이 목록 (unified diff 줄, 비어 있으면 골든과 일치)"""
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        ws = Path(workspace).expanduser() if workspace else work / "ws"
        ws.mkdir(parents=True, exist_ok=True)
        summary, build = run_emit(ws, work)
    want_summary = normalise(json.loads((GOLDEN / "build_summary.golden.json").read_text(encoding="utf-8")))
    want_build = (GOLDEN / "BUILD.bazel.golden").read_text(encoding="utf-8")
    diff = list(difflib.unified_diff(want_summary.splitlines(), normalise(summary).splitlines(),
                                     "golden/build_summary", "current", lineterm=""))
    diff += list(difflib.unified_diff(want_build.splitlines(), build.splitlines(),
                                      "golden/BUILD.bazel", "current", lineterm=""))
    return diff


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--workspace", type=Path, default=None,
                        help="BUILD 를 쓸 워크스페이스 (기본: 임시 디렉터리)")
    args = parser.parse_args()
    diff = check(args.workspace)
    if diff:
        print("\n".join(diff))
        print("[자동차 회귀] 골든과 다르다", file=sys.stderr)
        return 1
    print("[자동차 회귀] build_summary · BUILD.bazel 골든과 일치")
    return 0


if __name__ == "__main__":
    sys.exit(main())
