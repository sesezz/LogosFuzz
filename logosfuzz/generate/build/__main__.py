"""
CMake / prebuilt 어댑터 확인용 진입점 (GENERIC-B)
================================================

컨트롤러(``--mode generic``) 없이 **어댑터만** 시험한다. 손으로 쓴 하네스를 프로필의
라이브러리에 링크해 퍼저 바이너리를 만든다.

    # 라이브러리만 계측 빌드 (캐시됨)
    python -m logosfuzz.generate.build --profile targets/libsndfile.json --prepare-only

    # 수동 하네스를 빌드
    python -m logosfuzz.generate.build --profile targets/libsndfile.json \\
        --harness my_fuzz.c

    # 커버리지 변형(<build_dir>-cov)
    python -m logosfuzz.generate.build --profile targets/libsndfile.json \\
        --harness my_fuzz.c --coverage

성공하면 실행 파일 경로를 출력한다. 그 경로가 EXE 의 ``LogicGroup.harness_path`` 로 그대로 쓰인다.
Bazel 프로필은 이 도구 대신 ``ctr_06_01_controller --mode bazel`` 로 빌드한다.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional, Sequence

from logosfuzz.common.target_profile import ProfileError, load_profile

from . import HarnessSpec, Runner, adapter_for


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m logosfuzz.generate.build",
        description="CMake/prebuilt 어댑터로 수동 하네스를 빌드한다 (어댑터 확인용)",
    )
    parser.add_argument("--profile", required=True, type=Path, help="targets/*.json")
    parser.add_argument("--harness", type=Path, help="빌드할 하네스 소스 (.c / .cc)")
    parser.add_argument("--name", default="", help="바이너리 이름 (기본: 하네스 파일 이름)")
    parser.add_argument("--work-dir", type=Path, default=None,
                        help="하네스 소스·바이너리를 둘 위치 (기본: out/generic/<name>)")
    parser.add_argument("--base-dir", type=Path, default=None,
                        help="상대 source_root 의 기준 (기본: 현재 작업 디렉터리)")
    parser.add_argument("--coverage", action="store_true",
                        help="<build_dir>-cov 에 llvm-cov 계측 변형을 만든다")
    parser.add_argument("--force", action="store_true", help="캐시를 무시하고 라이브러리를 다시 빌드")
    parser.add_argument("--prepare-only", action="store_true", help="라이브러리 빌드까지만")
    return parser


def main(argv: Optional[Sequence[str]] = None, *, runner: Optional[Runner] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not args.prepare_only and args.harness is None:
        parser.error("--harness 가 필요하다 (라이브러리만 빌드하려면 --prepare-only)")

    try:
        profile = load_profile(args.profile, base_dir=args.base_dir)
    except ProfileError as exc:
        print(f"[BUILD 오류] {exc}", file=sys.stderr)
        return 2
    if profile.is_bazel:
        print("[BUILD 오류] bazel 프로필은 이 도구로 빌드하지 않는다 "
              "(ctr_06_01_controller --mode bazel 을 쓴다)", file=sys.stderr)
        return 2

    adapter = adapter_for(profile, work_dir=args.work_dir, coverage=args.coverage, runner=runner)

    prepared = adapter.prepare(force=args.force)
    print(f"[PREPARE] {'OK' if prepared.ok else 'FAIL'} {prepared.target} ({prepared.duration_s:.1f}s)")
    # 캐시를 버리고 다시 configure 했다는 사실은 성공했을 때도 보여야 한다.
    # 조용히 지나가면 "왜 2분이나 걸렸지" 로만 남는다.
    for line in prepared.log.splitlines():
        if line.startswith("INFO: "):
            print("  " + line)
    if not prepared.ok:
        print(prepared.short_log or prepared.log[-800:], file=sys.stderr)
        return 1
    if args.prepare_only:
        return 0

    harness: Path = args.harness
    try:
        source = harness.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"[BUILD 오류] 하네스를 읽을 수 없다: {harness} ({exc})", file=sys.stderr)
        return 2

    spec = HarnessSpec(name=args.name or harness.stem, srcs=(harness.name,))
    adapter.emit_build_definition(spec, source)
    result = adapter.build(spec)
    if not result.ok:
        print(f"[BUILD] FAIL {spec.name} ({result.duration_s:.1f}s)")
        print(result.short_log or result.log[-800:], file=sys.stderr)
        return 1
    print(f"[BUILD] OK {spec.name} ({result.duration_s:.1f}s)\n  -> {result.binary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
