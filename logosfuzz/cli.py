"""LogosFuzz CLI (EXE 파트).

설계서 EXE-04-00 명세:
  logosfuzz fuzz --engine <libfuzzer|afl++> --timeout <sec> --docker

로직 그룹 소스:
  --groups <json> 로 명시하거나, 미지정 시 --harness-dir 안의 실행 파일들을
  각각 하나의 그룹으로 자동 인식한다(SCH 산출물 연동 전까지의 편의 기능).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from logosfuzz.config import Engine, FuzzConfig, LogicGroup
from logosfuzz.execute.errors import ExecuteError
from logosfuzz.execute.fuzz_session import FuzzSession


def discover_groups(harness_dir: Path, groups_spec: Path | None) -> list:
    if groups_spec:
        data = json.loads(Path(groups_spec).read_text())
        out = []
        for g in data:
            out.append(LogicGroup(
                name=g["name"],
                harness_path=Path(g["harness"]),
                corpus_dir=Path(g["corpus"]) if g.get("corpus") else None,
            ))
        return out
    # 자동 탐색: harness_dir 안의 파일 각각을 그룹으로.
    groups = []
    if harness_dir.exists():
        for f in sorted(harness_dir.iterdir()):
            if f.is_file():
                groups.append(LogicGroup(name=f.stem, harness_path=Path(f.name)))
    return groups


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="logosfuzz", description="LogosFuzz 퍼징 프레임워크")
    sub = p.add_subparsers(dest="command", required=True)

    f = sub.add_parser("fuzz", help="Docker 격리 환경에서 퍼징 실행 (EXE-04-01)")
    f.add_argument("--engine", default="libfuzzer",
                   help="퍼징 엔진: libfuzzer | afl++ (기본 libfuzzer)")
    f.add_argument("--timeout", type=int, default=60,
                   help="그룹별 퍼징 시간(초, 기본 60)")
    f.add_argument("--docker", dest="docker", action="store_true", default=True,
                   help="Docker 격리 실행(기본값)")
    f.add_argument("--no-docker", dest="docker", action="store_false",
                   help="호스트에서 직접 실행(디버그용, 격리 없음)")
    f.add_argument("--harness-dir", type=Path, default=Path("harnesses"),
                   help="하네스(GEN 산출물) 디렉토리")
    f.add_argument("--output", "-o", type=Path, default=Path("out"),
                   help="출력 디렉토리(crashes/, logs/, summary)")
    f.add_argument("--groups", type=Path, default=None,
                   help="로직 그룹 정의 JSON(미지정 시 harness-dir 자동 탐색)")
    f.add_argument("--image", default="logosfuzz-exec:latest", help="격리 이미지 태그")
    f.add_argument("--no-build", action="store_true", help="이미지 자동 빌드 생략")
    return p


def main(argv: list | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command != "fuzz":
        return 2

    try:
        engine = Engine.parse(args.engine)
        config = FuzzConfig(
            engine=engine,
            timeout_sec=args.timeout,
            use_docker=args.docker,
            harness_dir=args.harness_dir,
            output_dir=args.output,
            image=args.image,
        )
        groups = discover_groups(args.harness_dir, args.groups)
        if not groups:
            print(f"[오류] 실행할 로직 그룹이 없습니다. --harness-dir({args.harness_dir}) "
                  f"또는 --groups를 확인하세요.", file=sys.stderr)
            return 1

        session = FuzzSession(config)
        summary = session.run(groups, ensure_image=not args.no_build)
        return 0 if summary.total_crashes == 0 else 3  # 3: 크래시 발견(analyze 필요)
    except ExecuteError as e:
        print(f"[EXE 오류] {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
