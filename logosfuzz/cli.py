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

from logosfuzz.config import CoverageMode, Engine, FuzzConfig, LogicGroup
from logosfuzz.execute.errors import ExecuteError
from logosfuzz.execute.fuzz_session import FuzzSession
from logosfuzz.reporting.summary import (
    ValidationSummaryError,
    build_validation_summary,
    load_json,
    write_validation_summary,
)


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
    f.add_argument("--coverage", default="none",
                   help="커버리지 계측(EXE-04-04): none | llvm-cov | sancov (기본 none). "
                        "하네스가 해당 계측 플래그로 빌드돼 있어야 수집된다.")

    # ANA 단계(Step 5/6): 크래시 중복 제거(ANA-05-04) → 정/오탐 판별(ANA-05-01)
    a = sub.add_parser("analyze",
                       help="크래시 분석: 중복 제거(ANA-05-04)+정/오탐 판별(ANA-05-01)")
    a.add_argument("inputs", nargs="+",
                   help="EXE-04-02 sanitizer 산출물(JSONL/디렉터리/fuzz_summary.json)")
    a.add_argument("--depth", type=int, default=3, help="시그니처 상위 프레임 수(기본 3)")
    a.add_argument("--output", "-o", type=Path, default=None, help="통합 결과 JSON 저장 경로")
    a.add_argument("--source-root", help="대상 C/C++ 소스 트리(도달 가능성 증거 수집)")
    a.add_argument("--harness-dir", help="크래시를 낸 하네스 소스 디렉터리(선택)")

    s = sub.add_parser(
        "summary",
        help="fuzz_summary.json과 analyze 결과를 공유용 validation-summary.json으로 통합",
    )
    s.add_argument("--run", required=True, type=Path, help="fuzz_summary.json 경로")
    s.add_argument("--analysis", type=Path, default=None, help="analyze 결과 JSON 경로")
    s.add_argument("--gen", "--generation", dest="generation", type=Path, default=None,
                   help="GEN-03-04 gen_validation_summary.json 경로")
    s.add_argument("--selection", type=Path, default=None,
                   help="EXT/SCH 대상 선정·제약 조건 결과 JSON 경로")
    s.add_argument("--output", "-o", type=Path, required=True,
                   help="표준 검증 결과 JSON 저장 경로")
    s.add_argument("--project", default="", help="프로젝트 또는 대상 이름")
    s.add_argument("--environment", default="", help="실행 환경(local|ec2)")
    s.add_argument("--target", default="", help="검증 대상 이름")
    s.add_argument("--commit", dest="commit_sha", default="", help="검증한 커밋 SHA")

    r = sub.add_parser(
        "regression",
        help="매니페스트 기반 컴파일/실행 회귀 스위트 실행",
    )
    r.add_argument("--manifest", required=True, type=Path,
                   help="회귀 케이스 매니페스트 JSON 경로 (cases: [{name, run, expected_status, ...}])")
    r.add_argument("--output", "-o", type=Path, default=Path("out"),
                   help="regression-summary.json과 케이스별 로그를 저장할 디렉토리")
    r.add_argument("--failed-only", action="store_true",
                   help="직전 실행에서 expected_status와 불일치했던 케이스만 재실행")
    return p


def main(argv: list | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.command == "summary":
        try:
            run = load_json(args.run)
            analysis = load_json(args.analysis) if args.analysis else None
            generation = load_json(args.generation) if args.generation else None
            selection = load_json(args.selection) if args.selection else None
            metadata = {
                key: value for key, value in {
                    "project": args.project,
                    "environment": args.environment,
                    "target": args.target,
                    "commit": args.commit_sha,
                }.items() if value
            }
            result = build_validation_summary(
                run,
                analysis,
                metadata=metadata,
                generation_summary=generation,
                selection_summary=selection,
            )
            path = write_validation_summary(args.output, result)
        except (OSError, ValidationSummaryError) as e:
            print(f"[SUMMARY 오류] {e}", file=sys.stderr)
            return 1
        print(
            f"[SUMMARY] 그룹 {result['metrics']['groups']}개 | "
            f"크래시 {result['metrics']['crashes']}건 | "
            f"정탐 {result['metrics']['true_positive']} | "
            f"오탐 {result['metrics']['false_positive']} | "
            f"검토필요 {result['metrics']['needs_review']}"
        )
        print(f"  -> {path}")
        return 0

    if args.command == "analyze":
        # ANA 파트로 위임(설계서 기능 흐름도의 analyze 명령)
        from logosfuzz.analyze.cli import _run_analyze
        return _run_analyze(args)

    if args.command == "regression":
        from logosfuzz.execute.regression import RegressionRunner
        try:
            summary = RegressionRunner(args.output).run_manifest(
                args.manifest, failed_only=args.failed_only
            )
        except (OSError, ValueError) as e:
            print(f"[REGRESSION 오류] {e}", file=sys.stderr)
            return 1
        print(
            f"[REGRESSION] {summary['suite']} | 총 {summary['total']}건 | "
            f"일치 {summary['matched']} | 불일치 {summary['failed']}"
        )
        print(f"  -> {args.output / 'regression-summary.json'}")
        return 0 if summary["failed"] == 0 else 1

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
            coverage=CoverageMode.parse(args.coverage),
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
