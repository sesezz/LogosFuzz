"""
S-CORE(baselibs) 저장소에 퍼징 오버레이를 적용한다.

baselibs 를 포크하지 않고 파일만 얹는다. baselibs 는 계속 갱신되므로
diff 패치가 아니라 **마커 기반 append + 파일 복사**로 구현했다. 같은
저장소에 여러 번 실행해도 결과가 같다(멱등).

    python -m logosfuzz.generate.bazel.apply_overlay --baselibs-root ~/baselibs
    python -m logosfuzz.generate.bazel.apply_overlay --baselibs-root ~/baselibs --dry-run
    python -m logosfuzz.generate.bazel.apply_overlay --baselibs-root ~/baselibs --revert

적용 후 실행:

    cd <baselibs-root>
    bazel run --config=fuzz //score/json/fuzz:json_parser_fuzz_test_run -- -runs=2000000

회귀 확인(오버레이가 기존 GCC 빌드를 깨지 않았는지):

    bazel build --config=bl-x86_64-linux //score/json:json
"""
from __future__ import annotations

import argparse
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List

OVERLAY_ROOT = Path(__file__).parent / "overlay"

# append 대상 파일과 스니펫. 마커는 스니펫 첫 줄/끝 줄에 들어 있다.
MODULE_MARKER = "logosfuzz overlay: rules_fuzzing"
BAZELRC_MARKER = "logosfuzz overlay: fuzz config"


@dataclass
class Action:
    """적용할 변경 1건. dry-run 출력과 실제 적용이 같은 목록을 쓴다."""

    kind: str  # "append" | "copy" | "skip"
    target: Path
    detail: str

    def __str__(self) -> str:
        return f"  [{self.kind:6}] {self.target}  {self.detail}"


def _marked_block(snippet_path: Path) -> str:
    return snippet_path.read_text(encoding="utf-8").rstrip("\n") + "\n"


def _plan_append(target: Path, snippet_path: Path, marker: str) -> Action:
    if not target.exists():
        return Action("skip", target, f"대상 파일 없음 - baselibs 루트가 맞는지 확인")
    if marker in target.read_text(encoding="utf-8"):
        return Action("skip", target, "이미 적용됨")
    return Action("append", target, f"<- {snippet_path.name}")


def _plan_copies(baselibs_root: Path) -> List[Action]:
    actions: List[Action] = []
    tree_root = OVERLAY_ROOT / "score"
    for src in sorted(tree_root.rglob("*")):
        if src.is_dir():
            continue
        rel = src.relative_to(OVERLAY_ROOT)
        dst = baselibs_root / rel
        if dst.exists() and dst.read_bytes() == src.read_bytes():
            actions.append(Action("skip", dst, "내용 동일"))
        else:
            actions.append(Action("copy", dst, f"<- overlay/{rel}"))
    return actions


def plan(baselibs_root: Path) -> List[Action]:
    return [
        _plan_append(
            baselibs_root / "MODULE.bazel",
            OVERLAY_ROOT / "module_snippet.bazel",
            MODULE_MARKER,
        ),
        _plan_append(
            baselibs_root / ".bazelrc",
            OVERLAY_ROOT / "bazelrc_snippet",
            BAZELRC_MARKER,
        ),
        *_plan_copies(baselibs_root),
    ]


def apply(actions: List[Action]) -> None:
    for action in actions:
        if action.kind == "append":
            name = "module_snippet.bazel" if action.target.name == "MODULE.bazel" else "bazelrc_snippet"
            block = _marked_block(OVERLAY_ROOT / name)
            with action.target.open("a", encoding="utf-8") as handle:
                handle.write("\n" + block)
        elif action.kind == "copy":
            rel = action.detail.split("<- overlay/", 1)[1]
            action.target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(OVERLAY_ROOT / rel, action.target)


def revert(baselibs_root: Path) -> List[str]:
    """마커 블록과 복사한 파일을 제거한다. baselibs 원본 줄은 건드리지 않는다."""
    removed: List[str] = []

    for filename, marker in (("MODULE.bazel", MODULE_MARKER), (".bazelrc", BAZELRC_MARKER)):
        target = baselibs_root / filename
        if not target.exists():
            continue
        lines = target.read_text(encoding="utf-8").splitlines(keepends=True)
        kept, inside = [], False
        for line in lines:
            if f">>> {marker} >>>" in line:
                inside = True
                continue
            if f"<<< {marker} <<<" in line:
                inside = False
                continue
            if not inside:
                kept.append(line)
        if len(kept) != len(lines):
            target.write_text("".join(kept).rstrip("\n") + "\n", encoding="utf-8")
            removed.append(f"{filename} (마커 블록 제거)")

    fuzz_dir = baselibs_root / "score" / "json" / "fuzz"
    if fuzz_dir.exists():
        shutil.rmtree(fuzz_dir)
        removed.append(str(fuzz_dir))

    return removed


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="baselibs 에 퍼징 오버레이 적용")
    parser.add_argument("--baselibs-root", required=True, type=Path)
    parser.add_argument("--dry-run", action="store_true", help="적용하지 않고 계획만 출력")
    parser.add_argument("--revert", action="store_true", help="오버레이 제거")
    args = parser.parse_args(argv)

    root: Path = args.baselibs_root.expanduser().resolve()
    if not (root / "MODULE.bazel").exists():
        print(f"baselibs 루트가 아닌 것 같다 (MODULE.bazel 없음): {root}", file=sys.stderr)
        return 2

    if args.revert:
        removed = revert(root)
        print("제거:" if removed else "제거할 것 없음")
        for item in removed:
            print(f"  {item}")
        return 0

    actions = plan(root)
    print(f"대상: {root}")
    for action in actions:
        print(action)

    if args.dry_run:
        print("\n--dry-run 이므로 적용하지 않았다.")
        return 0

    apply(actions)
    changed = sum(1 for a in actions if a.kind != "skip")
    print(f"\n적용 완료: {changed}건 변경, {len(actions) - changed}건 건너뜀")
    print("\n다음 단계:")
    print(f"  cd {root}")
    print("  bazel run --config=fuzz //score/json/fuzz:json_parser_fuzz_test_run -- -runs=2000000")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
