import argparse
import json
import os
import shlex
from pathlib import Path

from src.ast_analyzer import analyze_file
from src.compile_commands import load_compile_commands


def extract_clang_args(command: str):
    parts = shlex.split(command)
    clang_args = []
    for i, part in enumerate(parts):
        if part.startswith("-I") or part.startswith("-D") or part.startswith("-std="):
            clang_args.append(part)
        elif part == "-isystem" and i + 1 < len(parts):
            clang_args.extend([part, parts[i + 1]])
    return clang_args


def normalize_path(path: str) -> str:
    if os.path.exists(path):
        return path

    if os.name == 'nt' and path.startswith('/mnt/'):
        parts = path.split('/')
        if len(parts) >= 4:
            drive = parts[2].upper()
            windows_path = Path(drive + ':' + os.sep + os.path.join(*parts[3:]))
            if windows_path.exists():
                return str(windows_path)

    return path


def analyze_compile_commands(path: str, output_path: str = None):
    entries = load_compile_commands(path)
    results = []
    for entry in entries:
        file_path = entry.get("file")
        if not file_path:
            continue
        command = entry.get("command", "")
        clang_args = extract_clang_args(command)
        if entry.get("directory"):
            file_path = os.path.join(entry["directory"], file_path)
        file_path = normalize_path(file_path)
        results.append({"file": file_path, "analysis": analyze_file(file_path, clang_args=clang_args)})

    if output_path:
        Path(output_path).write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    return results


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Analyze compile_commands.json entries using AST analyzer.")
    parser.add_argument("--compile-db", required=True, help="Path to compile_commands.json")
    parser.add_argument("--output", help="Optional JSON output path")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    results = analyze_compile_commands(args.compile_db, output_path=args.output)
    print(json.dumps(results, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
