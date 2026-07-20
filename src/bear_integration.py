import argparse
import json
import os
import shutil
import subprocess
from typing import Optional


def run_bear_build(build_command: str, output_path: Optional[str] = None, cwd: Optional[str] = None):
    """Run a build through bear and write a compile_commands.json file."""
    if not shutil.which("bear"):
        raise FileNotFoundError("bear executable not found in PATH")

    if output_path is None:
        output_path = os.path.join(cwd or os.getcwd(), "compile_commands.json")

    cmd = ["bear", "--output", output_path, "--", *build_command.split()]
    completed = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )

    if completed.returncode != 0:
        raise RuntimeError(
            f"bear build failed: {completed.stderr.strip() or completed.stdout.strip()}"
        )

    if not os.path.exists(output_path):
        raise FileNotFoundError(f"compile database was not created: {output_path}")

    with open(output_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    return {"status": "ok", "output_path": output_path, "data": data}


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Run bear to generate compile_commands.json")
    parser.add_argument(
        "--build",
        required=True,
        help="Build command to run under bear, e.g. 'gcc -c sample.c -o sample.o'",
    )
    parser.add_argument(
        "--output",
        default="compile_commands.json",
        help="Output compile_commands JSON path",
    )
    parser.add_argument(
        "--cwd",
        default=None,
        help="Working directory for the build command",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    result = run_bear_build(args.build, output_path=args.output, cwd=args.cwd)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
