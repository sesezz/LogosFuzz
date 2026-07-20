import json
from pathlib import Path
from typing import List


def load_compile_commands(path: str) -> List[dict]:
    """Load compile_commands.json and return a list of compile command entries."""
    commands_path = Path(path)
    with commands_path.open("r", encoding="utf-8") as fh:
        entries = json.load(fh)

    if not isinstance(entries, list):
        raise ValueError("compile_commands.json must contain a JSON list of entries")

    return entries


def list_sources(path: str):
    return [entry["file"] for entry in load_compile_commands(path)]
