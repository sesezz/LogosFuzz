"""ANA 입력 로더: EXE-04-02 산출물의 :class:`CrashRecord` 목록 변환

지원 입력
---------
1. 그룹별 JSONL: ``out/logs/sanitizer/<group>.jsonl`` (한 줄당 결함 1건)
2. 세션 요약: ``out/fuzz_summary.json`` (그룹별 ``sanitizer_findings`` 배열)

손상 파일·라인은 건너뛰고 읽을 수 있는 레코드만 수집
"""

from __future__ import annotations

import json
from pathlib import Path

from logosfuzz.analyze.models import CrashRecord


def load_jsonl_findings(path: str | Path, group: str = "") -> list[CrashRecord]:
    """단일 JSONL 파일의 레코드 목록 로드"""
    p = Path(path)
    group = group or p.stem
    records: list[CrashRecord] = []
    text = p.read_text(encoding="utf-8")
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue  # 손상 라인 건너뜀
        if isinstance(data, dict):
            records.append(CrashRecord.from_finding(data, group=group))
    return records


def load_sanitizer_dir(logs_dir: str | Path) -> list[CrashRecord]:
    """디렉터리 아래의 모든 ``*.jsonl``을 재귀적으로 읽는다.

    ``logosfuzz fuzz``의 출력 디렉터리(예: ``out/``)를 그대로 넘겨도,
    한 단계 아래인 ``out/logs/sanitizer/*.jsonl``까지 찾아내도록
    ``glob`` 대신 ``rglob``을 사용한다. 같은 디렉터리에 ``fuzz_summary.json``이
    있으면 그것도 함께 읽는다(둘 다 있어도 CrashRecord는 이후 단계에서
    중복 제거되므로 안전하다).
    """
    root = Path(logs_dir)
    records: list[CrashRecord] = []
    if not root.exists():
        return records
    for f in sorted(root.rglob("*.jsonl")):
        records.extend(load_jsonl_findings(f, group=f.stem))
    summary = root / "fuzz_summary.json"
    if summary.exists():
        records.extend(load_fuzz_summary(summary))
    return records


def load_fuzz_summary(path: str | Path) -> list[CrashRecord]:
    """``fuzz_summary.json`` 그룹별 ``sanitizer_findings`` 레코드 로드 (키 재귀 탐색)"""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    records: list[CrashRecord] = []

    def visit(node, group_hint: str = "") -> None:
        if isinstance(node, dict):
            grp = str(node.get("group") or node.get("name") or group_hint)
            findings = node.get("sanitizer_findings")
            if isinstance(findings, list):
                for fnd in findings:
                    if isinstance(fnd, dict):
                        records.append(CrashRecord.from_finding(fnd, group=grp))
            for key, value in node.items():
                if key != "sanitizer_findings":
                    visit(value, grp)
        elif isinstance(node, list):
            for item in node:
                visit(item, group_hint)

    visit(data)
    return records


def load_records(inputs: list[str | Path]) -> list[CrashRecord]:
    """입력 경로 목록(파일/디렉터리 혼합) 자동 판별 및 레코드 통합

    - 디렉터리          → ``load_sanitizer_dir``
    - ``*.jsonl`` 파일   → ``load_jsonl_findings``
    - 그 외 ``*.json``   → ``load_fuzz_summary``
    """
    records: list[CrashRecord] = []
    for item in inputs:
        p = Path(item)
        if p.is_dir():
            records.extend(load_sanitizer_dir(p))
        elif p.suffix == ".jsonl":
            records.extend(load_jsonl_findings(p))
        else:
            records.extend(load_fuzz_summary(p))
    return records
