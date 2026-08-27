"""ANA 입력 로더: EXE-04-02 산출물을 :class:`CrashRecord` 목록으로 읽는다.

지원 입력
---------
1. 그룹별 JSONL: ``out/logs/sanitizer/<group>.jsonl`` — EXE-04-02가
   ``write_findings()``로 남긴 결함 스트림. 한 줄당 결함 1건.
2. 세션 요약: ``out/fuzz_summary.json`` — 각 그룹에 ``sanitizer_findings``
   배열이 포함된다(EXE-04-02 개발보고서 §"출력").

파일이 깨졌거나 일부 라인이 JSON이 아니어도 전체가 죽지 않고(파이프라인
견고성) 읽을 수 있는 레코드만 모은다.
"""

from __future__ import annotations

import json
from pathlib import Path

from logosfuzz.analyze.models import CrashRecord


def load_jsonl_findings(path: str | Path, group: str = "") -> list[CrashRecord]:
    """단일 JSONL 파일에서 레코드 목록을 읽는다."""
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
            continue  # 손상 라인은 건너뛴다
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
    """``fuzz_summary.json``의 그룹별 ``sanitizer_findings``에서 레코드를 읽는다.

    요약 JSON의 정확한 스키마는 그룹 목록을 담은 dict거나 list일 수 있으므로,
    ``sanitizer_findings`` 키를 재귀적으로 탐색해 최대한 견고하게 수집한다.
    """
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
    """입력 경로 목록(파일/디렉터리 혼합)을 자동 판별해 레코드로 통합한다.

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
