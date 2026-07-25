"""
ANA-05-02: CVEReport 를 JSON / Markdown 두 가지 산출 포맷으로 변환.

- JSON: CTR-06(제어) 및 ANA-05-03(지식베이스 역피드백) 단계에서 기계적으로
  소비하기 위한 포맷.
- Markdown: 개발팀/제보 담당자가 사람이 읽고 바로 CNA(CVE Numbering Authority)
  제보 양식에 옮겨 담을 수 있도록 하는 포맷. OSS-Fuzz 이슈 리포트 관례를 따라
  요약 -> 영향 -> 재현 절차 -> PoC -> 스택트레이스 순으로 구성한다.
"""

from __future__ import annotations

import json

from schema import CVEReport


def render_json(report: CVEReport, indent: int = 2) -> str:
    return json.dumps(report.to_dict(), ensure_ascii=False, indent=indent)


def render_markdown(report: CVEReport) -> str:
    r = report
    lines: list[str] = []

    lines.append(f"# [{r.report_id}] {r.title}")
    lines.append("")
    lines.append(f"> 상태: `{r.status.value}` · 발견일시: {r.discovered_at} · 도구: {r.discovery_tool}")
    lines.append("")

    lines.append("## 요약")
    lines.append(r.description)
    lines.append("")

    lines.append("## 취약점 분류")
    lines.append(f"- **CWE**: {r.cwe.id} ({r.cwe.name})")
    if r.cwe.related_ids:
        lines.append(f"  - 관련 CWE: {', '.join(r.cwe.related_ids)}")
    lines.append(f"- **CVSS 3.1**: {r.cvss.base_score} ({r.cvss.severity})")
    lines.append(f"  - Vector: `{r.cvss.vector}`")
    if r.cvss.is_estimated:
        lines.append(
            "  - ⚠️ 이 CVSS 값은 자동 휴리스틱 초안입니다. "
            "제보 전 담당자의 수동 검토/보정이 필요합니다."
        )
    lines.append("")

    lines.append("## 영향받는 컴포넌트")
    ac = r.affected_component
    lines.append(f"- 라이브러리: **{ac.library_name}**" + (f" (v{ac.version})" if ac.version else ""))
    if ac.function_signature:
        lines.append(f"- 함수 시그니처: `{ac.function_signature}`")
    if ac.repository_url:
        lines.append(f"- 저장소: {ac.repository_url}")
    lines.append("")

    lines.append("## 정탐/오탐 판정 (ANA-05-01)")
    t = r.triage
    lines.append(f"- 판정: **{t.verdict.value}** (신뢰도 {t.confidence:.2f}, 모델: {t.triage_model})")
    lines.append(f"- 판정 근거: {t.rationale}")
    lines.append("")

    lines.append("## 재현 방법")
    rep = r.reproduction
    for step in rep.reproduction_steps:
        lines.append(step)
    lines.append("")
    lines.append(f"- 하네스: `{rep.harness_code_path}` (harness_id: {rep.harness_id})")
    lines.append(f"- 퍼징 실행 ID: {rep.run_id}")
    if rep.poc_input_path:
        lines.append(f"- PoC 입력 파일: `{rep.poc_input_path}`")
    lines.append("")

    lines.append("## 크래시 상세")
    cd = r.crash_details
    lines.append(f"- Sanitizer: {cd.sanitizer}")
    lines.append(f"- 에러 유형: `{cd.error_type}`")
    if cd.crash_location:
        lines.append(f"- 크래시 위치: `{cd.crash_location}`")
    if cd.access_type and cd.access_size is not None:
        lines.append(f"- 접근: {cd.access_type} of size {cd.access_size}")
    if cd.fault_address:
        lines.append(f"- Fault address: `{cd.fault_address}`")
    if cd.freed_at_location:
        lines.append(f"- Free 호출 위치: `{cd.freed_at_location}`")
    if cd.allocated_at_location:
        lines.append(f"- 최초 할당(malloc) 위치: `{cd.allocated_at_location}`")
    lines.append("")
    lines.append("### 스택트레이스")
    lines.append("```")
    for frame in cd.stack_trace:
        loc = f" {frame['location']}" if frame.get("location") else ""
        lines.append(f"#{frame['frame']} {frame['function']}{loc}")
    lines.append("```")
    lines.append("")

    lines.append("<details><summary>원본 Sanitizer 로그 전문</summary>")
    lines.append("")
    lines.append("```")
    lines.append(cd.raw_asan_log.strip())
    lines.append("```")
    lines.append("</details>")
    lines.append("")

    if r.references:
        lines.append("## 참조")
        for ref in r.references:
            lines.append(f"- {ref}")

    return "\n".join(lines)
