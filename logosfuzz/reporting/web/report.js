/* ── 샘플 데이터 ─────────────────────────────── */
const SAMPLE = {
  "schema_version": "1.0",
  "generated_at": "2026-08-17T15:00:00+09:00",
  "metadata": {
    "project": "can-utils",
    "environment": "wsl2-local",
    "target": "lib.c / parse_canframe",
    "commit": "1828168"
  },
  "run": {
    "engine": "libfuzzer",
    "timeout_sec": 30,
    "total_groups": 5,
    "total_crashes": 3,
    "groups": [
      { "name": "lg_1", "status": "passed",  "exec_per_sec": 1796187, "coverage": 5,  "crash_count": 0, "timed_out": false, "compile_error_count": 0 },
      { "name": "lg_2", "status": "passed",  "exec_per_sec": 2,       "coverage": 29, "crash_count": 0, "timed_out": false, "compile_error_count": 0 },
      { "name": "lg_3", "status": "crashed", "exec_per_sec": 0,       "coverage": 9,  "crash_count": 1, "timed_out": false, "compile_error_count": 0 },
      { "name": "lg_4", "status": "crashed", "exec_per_sec": 0,       "coverage": 9,  "crash_count": 1, "timed_out": false, "compile_error_count": 0 },
      { "name": "lg_5", "status": "crashed", "exec_per_sec": 0,       "coverage": 3,  "crash_count": 1, "timed_out": false, "compile_error_count": 0 }
    ]
  },
  "analysis": {
    "status": "completed",
    "triage_model": "logosfuzz-rule-triage/v1",
    "summary": { "true_positive": 0, "false_positive": 3, "needs_review": 0 },
    "findings": [
      {
        "cluster_id": "CL-37ffe853f21a",
        "bug_type": "heap-buffer-overflow",
        "crash_location": "can-utils/lib.c:185",
        "error_reason": "READ of size 1",
        "triage_result": {
          "verdict": "false_positive", "confidence": 0.95,
          "rationale": "호출 경로 분석 결과 fgets → sscanf → parse_canframe 흐름에서 null terminator가 항상 보장됨. 하네스의 API 규약 위반으로 판명."
        }
      },
      {
        "cluster_id": "CL-3eda23ef26e2",
        "bug_type": "heap-buffer-overflow",
        "crash_location": "can-utils/lib.c:168",
        "error_reason": "READ of size 2",
        "triage_result": {
          "verdict": "false_positive", "confidence": 0.95,
          "rationale": "버그 1(lib.c:185)의 파생 현상. null-terminated 입력으로 단독 재현 불가."
        }
      },
      {
        "cluster_id": "CL-lg5-const",
        "bug_type": "overwrites-const-input",
        "crash_location": "harness_lg_5.c",
        "error_reason": "fuzz target overwrites its const input",
        "triage_result": {
          "verdict": "false_positive", "confidence": 1.0,
          "rationale": "타겟 버그 아님. LLM 하네스가 const uint8_t *data를 직접 캐스팅해서 넘긴 하네스 설계 문제."
        }
      }
    ]
  },
  "gen": {
    "status": "completed", "model": "gpt-4o-mini",
    "total_groups": 5, "validated_groups": 5, "failed_groups": 0
  },
  "metrics": {
    "groups": 5, "passed_groups": 2, "failed_groups": 0,
    "timed_out_groups": 0, "crashed_groups": 3,
    "crashes": 3, "sanitizer_findings": 3,
    "true_positive": 0, "false_positive": 3, "needs_review": 0
  }
};

/* ── 전역 상태 ───────────────────────────────── */
let currentData = null;

/* ── 진입점 ──────────────────────────────────── */
document.addEventListener("DOMContentLoaded", () => {
  setupDropZone();
  setupFileInput();
  document.getElementById("load-sample").addEventListener("click", () => render(SAMPLE));
  document.getElementById("download-btn").addEventListener("click", downloadJSON);
});

/* ── 드래그앤드롭 ────────────────────────────── */
function setupDropZone() {
  const zone = document.getElementById("drop-zone");

  zone.addEventListener("dragover", e => {
    e.preventDefault();
    zone.classList.add("over");
  });

  zone.addEventListener("dragleave", () => zone.classList.remove("over"));

  zone.addEventListener("drop", e => {
    e.preventDefault();
    zone.classList.remove("over");
    const file = e.dataTransfer.files[0];
    if (file) readFile(file);
  });
}

function setupFileInput() {
  document.getElementById("file-input").addEventListener("change", e => {
    const file = e.target.files[0];
    if (file) readFile(file);
  });
}

function readFile(file) {
  const reader = new FileReader();
  reader.onload = e => {
    try {
      const data = JSON.parse(e.target.result);
      render(data);
    } catch {
      alert("JSON 파싱 실패. 올바른 validation-summary.json 파일인지 확인해주세요.");
    }
  };
  reader.readAsText(file);
}

/* ── 렌더 ────────────────────────────────────── */
function render(data) {
  currentData = data;

  document.getElementById("drop-zone").classList.add("hidden");
  document.getElementById("report").classList.remove("hidden");

  renderHeader(data);
  renderSummaryBar(data);
  renderMetrics(data);
  renderGroups(data);
  renderFindings(data);
  renderGen(data);
}

function renderHeader(data) {
  const meta = data.metadata || {};
  const commit = meta.commit ? `@${meta.commit}` : "";
  document.getElementById("header-meta").textContent =
    `${meta.project || "—"}  ${commit}  ·  ${formatDate(data.generated_at)}`;
}

function renderSummaryBar(data) {
  const meta = data.metadata || {};
  setText("v-project",   meta.project     || "—");
  setText("v-env",       meta.environment || "—");
  setText("v-target",    meta.target      || "—");
  setText("v-generated", formatDate(data.generated_at));
}

function renderMetrics(data) {
  const m = data.metrics || {};
  const run = data.run || {};
  setText("m-groups",  m.groups  ?? run.total_groups  ?? "—");
  setText("m-crashes", m.crashes ?? run.total_crashes ?? "—");
  setText("m-tp",      m.true_positive  ?? "—");
  setText("m-fp",      m.false_positive ?? "—");
  setText("m-review",  m.needs_review   ?? "—");
  setText("m-engine",  run.engine       || "—");
}

function renderGroups(data) {
  const groups = (data.run || {}).groups || [];
  const tbody = document.getElementById("group-tbody");
  tbody.innerHTML = "";

  if (!groups.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty-msg">그룹 데이터 없음</td></tr>`;
    return;
  }

  groups.forEach(g => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${esc(g.target || g.group || g.name || "—")}</td>
      <td>${badgeHTML(g.status)}</td>
      <td>${fmtNum(g.exec_per_sec)}</td>
      <td>${g.coverage ?? "—"}</td>
      <td>${g.crash_count ?? 0}</td>
      <td>${g.timed_out ? 1 : 0}</td>
      <td>${g.compile_error_count ?? 0}</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderFindings(data) {
  const container = document.getElementById("findings-container");
  const findings = (data.analysis || {}).findings || [];

  if (!findings.length) {
    container.innerHTML = `<p class="empty-msg">크래시 없음</p>`;
    return;
  }

  container.innerHTML = findings.map(f => {
    const t = f.triage_result || {};
    const verdict = t.verdict || "needs_review";
    const verdictClass = verdict === "true_positive" ? "tp"
                       : verdict === "false_positive" ? "fp" : "nr";
    const verdictLabel = verdict === "true_positive" ? "정탐"
                       : verdict === "false_positive" ? "오탐" : "검토 필요";
    const conf = typeof t.confidence === "number" ? t.confidence : null;
    const cardClass = verdict === "true_positive" ? "verdict-tp"
                    : verdict === "false_positive" ? "verdict-fp" : "verdict-nr";

    return `
      <div class="finding-card ${cardClass}">
        <div class="finding-header">
          <div>
            <div class="finding-id">${esc(f.cluster_id || "")}</div>
            <div class="finding-type">${esc(f.bug_type || "unknown")}</div>
          </div>
          <span class="verdict-badge ${verdictClass}">${verdictLabel}</span>
        </div>
        <div class="finding-loc">📍 ${esc(f.crash_location || "—")}  ·  ${esc(f.error_reason || "")}</div>
        <div class="finding-rationale">${esc(t.rationale || "—")}</div>
        ${conf !== null ? `
          <div class="conf-bar-wrap">
            <span class="conf-label">신뢰도 ${Math.round(conf * 100)}%</span>
            <div class="conf-bar-bg">
              <div class="conf-bar-fill" style="width:${conf * 100}%"></div>
            </div>
          </div>` : ""}
      </div>
    `;
  }).join("");
}

function renderGen(data) {
  const gen = data.gen || {};
  const container = document.getElementById("gen-summary");

  if (!gen.status || gen.status === "not_run") {
    container.innerHTML = `<span class="empty-msg">GEN 단계 미실행</span>`;
    return;
  }

  const items = [
    { key: "모델",       val: gen.model || "—" },
    { key: "전체 그룹",  val: gen.total_groups ?? "—" },
    { key: "검증 성공",  val: gen.validated_groups ?? "—" },
    { key: "실패 그룹",  val: gen.failed_groups ?? 0 },
    { key: "상태",       val: gen.status },
  ];

  container.innerHTML = items.map(i => `
    <div class="gen-item">
      <span class="gen-key">${i.key}</span>
      <span class="gen-val">${esc(String(i.val))}</span>
    </div>
  `).join("");
}

/* ── 다운로드 ────────────────────────────────── */
function downloadJSON() {
  if (!currentData) return;
  const blob = new Blob([JSON.stringify(currentData, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "validation-summary.json";
  a.click();
  URL.revokeObjectURL(url);
}

/* ── 유틸 ────────────────────────────────────── */
function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function esc(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function fmtNum(n) {
  if (n === undefined || n === null) return "—";
  return Number(n).toLocaleString("ko-KR");
}

function formatDate(iso) {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString("ko-KR", {
      year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit"
    });
  } catch {
    return iso;
  }
}

function badgeHTML(status) {
  const map = {
    passed:        ["passed",        "통과"],
    crashed:       ["crashed",       "크래시"],
    timeout:       ["timeout",       "타임아웃"],
    failed:        ["failed",        "실패"],
    compile_failed:["compile_failed","컴파일 실패"],
  };
  const [cls, label] = map[status] || ["", status || "—"];
  return `<span class="badge badge-${cls}">${label}</span>`;
}
