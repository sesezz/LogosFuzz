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
    "total_groups": 5, "validated_groups": 5, "failed_groups": 0,
    "groups": [
      { "group_id": "lg_1", "status": "validated", "rounds": 1,
        "generation_attempts": 1, "repair_attempts": 0, "failed_step": null, "reason": "" },
      { "group_id": "lg_5", "status": "validated", "rounds": 2,
        "generation_attempts": 2, "repair_attempts": 1,
        "failed_step": "compile", "reason": "첫 시도에서 헤더 누락으로 컴파일 실패, LLM 자가치유로 재생성 성공" }
    ]
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
let currentFileName = "";

/* ── 진입점 ──────────────────────────────────── */
document.addEventListener("DOMContentLoaded", () => {
  setupFileInput();
  setupDropZone();
  setupGlobalDrop();
  document.getElementById("load-sample").addEventListener("click", () => {
    clearNotice();
    currentFileName = "샘플 (can-utils)";
    render(SAMPLE);
  });
  document.getElementById("open-btn").addEventListener("click", openFileDialog);
  document.getElementById("download-btn").addEventListener("click", downloadJSON);
});

/* ── 파일 불러오기 ───────────────────────────── */
function openFileDialog() {
  document.getElementById("file-input").click();
}

function setupFileInput() {
  document.getElementById("file-input").addEventListener("change", e => {
    const file = e.target.files[0];
    if (file) readFile(file);
  });
}

/* 초기 화면의 드롭존: 영역 아무 곳이나 눌러도 파일 선택창이 열린다. */
function setupDropZone() {
  const zone = document.getElementById("drop-zone");
  zone.addEventListener("click", e => {
    if (e.target.closest("button, label, input")) return;   // 버튼·라벨은 자기 동작이 있다
    openFileDialog();
  });
}

/* 화면 어디에 끌어다 놔도 그 파일로 리포트를 바꾼다(리포트를 보는 중에도).
 * 파일이 아닌 드래그(텍스트 선택 등)는 건드리지 않는다. */
function setupGlobalDrop() {
  let depth = 0;
  const hasFiles = e =>
    !!e.dataTransfer && Array.from(e.dataTransfer.types || []).includes("Files");

  window.addEventListener("dragenter", e => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    depth += 1;
    document.body.classList.add("dragging");
  });
  window.addEventListener("dragover", e => {
    if (hasFiles(e)) e.preventDefault();       // drop 이벤트가 오려면 필요하다
  });
  window.addEventListener("dragleave", e => {
    if (!hasFiles(e)) return;
    depth = Math.max(0, depth - 1);
    if (depth === 0) document.body.classList.remove("dragging");
  });
  window.addEventListener("drop", e => {
    if (!hasFiles(e)) return;
    e.preventDefault();                          // 브라우저가 파일을 직접 열지 않게
    depth = 0;
    document.body.classList.remove("dragging");
    const file = e.dataTransfer.files[0];
    if (file) readFile(file);
  });
}

function readFile(file) {
  const reader = new FileReader();
  reader.onload = e => {
    let data;
    try {
      data = JSON.parse(e.target.result);
    } catch {
      showNotice(`“${file.name}” 은(는) JSON 이 아닙니다. 올바른 validation-summary.json 인지 확인해 주세요.`);
      return;
    }
    if (!isSummary(data)) {
      showNotice(`“${file.name}” 은(는) validation-summary.json 형식이 아닙니다 (run / metrics / build_units 가 없음).`);
      return;
    }
    clearNotice();
    currentFileName = file.name;
    render(data);
    window.scrollTo({ top: 0 });
  };
  reader.onerror = () => showNotice(`“${file.name}” 을(를) 읽지 못했습니다.`);
  reader.readAsText(file);
  // 같은 파일을 다시 골라도 change 가 발생하도록 비운다.
  document.getElementById("file-input").value = "";
}

function isSummary(data) {
  return !!data && typeof data === "object" && !Array.isArray(data)
    && !!(data.run || data.metrics || data.build_units);
}

/* 실패해도 이미 불러온 리포트는 그대로 둔다. */
function showNotice(message) {
  const el = document.getElementById("notice");
  el.className = "notice notice-error";
  el.innerHTML = `<span>${esc(message)}</span>`
    + `<button class="notice-close" type="button" aria-label="닫기">✕</button>`;
  el.querySelector(".notice-close").addEventListener("click", clearNotice);
}

function clearNotice() {
  const el = document.getElementById("notice");
  el.className = "notice hidden";
  el.innerHTML = "";
}

/* ── 렌더 ────────────────────────────────────── */
function render(data) {
  currentData = data;

  document.getElementById("drop-zone").classList.add("hidden");
  document.getElementById("report").classList.remove("hidden");
  document.getElementById("header-actions").classList.remove("hidden");

  renderHeader(data);
  renderSummaryBar(data);
  renderMetrics(data);
  renderGroups(data);
  renderBuildUnits(data);
  renderFindings(data);
  renderGen(data);
}

function renderHeader(data) {
  const meta = data.metadata || {};
  const commit = meta.commit ? ` @${meta.commit}` : "";
  const text = [currentFileName, `${meta.project || "—"}${commit}`, formatDate(data.generated_at)]
    .filter(Boolean).join("  ·  ");
  const el = document.getElementById("header-meta");
  el.textContent = text;
  el.title = text;
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

  // 크래시가 있으면 카드를 빨갛게 — 한눈에 보이게.
  const crashes = Number(m.crashes ?? run.total_crashes ?? 0);
  const card = document.getElementById("mc-crashes");
  if (card) card.classList.toggle("accent-red", Number.isFinite(crashes) && crashes > 0);
}

function renderGroups(data) {
  const groups = (data.run || {}).groups || [];
  setCount("c-groups", groups.length);
  const tbody = document.getElementById("group-tbody");
  tbody.innerHTML = "";

  if (!groups.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty-msg">그룹 데이터 없음</td></tr>`;
    return;
  }

  groups.forEach(g => {
    const name = g.target || g.group || g.name || "—";
    const tr = document.createElement("tr");
    // 긴 이름은 한 줄로 줄이고(title 로 전체 표시), 숫자도 문자열이 마크업이 되지 않게 이스케이프한다.
    tr.innerHTML = `
      <td class="cell-name" title="${esc(name)}">${esc(name)}</td>
      <td>${badgeHTML(g.status)}</td>
      <td class="num">${esc(fmtNum(g.exec_per_sec))}</td>
      <td class="num">${esc(String(g.coverage ?? "—"))}</td>
      <td class="num">${esc(String(g.crash_count ?? 0))}</td>
      <td class="num">${g.timed_out ? 1 : 0}</td>
      <td class="num">${esc(String(g.compile_error_count ?? 0))}</td>
    `;
    tbody.appendChild(tr);
  });
}

/* ── 빌드 단위별 결과 ────────────────────────────
 * validation-summary.json 의 최상위 `build_units`(reporting/summary.py)를 카드로 그린다.
 * Bazel 타깃(빌드 단위) 하나가 Logic Group 여럿을 가질 수 있어서, 그룹 표와 별도로
 * "어느 타깃이 빌드됐고(자가치유 여부) 퍼징 결과가 어땠나"를 한눈에 본다.
 * 표 대신 카드인 이유: 타깃·그룹 이름이 길어서 열이 많은 표는 중간에서 깨진다.
 * 필드가 없으면(예전 산출물) 섹션을 통째로 숨긴다 — 기존 샘플 JSON 은 화면이 그대로다.
 * 모든 값은 innerHTML 로 들어가므로 문자열은 esc(), 숫자는 genNum() 으로 강제 변환한다. */
const BUILD_STATUS_BADGE = {
  built:     ["passed",   "빌드 성공"],
  repaired:  ["repaired", "자가치유 후 성공"],
  failed:    ["failed",   "빌드 실패"],
  emitted:   ["emitted",  "파일만 생성"],
  not_built: ["notrun",   "빌드 정보 없음"],
};
const RUN_STATUS_BADGE = {
  passed:  ["passed",  "통과"],
  crashed: ["crashed", "크래시"],
  timeout: ["timeout", "타임아웃"],
  failed:  ["failed",  "실패"],
  not_run: ["notrun",  "미실행"],
};
const UNASSIGNED_UNIT = "(unassigned)";

function mappedBadge(map, status) {
  const [cls, label] = map[status] || ["", status || "—"];
  return `<span class="badge${cls ? ` badge-${cls}` : ""}">${esc(label)}</span>`;
}

/** 카드 왼쪽 띠 색: 문제가 있는 순서대로 우선한다. */
function buTone(u) {
  if (u.build_target === UNASSIGNED_UNIT) return "unassigned";
  if (u.build_status === "failed") return "bad";
  if (u.run_status === "crashed") return "crash";
  if (u.build_status === "repaired") return "repaired";
  return "ok";
}

function buCardHTML(u) {
  const target = u.build_target || "—";
  const groups = (Array.isArray(u.groups) ? u.groups : [])
    .map(g => `<span class="chip" title="${esc(g)}">${esc(g)}</span>`).join("");
  const crashes = genNum(u.crashes, 0);
  const sanitizer = genNum(u.sanitizer_findings, 0);
  const execs = `${u.execs_estimated === true ? "~" : ""}${fmtNum(genNum(u.execs, 0))}`;

  return `
    <article class="bu-card bu-${buTone(u)}">
      <div class="bu-head">
        <div class="bu-target" title="${esc(target)}">${esc(target)}</div>
        ${mappedBadge(BUILD_STATUS_BADGE, u.build_status)}
      </div>
      <div class="bu-groups">${groups || `<span class="chip">그룹 없음</span>`}</div>
      <dl class="bu-stats">
        <div><dt>실행</dt><dd>${mappedBadge(RUN_STATUS_BADGE, u.run_status)}</dd></div>
        <div><dt>크래시</dt><dd class="${crashes > 0 ? "is-bad" : ""}">${crashes}</dd></div>
        <div><dt>sanitizer</dt><dd class="${sanitizer > 0 ? "is-bad" : ""}">${sanitizer}</dd></div>
        <div><dt>execs</dt><dd>${esc(execs)}</dd></div>
        <div><dt>커버리지</dt><dd>${esc(fmtNum(genNum(u.coverage, 0)))}</dd></div>
        <div><dt>빌드 라운드</dt><dd>${genNum(u.rounds_used, 0)}</dd></div>
      </dl>
    </article>
  `;
}

function renderBuildUnits(data) {
  const section = document.getElementById("build-units-section");
  const bu = data.build_units;
  const units = bu && Array.isArray(bu.units) ? bu.units : [];

  if (!bu || bu.status === "not_run" || !units.length) {
    section.classList.add("hidden");
    return;
  }
  section.classList.remove("hidden");

  const built = genNum(bu.built_units, 0);
  const repaired = genNum(bu.repaired_units, 0);
  const failed = genNum(bu.failed_units, 0);
  const crashed = genNum(bu.crashed_units, 0);
  const total = genNum(bu.total_units, units.length);
  setCount("c-units", total);

  const stats = [
    { key: "빌드 단위",   val: total,    cls: "" },
    { key: "빌드 성공",   val: built,    cls: built > 0 ? "is-good" : "" },
    { key: "자가치유 복구", val: repaired, cls: repaired > 0 ? "is-info" : "" },
    { key: "빌드 실패",   val: failed,   cls: failed > 0 ? "is-bad" : "" },
    { key: "크래시 발생", val: crashed,  cls: crashed > 0 ? "is-bad" : "" },
    { key: "빌드 시스템", val: [bu.build_system, bu.config].filter(Boolean).join(" · ") || "—", cls: "is-text" },
  ];
  document.getElementById("bu-summary").innerHTML = stats.map(s => `
    <div class="bu-stat">
      <span class="bu-stat-key">${s.key}</span>
      <span class="bu-stat-val ${s.cls}">${esc(String(s.val))}</span>
    </div>
  `).join("");

  document.getElementById("bu-grid").innerHTML = units.map(buCardHTML).join("");

  const notes = [];
  if (units.some(u => u.execs_estimated === true)) {
    notes.push("execs 앞의 ~ 는 퍼징 요약에 총 실행 횟수가 없어 exec/s × 실행 시간으로 추정한 값입니다.");
  }
  if (units.some(u => u.build_target === UNASSIGNED_UNIT)) {
    notes.push("(unassigned) 는 빌드 결과와 이름이 맞는 그룹을 찾지 못한 퍼징 그룹입니다.");
  }
  document.getElementById("bu-notes").innerHTML =
    notes.map(n => `<p class="bu-note">${esc(n)}</p>`).join("");
}

function renderFindings(data) {
  const container = document.getElementById("findings-container");
  const findings = (data.analysis || {}).findings || [];
  setCount("c-findings", findings.length || "");

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
  const groupsContainer = document.getElementById("gen-groups");

  if (!gen.status || gen.status === "not_run") {
    container.innerHTML = `<span class="empty-msg">GEN 단계 미실행</span>`;
    groupsContainer.innerHTML = "";
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

  renderGenGroups(gen.groups || [], groupsContainer);
}

function renderGenGroups(groups, container) {
  if (!groups.length) {
    container.innerHTML = "";
    return;
  }

  container.innerHTML = groups.map(g => {
    // 숫자 필드도 innerHTML 로 들어가므로 문자열을 그대로 흘리면 안 된다.
    // 이 파일의 다른 렌더러(fmtNum)와 같이 Number() 로 강제 변환해서,
    // 손상된 JSON 의 문자열이 마크업으로 해석되지 않게 한다.
    const generated = genNum(g.generation_attempts, 1);
    const repaired = genNum(g.repair_attempts, 0);
    const rounds = genNum(g.rounds, 1);

    const attempts = `생성 ${generated}회`
      + (repaired ? ` · 자가치유 ${repaired}회` : "");
    const hasIssue = !!g.failed_step || repaired > 0;
    const errorLine = g.failed_step
      ? `<div class="gen-group-error">실패 단계: ${esc(g.failed_step)}${g.reason ? ` — ${esc(g.reason)}` : ""}</div>`
      : "";

    return `
      <div class="gen-group-card ${hasIssue ? "has-issue" : ""}">
        <div class="gen-group-header">
          <span class="gen-group-id">${esc(g.group_id || "—")}</span>
          <span class="gen-group-status">${esc(g.status || "—")}</span>
        </div>
        <div class="gen-group-attempts">${attempts} · ${rounds}라운드</div>
        ${errorLine}
      </div>
    `;
  }).join("");
}

/** 숫자로 못 읽히는 값(누락·문자열·NaN)만 기본값으로 떨어뜨린다.
 *
 *  진짜 0 은 0 으로 남긴다. `summary.py` 의 `_int()` 가 필드 누락을 0 으로
 *  기록하므로, 0 을 1 로 바꾸면 JSON 에 없는 수치를 지어내는 셈이 된다.
 */
function genNum(value, fallback) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
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

/** 섹션 제목 옆 개수 칩. 빈 값이면 칩이 사라진다(CSS :empty). */
function setCount(id, n) {
  const el = document.getElementById(id);
  if (el) el.textContent = n === "" || n === null || n === undefined ? "" : String(n);
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
  // 알 수 없는 상태 문자열이 마크업이 되지 않게 이스케이프한다.
  return `<span class="badge${cls ? ` badge-${cls}` : ""}">${esc(label)}</span>`;
}
