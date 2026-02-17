// GvBot Console — gvai-safety-systems
// Always works: loads local demo signals first, then tries external GodScore CI CSVs.

const SOURCES = [
  // Local demo (always available)
  "data/demo_signals.csv",

  // External (optional)
  "https://willshacklett.github.io/godscore-ci/data/longitudinal/summary_history_binned.csv",
  "https://willshacklett.github.io/godscore-ci/data/longitudinal/summary_history.csv",
];

const els = {
  statePill: document.getElementById("statePill"),
  stateDesc: document.getElementById("stateDesc"),
  runStamp: document.getElementById("runStamp"),
  godscore: document.getElementById("godscore"),
  risk: document.getElementById("risk"),
  drift: document.getElementById("drift"),
  recovery: document.getElementById("recovery"),
  recentTable: document.getElementById("recentTable"),
  dataSource: document.getElementById("dataSource"),
  faceImg: document.getElementById("faceImg"),
  faceStatus: document.getElementById("faceStatus"),
};

function splitCSVLine(line) {
  const out = [];
  let cur = "";
  let inQ = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"') { inQ = !inQ; continue; }
    if (c === "," && !inQ) { out.push(cur); cur = ""; continue; }
    cur += c;
  }
  out.push(cur);
  return out;
}

function parseCSV(text) {
  const lines = text.trim().split(/\r?\n/);
  if (lines.length < 2) return [];
  const headers = splitCSVLine(lines[0]).map(h => h.trim().toLowerCase());
  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    const cols = splitCSVLine(lines[i]);
    if (!cols.length) continue;
    const row = {};
    headers.forEach((h, idx) => row[h] = (cols[idx] ?? "").trim());
    rows.push(row);
  }
  return rows;
}

function pickField(row, candidates) {
  for (const c of candidates) {
    if (row[c] !== undefined && row[c] !== "") return row[c];
  }
  return "";
}

function toNum(v) {
  const n = Number(String(v).replace(/[%]/g, ""));
  return Number.isFinite(n) ? n : NaN;
}

function fmt(n, digits = 2) {
  if (!Number.isFinite(n)) return "—";
  return n % 1 === 0 ? String(n) : n.toFixed(digits);
}

function escapeHtml(s){
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"
  }[c]));
}

function setState(state, desc) {
  document.body.classList.remove("state-stable", "state-drift", "state-recovery");
  if (state === "STABLE") document.body.classList.add("state-stable");
  if (state === "DRIFT") document.body.classList.add("state-drift");
  if (state === "RECOVERY") document.body.classList.add("state-recovery");

  els.statePill.textContent = state;
  els.stateDesc.textContent = desc;
}

function deriveState(latest) {
  const gs = toNum(pickField(latest, ["godscore", "score", "god_score"]));
  const risk = toNum(pickField(latest, ["risk", "dgv", "cumulative_dgv", "cum_dgv"]));
  const drift = toNum(pickField(latest, ["drift", "delta", "drift_score"]));

  const recoveryMode =
    (Number.isFinite(drift) && drift >= 0.35) ||
    (Number.isFinite(risk) && risk >= 0.65) ||
    (Number.isFinite(gs) && gs <= 60);

  const driftMode =
    (Number.isFinite(drift) && drift >= 0.20) ||
    (Number.isFinite(risk) && risk >= 0.45) ||
    (Number.isFinite(gs) && gs <= 75);

  if (recoveryMode) return { state: "RECOVERY", desc: "Constraint enforcement active. Course-correcting." };
  if (driftMode) return { state: "DRIFT", desc: "Early warning. Drift detected — tighten constraints." };
  return { state: "STABLE", desc: "Stable state. Low drift. Memory aligned." };
}

function renderLatest(latest) {
  const ts = pickField(latest, ["timestamp", "time", "run_time", "date", "run_timestamp"]);
  const gs = toNum(pickField(latest, ["godscore", "score", "god_score"]));
  const risk = toNum(pickField(latest, ["risk", "dgv", "cumulative_dgv", "cum_dgv"]));
  const drift = toNum(pickField(latest, ["drift", "delta", "drift_score"]));
  const rec = toNum(pickField(latest, ["recoverability", "recovery", "rhl"]));

  els.runStamp.textContent = ts ? ts : "Latest run";
  els.godscore.textContent = fmt(gs, 1);
  els.risk.textContent = fmt(risk, 3);
  els.drift.textContent = fmt(drift, 3);
  els.recovery.textContent = Number.isFinite(rec) ? fmt(rec, 3) : "—";
}

function renderRecent(rows) {
  const tail = rows.slice(-12).reverse();
  if (!tail.length) {
    els.recentTable.innerHTML = `<tr><td colspan="5" class="muted">No rows found.</td></tr>`;
    return;
  }

  els.recentTable.innerHTML = tail.map(r => {
    const ts = pickField(r, ["timestamp","time","run_time","date","run_timestamp"]) || "—";
    const gs = toNum(pickField(r, ["godscore","score","god_score"]));
    const risk = toNum(pickField(r, ["risk","dgv","cumulative_dgv","cum_dgv"]));
    const drift = toNum(pickField(r, ["drift","delta","drift_score"]));
    const s = deriveState(r).state;

    return `<tr>
      <td>${escapeHtml(ts)}</td>
      <td>${escapeHtml(fmt(gs,1))}</td>
      <td>${escapeHtml(fmt(risk,3))}</td>
      <td>${escapeHtml(fmt(drift,3))}</td>
      <td><span class="pill">${escapeHtml(s)}</span></td>
    </tr>`;
  }).join("");
}

async function loadFirstAvailable() {
  for (const url of SOURCES) {
    try {
      const res = await fetch(url, { cache: "no-store" });
      if (!res.ok) continue;
      const text = await res.text();
      const rows = parseCSV(text);
      if (rows.length) return { url, rows };
    } catch (e) { /* try next */ }
  }
  throw new Error("No CSV source available.");
}

function wireFaceStatus(){
  if (!els.faceImg || !els.faceStatus) return;

  els.faceImg.addEventListener("load", () => {
    els.faceStatus.textContent = "face: loaded";
  });

  els.faceImg.addEventListener("error", () => {
    els.faceStatus.textContent = "face: fallback";
  });
}

(async function init(){
  wireFaceStatus();

  try {
    const { url, rows } = await loadFirstAvailable();
    els.dataSource.textContent = `Source: ${url}`;

    const latest = rows[rows.length - 1];
    renderLatest(latest);
    renderRecent(rows);

    const st = deriveState(latest);
    setState(st.state, st.desc);

    // If using local demo, say so.
    if (url.includes("data/demo_signals.csv")) {
      els.stateDesc.textContent = "Demo signals loaded. External signals optional.";
    }
  } catch (err) {
    setState("ERROR", "Signals could not be loaded.");
    els.dataSource.textContent = "Source: (missing)";
    els.recentTable.innerHTML = `<tr><td colspan="5" class="muted">${escapeHtml(err.message)}</td></tr>`;
  }
})();
