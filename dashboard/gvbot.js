// GvBot Console — gvai-safety-systems
// Always works: loads local demo signals first, then tries external GodScore CI CSVs.
// Chat: calls a secure relay (Cloudflare Worker) so keys stay off GitHub Pages.

// ===============================
// 0) CONFIG
// ===============================

// 1) Demo always present (relative to /dashboard/)
const SOURCES = [
  // Local demo (always available)
  "data/demo_signals.csv",

  // External (optional)
  "https://willshacklett.github.io/godscore-ci/data/longitudinal/summary_history_binned.csv",
  "https://willshacklett.github.io/godscore-ci/data/longitudinal/summary_history.csv",
];

// 2) Face asset
const FACE_SRC = "./assets/gv_face.jpg";

// 3) Relay (Cloudflare Worker) — PASTE YOUR URL HERE
// Example: https://gvbot-relay.yourname.workers.dev
const RELAY_URL = ""; // <-- SET THIS

// ===============================
// 1) DOM HOOKS
// ===============================

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

  // Chat UI (these IDs should exist in your index.html)
  chatLog: document.getElementById("chatLog"),
  chatInput: document.getElementById("chatInput"),
  sendBtn: document.getElementById("sendBtn"),
};

// If your HTML uses different IDs, we’ll still try some fallbacks:
if (!els.chatLog) els.chatLog = document.querySelector(".chatLog") || document.querySelector("#chat");
if (!els.chatInput) els.chatInput = document.querySelector('input[placeholder*="Talk"]') || document.querySelector("input");
if (!els.sendBtn) els.sendBtn = document.querySelector("button#send") || document.querySelector("button");

// ===============================
// 2) UI HELPERS
// ===============================

function setPill(state, text) {
  if (!els.statePill) return;
  els.statePill.textContent = state;
  els.statePill.classList.remove("ok", "warn", "bad");
  if (state === "STABLE") els.statePill.classList.add("ok");
  else if (state === "WARN") els.statePill.classList.add("warn");
  else if (state === "ERROR") els.statePill.classList.add("bad");
  if (els.stateDesc) els.stateDesc.textContent = text || "";
}

function setText(el, txt) {
  if (!el) return;
  el.textContent = (txt === undefined || txt === null || txt === "") ? "—" : String(txt);
}

function fmt(n, digits = 3) {
  const num = Number(n);
  if (!Number.isFinite(num)) return "—";
  return num.toFixed(digits);
}

function nowStamp() {
  const d = new Date();
  // Local-friendly: YYYY-MM-DD HH:MM:SS
  const pad = (x) => String(x).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

// ===============================
// 3) CSV PARSING
// ===============================

function splitCSVLine(line) {
  const out = [];
  let cur = "";
  let inQ = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];

    if (ch === '"') {
      // double-quote escape
      if (inQ && line[i + 1] === '"') {
        cur += '"';
        i++;
      } else {
        inQ = !inQ;
      }
    } else if (ch === "," && !inQ) {
      out.push(cur);
      cur = "";
    } else {
      cur += ch;
    }
  }
  out.push(cur);
  return out;
}

function parseCSV(text) {
  const lines = text.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (lines.length < 2) return { headers: [], rows: [] };

  const headers = splitCSVLine(lines[0]).map((h) => h.trim());
  const rows = [];

  for (let i = 1; i < lines.length; i++) {
    const cols = splitCSVLine(lines[i]);
    const row = {};
    for (let j = 0; j < headers.length; j++) {
      row[headers[j]] = (cols[j] ?? "").trim();
    }
    rows.push(row);
  }

  return { headers, rows };
}

// ===============================
// 4) SIGNALS LOADING
// ===============================

async function fetchText(url) {
  const resp = await fetch(url, { cache: "no-store" });
  if (!resp.ok) throw new Error(`${resp.status} ${resp.statusText}`);
  return await resp.text();
}

function pickLatestRow(rows) {
  if (!rows || rows.length === 0) return null;

  // Try common timestamp column names
  const timeKeys = ["timestamp", "time", "run_time", "created_at", "date", "ts"];
  const key = timeKeys.find((k) => k in rows[0]);

  if (!key) {
    // fallback: last row
    return rows[rows.length - 1];
  }

  // sort by parsed date if possible
  const scored = rows
    .map((r) => {
      const t = Date.parse(r[key]);
      return { r, t: Number.isFinite(t) ? t : -Infinity };
    })
    .sort((a, b) => a.t - b.t);

  return scored[scored.length - 1]?.r || rows[rows.length - 1];
}

function extractMetrics(row) {
  // Try multiple header variants so this works with different CSVs
  const getAny = (keys) => {
    for (const k of keys) {
      if (row && row[k] !== undefined && row[k] !== "") return row[k];
    }
    return "";
  };

  const godscore = getAny(["godscore", "GodScore", "score", "trust", "trust_score"]);
  const risk = getAny(["risk", "Risk", "dgV", "dgv", "cumulative_dgv"]);
  const drift = getAny(["drift", "Drift", "delta", "delta_gv"]);
  const recovery = getAny(["recoverability", "recovery", "Recovery", "recover", "rhl"]);

  const timestamp = getAny(["timestamp", "time", "run_time", "created_at", "date", "ts"]);

  return {
    godscore,
    risk,
    drift,
    recovery,
    timestamp,
  };
}

function renderRecent(rows, max = 8) {
  if (!els.recentTable) return;

  const last = rows.slice(-max);
  let html = `<table class="table"><thead><tr>
    <th>Time</th><th>GodScore</th><th>Risk</th><th>Drift</th><th>Recovery</th>
  </tr></thead><tbody>`;

  for (const r of last) {
    const m = extractMetrics(r);
    html += `<tr>
      <td>${escapeHtml(m.timestamp || "—")}</td>
      <td>${escapeHtml(m.godscore || "—")}</td>
      <td>${escapeHtml(m.risk || "—")}</td>
      <td>${escapeHtml(m.drift || "—")}</td>
      <td>${escapeHtml(m.recovery || "—")}</td>
    </tr>`;
  }

  html += `</tbody></table>`;
  els.recentTable.innerHTML = html;
}

async function loadSignals() {
  for (const url of SOURCES) {
    try {
      const txt = await fetchText(url);
      const { rows } = parseCSV(txt);
      if (!rows || rows.length === 0) throw new Error("No rows");

      const latest = pickLatestRow(rows);
      const m = extractMetrics(latest);

      // Update UI
      setText(els.godscore, m.godscore ? String(m.godscore) : "—");
      setText(els.risk, m.risk ? fmt(m.risk, 3) : "—");
      setText(els.drift, m.drift ? fmt(m.drift, 3) : "—");
      setText(els.recovery, m.recovery ? fmt(m.recovery, 3) : "—");

      setText(els.runStamp, m.timestamp || nowStamp());
      if (els.dataSource) els.dataSource.textContent = `Source: ${url}`;

      // State pill
      setPill("STABLE", url.includes("demo_signals") ? "Demo signals loaded. External signals optional." : "External signals loaded.");

      // Recent table
      renderRecent(rows);

      return { ok: true, source: url };
    } catch (e) {
      // try next source
      continue;
    }
  }

  // All failed
  setPill("ERROR", "Could not load signals. See Source + Pages path.");
  if (els.dataSource) els.dataSource.textContent = "Source: (missing)";
  return { ok: false };
}

// ===============================
// 5) FACE LOADING
// ===============================

function loadFace() {
  if (!els.faceImg) return;

  els.faceImg.onload = () => {
    if (els.faceStatus) els.faceStatus.textContent = "Open face asset - face: loaded";
  };

  els.faceImg.onerror = () => {
    if (els.faceStatus) els.faceStatus.textContent = "Open face asset - face: loading…";
  };

  els.faceImg.src = FACE_SRC;
}

// ===============================
// 6) CHAT + RELAY
// ===============================

function appendChat(role, text) {
  if (!els.chatLog) return;

  // If your chatLog is a div container, append cards.
  const wrap = document.createElement("div");
  wrap.className = "chatRow " + (role === "user" ? "chatUser" : "chatGv");

  wrap.innerHTML = `
    <div class="chatRole">${role === "user" ? "You" : "Gv"}</div>
    <div class="chatBubble">${escapeHtml(text)}</div>
  `;

  els.chatLog.appendChild(wrap);
  els.chatLog.scrollTop = els.chatLog.scrollHeight;
}

async function callRelay(messages) {
  if (!RELAY_URL || RELAY_URL.trim() === "") {
    throw new Error("Relay URL not set. Paste your Cloudflare Worker URL into RELAY_URL in gvbot.js.");
  }

  const resp = await fetch(RELAY_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ messages }),
  });

  if (!resp.ok) {
    const txt = await resp.text();
    throw new Error(`Relay error (${resp.status}): ${txt}`);
  }

  const data = await resp.json();
  return (data && data.reply) ? String(data.reply) : "";
}

function setSendEnabled(on) {
  if (els.sendBtn) els.sendBtn.disabled = !on;
  if (els.chatInput) els.chatInput.disabled = !on;
}

async function onSend() {
  if (!els.chatInput) return;
  const userText = (els.chatInput.value || "").trim();
  if (!userText) return;

  els.chatInput.value = "";
  appendChat("user", userText);

  setSendEnabled(false);

  try {
    const messages = [{ role: "user", content: userText }];
    const reply = await callRelay(messages);

    appendChat("gv", reply || "…");
  } catch (e) {
    // Fallback message
    appendChat(
      "gv",
      `I'm here. Next we’ll connect me to a secure backend relay so I can think and remember safely.\n\nFor now: ${e.message}`
    );
  } finally {
    setSendEnabled(true);
  }
}

function wireChat() {
  if (!els.chatInput || !els.sendBtn) return;

  els.sendBtn.addEventListener("click", onSend);

  els.chatInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") onSend();
  });
}

// ===============================
// 7) BOOT
// ===============================

(async function boot() {
  try {
    loadFace();
    wireChat();
    await loadSignals();
  } catch (e) {
    setPill("ERROR", "Boot failed.");
  }
})();
