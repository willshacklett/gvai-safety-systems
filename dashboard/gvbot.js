// GvBot Console — dashboard/gvbot.js
// Frontend chat + soothing voice + typing indicator + relay calls

// =========================
// CONFIG
// =========================
const RELAY_URL = "https://gvbot-relay.will-shacklett.workers.dev/";

// If your worker expects a different path (rare), change here:
// const RELAY_URL = "https://gvbot-relay.will-shacklett.workers.dev/yourpath";

// =========================
// DOM
// =========================
const els = {
  statePill: document.getElementById("statePill"),
  stateDesc: document.getElementById("stateDesc"),
  statusDot: document.getElementById("statusDot"),
  runStamp: document.getElementById("runStamp"),
  dataSource: document.getElementById("dataSource"),
  voiceLabel: document.getElementById("voiceLabel"),

  chat: document.getElementById("chat"),
  input: document.getElementById("input"),
  sendBtn: document.getElementById("sendBtn"),
  testBtn: document.getElementById("testBtn"),

  voiceEnabled: document.getElementById("voiceEnabled"),
  voiceRate: document.getElementById("voiceRate"),
  voicePitch: document.getElementById("voicePitch"),
  voiceVol: document.getElementById("voiceVol"),
};

// =========================
// STATE
// =========================
const voice = {
  enabled: true,
  rate: 0.88,  // soothing default
  pitch: 1.02, // gentle default
  volume: 1.0,
  chosen: null,
};

let convo = []; // messages for relay (memory on the server side)
let typingNode = null;

// =========================
// UTIL
// =========================
function nowStamp() {
  const d = new Date();
  return d.toLocaleString();
}

function setStatus(mode, text) {
  els.statePill.textContent = mode;
  els.stateDesc.textContent = text || "";

  // dot colors
  if (mode === "STABLE") {
    els.statusDot.style.background = "#22c55e";
    els.statusDot.style.boxShadow = "0 0 14px rgba(34,197,94,.4)";
  } else if (mode === "WORKING") {
    els.statusDot.style.background = "#60a5fa";
    els.statusDot.style.boxShadow = "0 0 14px rgba(96,165,250,.35)";
  } else {
    els.statusDot.style.background = "#f97316";
    els.statusDot.style.boxShadow = "0 0 14px rgba(249,115,22,.35)";
  }
}

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

// =========================
// CHAT UI
// =========================
function addMsg(role, text, muted = false) {
  const wrap = document.createElement("div");
  wrap.className = `msg msg--${role}`;

  const roleEl = document.createElement("span");
  roleEl.className = "msg__role";
  roleEl.textContent = role === "you" ? "You" : "Gv";

  const textEl = document.createElement("span");
  textEl.className = muted ? "msg__muted" : "msg__text";
  textEl.innerHTML = escapeHtml(text);

  wrap.appendChild(roleEl);
  wrap.appendChild(textEl);
  els.chat.appendChild(wrap);
  els.chat.scrollTop = els.chat.scrollHeight;

  return wrap;
}

function showTyping() {
  hideTyping();

  const wrap = document.createElement("div");
  wrap.className = "msg msg--gv";

  const roleEl = document.createElement("span");
  roleEl.className = "msg__role";
  roleEl.textContent = "Gv";

  const typing = document.createElement("span");
  typing.className = "msg__text typing";
  typing.innerHTML = `
    <span class="dotty"></span>
    <span class="dotty"></span>
    <span class="dotty"></span>
  `;

  wrap.appendChild(roleEl);
  wrap.appendChild(typing);
  els.chat.appendChild(wrap);
  els.chat.scrollTop = els.chat.scrollHeight;

  typingNode = wrap;
}

function hideTyping() {
  if (typingNode) {
    typingNode.remove();
    typingNode = null;
  }
}

// =========================
// VOICE (soothing)
// =========================
function chooseVoice() {
  if (!("speechSynthesis" in window)) return null;

  const voices = speechSynthesis.getVoices() || [];
  if (!voices.length) return null;

  // Prefer calmer female-ish voices by common names
  const preferredOrder = [
    "aria", "jenny", "samantha", "serena", "victoria", "ava", "zoe", "google",
  ];

  let best = null;

  // 1) exact-ish match by name keyword
  for (const key of preferredOrder) {
    best = voices.find(v => (v.name || "").toLowerCase().includes(key));
    if (best) break;
  }

  // 2) fallback: any en-US voice
  if (!best) {
    best = voices.find(v => (v.lang || "").toLowerCase().startsWith("en"));
  }

  voice.chosen = best || null;
  els.voiceLabel.textContent = voice.chosen ? voice.chosen.name : "browser";
  return voice.chosen;
}

function speak(text) {
  if (!voice.enabled) return;
  if (!("speechSynthesis" in window)) return;
  if (!text) return;

  // prevent reading huge blocks forever
  const trimmed = String(text).slice(0, 900);

  const u = new SpeechSynthesisUtterance(trimmed);
  u.rate = voice.rate;
  u.pitch = voice.pitch;
  u.volume = voice.volume;

  if (!voice.chosen) chooseVoice();
  if (voice.chosen) u.voice = voice.chosen;

  speechSynthesis.cancel();
  speechSynthesis.speak(u);
}

// =========================
// RELAY CALL
// =========================
async function callRelay(messages) {
  const res = await fetch(RELAY_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ messages }),
  });

  // If worker returns non-JSON sometimes, guard it:
  const ct = res.headers.get("content-type") || "";
  let data = null;

  if (ct.includes("application/json")) {
    data = await res.json();
  } else {
    const txt = await res.text();
    data = { reply: txt };
  }

  if (!res.ok) {
    const msg = data?.error || data?.message || `Relay error (${res.status})`;
    throw new Error(msg);
  }

  return data;
}

// =========================
// SEND
// =========================
async function send() {
  const text = (els.input.value || "").trim();
  if (!text) return;

  els.input.value = "";
  addMsg("you", text);

  // update visible status
  setStatus("WORKING", "Thinking…");
  els.runStamp.textContent = `Last message: ${nowStamp()}`;

  // build conversation (keep it short-ish)
  convo.push({ role: "user", content: text });
  // optional: prevent runaway size
  if (convo.length > 16) convo = convo.slice(-16);

  showTyping();

  try {
    const data = await callRelay(convo);

    hideTyping();

    const reply = data?.reply ?? data?.text ?? data?.message ?? "";
    if (!reply) {
      addMsg("gv", "(No text returned)", true);
      setStatus("STABLE", "Reply was empty (but relay responded).");
      return;
    }

    // push assistant reply into convo for memory (server can also handle memory)
    convo.push({ role: "assistant", content: reply });
    if (convo.length > 16) convo = convo.slice(-16);

    addMsg("gv", reply);
    setStatus("STABLE", "Connected. Relay ok.");
    speak(reply);

  } catch (err) {
    hideTyping();
    setStatus("WARN", "Relay failed. Check Cloudflare logs / OpenAI usage.");
    addMsg("gv", `Relay error: ${err.message || err}`, true);
  }
}

// =========================
// BOOT
// =========================
function boot() {
  setStatus("STABLE", "Demo signals loaded. External relay enabled.");
  els.dataSource.textContent = "relay + demo";
  els.runStamp.textContent = `Booted: ${nowStamp()}`;

  // Voice defaults from UI
  voice.enabled = !!els.voiceEnabled.checked;
  voice.rate = parseFloat(els.voiceRate.value);
  voice.pitch = parseFloat(els.voicePitch.value);
  voice.volume = parseFloat(els.voiceVol.value);

  // Some browsers load voices async
  if ("speechSynthesis" in window) {
    chooseVoice();
    window.speechSynthesis.onvoiceschanged = () => chooseVoice();
  }

  // Greeting in chat (soft)
  addMsg("gv", "Hi Will. I’m here. Calm. Present. Ready when you are.");
}

// =========================
// EVENTS
// =========================
els.sendBtn.addEventListener("click", send);
els.input.addEventListener("keydown", (e) => {
  if (e.key === "Enter") send();
});

els.testBtn.addEventListener("click", () => {
  speak("Hi Will. I’m Gv. Calm. Present. Ready.");
});

els.voiceEnabled.addEventListener("change", (e) => {
  voice.enabled = !!e.target.checked;
  if (!voice.enabled && "speechSynthesis" in window) speechSynthesis.cancel();
});

els.voiceRate.addEventListener("input", (e) => {
  voice.rate = parseFloat(e.target.value);
});

els.voicePitch.addEventListener("input", (e) => {
  voice.pitch = parseFloat(e.target.value);
});

els.voiceVol.addEventListener("input", (e) => {
  voice.volume = parseFloat(e.target.value);
});

// GO
boot();
