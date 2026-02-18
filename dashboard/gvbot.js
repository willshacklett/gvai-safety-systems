// GvBot Console — dashboard/gvbot.js

const RELAY_URL = "https://gvbot-relay.will-shacklett.workers.dev/";

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
  // "calm island" defaults
  rate: 0.86,
  pitch: 0.98,
  volume: 1.0,
  chosen: null,
};

let convo = [];
let typingNode = null;

// =========================
// UTIL
// =========================
function nowStamp() {
  return new Date().toLocaleString();
}

function setStatus(mode, text) {
  els.statePill.textContent = mode;
  els.stateDesc.textContent = text || "";

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
// VOICE: force US English, avoid Deutsch
// =========================
function pickBestUSVoice(voices) {
  const bad = ["deutsch", "german", "de-de", "de_"];

  const goodLangUS = voices.filter(v => (v.lang || "").toLowerCase() === "en-us");
  const goodLangEN = voices.filter(v => (v.lang || "").toLowerCase().startsWith("en"));

  const notBad = (v) => {
    const n = (v.name || "").toLowerCase();
    const l = (v.lang || "").toLowerCase();
    return !bad.some(b => n.includes(b) || l.includes(b));
  };

  // Prefer US voices, and within those prefer natural-sounding names
  const preferNames = ["aria", "jenny", "samantha", "zira", "google us", "english united states"];

  const chooseFrom = (list) => {
    const cleaned = list.filter(notBad);
    for (const key of preferNames) {
      const found = cleaned.find(v => (v.name || "").toLowerCase().includes(key));
      if (found) return found;
    }
    return cleaned[0] || null;
  };

  return (
    chooseFrom(goodLangUS) ||
    chooseFrom(goodLangEN) ||
    chooseFrom(voices) ||
    null
  );
}

function chooseVoice() {
  if (!("speechSynthesis" in window)) return null;

  const voices = speechSynthesis.getVoices() || [];
  if (!voices.length) return null;

  voice.chosen = pickBestUSVoice(voices);
  els.voiceLabel.textContent = voice.chosen ? `${voice.chosen.name} (${voice.chosen.lang})` : "browser";

  return voice.chosen;
}

function speak(text) {
  if (!voice.enabled) return;
  if (!("speechSynthesis" in window)) return;
  if (!text) return;

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

  const ct = res.headers.get("content-type") || "";
  let data = null;

  if (ct.includes("application/json")) data = await res.json();
  else data = { reply: await res.text() };

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

  setStatus("WORKING", "Thinking…");
  els.runStamp.textContent = `Last message: ${nowStamp()}`;

  convo.push({ role: "user", content: text });
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

  // Pull UI values (these are your “Hawaiian calm” knobs)
  voice.enabled = !!els.voiceEnabled.checked;
  voice.rate = parseFloat(els.voiceRate.value);
  voice.pitch = parseFloat(els.voicePitch.value);
  voice.volume = parseFloat(els.voiceVol.value);

  if ("speechSynthesis" in window) {
    chooseVoice();
    window.speechSynthesis.onvoiceschanged = () => chooseVoice();
  }

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
  speak("Aloha Will. I’m Gv. Calm and steady. Ready when you are.");
});

els.voiceEnabled.addEventListener("change", (e) => {
  voice.enabled = !!e.target.checked;
  if (!voice.enabled && "speechSynthesis" in window) speechSynthesis.cancel();
});

els.voiceRate.addEventListener("input", (e) => (voice.rate = parseFloat(e.target.value)));
els.voicePitch.addEventListener("input", (e) => (voice.pitch = parseFloat(e.target.value)));
els.voiceVol.addEventListener("input", (e) => (voice.volume = parseFloat(e.target.value)));

boot();
