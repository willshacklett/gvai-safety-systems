/* =========================
   GvBot Console (frontend)
   - Sends chat to Cloudflare relay
   - Animates avatar while speaking
   - Voice picker (best you can do for “accent”)
========================= */

const RELAY_URL = "https://gvbot-relay.will-shacklett.workers.dev/"; // your Worker
const AVATAR_URL = "./assets/gv-face.jpg"; // MUST exist exactly (case-sensitive on Pages)
const STORAGE_KEY = "gvbot_chat_v1";

const els = {
  chatBox: document.getElementById("chatBox"),
  input: document.getElementById("input"),
  sendBtn: document.getElementById("sendBtn"),
  connLine: document.getElementById("connLine"),
  statusPill: document.getElementById("statusPill"),
  lastMsg: document.getElementById("lastMsg"),
  bootLine: document.getElementById("bootLine"),
  avatarWrap: document.getElementById("gvAvatarWrap"),
  avatarImg: document.getElementById("gvAvatarImg"),
  avatarStatus: document.getElementById("gvAvatarStatus"),
  voiceEnabled: document.getElementById("voiceEnabled"),
  voiceRate: document.getElementById("voiceRate"),
  voicePitch: document.getElementById("voicePitch"),
  voiceVol: document.getElementById("voiceVol"),
  voiceSelect: document.getElementById("voiceSelect"),
  voiceBadge: document.getElementById("voiceBadge"),
  testVoiceBtn: document.getElementById("testVoiceBtn"),
};

const state = {
  messages: [],
  speaking: false,
  voice: {
    enabled: true,
    rate: 0.94,
    pitch: 1.02,
    volume: 1.0,
    selectedVoiceURI: "",
  }
};

/* =========================
   Boot
========================= */
function nowStr() {
  try {
    return new Date().toLocaleString();
  } catch { return String(Date.now()); }
}

els.bootLine.textContent = `Booted: ${nowStr()}`;

/* =========================
   Avatar load + error
========================= */
function loadAvatar() {
  els.avatarImg.onload = () => {
    els.avatarStatus.textContent = "Avatar loaded.";
  };
  els.avatarImg.onerror = () => {
    els.avatarStatus.innerHTML =
      `Gv face not found<br/>
       <span style="color:rgba(231,234,240,0.55)">Expected: <code>dashboard/assets/gv-face.jpg</code></span><br/>
       <span style="color:rgba(231,234,240,0.45)">GitHub Pages is case-sensitive (gv-face.jpg ≠ GV-FACE.JPG)</span>`;
  };
  els.avatarImg.src = AVATAR_URL + "?v=" + Date.now();
}
loadAvatar();

/* Random blink to feel “alive” */
setInterval(() => {
  els.avatarWrap.classList.add("blink");
  setTimeout(() => els.avatarWrap.classList.remove("blink"), 120);
}, 5200);

/* =========================
   Chat rendering
========================= */
function escapeHtml(s) {
  return String(s)
    .replaceAll("&","&amp;")
    .replaceAll("<","&lt;")
    .replaceAll(">","&gt;")
    .replaceAll('"',"&quot;")
    .replaceAll("'","&#039;");
}

function addMsg(role, text) {
  const wrap = document.createElement("div");
  wrap.className = `msg ${role}`;

  const who = document.createElement("span");
  who.className = "who";
  who.textContent = role === "you" ? "You" : "Gv";

  const bubble = document.createElement("span");
  bubble.className = "bubble";
  bubble.innerHTML = escapeHtml(text).replaceAll("\n","<br/>");

  wrap.appendChild(who);
  wrap.appendChild(bubble);
  els.chatBox.appendChild(wrap);
  els.chatBox.scrollTop = els.chatBox.scrollHeight;
}

function saveChat() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state.messages.slice(-30)));
  } catch {}
}

function loadChat() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return;
    const msgs = JSON.parse(raw);
    if (!Array.isArray(msgs)) return;
    state.messages = msgs;
    // render
    els.chatBox.innerHTML = "";
    for (const m of msgs) {
      addMsg(m.role === "user" ? "you" : "gv", m.content);
    }
  } catch {}
}
loadChat();

/* Seed a friendly first line if empty */
if (state.messages.length === 0) {
  addMsg("gv", "Hi Will. I’m here. Calm. Present. Ready when you are.");
  state.messages.push({ role: "assistant", content: "Hi Will. I’m here. Calm. Present. Ready when you are." });
  saveChat();
}

/* =========================
   Voice system (Web Speech)
   Note: Browsers do NOT let us force a “Hawaiian accent”.
   Best path: pick an en-US voice that sounds closest + tune rate/pitch.
========================= */
function getVoicesSafe() {
  try { return window.speechSynthesis?.getVoices?.() || []; }
  catch { return []; }
}

function rebuildVoiceList() {
  const voices = getVoicesSafe();

  // Prefer en-US first, then English
  const sorted = voices.slice().sort((a,b) => {
    const aUS = (a.lang || "").toLowerCase().startsWith("en-us") ? 0 : 1;
    const bUS = (b.lang || "").toLowerCase().startsWith("en-us") ? 0 : 1;
    if (aUS !== bUS) return aUS - bUS;
    const aEn = (a.lang || "").toLowerCase().startsWith("en") ? 0 : 1;
    const bEn = (b.lang || "").toLowerCase().startsWith("en") ? 0 : 1;
    if (aEn !== bEn) return aEn - bEn;
    return (a.name || "").localeCompare(b.name || "");
  });

  els.voiceSelect.innerHTML = "";

  const optAuto = document.createElement("option");
  optAuto.value = "";
  optAuto.textContent = "Auto (best en-US)";
  els.voiceSelect.appendChild(optAuto);

  for (const v of sorted) {
    const o = document.createElement("option");
    o.value = v.voiceURI || v.name;
    o.textContent = `${v.name} — ${v.lang}`;
    els.voiceSelect.appendChild(o);
  }

  // restore selection
  els.voiceSelect.value = state.voice.selectedVoiceURI || "";

  // badge
  const chosen = sorted.find(v => (v.voiceURI || v.name) === state.voice.selectedVoiceURI);
  if (chosen) els.voiceBadge.textContent = `${chosen.name} (${chosen.lang})`;
  else els.voiceBadge.textContent = "Auto";
}

// Some browsers populate voices async
if ("speechSynthesis" in window) {
  rebuildVoiceList();
  window.speechSynthesis.onvoiceschanged = () => rebuildVoiceList();
}

function pickPreferredVoice() {
  const voices = getVoicesSafe();
  if (!voices.length) return null;

  const wantedURI = state.voice.selectedVoiceURI;
  if (wantedURI) {
    const exact = voices.find(v => (v.voiceURI || v.name) === wantedURI);
    if (exact) return exact;
  }

  // Auto: prefer en-US voices that are usually smooth
  const preferNames = [
    "Microsoft Zira",
    "Microsoft Jenny",
    "Microsoft Aria",
    "Samantha",
    "Google US English",
    "Google English"
  ];

  const enUS = voices.filter(v => (v.lang || "").toLowerCase().startsWith("en-us"));
  for (const n of preferNames) {
    const match = enUS.find(v => (v.name || "").toLowerCase().includes(n.toLowerCase()));
    if (match) return match;
  }

  return enUS[0] || voices.find(v => (v.lang || "").toLowerCase().startsWith("en")) || voices[0];
}

function setSpeaking(on) {
  state.speaking = on;
  if (on) els.avatarWrap.classList.add("speaking");
  else els.avatarWrap.classList.remove("speaking");
}

function speak(text) {
  if (!state.voice.enabled) return;
  if (!("speechSynthesis" in window)) return;

  const u = new SpeechSynthesisUtterance(text);
  u.rate = state.voice.rate;
  u.pitch = state.voice.pitch;
  u.volume = state.voice.volume;

  const v = pickPreferredVoice();
  if (v) u.voice = v;

  u.onstart = () => setSpeaking(true);
  u.onend = () => setSpeaking(false);
  u.onerror = () => setSpeaking(false);

  // Cancel previous
  window.speechSynthesis.cancel();
  window.speechSynthesis.speak(u);
}

els.voiceEnabled.addEventListener("change", (e) => {
  state.voice.enabled = !!e.target.checked;
  if (!state.voice.enabled) {
    try { window.speechSynthesis.cancel(); } catch {}
    setSpeaking(false);
  }
});

els.voiceRate.addEventListener("input", (e) => {
  state.voice.rate = parseFloat(e.target.value);
});

els.voicePitch.addEventListener("input", (e) => {
  state.voice.pitch = parseFloat(e.target.value);
});

els.voiceVol.addEventListener("input", (e) => {
  state.voice.volume = parseFloat(e.target.value);
});

els.voiceSelect.addEventListener("change", (e) => {
  state.voice.selectedVoiceURI = e.target.value || "";
  rebuildVoiceList();
});

els.testVoiceBtn.addEventListener("click", () => {
  speak("Aloha, Will. I’m Gv. Calm. Present. Ready when you are.");
});

/* =========================
   Relay health check
========================= */
async function relayHealth() {
  try {
    const res = await fetch(RELAY_URL, { method: "GET" });
    if (res.ok) {
      els.connLine.textContent = "Relay ok.";
      els.statusPill.textContent = "STABLE";
      return;
    }
    els.connLine.textContent = `Relay responded (${res.status}).`;
    els.statusPill.textContent = "WARN";
  } catch {
    els.connLine.textContent = "Relay unreachable (check URL/DNS).";
    els.statusPill.textContent = "DOWN";
  }
}
relayHealth();

/* =========================
   Send message
========================= */
function updateLastMsg() {
  els.lastMsg.textContent = nowStr();
}

async function sendMessage() {
  const text = (els.input.value || "").trim();
  if (!text) return;

  addMsg("you", text);
  state.messages.push({ role: "user", content: text });
  state.messages = state.messages.slice(-20);
  saveChat();
  updateLastMsg();

  els.input.value = "";
  els.input.focus();

  try {
    const res = await fetch(RELAY_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        messages: state.messages
      })
    });

    const data = await res.json().catch(() => ({}));
    const reply = (data && data.reply) ? String(data.reply) : "(No text returned)";

    addMsg("gv", reply);
    state.messages.push({ role: "assistant", content: reply });
    state.messages = state.messages.slice(-20);
    saveChat();
    updateLastMsg();

    speak(reply);
    els.connLine.textContent = "Relay ok.";
    els.statusPill.textContent = "STABLE";

  } catch (err) {
    addMsg("gv", "Relay error. (Check Worker logs / CORS / key.)");
    els.connLine.textContent = "Relay error.";
    els.statusPill.textContent = "WARN";
  }
}

els.sendBtn.addEventListener("click", sendMessage);
els.input.addEventListener("keydown", (e) => {
  if (e.key === "Enter") sendMessage();
});
