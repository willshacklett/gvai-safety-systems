/* =========================
   GvBot Console (dashboard)
========================= */

const RELAY_URL = "https://gvbot-relay.will-shacklett.workers.dev/";

const chatEl = document.getElementById("chat");
const inputEl = document.getElementById("input");

const voiceEnabledEl = document.getElementById("voiceEnabled");
const voiceRateEl = document.getElementById("voiceRate");
const voicePitchEl = document.getElementById("voicePitch");

/* =========================
   CHAT
========================= */

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function addMessage(role, text) {
  const div = document.createElement("div");
  div.className = "message " + role;

  const label = role === "you" ? "You" : "Gv";
  div.innerHTML = `<strong>${label}:</strong> ${escapeHtml(text)}`;

  chatEl.appendChild(div);
  chatEl.scrollTop = chatEl.scrollHeight;
}

async function callRelay(userText) {
  const res = await fetch(RELAY_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      messages: [{ role: "user", content: userText }]
    })
  });

  const raw = await res.text();

  let data;
  try {
    data = JSON.parse(raw);
  } catch {
    data = { reply: raw };
  }

  if (!res.ok) {
    throw new Error(data?.error || "Relay error");
  }

  return data;
}

/* =========================
   GLOBAL FUNCTIONS (for onclick)
========================= */

window.sendMessage = async function () {
  const text = inputEl.value.trim();
  if (!text) return;

  addMessage("you", text);
  inputEl.value = "";

  try {
    const data = await callRelay(text);
    const reply = data.reply || "(No text returned)";
    addMessage("gv", reply);
    speak(reply);
  } catch (err) {
    addMessage("gv", "Relay error: " + err.message);
  }
};

window.testVoice = function () {
  speak("Hi Will. I’m Gv. Calm. Present. Ready.");
};

/* =========================
   VOICE
========================= */

const voice = {
  enabled: true,
  rate: 0.95,
  pitch: 1.05,
  volume: 1
};

function pickPreferredVoice() {
  if (!("speechSynthesis" in window)) return null;

  const voices = speechSynthesis.getVoices();
  if (!voices.length) return null;

  const preferred = voices.find(v =>
    v.name.toLowerCase().includes("aria") ||
    v.name.toLowerCase().includes("jenny") ||
    v.name.toLowerCase().includes("samantha") ||
    v.name.toLowerCase().includes("zira") ||
    v.name.toLowerCase().includes("google")
  );

  return preferred || voices[0];
}

function speak(text) {
  if (!voice.enabled) return;
  if (!("speechSynthesis" in window)) return;

  const u = new SpeechSynthesisUtterance(text);
  u.rate = voice.rate;
  u.pitch = voice.pitch;
  u.volume = voice.volume;

  const chosen = pickPreferredVoice();
  if (chosen) u.voice = chosen;

  speechSynthesis.cancel();
  speechSynthesis.speak(u);
}

if ("speechSynthesis" in window) {
  speechSynthesis.onvoiceschanged = () => {};
}

/* =========================
   VOICE UI EVENTS
========================= */

voice.enabled = voiceEnabledEl.checked;

voiceEnabledEl.addEventListener("change", e => {
  voice.enabled = e.target.checked;
  if (!voice.enabled) speechSynthesis.cancel();
});

voiceRateEl.addEventListener("input", e => {
  voice.rate = parseFloat(e.target.value);
});

voicePitchEl.addEventListener("input", e => {
  voice.pitch = parseFloat(e.target.value);
});

/* Enter key send */
inputEl.addEventListener("keydown", e => {
  if (e.key === "Enter") {
    e.preventDefault();
    window.sendMessage();
  }
});

/* Boot message */
addMessage("gv", "Ready.");
