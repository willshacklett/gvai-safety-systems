/* =========================
   GvBot Console (dashboard)
   - Works with:
     #chat, #input
     onclick="sendMessage()", onclick="testVoice()"
========================= */

/* =========================
   CONFIG
========================= */
const RELAY_URL = "https://gvbot-relay.will-shacklett.workers.dev/";

/* =========================
   ELEMENTS
========================= */
const chatEl = document.getElementById("chat");
const inputEl = document.getElementById("input");

const voiceEnabledEl = document.getElementById("voiceEnabled");
const voiceRateEl = document.getElementById("voiceRate");
const voicePitchEl = document.getElementById("voicePitch");

/* =========================
   CHAT UI
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
  if (!chatEl) return;

  const div = document.createElement("div");
  div.className = "message " + role;

  const label = role === "you" ? "You" : "Gv";
  div.innerHTML = `<strong>${label}:</strong> ${escapeHtml(text)}`;

  chatEl.appendChild(div);
  chatEl.scrollTop = chatEl.scrollHeight;
}

/* =========================
   VOICE
========================= */
const voice = {
  enabled: true,
  rate: 0.95,
  pitch: 1.05,
  volume: 1,
};

function pickPreferredVoice() {
  if (!("speechSynthesis" in window)) return null;

  const voices = speechSynthesis.getVoices() || [];
  if (!voices.length) return null;

  // Prefer more natural voices if present
  const wanted = [
    "aria",
    "jenny",
    "samantha",
    "serena",
    "victoria",
    "ava",
    "google",
    "zira",
  ];

  const found = voices.find(v => wanted.some(w => v.name.toLowerCase().includes(w)));
  return found || voices[0] || null;
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

/* Make sure voices are loaded in some browsers */
if ("speechSynthesis" in window) {
  speechSynthesis.onvoiceschanged = () => {};
}

/* =========================
   RELAY CALL
========================= */
async function callRelay(userText) {
  const payload = {
    messages: [{ role: "user", content: userText }],
  };

  const res = await fetch(RELAY_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  // If the relay returns non-JSON sometimes, protect parsing
  const raw = await res.text();
  let data = {};
  try {
    data = JSON.parse(raw);
  } catch {
    data = { reply: raw };
  }

  if (!res.ok) {
    const msg =
      data?.error ||
      data?.message ||
      `Relay error (${res.status})`;
    throw new Error(msg);
  }

  return data;
}

/* =========================
   GLOBAL FUNCTIONS
   (needed for onclick="...")
========================= */
window.sendMessage = async function sendMessage() {
  const text = (inputEl?.value || "").trim();
  if (!text) return;

  addMessage("you", text);
  inputEl.value = "";

  try {
    const data = await callRelay(text);

    const reply =
      data?.reply ||
      data?.message ||
      "(No text returned)";

    addMessage("gv", reply);
    speak(reply);
  } catch (err) {
    addMessage("gv", `Relay error: ${err.message || "unknown"}`);
  }
};

window.testVoice = function testVoice() {
  speak("Hi Will. I’m Gv. Calm. Present. Ready.");
};

/* =========================
   UI EVENTS
========================= */
if (voiceEnabledEl) {
  voice.enabled = voiceEnabledEl.checked;
  voiceEnabledEl.addEventListener("change", (e) => {
    voice.enabled = e.target.checked;
    if (!voice.enabled && "speechSynthesis" in window) speechSynthesis.cancel();
  });
}

if (voiceRateEl) {
  voice.rate = parseFloat(voiceRateEl.value || "0.95");
  voiceRateEl.addEventListener("input", (e) => {
    voice.rate = parseFloat(e.target.value);
  });
}

if (voicePitchEl) {
  voice.pitch = parseFloat(voicePitchEl.value || "1.05");
  voicePitchEl.addEventListener("input", (e) => {
    voice.pitch = parseFloat(e.target.value);
  });
}

/* Enter key to send */
if (inputEl) {
  inputEl.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      window.sendMessage();
    }
  });
}

/* Boot line so you know JS is loaded */
addMessage("gv", "Ready.");
