/* =========================================================
   GvBot Console — gvbot.js
   - Relay chat
   - TTS voice
   - Avatar "alive" motions (via CSS classes)
========================================================= */

/* -------------------------
   CONFIG
------------------------- */

const RELAY_URL = "https://gvbot-relay.will-shacklett.workers.dev/";

// Avatar image path (GitHub Pages is case-sensitive)
const AVATAR_SRC = "assets/gv-face.jpg";

/* -------------------------
   DOM
------------------------- */

const $ = (sel) => document.querySelector(sel);

const els = {
  avatarImg: $("#gvAvatarImg"),
  avatarWrap: $("#gvAvatarWrap"),
  avatarStatus: $("#gvAvatarStatus"),
  chat: $("#chat"),
  input: $("#input"),
  sendBtn: $("#sendBtn"),

  voiceEnabled: $("#voiceEnabled"),
  rate: $("#voiceRate"),
  pitch: $("#voicePitch"),
  vol: $("#voiceVol"),
  testVoiceBtn: $("#testVoiceBtn"),

  relayStatusDot: $("#relayDot"),
  relayStatusText: $("#relayText"),
  voiceName: $("#voiceName"),
  sourceLabel: $("#sourceLabel"),
  lastMsg: $("#lastMsg"),
};

/* -------------------------
   STATE
------------------------- */

const state = {
  voice: {
    enabled: true,
    rate: 0.92,  // softer / less robotic
    pitch: 1.02,
    volume: 1.0,
  },
  preferredVoice: null,
  speaking: false,
  blinkTimer: null,
  lastAssistantText: "",
};

/* -------------------------
   INIT
------------------------- */

boot();

function boot() {
  // Avatar image
  if (els.avatarImg) {
    els.avatarImg.src = AVATAR_SRC;

    els.avatarImg.addEventListener("error", () => {
      if (els.avatarStatus) {
        els.avatarStatus.textContent =
          "Gv face not found. Expected: dashboard/" + AVATAR_SRC + " (case-sensitive).";
      }
      if (els.avatarWrap) els.avatarWrap.classList.add("avatar-missing");
    });

    els.avatarImg.addEventListener("load", () => {
      if (els.avatarStatus) els.avatarStatus.textContent = "Gv face loaded.";
      if (els.avatarWrap) els.avatarWrap.classList.remove("avatar-missing");
      startBlinking();
    });
  }

  // Wire UI defaults
  if (els.voiceEnabled) els.voiceEnabled.checked = true;
  if (els.rate) els.rate.value = String(state.voice.rate);
  if (els.pitch) els.pitch.value = String(state.voice.pitch);
  if (els.vol) els.vol.value = String(state.voice.volume);

  // Events
  if (els.sendBtn) els.sendBtn.addEventListener("click", sendMessage);
  if (els.input) {
    els.input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") sendMessage();
    });
  }

  if (els.voiceEnabled) {
    els.voiceEnabled.addEventListener("change", (e) => {
      state.voice.enabled = !!e.target.checked;
      if (!state.voice.enabled) window.speechSynthesis?.cancel();
    });
  }
  if (els.rate) els.rate.addEventListener("input", (e) => (state.voice.rate = parseFloat(e.target.value)));
  if (els.pitch) els.pitch.addEventListener("input", (e) => (state.voice.pitch = parseFloat(e.target.value)));
  if (els.vol) els.vol.addEventListener("input", (e) => (state.voice.volume = parseFloat(e.target.value)));

  if (els.testVoiceBtn) {
    els.testVoiceBtn.addEventListener("click", () => {
      speak("Hi Will. I’m Gv. Calm. Present. Right here with you.");
    });
  }

  // Voice selection (async on some browsers)
  initVoices();

  // Initial UI
  setRelayStatus(true, "Connected. Relay ok.");
  setSource("relay + demo");
  addSystemLine("Gv: Ready.");
}

function setRelayStatus(ok, text) {
  if (els.relayStatusDot) els.relayStatusDot.classList.toggle("ok", !!ok);
  if (els.relayStatusText) els.relayStatusText.textContent = text || (ok ? "Connected." : "Disconnected.");
}

function setSource(label) {
  if (els.sourceLabel) els.sourceLabel.textContent = label || "relay";
}

function setLastMessage(tsText) {
  if (els.lastMsg) els.lastMsg.textContent = tsText || "";
}

/* -------------------------
   CHAT UI
------------------------- */

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function addLine(role, text) {
  const div = document.createElement("div");
  div.className = "line " + role;
  div.innerHTML = `<span class="who">${role === "you" ? "You" : "Gv"}</span> <span class="msg">${escapeHtml(
    text
  )}</span>`;
  els.chat.appendChild(div);
  els.chat.scrollTop = els.chat.scrollHeight;
}

function addSystemLine(text) {
  const div = document.createElement("div");
  div.className = "line system";
  div.innerHTML = `<span class="msg">${escapeHtml(text)}</span>`;
  els.chat.appendChild(div);
  els.chat.scrollTop = els.chat.scrollHeight;
}

/* -------------------------
   SEND -> RELAY
------------------------- */

async function sendMessage() {
  const text = (els.input?.value || "").trim();
  if (!text) return;

  addLine("you", text);
  els.input.value = "";

  try {
    // optimistic status
    setRelayStatus(true, "Connected. Relay ok.");

    const res = await fetch(RELAY_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        messages: [{ role: "user", content: text }],
      }),
    });

    const data = await res.json().catch(() => ({}));
    const reply = (data && (data.reply || data.text || data.message)) || "";

    if (!reply) {
      addLine("gv", "(No text returned)");
      return;
    }

    state.lastAssistantText = reply;
    addLine("gv", reply);

    setLastMessage(new Date().toLocaleString());
    speak(reply);
  } catch (err) {
    console.error(err);
    setRelayStatus(false, "Relay error.");
    addLine("gv", "Relay error. Check Cloudflare logs.");
  }
}

/* -------------------------
   VOICE (TTS)
------------------------- */

function initVoices() {
  if (!("speechSynthesis" in window)) {
    if (els.voiceName) els.voiceName.textContent = "Voice: (not supported)";
    return;
  }

  const pick = () => {
    const voices = window.speechSynthesis.getVoices() || [];

    // Prefer US English female-ish voices (best effort)
    const preferredOrder = [
      // Microsoft (Edge/Windows)
      (v) => /zira/i.test(v.name) && /en-us/i.test(v.lang),
      (v) => /jenny/i.test(v.name) && /en-us/i.test(v.lang),
      (v) => /aria/i.test(v.name) && /en-us/i.test(v.lang),
      // Google voices
      (v) => /google/i.test(v.name) && /en-us/i.test(v.lang),
      // Any en-US
      (v) => /en-us/i.test(v.lang),
      // Any English
      (v) => /^en/i.test(v.lang),
    ];

    let chosen = null;
    for (const rule of preferredOrder) {
      chosen = voices.find(rule);
      if (chosen) break;
    }

    state.preferredVoice = chosen || voices[0] || null;

    if (els.voiceName) {
      els.voiceName.textContent = state.preferredVoice
        ? `${state.preferredVoice.name} (${state.preferredVoice.lang})`
        : "Voice: (none found)";
    }
  };

  pick();
  window.speechSynthesis.onvoiceschanged = pick;
}

// Make TTS sound less robotic:
// - Chunk into sentences so the browser "breathes"
// - Add tiny random pitch drift per chunk
function speak(text) {
  if (!state.voice.enabled) return;
  if (!("speechSynthesis" in window)) return;

  const synth = window.speechSynthesis;
  synth.cancel();

  const chunks = splitForTTS(text);

  if (!chunks.length) return;

  setSpeaking(true);

  let i = 0;
  const speakNext = () => {
    if (i >= chunks.length) {
      setSpeaking(false);
      return;
    }

    const chunk = chunks[i++];

    const u = new SpeechSynthesisUtterance(chunk);

    // Base values
    u.rate = clamp(state.voice.rate, 0.7, 1.2);
    u.pitch = clamp(state.voice.pitch, 0.8, 1.2);
    u.volume = clamp(state.voice.volume, 0, 1);

    // Tiny human-ish variation
    u.pitch = clamp(u.pitch + (Math.random() * 0.04 - 0.02), 0.8, 1.2);

    if (state.preferredVoice) u.voice = state.preferredVoice;

    u.onend = () => {
      // small pause between chunks
      setTimeout(speakNext, 120);
    };
    u.onerror = () => {
      setSpeaking(false);
    };

    synth.speak(u);
  };

  speakNext();
}

function splitForTTS(text) {
  const clean = String(text || "").trim();
  if (!clean) return [];

  // Split on sentence-ish punctuation while keeping it readable.
  // Also limit chunk size to avoid long monotone blocks.
  const rough = clean
    .replace(/\s+/g, " ")
    .split(/(?<=[\.\!\?\:\;])\s+/g);

  const out = [];
  let buf = "";

  for (const part of rough) {
    if ((buf + " " + part).trim().length > 160) {
      if (buf.trim()) out.push(buf.trim());
      buf = part;
    } else {
      buf = (buf + " " + part).trim();
    }
  }
  if (buf.trim()) out.push(buf.trim());

  return out;
}

function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n));
}

/* -------------------------
   AVATAR "ALIVE" STATES
   (CSS does the motion; JS just toggles classes)
------------------------- */

function setSpeaking(on) {
  state.speaking = !!on;
  if (!els.avatarWrap) return;
  els.avatarWrap.classList.toggle("speaking", state.speaking);
}

function startBlinking() {
  if (!els.avatarWrap) return;
  if (state.blinkTimer) clearInterval(state.blinkTimer);

  // Random-ish blink cadence
  state.blinkTimer = setInterval(() => {
    if (state.speaking) return; // optional: don’t blink while speaking
    els.avatarWrap.classList.add("blink");
    setTimeout(() => els.avatarWrap.classList.remove("blink"), 160);
  }, 2600);
}
