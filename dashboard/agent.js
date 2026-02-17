/* dashboard/agent.js
   GvBot Agent Shell (frontend)
   - No secrets stored here
   - Calls a backend later (Worker/API) via window.GVBOT_AGENT_ENDPOINT
   - For now: stub response + built-in TTS
*/

(function () {
  const state = {
    endpoint: localStorage.getItem("gvbot.endpoint") || "",
    voice: localStorage.getItem("gvbot.voice") || "default",
    speaking: false,
  };

  function $(id) {
    return document.getElementById(id);
  }

  function logLine(role, text) {
    const box = $("chatLog");
    if (!box) return;

    const row = document.createElement("div");
    row.className = "chatRow " + (role === "user" ? "user" : "bot");

    const badge = document.createElement("div");
    badge.className = "chatBadge";
    badge.textContent = role === "user" ? "You" : "Gv";

    const msg = document.createElement("div");
    msg.className = "chatMsg";
    msg.textContent = text;

    row.appendChild(badge);
    row.appendChild(msg);
    box.appendChild(row);

    box.scrollTop = box.scrollHeight;
  }

  function setStatus(text, kind) {
    const el = $("agentStatus");
    if (!el) return;
    el.textContent = text || "";
    el.className = "agentStatus " + (kind || "idle");
  }

  function getSelectedVoice() {
    const voices = window.speechSynthesis ? window.speechSynthesis.getVoices() : [];
    if (!voices || !voices.length) return null;

    const pref = localStorage.getItem("gvbot.voiceName");
    if (pref) {
      const found = voices.find(v => v.name === pref);
      if (found) return found;
    }
    return voices[0] || null;
  }

  function speak(text) {
    if (!window.speechSynthesis || !window.SpeechSynthesisUtterance) return;

    // stop any previous
    window.speechSynthesis.cancel();

    const u = new SpeechSynthesisUtterance(text);
    const v = getSelectedVoice();
    if (v) u.voice = v;

    u.rate = 1.0;
    u.pitch = 1.0;

    state.speaking = true;
    setStatus("Speaking…", "speaking");

    u.onend = () => {
      state.speaking = false;
      setStatus("Ready.", "ok");
    };
    u.onerror = () => {
      state.speaking = false;
      setStatus("Speech error (browser TTS).", "warn");
    };

    window.speechSynthesis.speak(u);
  }

  async function agentReply(userText) {
    // Commit 1: stub response. Commit 2 will call backend.
    // Keep this deterministic + helpful.
    const reply =
      "I’m here. Next we’ll connect me to a secure backend relay so I can think and remember safely. " +
      "For now, I can speak and take messages—your next commit will give me an LLM brain.";
    return reply;
  }

  async function handleSend() {
    const input = $("chatInput");
    if (!input) return;

    const text = (input.value || "").trim();
    if (!text) return;

    input.value = "";
    logLine("user", text);
    setStatus("Thinking…", "thinking");

    try {
      const reply = await agentReply(text);
      logLine("bot", reply);
      speak(reply);
      // also mirror in the “Signal” bar if present
      const sig = $("signalText");
      if (sig) sig.textContent = reply;
    } catch (e) {
      console.error(e);
      setStatus("Agent error. Check console.", "err");
      logLine("bot", "Something broke. Check console logs.");
    }
  }

  function openSettings() {
    $("settingsModal")?.classList.add("open");
    const ep = $("endpointInput");
    if (ep) ep.value = state.endpoint;
  }

  function closeSettings() {
    $("settingsModal")?.classList.remove("open");
  }

  function saveSettings() {
    const ep = $("endpointInput")?.value?.trim() || "";
    state.endpoint = ep;
    localStorage.setItem("gvbot.endpoint", ep);
    setStatus(ep ? "Endpoint saved (backend next).": "Ready (backend next).", "ok");
    closeSettings();
  }

  function bind() {
    $("sendBtn")?.addEventListener("click", handleSend);
    $("chatInput")?.addEventListener("keydown", (e) => {
      if (e.key === "Enter") handleSend();
    });

    $("agentSettingsBtn")?.addEventListener("click", openSettings);
    $("settingsClose")?.addEventListener("click", closeSettings);
    $("settingsSave")?.addEventListener("click", saveSettings);

    // click outside modal closes
    $("settingsModal")?.addEventListener("click", (e) => {
      if (e.target && e.target.id === "settingsModal") closeSettings();
    });

    // warm up voices list on some browsers
    if (window.speechSynthesis) {
      window.speechSynthesis.onvoiceschanged = () => {};
      window.speechSynthesis.getVoices();
    }

    setStatus("Ready (agent shell).", "ok");
  }

  document.addEventListener("DOMContentLoaded", bind);
})();
