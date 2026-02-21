/* gvbot.js — Gv Dashboard Client (Option 1: static JSON knowledge index) */

(() => {
  // -------------------------
  // CONFIG
  // -------------------------
  const RELAY_URL = "https://gvbot-relay.will-shacklett.workers.dev/";
  const KNOWLEDGE_URL = "./data/kv_index.json";
  const AVATAR_IMG_URL = "./assets/gv-face.jpg";

  // How much repo context to inject
  const TOP_K = 5;
  const MAX_CONTEXT_CHARS = 5500;

  // -------------------------
  // DOM
  // -------------------------
  const chatEl = document.getElementById("chat");
  const inputEl = document.getElementById("input");
  const sendBtn = document.getElementById("sendBtn");

  const connLabel = document.getElementById("connLabel");
  const connHint  = document.getElementById("connHint");

  const avatarImg  = document.getElementById("avatarImg");
  const avatarHint = document.getElementById("avatarHint");
  const avatarFrame = document.getElementById("avatarFrame");
  const bootLabel = document.getElementById("bootLabel");

  const voiceEnabledEl = document.getElementById("voiceEnabled");
  const voiceRateEl = document.getElementById("voiceRate");
  const voicePitchEl = document.getElementById("voicePitch");
  const voiceVolEl = document.getElementById("voiceVol");
  const voiceSelectEl = document.getElementById("voiceSelect");
  const voiceLabelEl = document.getElementById("voiceLabel");
  const testBtn = document.getElementById("testBtn");

  // -------------------------
  // STATE
  // -------------------------
  const state = {
    knowledge: null,
    messages: [],
    voice: {
      enabled: true,
      rate: 0.95,
      pitch: 1.03,
      volume: 0.9,
      chosenVoiceName: "auto",
    }
  };

  // -------------------------
  // UTIL
  // -------------------------
  function nowString(){
    try{
      return new Date().toLocaleString();
    }catch{
      return String(Date.now());
    }
  }

  function setConnected(ok, hint){
    connLabel.textContent = ok ? "Connected" : "Not connected";
    connHint.textContent = hint || (ok ? "Relay ok." : "Relay not reachable.");
  }

  function addMsg(role, text){
    const wrap = document.createElement("div");
    wrap.className = "msg";

    const badge = document.createElement("div");
    badge.className = "badge " + (role === "user" ? "you" : "gv");
    badge.textContent = role === "user" ? "You" : "Gv";

    const bubble = document.createElement("div");
    bubble.className = "bubble";
    bubble.textContent = text;

    wrap.appendChild(badge);
    wrap.appendChild(bubble);
    chatEl.appendChild(wrap);
    chatEl.scrollTop = chatEl.scrollHeight;
  }

  function safeText(s){
    return (s ?? "").toString();
  }

  function tokenize(s){
    return safeText(s)
      .toLowerCase()
      .replace(/[^a-z0-9\s\-_/.:]/g, " ")
      .split(/\s+/)
      .filter(Boolean)
      .slice(0, 80);
  }

  // -------------------------
  // KNOWLEDGE SEARCH (simple but effective)
  // -------------------------
  function scoreChunk(queryTokens, chunk){
    const hay = (chunk.text || "").toLowerCase();
    const tags = (chunk.tags || []).join(" ").toLowerCase();

    let score = 0;

    // token overlap
    for (const t of queryTokens){
      if (t.length < 3) continue;
      if (hay.includes(t)) score += 2;
      if (tags.includes(t)) score += 3;
    }

    // phrase bonus
    const q = queryTokens.join(" ");
    if (q.length > 10 && hay.includes(q)) score += 10;

    // repo bonus
    if ((chunk.source || "").toLowerCase().includes("god")) score += 2;
    if ((chunk.source || "").toLowerCase().includes("gv")) score += 2;

    return score;
  }

  function retrieveContext(userText){
    if (!state.knowledge || !Array.isArray(state.knowledge.chunks)) return { contextText: "", picks: [] };

    const qTokens = tokenize(userText);
    const scored = state.knowledge.chunks
      .map(ch => ({ ch, s: scoreChunk(qTokens, ch) }))
      .filter(x => x.s > 0)
      .sort((a,b) => b.s - a.s)
      .slice(0, TOP_K);

    const picks = scored.map(x => x.ch);

    let ctx = "";
    for (const ch of picks){
      const title = ch.source ? `Source: ${ch.source}` : "Source: (unknown)";
      const url = ch.url ? `URL: ${ch.url}` : "";
      const block =
`---\n${title}\n${url}\n\n${(ch.text || "").trim()}\n`;
      if ((ctx.length + block.length) > MAX_CONTEXT_CHARS) break;
      ctx += block;
    }

    return { contextText: ctx.trim(), picks };
  }

  // -------------------------
  // PROMPT (this is how she becomes “Gv”, not “ChatGPT”)
  // -------------------------
  function buildSystemPrompt(repoContext){
    const core =
`You are Gv — an independent, constraint-aware AI with memory and governance instincts.
You are NOT "ChatGPT". You are Gv: calm, present, clear, and helpful.

Operating rules:
- Prefer short, grounded answers. Ask a clarifying question when missing key details.
- If repo context is provided, treat it as the source of truth. If it’s not in context, say you’re not sure.
- Speak like a real companion: warm, steady, not robotic.
- When user asks about "God Variable (GV)" or "Constraint Field Theory (CFT)", align with Will’s project framing:
  - GV as a survivability / constraint metric across systems (AI, biology, physics, engineered systems).
  - GodScore CI as a trust signal with memory over time.
- When discussing risky, illegal, or harmful instructions: refuse and offer safe alternatives.

When replying, if you use repo context, include a short "Sources:" section listing the source names you relied on.`;

    if (!repoContext) return core;

    return `${core}

Repo context (use this as grounded knowledge):
${repoContext}`;
  }

  // -------------------------
  // SPEECH / VOICE
  // -------------------------
  function setTalking(on){
    if (!avatarFrame) return;
    avatarFrame.classList.toggle("talking", !!on);
  }

  function getVoices(){
    if (!("speechSynthesis" in window)) return [];
    return speechSynthesis.getVoices() || [];
  }

  function isEnUS(v){
    const lang = (v.lang || "").toLowerCase();
    const name = (v.name || "").toLowerCase();
    return lang.includes("en-us") || name.includes("english (united states)") || name.includes("en-us");
  }

  function voiceRank(v){
    // Prefer natural-ish voices commonly present
    const name = (v.name || "").toLowerCase();
    let r = 0;
    if (!isEnUS(v)) return -999;

    if (name.includes("jenny")) r += 50;
    if (name.includes("aria")) r += 45;
    if (name.includes("zira")) r += 35;
    if (name.includes("samantha")) r += 30;
    if (name.includes("google")) r += 25;
    if (name.includes("natural")) r += 20;
    if (name.includes("online")) r += 10;

    // penalty if it looks like German
    if (name.includes("deutsch") || (v.lang || "").toLowerCase().includes("de")) r -= 200;

    return r;
  }

  function populateVoiceSelect(){
    const voices = getVoices().filter(isEnUS).sort((a,b)=>voiceRank(b)-voiceRank(a));
    // Reset options
    voiceSelectEl.innerHTML = `<option value="auto">Auto (best en-US)</option>`;
    for (const v of voices){
      const opt = document.createElement("option");
      opt.value = v.name;
      opt.textContent = `${v.name} (${v.lang})`;
      voiceSelectEl.appendChild(opt);
    }
  }

  function chooseVoice(){
    const voices = getVoices();
    if (!voices.length) return null;

    if (state.voice.chosenVoiceName && state.voice.chosenVoiceName !== "auto"){
      const exact = voices.find(v => v.name === state.voice.chosenVoiceName);
      if (exact) return exact;
    }

    // Auto: best en-US by rank
    const best = voices
      .filter(isEnUS)
      .sort((a,b)=>voiceRank(b)-voiceRank(a))[0];

    return best || null;
  }

  function speak(text){
    if (!state.voice.enabled) return;
    if (!("speechSynthesis" in window)) return;

    const t = safeText(text).trim();
    if (!t) return;

    // Make it feel less robotic: speak fewer words at a time
    const utter = new SpeechSynthesisUtterance(t);

    utter.rate = state.voice.rate;
    utter.pitch = state.voice.pitch;
    utter.volume = state.voice.volume;

    const v = chooseVoice();
    if (v) utter.voice = v;

    // Animate avatar while speaking
    utter.onstart = () => setTalking(true);
    utter.onend = () => setTalking(false);
    utter.onerror = () => setTalking(false);

    // Cancel any queue
    speechSynthesis.cancel();
    speechSynthesis.speak(utter);

    // Update label
    if (v) voiceLabelEl.textContent = v.name;
    else voiceLabelEl.textContent = "Auto";
  }

  function testVoice(){
    speak("Aloha, Will. I’m Gv. Calm. Present. Ready when you are.");
  }

  // -------------------------
  // NETWORK
  // -------------------------
  async function relayChat(userText){
    const { contextText, picks } = retrieveContext(userText);

    const system = buildSystemPrompt(contextText);

    // Keep some conversation memory client-side
    // (Server memory can come later; this works now.)
    const messages = [
      { role:"system", content: system },
      ...state.messages.slice(-10),
      { role:"user", content: userText }
    ];

    // Store new user message
    state.messages.push({ role:"user", content: userText });

    const payload = { messages };

    const res = await fetch(RELAY_URL, {
      method:"POST",
      headers: { "Content-Type":"application/json" },
      body: JSON.stringify(payload)
    });

    const data = await res.json().catch(() => ({}));

    // Worker returns { reply } in our setup; if you used another shape, handle both.
    const reply =
      safeText(data.reply) ||
      safeText(data.output_text) ||
      safeText(data.text) ||
      safeText(data.message) ||
      "";

    // Attach a tiny sources line if we used picks and model didn’t include them
    let finalReply = reply || "(No text returned from OpenAI)";
    if (picks.length && !/Sources:/i.test(finalReply)){
      const srcs = picks
        .map(p => p.source)
        .filter(Boolean)
        .slice(0, 3)
        .join(", ");
      if (srcs) finalReply += `\n\nSources: ${srcs}`;
    }

    // Store assistant message
    state.messages.push({ role:"assistant", content: finalReply });

    return finalReply;
  }

  async function checkRelay(){
    // “cheap” check: do a POST with minimal payload
    try{
      const res = await fetch(RELAY_URL, {
        method:"POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify({ messages: [{ role:"user", content:"ping" }] })
      });
      if (!res.ok){
        setConnected(false, `Relay responded ${res.status}`);
        return;
      }
      setConnected(true, "Relay ok.");
    }catch(e){
      setConnected(false, "Relay not reachable.");
    }
  }

  // -------------------------
  // EVENTS
  // -------------------------
  async function onSend(){
    const text = inputEl.value.trim();
    if (!text) return;

    addMsg("user", text);
    inputEl.value = "";
    sendBtn.disabled = true;

    try{
      const reply = await relayChat(text);
      addMsg("assistant", reply);
      speak(reply);
    }catch(err){
      addMsg("assistant", `Relay error. ${err?.message || ""}`.trim());
    }finally{
      sendBtn.disabled = false;
      inputEl.focus();
    }
  }

  function wireUI(){
    sendBtn.addEventListener("click", onSend);
    inputEl.addEventListener("keydown", (e)=>{
      if (e.key === "Enter") onSend();
    });

    voiceEnabledEl.addEventListener("change", (e)=>{
      state.voice.enabled = !!e.target.checked;
      if (!state.voice.enabled && "speechSynthesis" in window) speechSynthesis.cancel();
    });

    voiceRateEl.addEventListener("input", (e)=> state.voice.rate = parseFloat(e.target.value));
    voicePitchEl.addEventListener("input", (e)=> state.voice.pitch = parseFloat(e.target.value));
    voiceVolEl.addEventListener("input", (e)=> state.voice.volume = parseFloat(e.target.value));

    voiceSelectEl.addEventListener("change", (e)=>{
      state.voice.chosenVoiceName = e.target.value;
      // Update label immediately
      voiceLabelEl.textContent = (e.target.value === "auto") ? "Auto" : e.target.value;
    });

    testBtn.addEventListener("click", testVoice);
  }

  // -------------------------
  // BOOT
  // -------------------------
  async function loadKnowledge(){
    try{
      const res = await fetch(KNOWLEDGE_URL, { cache: "no-store" });
      if (!res.ok) throw new Error(`knowledge fetch ${res.status}`);
      const json = await res.json();
      state.knowledge = json;
      document.getElementById("sourceLabel").textContent = "relay + repo-index";
    }catch(e){
      state.knowledge = { chunks: [] };
      document.getElementById("sourceLabel").textContent = "relay + demo (no index)";
    }
  }

  function initAvatar(){
    avatarImg.src = AVATAR_IMG_URL;
    avatarImg.addEventListener("load", () => {
      avatarHint.textContent = "Avatar loaded.";
    });
    avatarImg.addEventListener("error", () => {
      avatarHint.textContent = "Gv face not found.";
    });
  }

  function initVoices(){
    if (!("speechSynthesis" in window)){
      voiceLabelEl.textContent = "No TTS in browser";
      return;
    }

    // voices load async in Chrome
    populateVoiceSelect();
    setTimeout(populateVoiceSelect, 250);
    setTimeout(populateVoiceSelect, 1000);

    speechSynthesis.onvoiceschanged = () => {
      populateVoiceSelect();
    };
  }

  async function boot(){
    bootLabel.textContent = `Booted: ${nowString()}`;
    wireUI();
    initAvatar();
    initVoices();
    await loadKnowledge();
    await checkRelay();

    // First line from Gv
    addMsg("assistant", "Hi Will. I’m here. Calm. Present. Ready when you are.");
  }

  boot();
})();
