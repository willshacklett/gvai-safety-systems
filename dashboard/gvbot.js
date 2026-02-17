// GvBot Console — Relay Edition
// Connects to Cloudflare Worker relay

const RELAY_URL = "https://gvbot-relay.will-shacklett.workers.dev/";

const chatBox = document.getElementById("chatBox");
const input = document.getElementById("userInput");
const sendBtn = document.getElementById("sendBtn");

function appendMessage(role, text) {
  const wrapper = document.createElement("div");
  wrapper.className = role === "user" ? "msg user" : "msg gv";
  wrapper.innerHTML = `
    <div class="bubble">
      <strong>${role === "user" ? "You" : "Gv"}</strong>
      <div>${text}</div>
    </div>
  `;
  chatBox.appendChild(wrapper);
  chatBox.scrollTop = chatBox.scrollHeight;
}

async function sendMessage() {
  const message = input.value.trim();
  if (!message) return;

  appendMessage("user", message);
  input.value = "";

  appendMessage("gv", "Thinking...");

  try {
    const response = await fetch(RELAY_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        messages: [
          { role: "user", content: message }
        ]
      })
    });

    const data = await response.json();

    // Remove "Thinking..."
    chatBox.removeChild(chatBox.lastChild);

    if (data.reply) {
      appendMessage("gv", data.reply);
    } else {
      appendMessage("gv", "(No text returned)");
    }

  } catch (err) {
    chatBox.removeChild(chatBox.lastChild);
    appendMessage("gv", "Relay error. Check backend.");
    console.error(err);
  }
}

sendBtn.addEventListener("click", sendMessage);

input.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    sendMessage();
  }
});
