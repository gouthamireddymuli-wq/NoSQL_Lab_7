/**
 * Floating AI Threat Intelligence Widget
 * Injects a global bottom-right AI Assistant launcher across all CTI Platform pages.
 */

(function () {
  const currentPath = window.location.pathname.split("/").pop() || "index.html";
  if (currentPath === "chatbot.html") return; // Already on full chatbot page

  // Inject CSS
  const style = document.createElement("style");
  style.innerHTML = `
    .ai-fab-container {
      position: fixed;
      bottom: 24px;
      right: 24px;
      z-index: 9999;
      display: flex;
      flex-direction: column;
      align-items: flex-end;
    }
    .ai-fab-btn {
      width: 54px;
      height: 54px;
      border-radius: 50%;
      background: linear-gradient(135deg, #00d4ff 0%, #9b59b6 100%);
      border: 2px solid rgba(255, 255, 255, 0.2);
      box-shadow: 0 4px 20px rgba(0, 212, 255, 0.4);
      color: #fff;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.35rem;
      cursor: pointer;
      transition: transform 0.25s, box-shadow 0.25s;
    }
    .ai-fab-btn:hover {
      transform: scale(1.08);
      box-shadow: 0 6px 25px rgba(0, 212, 255, 0.6);
    }
    .ai-fab-badge {
      position: absolute;
      top: -3px;
      right: -3px;
      background: #ff4444;
      color: #fff;
      font-size: 0.65rem;
      font-weight: 700;
      border-radius: 10px;
      padding: 1px 5px;
      border: 1px solid #111827;
    }
    .ai-fab-popup {
      display: none;
      width: 380px;
      height: 520px;
      background: #111827;
      border: 1px solid #1f2937;
      border-radius: 12px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.6);
      margin-bottom: 12px;
      flex-direction: column;
      overflow: hidden;
      animation: popIn 0.2s ease-out;
    }
    @keyframes popIn {
      from { opacity: 0; transform: translateY(15px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .ai-fab-popup.open {
      display: flex;
    }
    .ai-popup-header {
      background: #0d1117;
      border-bottom: 1px solid #1f2937;
      padding: 0.75rem 1rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .ai-popup-messages {
      flex: 1;
      overflow-y: auto;
      padding: 0.75rem;
      display: flex;
      flex-direction: column;
      gap: 0.6rem;
      font-size: 0.8rem;
    }
    .ai-popup-bubble {
      padding: 0.6rem 0.8rem;
      border-radius: 6px;
      line-height: 1.4;
      max-width: 90%;
    }
    .ai-pop-user {
      align-self: flex-end;
      background: rgba(0, 212, 255, 0.15);
      border: 1px solid rgba(0, 212, 255, 0.3);
      color: #e0f2fe;
    }
    .ai-pop-bot {
      align-self: flex-start;
      background: #070b14;
      border: 1px solid rgba(255, 255, 255, 0.08);
      color: #f1f5f9;
    }
    .ai-popup-input-bar {
      border-top: 1px solid #1f2937;
      padding: 0.5rem 0.75rem;
      background: #0d1117;
      display: flex;
      gap: 0.4rem;
    }
    .ai-popup-input-bar input {
      flex: 1;
      background: #070b14;
      border: 1px solid #1f2937;
      color: #fff;
      padding: 0.4rem 0.6rem;
      border-radius: 4px;
      font-size: 0.8rem;
      outline: none;
    }
  `;
  document.head.appendChild(style);

  // Inject HTML Shell
  const container = document.createElement("div");
  container.className = "ai-fab-container";
  container.innerHTML = `
    <div class="ai-fab-popup" id="ai-fab-popup">
      <div class="ai-popup-header">
        <div style="display:flex;align-items:center;gap:0.4rem;font-size:0.85rem;font-weight:700;color:#e2e8f0;">
          <i class="fas fa-robot" style="color:#00d4ff;"></i> CTI AI Assistant
        </div>
        <div style="display:flex;align-items:center;gap:0.5rem;">
          <a href="chatbot.html" style="font-size:0.7rem;color:#00d4ff;" title="Open full interface"><i class="fas fa-expand-alt"></i></a>
          <button id="ai-close-btn" style="background:none;border:none;color:#6b7280;cursor:pointer;"><i class="fas fa-times"></i></button>
        </div>
      </div>
      <div class="ai-popup-messages" id="ai-pop-messages">
        <div class="ai-popup-bubble ai-pop-bot">
          👋 Hi! Ask about Anticipated, Active, Evolving, or Resolved threats, or click below to audit local host vulnerabilities.
          <div style="margin-top:0.4rem;display:flex;gap:0.3rem;flex-wrap:wrap;">
            <button class="btn btn-primary btn-sm" style="font-size:0.7rem;padding:0.2rem 0.5rem;" onclick="window.sendFabMsg('Scan system for vulnerabilities')">⚡ Scan Host</button>
            <button class="btn btn-outline btn-sm" style="font-size:0.7rem;padding:0.2rem 0.5rem;" onclick="window.sendFabMsg('What are the Anticipated threats for Linux?')">Linux CVEs</button>
          </div>
        </div>
      </div>
      <div class="ai-popup-input-bar">
        <input type="text" id="ai-pop-input" placeholder="Ask AI Analyst..." />
        <button class="btn btn-primary btn-sm" id="ai-pop-send"><i class="fas fa-paper-plane"></i></button>
      </div>
    </div>
    <div class="ai-fab-btn" id="ai-fab-btn" title="Open AI Threat Intelligence Assistant">
      <i class="fas fa-robot"></i>
      <div class="ai-fab-badge">AI</div>
    </div>
  `;
  document.body.appendChild(container);

  const fabBtn = document.getElementById("ai-fab-btn");
  const popup = document.getElementById("ai-fab-popup");
  const closeBtn = document.getElementById("ai-close-btn");
  const input = document.getElementById("ai-pop-input");
  const sendBtn = document.getElementById("ai-pop-send");
  const messagesBox = document.getElementById("ai-pop-messages");

  fabBtn.addEventListener("click", () => popup.classList.toggle("open"));
  closeBtn.addEventListener("click", () => popup.classList.remove("open"));

  let fabSessionId = localStorage.getItem("cti_chat_session") || "session-fab";

  window.sendFabMsg = function (text) {
    if (input) input.value = text;
    executeFabSend();
  };

  async function executeFabSend() {
    const text = (input.value || "").trim();
    if (!text) return;
    input.value = "";

    // Append user
    const uDiv = document.createElement("div");
    uDiv.className = "ai-popup-bubble ai-pop-user";
    uDiv.innerText = text;
    messagesBox.appendChild(uDiv);
    messagesBox.scrollTop = messagesBox.scrollHeight;

    // Loading indicator
    const loadDiv = document.createElement("div");
    loadDiv.className = "ai-popup-bubble ai-pop-bot";
    loadDiv.innerHTML = `<i class="fas fa-spinner fa-spin"></i> Analyzing CTI vectors...`;
    messagesBox.appendChild(loadDiv);
    messagesBox.scrollTop = messagesBox.scrollHeight;

    try {
      const res = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ session_id: fabSessionId, message: text, top_k: 2 })
      });
      const data = await res.json();
      loadDiv.innerHTML = `<div style="font-size:0.78rem;line-height:1.4;">${(data.response || "").substring(0, 400)}...</div><div style="margin-top:0.4rem;"><a href="chatbot.html" style="font-size:0.7rem;color:#00d4ff;">Open Full Threat Advisory &rarr;</a></div>`;
    } catch (e) {
      loadDiv.innerHTML = `⚠️ Error: ${e.message}`;
    }
    messagesBox.scrollTop = messagesBox.scrollHeight;
  }

  sendBtn.addEventListener("click", executeFabSend);
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") executeFabSend();
  });
})();
