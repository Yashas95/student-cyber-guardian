/**
 * content.ts — Injected into every web page
 * Sends page text to background and renders in-page risk alerts.
 */
// ─── Respond to background requests ──────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message.type === "GET_PAGE_TEXT") {
        const text = document.body?.innerText?.slice(0, 3000) ?? ""; // 3k chars max — no more needed
        sendResponse({ text, title: document.title });
        return true;
    }
    if (message.type === "SHOW_RISK_ALERT") {
        showRiskBanner(message.result);
    }
});
function showRiskBanner(result) {
    // Avoid duplicate banners
    if (document.getElementById("scg-banner"))
        return;
    const colors = {
        safe: { bg: "#f0fdf4", border: "#22c55e", icon: "✅" },
        suspicious: { bg: "#fffbeb", border: "#f59e0b", icon: "⚠️" },
        dangerous: { bg: "#fef2f2", border: "#ef4444", icon: "🚨" }
    };
    const c = colors[result.riskLevel];
    const banner = document.createElement("div");
    banner.id = "scg-banner";
    banner.style.cssText = `
    all: initial;
    position: fixed;
    top: 16px;
    right: 16px;
    z-index: 2147483647;
    width: 320px;
    background: ${c.bg};
    border: 2px solid ${c.border};
    border-radius: 12px;
    padding: 14px 16px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: 13px;
    color: #1f2937;
    box-shadow: 0 8px 24px rgba(0,0,0,0.12);
    animation: scgSlideIn 0.3s ease;
  `;
    banner.innerHTML = `
    <style>
      @keyframes scgSlideIn {
        from { transform: translateX(120%); opacity: 0; }
        to   { transform: translateX(0);    opacity: 1; }
      }
      #scg-banner * { box-sizing: border-box; margin: 0; padding: 0; }
      #scg-close { cursor: pointer; float: right; background: none; border: none;
                   font-size: 16px; color: #6b7280; line-height: 1; }
      #scg-close:hover { color: #111; }
      #scg-tips { margin-top: 10px; padding-top: 10px; border-top: 1px solid ${c.border}40; }
      #scg-tips li { margin: 4px 0 4px 16px; list-style: disc; line-height: 1.4; }
      #scg-learn { display: none; }
      #scg-learn-btn { cursor: pointer; color: #4f46e5; background: none; border: none;
                       font-size: 12px; margin-top: 8px; text-decoration: underline; }
    </style>
    <div style="display:flex; align-items:flex-start; gap:8px;">
      <span style="font-size:20px; line-height:1;">${c.icon}</span>
      <div style="flex:1;">
        <strong style="font-size:14px; display:block; margin-bottom:4px; color:#111;">
          ${result.riskLevel === "dangerous" ? "Danger" : result.riskLevel === "suspicious" ? "Suspicious Site" : "Site Check"}
        </strong>
        <span>${result.explanation}</span>
        <div>
          <button id="scg-learn-btn">▶ Safety tips</button>
        </div>
        <div id="scg-learn">
          <ul id="scg-tips">
            ${result.tips.map(t => `<li>${t}</li>`).join("")}
          </ul>
        </div>
      </div>
      <button id="scg-close">✕</button>
    </div>
  `;
    document.body.appendChild(banner);
    banner.querySelector("#scg-close").addEventListener("click", () => banner.remove());
    const learnBtn = banner.querySelector("#scg-learn-btn");
    const learnSection = banner.querySelector("#scg-learn");
    learnBtn.addEventListener("click", () => {
        const isOpen = learnSection.style.display === "block";
        learnSection.style.display = isOpen ? "none" : "block";
        learnBtn.textContent = isOpen ? "▶ Safety tips" : "▼ Safety tips";
    });
    // Auto-dismiss safe banners after 4s; keep warnings visible
    if (result.riskLevel === "safe") {
        setTimeout(() => banner.remove(), 4000);
    }
}
