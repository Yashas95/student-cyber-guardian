/**
 * whisperToast.ts — Non-intrusive "whisper" notifications
 * Injected via contentEnhanced.ts on every page.
 * Shows only when something genuinely interesting is found.
 * Auto-dismisses in 4s. Never shown more than once per page.
 * Slides in from bottom-right in Guardian dark theme.
 */
const TOAST_ID = "scg-whisper-toast";
const SESSION_KEY = "scg_toast_shown_" + location.href;
/**
 * Render a whisper toast. Safe to call multiple times — only shows once per page.
 */
export function renderWhisperToast(payload) {
    // Never on chrome:// or extension pages
    if (location.protocol === "chrome:" ||
        location.protocol === "chrome-extension:" ||
        location.hostname === "localhost" ||
        location.hostname === "127.0.0.1")
        return;
    // Never show more than once per page load
    if (document.getElementById(TOAST_ID))
        return;
    if (sessionStorage.getItem(SESSION_KEY))
        return;
    sessionStorage.setItem(SESSION_KEY, "1");
    const accentColors = {
        safe: "#22c55e",
        info: "#4f46e5",
        warn: "#f59e0b",
        discovery: "#a78bfa",
    };
    const accent = accentColors[payload.type];
    const toast = document.createElement("div");
    toast.id = TOAST_ID;
    toast.style.cssText = `
    all: initial;
    position: fixed;
    bottom: 24px;
    right: 24px;
    z-index: 2147483647;
    width: 300px;
    background: #0f0f1a;
    border: 1.5px solid ${accent};
    border-radius: 14px;
    padding: 14px 16px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: 13px;
    color: #e2e8f0;
    box-shadow: 0 8px 32px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.05);
    cursor: pointer;
    animation: scgWhisperIn 0.35s cubic-bezier(0.34,1.56,0.64,1) both;
    transform-origin: bottom right;
  `;
    toast.innerHTML = `
    <style>
      @keyframes scgWhisperIn {
        from { transform: translateY(20px) scale(0.92); opacity: 0; }
        to   { transform: translateY(0)    scale(1);    opacity: 1; }
      }
      @keyframes scgWhisperOut {
        from { transform: translateY(0) scale(1); opacity: 1; }
        to   { transform: translateY(12px) scale(0.95); opacity: 0; }
      }
      #${TOAST_ID} * { box-sizing: border-box; margin: 0; padding: 0; }
      #scg-toast-row { display: flex; align-items: flex-start; gap: 10px; }
      #scg-toast-dot {
        width: 8px; height: 8px; border-radius: 50%;
        background: ${accent}; flex-shrink: 0; margin-top: 3px;
      }
      #scg-toast-msg {
        flex: 1; font-size: 13px; color: #e2e8f0; line-height: 1.45;
      }
      #scg-toast-close {
        background: none; border: none; cursor: pointer;
        font-size: 14px; color: #64748b; line-height: 1;
        padding: 0; flex-shrink: 0;
      }
      #scg-toast-close:hover { color: #e2e8f0; }
      #scg-toast-hint {
        margin-top: 9px; padding-top: 9px;
        border-top: 1px solid rgba(255,255,255,0.08);
        font-size: 11px; color: #64748b;
      }
      #scg-toast-bar {
        position: absolute; bottom: 0; left: 0;
        height: 2px; background: ${accent}; border-radius: 0 0 14px 14px;
        width: 100%;
        animation: scgBarShrink 4s linear forwards;
      }
      @keyframes scgBarShrink {
        from { width: 100%; opacity: 1; }
        to   { width: 0%;   opacity: 0.5; }
      }
    </style>
    <div id="scg-toast-row">
      <div id="scg-toast-dot"></div>
      <div id="scg-toast-msg">${escapeHtml(payload.message)}</div>
      <button id="scg-toast-close">✕</button>
    </div>
    <div id="scg-toast-hint">Tap to see full report in Guardian</div>
    <div id="scg-toast-bar"></div>
  `;
    // Dismiss helper
    let dismissed = false;
    function dismiss() {
        if (dismissed)
            return;
        dismissed = true;
        toast.style.animation = "scgWhisperOut 0.25s ease forwards";
        setTimeout(() => toast.remove(), 260);
    }
    // Click anywhere on toast → open popup (via message to background)
    toast.addEventListener("click", (e) => {
        const target = e.target;
        if (target.id === "scg-toast-close") {
            dismiss();
            return;
        }
        dismiss();
        // Background will call chrome.action.openPopup() in response
        chrome.runtime.sendMessage({ type: "OPEN_POPUP" }).catch(() => { });
    });
    document.body.appendChild(toast);
    // Auto-dismiss after 4 seconds
    setTimeout(dismiss, 4000);
}
function escapeHtml(str) {
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}
