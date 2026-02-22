/**
 * contentEnhanced.ts
 * ─────────────────────────────────────────────────────────────
 * Enhanced content script — extracts deep page security context
 * for the threatDetector engine:
 *  • Auto-inspects every page at document_idle (no user action)
 *  • Scans all script sources for cryptomining patterns
 *  • Counts hidden iframes
 *  • Detects external form targets
 *  • Checks for mixed content
 *  • Monitors form submissions in real time
 *  • Warns on clipboard access attempts
 * ─────────────────────────────────────────────────────────────
 */

import type { PageSecurityContext } from "./threatDetector.js";
import type { PageContext } from "./pageInspector.js";
import { renderWhisperToast } from "./whisperToast.js";
import { analysePasswordStrength } from "./behaviorCoach.js";

// ─── Auto Page Inspector Context ────────────────────────────────────────────
// Runs automatically at document_idle and sends context to background.
// Background runs the full inspector pipeline and caches the result.

function extractPageContext(): PageContext {
  const scripts = [...document.querySelectorAll("script")];

  // All external script srcs
  const scriptSrcs = scripts
    .map(s => s.src)
    .filter(Boolean);

  // Short inline script snippets for pattern matching (first 300 chars)
  const scriptInlineHints = scripts
    .filter(s => !s.src && s.textContent?.trim())
    .map(s => (s.textContent ?? "").slice(0, 300))
    .slice(0, 20);

  // Detect known window globals (framework fingerprints)
  const GLOBALS_TO_CHECK = [
    "React", "__REACT_DEVTOOLS_GLOBAL_HOOK__", "__NEXT_DATA__", "__next",
    "Vue", "__VUE__", "__vue_app__",
    "angular", "ng",
    "__svelte",
    "wp", "wpApiSettings",
    "Shopify", "ShopifyAnalytics",
    "wixBiSession", "rendererModel",
    "Static",  // Squarespace: window.Static.SQUARESPACE_CONTEXT
    "firebase", "__FIREBASE_DEFAULTS__",
    "Intercom",
    "zE", "zESettings",
    "Stripe",
    "paypal", "PAYPAL",
    "jQuery",
    "$",
    // YouTube / Google
    "ytcfg", "ytInitialData", "yt", "ytInitialPlayerResponse",
    "Polymer",
    // AMP
    "AMP", "__AMP_SERVICES", "AMP_CONFIG",
  ];
  const windowGlobals: string[] = [];
  for (const g of GLOBALS_TO_CHECK) {
    try {
      if ((window as unknown as Record<string, unknown>)[g] !== undefined) windowGlobals.push(g);
    } catch { /* cross-origin guard */ }
  }

  // Meta tags
  const metaTags = [...document.querySelectorAll("meta")]
    .map(m => ({ name: m.getAttribute("name") ?? m.getAttribute("http-equiv") ?? "", content: m.getAttribute("content") ?? "" }))
    .filter(m => m.name && m.content)
    .slice(0, 30);

  // Form action targets
  const formActions = [...document.querySelectorAll("form")]
    .map(f => f.action)
    .filter(Boolean);

  // Iframes (total + hidden)
  const iframes = [...document.querySelectorAll("iframe")];
  const hiddenIframeCount = iframes.filter(f => {
    const style = window.getComputedStyle(f);
    const rect = f.getBoundingClientRect();
    return (
      style.display === "none" || style.visibility === "hidden" ||
      style.opacity === "0" || rect.width === 0 || rect.height === 0 ||
      parseInt(style.width) < 2 || parseInt(style.height) < 2
    );
  }).length;

  // Cookie count (rough)
  const cookieCount = document.cookie ? document.cookie.split(";").length : 0;

  // Unique third-party script domains
  const hostname = location.hostname;
  const thirdPartyDomains = [...new Set(
    scriptSrcs
      .map(src => { try { return new URL(src).hostname; } catch { return ""; } })
      .filter(h => h && h !== hostname && !h.endsWith("." + hostname))
  )].slice(0, 40);

  // CSP meta tag
  const hasCSP = document.querySelector('meta[http-equiv="Content-Security-Policy"]') !== null;

  // Mixed content
  const hasMixedContent = location.protocol === "https:" && (
    [...document.querySelectorAll("img, script, link, iframe")].some(el => {
      const src = (el as HTMLElement & { src?: string; href?: string }).src
        ?? (el as HTMLElement & { href?: string }).href ?? "";
      return src.startsWith("http://");
    })
  );

  // Password field
  const hasPasswordField = document.querySelector('input[type="password"]') !== null;

  return {
    url: location.href,
    hostname,
    protocol: location.protocol,
    scriptSrcs,
    scriptInlineHints,
    windowGlobals,
    metaTags,
    formActions,
    iframeCount: iframes.length,
    hiddenIframeCount,
    hasPasswordField,
    hasCSP,
    hasMixedContent,
    cookieCount,
    thirdPartyDomains,
    pageTitle: document.title,
  };
}

/** Auto-send page context to background for inspection */
function autoInspect(): void {
  // Skip chrome:// and extension pages
  if (location.protocol === "chrome:" || location.protocol === "chrome-extension:") return;
  try {
    const ctx = extractPageContext();
    chrome.runtime.sendMessage({ type: "PAGE_CONTEXT", ctx }).catch(() => { });
  } catch { /* guard against rare DOM errors */ }
}

// ─── Legacy: security context for threat detector ────────────────────────────

function extractSecurityContext(): PageSecurityContext {
  // Script sources
  const scripts = [...document.querySelectorAll("script")];
  const scriptSrcs = scripts
    .map(s => s.src || s.textContent || "")
    .filter(Boolean)
    .slice(0, 50); // cap to avoid huge messages

  // Inline script count
  const inlineScripts = scripts.filter(s => !s.src && s.textContent?.trim()).length;

  // Hidden iframes (zero-size, display:none, or off-screen)
  const iframes = [...document.querySelectorAll("iframe")];
  const hiddenIframes = iframes.filter(f => {
    const style = window.getComputedStyle(f);
    const rect = f.getBoundingClientRect();
    return (
      style.display === "none" ||
      style.visibility === "hidden" ||
      style.opacity === "0" ||
      rect.width === 0 || rect.height === 0 ||
      parseInt(style.width) < 2 || parseInt(style.height) < 2
    );
  }).length;

  // Forms posting to external domains
  const forms = [...document.querySelectorAll("form")];
  const ownOrigin = location.origin;
  const externalFormTargets = forms
    .map(f => f.action)
    .filter(action => action && !action.startsWith(ownOrigin) && action.startsWith("http"));

  // Password fields
  const hasPasswordField = document.querySelector('input[type="password"]') !== null;

  // Mixed content: HTTP resources on an HTTPS page
  const hasMixedContent = location.protocol === "https:" && (
    [...document.querySelectorAll("img, script, link, iframe")]
      .some(el => {
        const src = (el as HTMLElement & { src?: string; href?: string }).src
          ?? (el as HTMLElement & { href?: string }).href ?? "";
        return src.startsWith("http://");
      })
  );

  // CSP: check meta tag (header-based CSP is not accessible from JS)
  const hasCSP = document.querySelector('meta[http-equiv="Content-Security-Policy"]') !== null;

  return {
    hasCSP,
    hasMixedContent,
    hasPasswordField,
    hasHiddenIframes: hiddenIframes,
    externalFormTargets,
    inlineScripts,
    scriptSrcs,
    pageText: document.body?.innerText?.slice(0, 4000) ?? "",
    title: document.title
  };
}

// ─── Password Strength Coach (Layer 4) ────────────────────────────────────────

function monitorPasswordStrength(): void {
  document.addEventListener("input", (e) => {
    const target = e.target as HTMLInputElement;
    if (target.type !== "password") return;

    const val = target.value;
    if (val.length < 1) {
      removeCoachTooltip(target);
      return;
    }

    const analysis = analysePasswordStrength(val);
    if (analysis.score < 60) {
      showCoachTooltip(target, `Weak password (${analysis.strength}). ${analysis.suggestions[0]}`);
    } else {
      removeCoachTooltip(target);
    }
  }, { passive: true });
}

function showCoachTooltip(input: HTMLInputElement, text: string): void {
  let tooltip = input.parentNode?.querySelector(".scg-coach-tooltip") as HTMLElement;
  if (!tooltip) {
    tooltip = document.createElement("div");
    tooltip.className = "scg-coach-tooltip";
    tooltip.style.cssText = `
      position: absolute; right: 0; bottom: 100%; margin-bottom: 4px;
      background: #1f2937; color: white; padding: 4px 8px; border-radius: 4px;
      font-size: 11px; font-family: sans-serif; pointer-events: none; z-index: 9999;
      white-space: nowrap; box-shadow: 0 2px 4px rgba(0,0,0,0.2);
    `;
    // Ensure parent has positioning context
    const parent = input.parentNode as HTMLElement;
    if (getComputedStyle(parent).position === "static") parent.style.position = "relative";
    parent.appendChild(tooltip);
  }
  tooltip.textContent = "🛡️ " + text;
}

function removeCoachTooltip(input: HTMLInputElement): void {
  const tooltip = input.parentNode?.querySelector(".scg-coach-tooltip");
  tooltip?.remove();
}

// ─── Password field monitor (warn before submission) ──────────────────────────

function monitorForms(): void {
  document.querySelectorAll("form").forEach(form => {
    if (form.dataset.scgMonitored) return;
    form.dataset.scgMonitored = "1";

    form.addEventListener("submit", (e) => {
      const hasPwd = form.querySelector('input[type="password"]') !== null;
      if (!hasPwd) return;

      // Ask background: is this domain trusted?
      chrome.runtime.sendMessage(
        { type: "CHECK_FORM_SUBMIT", action: form.action, origin: location.origin },
        (response: { safe: boolean; reason?: string }) => {
          if (!response?.safe) {
            e.preventDefault();
            showFormWarning(form, response?.reason ?? "This form is submitting to an unexpected destination.");
          }
        }
      );
    });
  });
}

function showFormWarning(form: HTMLFormElement, reason: string): void {
  const existing = form.querySelector(".scg-form-warning");
  if (existing) return;

  const warn = document.createElement("div");
  warn.className = "scg-form-warning";
  warn.style.cssText = `
    all: initial;
    display: block;
    background: #fef2f2;
    border: 2px solid #ef4444;
    border-radius: 8px;
    padding: 10px 14px;
    margin: 8px 0;
    font-family: -apple-system, sans-serif;
    font-size: 13px;
    color: #1f2937;
  `;
  warn.innerHTML = `
    <strong style="color:#dc2626;">⚠️ Wait!</strong> ${reason}
    <br><small style="color:#6b7280;">Click submit again to proceed anyway, or close this tab.</small>
  `;
  form.insertBefore(warn, form.firstChild);

  // Allow re-submit after user sees warning
  setTimeout(() => {
    form.addEventListener("submit", () => warn.remove(), { once: true });
  }, 500);
}

// ─── Clipboard hijacking monitor ──────────────────────────────────────────────

function monitorClipboard(): void {
  // Detect pages that overwrite clipboard on copy (clipboard hijacking)
  document.addEventListener("copy", (e) => {
    const selection = window.getSelection()?.toString() ?? "";
    setTimeout(() => {
      navigator.clipboard.readText().then(clipText => {
        if (clipText !== selection && clipText.length > 0) {
          chrome.runtime.sendMessage({
            type: "THREAT_DETECTED",
            threat: "clipboard_hijack",
            detail: "This page modified your clipboard content when you copied text — a common crypto address swap attack."
          });
        }
      }).catch(() => { });
    }, 100);
  }, { passive: true });
}

// ─── Crypto address swap detection ───────────────────────────────────────────
// Detects if visible crypto addresses differ from what's actually in the DOM

function monitorCryptoAddresses(): void {
  const CRYPTO_ADDR_RE = /\b(0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|[A-Z2-7]{58})\b/g;
  const visibleText = document.body?.innerText ?? "";
  const htmlText = document.body?.innerHTML ?? "";

  const visibleAddresses = [...visibleText.matchAll(CRYPTO_ADDR_RE)].map(m => m[0]);
  const htmlAddresses = [...htmlText.matchAll(CRYPTO_ADDR_RE)].map(m => m[0]);

  // If HTML has more/different addresses than visible text, something is hidden
  const hiddenAddresses = htmlAddresses.filter(a => !visibleAddresses.includes(a));
  if (hiddenAddresses.length > 0) {
    chrome.runtime.sendMessage({
      type: "THREAT_DETECTED",
      threat: "hidden_crypto_address",
      detail: `${hiddenAddresses.length} hidden crypto address(es) found in page HTML. This may indicate a clipboard swap attack.`
    });
  }
}

// ─── Message handler ──────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === "GET_SECURITY_CONTEXT") {
    sendResponse(extractSecurityContext());
    return true;
  }
  if (message.type === "GET_PAGE_TEXT") {
    sendResponse({ text: document.body?.innerText?.slice(0, 4000) ?? "", title: document.title });
    return true;
  }
  if (message.type === "SHOW_RISK_ALERT") {
    showRiskBanner(message.result);
  }
  if (message.type === "SHOW_WHISPER_TOAST") {
    renderWhisperToast({ message: message.message, type: message.toastType ?? "info" });
  }
  if (message.type === "SHOW_CAMPUS_ALERT") {
    showCampusAlertToast(message.alert);
  }
});

// ─── In-page risk banner (same as before, kept here for self-containment) ────

function showRiskBanner(result: { riskLevel: string; headline?: string; explanation?: string; advice?: string[]; tips?: string[] }): void {
  if (document.getElementById("scg-banner")) return;

  const colors: Record<string, { bg: string; border: string; icon: string }> = {
    clean: { bg: "#f0fdf4", border: "#22c55e", icon: "✅" },
    low: { bg: "#f0fdf4", border: "#86efac", icon: "ℹ️" },
    medium: { bg: "#fffbeb", border: "#f59e0b", icon: "⚠️" },
    high: { bg: "#fef2f2", border: "#ef4444", icon: "🚨" },
    critical: { bg: "#fff1f2", border: "#be123c", icon: "☣️" },
    // legacy keys
    safe: { bg: "#f0fdf4", border: "#22c55e", icon: "✅" },
    suspicious: { bg: "#fffbeb", border: "#f59e0b", icon: "⚠️" },
    dangerous: { bg: "#fef2f2", border: "#ef4444", icon: "🚨" },
  };
  const c = colors[result.riskLevel] ?? colors.medium;
  const explanation = result.headline ?? result.explanation ?? "";
  const tips = result.advice ?? result.tips ?? [];

  const banner = document.createElement("div");
  banner.id = "scg-banner";
  banner.style.cssText = `
    all: initial; position: fixed; top: 16px; right: 16px; z-index: 2147483647;
    width: 330px; background: ${c.bg}; border: 2px solid ${c.border};
    border-radius: 12px; padding: 14px 16px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: 13px; color: #1f2937; box-shadow: 0 8px 24px rgba(0,0,0,0.12);
  `;
  banner.innerHTML = `
    <style>
      #scg-banner * { box-sizing:border-box; margin:0; padding:0; }
      #scg-close { cursor:pointer; float:right; background:none; border:none; font-size:16px; color:#6b7280; }
      #scg-close:hover { color:#111; }
      #scg-learn { display:none; margin-top:10px; padding-top:10px; border-top:1px solid ${c.border}50; }
      #scg-tips li { margin:4px 0 4px 16px; list-style:disc; line-height:1.4; }
      #scg-learn-btn { cursor:pointer; color:#4f46e5; background:none; border:none; font-size:12px; margin-top:8px; text-decoration:underline; }
    </style>
    <div style="display:flex;align-items:flex-start;gap:8px;">
      <span style="font-size:20px;line-height:1;">${c.icon}</span>
      <div style="flex:1;">
        <strong style="font-size:14px;display:block;margin-bottom:4px;">${explanation}</strong>
        <button id="scg-learn-btn">▶ What should I do?</button>
        <div id="scg-learn"><ul id="scg-tips">${tips.map((t: string) => `<li>${t}</li>`).join("")}</ul></div>
      </div>
      <button id="scg-close">✕</button>
    </div>
  `;
  document.body.appendChild(banner);
  banner.querySelector("#scg-close")!.addEventListener("click", () => banner.remove());
  const btn = banner.querySelector("#scg-learn-btn") as HTMLButtonElement;
  const div = banner.querySelector("#scg-learn") as HTMLDivElement;
  btn.addEventListener("click", () => {
    const open = div.style.display === "block";
    div.style.display = open ? "none" : "block";
    btn.textContent = open ? "▶ What should I do?" : "▼ What should I do?";
  });
  if (result.riskLevel === "safe" || result.riskLevel === "clean") setTimeout(() => banner.remove(), 4000);
}

// ─── Campus Alert Toast (whisper-style, bottom-right) ────────────────────────

function showCampusAlertToast(alert: { friendly_message?: string; threat_category?: string; severity?: string }): void {
  const TOAST_ID = "scg-campus-alert-toast";
  if (document.getElementById(TOAST_ID)) return;
  if (location.protocol === "chrome:" || location.protocol === "chrome-extension:") return;

  const accent = alert.severity === "critical" ? "#ef4444" : "#f59e0b";
  const message = alert.friendly_message
    ?? "A threat is active at your university right now. I'm watching out for you.";

  const toast = document.createElement("div");
  toast.id = TOAST_ID;
  toast.style.cssText = `
    all: initial;
    position: fixed;
    bottom: 24px;
    right: 24px;
    z-index: 2147483647;
    width: 320px;
    background: #0f0f1a;
    border: 1.5px solid ${accent};
    border-radius: 14px;
    padding: 14px 16px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: 13px;
    color: #e2e8f0;
    box-shadow: 0 8px 32px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.05);
    animation: scgCampusIn 0.35s cubic-bezier(0.34,1.56,0.64,1) both;
    transform-origin: bottom right;
  `;

  const escMsg = message.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

  toast.innerHTML = `
    <style>
      @keyframes scgCampusIn {
        from { transform: translateY(20px) scale(0.92); opacity: 0; }
        to   { transform: translateY(0)    scale(1);    opacity: 1; }
      }
      @keyframes scgCampusOut {
        from { transform: translateY(0) scale(1); opacity: 1; }
        to   { transform: translateY(12px) scale(0.95); opacity: 0; }
      }
      @keyframes scgPulseDot {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.4; }
      }
      #${TOAST_ID} * { box-sizing: border-box; margin: 0; padding: 0; }
      #scg-campus-row { display: flex; align-items: flex-start; gap: 10px; }
      #scg-campus-dot {
        width: 8px; height: 8px; border-radius: 50%;
        background: ${accent}; flex-shrink: 0; margin-top: 3px;
        animation: scgPulseDot 1.5s ease-in-out infinite;
      }
      #scg-campus-msg { flex: 1; font-size: 13px; color: #e2e8f0; line-height: 1.45; }
      #scg-campus-label {
        font-size: 11px; font-weight: 700; color: ${accent};
        text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 6px;
      }
      #scg-campus-gotit {
        display: block; width: 100%; margin-top: 10px;
        background: rgba(255,255,255,0.08); border: 1px solid rgba(255,255,255,0.12);
        border-radius: 8px; padding: 6px 0; color: #e2e8f0;
        font-size: 12px; font-weight: 600; cursor: pointer;
        text-align: center; transition: background 0.15s;
      }
      #scg-campus-gotit:hover { background: rgba(255,255,255,0.14); }
      #scg-campus-bar {
        position: absolute; bottom: 0; left: 0;
        height: 2px; background: ${accent}; border-radius: 0 0 14px 14px;
        width: 100%; animation: scgBarShrink 6s linear forwards;
      }
      @keyframes scgBarShrink {
        from { width: 100%; opacity: 1; }
        to   { width: 0%;   opacity: 0.5; }
      }
    </style>
    <div id="scg-campus-row">
      <div id="scg-campus-dot"></div>
      <div id="scg-campus-msg">
        <div id="scg-campus-label">🛡️ Campus heads up</div>
        ${escMsg}
      </div>
    </div>
    <button id="scg-campus-gotit">Got it</button>
    <div id="scg-campus-bar"></div>
  `;

  let dismissed = false;
  function dismiss(): void {
    if (dismissed) return;
    dismissed = true;
    toast.style.animation = "scgCampusOut 0.25s ease forwards";
    setTimeout(() => toast.remove(), 260);
  }

  document.body.appendChild(toast);
  toast.querySelector("#scg-campus-gotit")!.addEventListener("click", dismiss);

  // Auto-dismiss after 6 seconds
  setTimeout(dismiss, 6000);
}

// ─── Init ─────────────────────────────────────────────────────────────────────

// Run all monitors + auto-inspection after DOM is settled
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => {
    monitorForms();
    monitorClipboard();
    monitorCryptoAddresses();
    monitorPasswordStrength();
    autoInspect();
  });
} else {
  monitorForms();
  monitorClipboard();
  monitorCryptoAddresses();
  monitorPasswordStrength();
  autoInspect();
}

// Re-run form monitor periodically to catch dynamically added forms (SPAs)
setInterval(monitorForms, 3000);
