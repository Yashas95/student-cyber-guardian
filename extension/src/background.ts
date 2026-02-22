/**
 * background.ts — Chrome Extension Service Worker
 * Coordinates scanning, badge updates, and messaging between content/popup.
 * v1.2: Added Campus Threat Pulse (anonymous, privacy-first campus alerts).
 */

import { analyzeThreats } from "./threatDetector.js";
import type { ThreatReport, PageSecurityContext } from "./threatDetector.js";
import { checkAllFeeds, refreshFeedsIfStale } from "./threatFeed.js";
import { saveScanRecord, getSettings, maybeFlushTelemetry } from "./storage.js";
import { runInspectorPipeline } from "./pageInspector.js";
import type { InspectorReport, PageContext } from "./pageInspector.js";
import {
  sendThreatSignal,
  mapThreatCategory,
  pollCampusAlerts,
  getCampusAlerts,
} from "./campusPulse.js";
import type { CampusAlert } from "./campusPulse.js";

// ─── Badge colours by severity (threat scanner) ───────────────────────────────

const BADGE_COLORS: Record<string, string> = {
  clean: "#22c55e",      // green
  low: "#86efac",        // light green
  medium: "#f59e0b",     // amber
  high: "#ef4444",       // red
  critical: "#be123c",   // dark red
  scanning: "#6366f1"    // indigo
};

const BADGE_LABELS: Record<string, string> = {
  clean: "✓",
  low: "ok",
  medium: "?",
  high: "!",
  critical: "✗"
};

// ─── Badge colours by inspector grade ────────────────────────────────────────

const GRADE_COLORS: Record<string, string> = {
  A: "#22c55e",   // safe green
  B: "#3b82f6",   // blue
  C: "#f59e0b",   // amber
  D: "#ef4444",   // red
  F: "#be123c",   // dark red
};

// ─── Caches (per tab, cleared on close) ──────────────────────────────────────

/** Legacy threat scan cache — existing behaviour */
const tabScanCache = new Map<number, ThreatReport>();

/** New inspector report cache — keyed by tabId */
const inspectorCache = new Map<number, InspectorReport>();

/** Track which sites we've shown toasts for (avoids repeat toasts on same tab) */
const toastShownTabs = new Set<number>();

/** Track seen tech stacks per tab for "first time" discovery toasts */
const seenTechIds = new Set<string>();

/**
 * Per-tab CSP header cache — populated by webRequest listener.
 * true  = CSP header was present in the HTTP response
 * false = no CSP header detected
 * undefined = we haven't seen this tab's response yet
 */
const tabCspHeaderCache = new Map<number, boolean>();

// ─── webRequest: capture CSP from HTTP response headers ──────────────────────

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.tabId < 0) return; // background requests have tabId -1
    const hasHeader = (details.responseHeaders ?? []).some(
      h => h.name.toLowerCase() === "content-security-policy"
    );
    // Only overwrite with "true"; don't overwrite a true with false from
    // sub-resources (we only care about the main document frame).
    if (details.frameId === 0) {
      tabCspHeaderCache.set(details.tabId, hasHeader);
    }
  },
  { urls: ["<all_urls>"], types: ["main_frame"] },
  ["responseHeaders"]
);

// ─── Badge helper (threat scanner) ───────────────────────────────────────────

async function updateBadge(tabId: number, result: ThreatReport): Promise<void> {
  const settings = await getSettings();
  if (!settings.showBadge) return;

  // Inspector badge takes priority if available
  if (inspectorCache.has(tabId)) return;

  const sev = result.overallSeverity;
  await chrome.action.setBadgeBackgroundColor({
    tabId,
    color: BADGE_COLORS[sev] ?? BADGE_COLORS.medium
  });
  await chrome.action.setBadgeText({
    tabId,
    text: BADGE_LABELS[sev] ?? "?"
  });
}

// ─── Inspector badge helper ───────────────────────────────────────────────────

async function updateInspectorBadge(tabId: number, report: InspectorReport): Promise<void> {
  const settings = await getSettings();
  if (!settings.showBadge) return;

  const color = GRADE_COLORS[report.grade] ?? GRADE_COLORS.C;
  const trackerText = report.trackerCount > 0 ? String(report.trackerCount) : report.gradeLabel;

  await chrome.action.setBadgeBackgroundColor({ tabId, color });
  await chrome.action.setBadgeText({ tabId, text: trackerText });
}

// ─── Whisper toast decision ───────────────────────────────────────────────────

async function maybeShowWhisperToast(tabId: number, report: InspectorReport): Promise<void> {
  // Never show more than once per tab navigation
  if (toastShownTabs.has(tabId)) return;

  let toastMessage: string | null = null;
  let toastType: "info" | "warn" | "safe" | "discovery" = "info";

  // Condition 1: Grade D or F — security concerns
  if (report.grade === "D" || report.grade === "F") {
    const httpsCheck = report.securityChecks.find(c => c.id === "https");
    if (httpsCheck && !httpsCheck.passed) {
      toastMessage = "⚠️ This page isn't encrypted. Don't enter any passwords or card numbers here.";
      toastType = "warn";
    } else {
      toastMessage = "I found some concerns with this page. Tap to see what I spotted.";
      toastType = "warn";
    }
  }

  // Condition 2: Many trackers (> 5) and not already toasted
  if (!toastMessage && report.trackerCount > 5) {
    toastMessage = `👁️ ${report.trackerCount} trackers on this page. Tap to see who's watching.`;
    toastType = "info";
  }

  // Condition 3: Payment processor detected
  if (!toastMessage) {
    const hasStripe = report.techStack.some(t => t.id === "stripe");
    const hasPaypal = report.techStack.some(t => t.id === "paypal");
    if (hasStripe) {
      toastMessage = "✅ Stripe is handling payments here — one of the most secure processors out there.";
      toastType = "safe";
    } else if (hasPaypal) {
      toastMessage = "✅ PayPal is handling payments on this page.";
      toastType = "safe";
    }
  }

  // Condition 4: First time seeing a new/interesting tech
  if (!toastMessage) {
    const interestingTech = ["svelte", "nextjs", "firebase", "cloudflare"];
    for (const tech of report.techStack) {
      if (interestingTech.includes(tech.id) && !seenTechIds.has(tech.id)) {
        seenTechIds.add(tech.id);
        toastMessage = `✨ New: This site uses ${tech.name} — ${tech.description} Tap to learn more.`;
        toastType = "discovery";
        break;
      }
    }
  }

  if (!toastMessage) return;

  toastShownTabs.add(tabId);

  // Send to content script to render
  chrome.tabs.sendMessage(tabId, {
    type: "SHOW_WHISPER_TOAST",
    message: toastMessage,
    toastType,
  }).catch(() => { /* tab may not be ready */ });
}

// ─── Scan orchestration (legacy threat scanner) ───────────────────────────────

async function performScan(tabId: number, url: string): Promise<void> {
  if (!url || url.startsWith("chrome://") || url.startsWith("about:")) return;

  const settings = await getSettings();
  if (!settings.scanOnNavigate) return;

  // Set scanning badge (only if no inspector result yet)
  if (!inspectorCache.has(tabId)) {
    chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE_COLORS.scanning });
    chrome.action.setBadgeText({ tabId, text: "…" });
  }

  // Request full security context from enhanced content script
  let ctx: Partial<PageSecurityContext> = {};
  try {
    const response = await chrome.tabs.sendMessage(tabId, { type: "GET_SECURITY_CONTEXT" });
    if (response) ctx = response as PageSecurityContext;
  } catch {
    // contentEnhanced.ts may not be ready yet — URL-only scan still works
  }

  // Run threat analysis (heuristic engine)
  const result = analyzeThreats(url, ctx);

  // Run live feed check in parallel (non-blocking — merge result if listed)
  checkAllFeeds(url).then(feedResult => {
    if (feedResult.listed) {
      const upgraded: ThreatReport = {
        ...result,
        overallSeverity: "critical",
        primaryThreat: result.primaryThreat === "clean" ? "malware" : result.primaryThreat,
        headline: `${feedResult.source} flagged this URL as ${feedResult.threat}. I've increased the alert level.`,
        friendlyHeadline: `I cross-checked this site against a threat database \u2014 it was flagged for ${feedResult.threat}. I've got you covered.`,
        score: Math.min(result.score + 40, 100)
      };
      tabScanCache.set(tabId, upgraded);
      updateBadge(tabId, upgraded);
      if (upgraded.overallSeverity !== "clean") {
        chrome.tabs.sendMessage(tabId, { type: "SHOW_RISK_ALERT", result: upgraded }).catch(() => { });
      }
    }
  }).catch(() => { });

  tabScanCache.set(tabId, result);

  // ── Campus Pulse: send anonymous threat signal (fire-and-forget) ──────────
  if (result.overallSeverity === "high" || result.overallSeverity === "critical") {
    const category = mapThreatCategory(result.primaryThreat, result.overallSeverity);
    if (category) {
      sendThreatSignal(url, category).catch(() => { /* best-effort */ });
    }
  }

  // Save privacy-safe record (domain only, no full URL)
  const hostname = new URL(url).hostname;
  await saveScanRecord({
    id: crypto.randomUUID(),
    riskLevel: result.overallSeverity === "clean" ? "safe"
      : result.overallSeverity === "low" ? "safe"
        : result.overallSeverity === "medium" ? "suspicious"
          : "dangerous",
    domain: hostname,
    timestamp: result.timestamp,
    factorIds: result.signals.filter(s => s.triggered).map(s => s.id)
  });

  await updateBadge(tabId, result);

  // Notify content script to show alert if not clean
  if (result.overallSeverity !== "clean" && result.overallSeverity !== "low") {
    chrome.tabs.sendMessage(tabId, { type: "SHOW_RISK_ALERT", result }).catch(() => { });
  }

  // Periodically flush anonymised telemetry (if opted in)
  maybeFlushTelemetry();
}

// ─── Page context extractor — injected into MAIN world so window.* globals are visible ───

/** This function is serialised and injected into the page's MAIN world. Must be self-contained. */
function extractPageContextForBackground(): Record<string, unknown> {
  const scripts = [...document.querySelectorAll("script")];
  const scriptSrcs = scripts.map((s: HTMLScriptElement) => (s as HTMLScriptElement).src).filter(Boolean);
  const scriptInlineHints = scripts
    .filter((s: HTMLScriptElement) => !(s as HTMLScriptElement).src && (s as HTMLScriptElement).textContent?.trim())
    .map((s: HTMLScriptElement) => ((s as HTMLScriptElement).textContent ?? "").slice(0, 300))
    .slice(0, 20);

  // ── Window globals — runs in MAIN world so these are real page globals ──
  const GLOBALS: string[] = [
    "React", "__REACT_DEVTOOLS_GLOBAL_HOOK__", "__NEXT_DATA__", "__next",
    "Vue", "__VUE__", "__vue_app__",
    "angular", "ng",
    "__svelte",
    "wp", "wpApiSettings",
    "Shopify", "ShopifyAnalytics",
    "wixBiSession", "rendererModel",
    "Static",
    "firebase", "__FIREBASE_DEFAULTS__",
    "Intercom",
    "zE", "zESettings",
    "Stripe",
    "paypal", "PAYPAL",
    "jQuery", "$",
    // YouTube / Google
    "ytcfg", "ytInitialData", "yt", "ytInitialPlayerResponse", "Polymer",
    // Instagram / Meta
    "instagramReadyCallbacks", "__instagram", "_sharedData", "IgCoreAnalytics",
    "requireLazy", "__d",   // Meta's module system (Instagram, Facebook)
    // TikTok
    "byted_acrawler", "TIKTOK_WEB_DATA",
    // AMP
    "AMP", "__AMP_SERVICES", "AMP_CONFIG",
    // Twitter/X
    "__INITIAL_STATE__", "twttr",
    // Reddit
    "r", "reddit",
  ];

  const windowGlobals: string[] = [];
  for (const g of GLOBALS) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      if ((window as any)[g] !== undefined) windowGlobals.push(g);
    } catch { /* ignore */ }
  }

  const metaTags = [...document.querySelectorAll("meta")]
    .map(m => ({ name: m.getAttribute("name") ?? m.getAttribute("http-equiv") ?? "", content: m.getAttribute("content") ?? "" }))
    .filter(m => m.name && m.content).slice(0, 30);

  const formActions = [...document.querySelectorAll("form")]
    .map((f: HTMLFormElement) => (f as HTMLFormElement).action).filter(Boolean);

  const iframes = [...document.querySelectorAll("iframe")];
  const hiddenIframeCount = iframes.filter(f => {
    const style = window.getComputedStyle(f as Element);
    const rect = (f as Element).getBoundingClientRect();
    return style.display === "none" || style.visibility === "hidden" ||
      style.opacity === "0" || rect.width === 0 || rect.height === 0 ||
      parseInt(style.width) < 2 || parseInt(style.height) < 2;
  }).length;

  const cookieCount = document.cookie ? document.cookie.split(";").length : 0;
  const hostname = location.hostname;
  const thirdPartyDomains = [...new Set(
    scriptSrcs.map((src: string) => { try { return new URL(src).hostname; } catch { return ""; } })
      .filter((h: string) => h && h !== hostname && !h.endsWith("." + hostname))
  )].slice(0, 40);

  // Check meta-tag CSP (some sites / extensions use this method)
  const hasCSPMeta = !!document.querySelector('meta[http-equiv="Content-Security-Policy"]');
  // NOTE: HTTP header–based CSP cannot be read from the page itself.
  // background.ts will merge the webRequest header result after injection.
  const hasCSP = hasCSPMeta;
  const hasMixedContent = location.protocol === "https:" && (
    [...document.querySelectorAll("img,script,link,iframe")].some(el => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const src = (el as any).src ?? (el as any).href ?? "";
      return typeof src === "string" && src.startsWith("http://");
    })
  );

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
    hasPasswordField: !!document.querySelector('input[type="password"]'),
    hasCSP,
    hasMixedContent,
    cookieCount,
    thirdPartyDomains,
    pageTitle: document.title,
  };
}

// ─── Inspector pipeline runner — called after MAIN-world context extraction ───

async function runInspectorForTab(tabId: number, url: string): Promise<void> {
  if (!url || url.startsWith("chrome://") || url.startsWith("about:") || url.startsWith("chrome-extension://")) return;

  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId },
      func: extractPageContextForBackground,
      world: "MAIN",   // ← KEY: sees real window.* globals from the page
    });

    const ctx = results?.[0]?.result;
    if (!ctx) return;

    // ── Merge HTTP-header CSP result captured by webRequest listener ──────────
    // The injected function can only see <meta> tag CSP (no access to headers).
    // tabCspHeaderCache holds the real answer from the HTTP response.
    const headerCSP = tabCspHeaderCache.get(tabId);
    if (headerCSP === true) {
      // Header-based CSP found — always counts as having CSP
      (ctx as Record<string, unknown>).hasCSP = true;
    } else if (headerCSP === false && !(ctx as Record<string, unknown>).hasCSP) {
      // Neither header nor meta-tag CSP detected
      (ctx as Record<string, unknown>).hasCSP = false;
    }
    // If headerCSP is undefined (listener hasn't fired yet), keep whatever the
    // meta-tag check found — this avoids false negatives on slow responses.

    const report = runInspectorPipeline(ctx as unknown as PageContext);
    inspectorCache.set(tabId, report);
    updateInspectorBadge(tabId, report);
    maybeShowWhisperToast(tabId, report);
  } catch {
    // Page may have restricted scripting (chrome://, PDFs, etc.) — silently skip
  }
}

// ─── Tab lifecycle listeners ──────────────────────────────────────────────────

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    // Clear stale cache on every navigation
    inspectorCache.delete(tabId);
    toastShownTabs.delete(tabId);
    // NOTE: tabCspHeaderCache is intentionally NOT cleared here —
    // the webRequest listener fires before onUpdated(complete), so by the time
    // we reach here the header result is already stored. Clearing it would
    // lose that result before runInspectorForTab reads it.
    // Run legacy threat scan + new inspector (both async, non-blocking)
    performScan(tabId, tab.url);
    runInspectorForTab(tabId, tab.url);
  }
});

chrome.tabs.onActivated.addListener(async (activeInfo) => {
  const tab = await chrome.tabs.get(activeInfo.tabId).catch(() => null);
  if (tab?.url) {
    performScan(activeInfo.tabId, tab.url);
    // Only run inspector if no cached result yet (avoid redundant work)
    if (!inspectorCache.has(activeInfo.tabId)) {
      runInspectorForTab(activeInfo.tabId, tab.url);
    }
  }
});

chrome.tabs.onRemoved.addListener(tabId => {
  tabScanCache.delete(tabId);
  inspectorCache.delete(tabId);
  toastShownTabs.delete(tabId);
  tabCspHeaderCache.delete(tabId); // ← clean up header cache too
});


// ─── Hourly alarm to refresh threat feeds ─────────────────────────────────────

chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create("refreshFeeds", { periodInMinutes: 60 });
  chrome.alarms.create("pollCampusAlerts", { periodInMinutes: 15 });
  refreshFeedsIfStale(); // also refresh immediately on install
  pollCampusAlerts().catch(() => { }); // initial poll on install
});

// Also poll on every service worker startup (covers browser restart)
pollCampusAlerts().catch(() => { });

chrome.alarms.onAlarm.addListener(async alarm => {
  if (alarm.name === "refreshFeeds") refreshFeedsIfStale();

  if (alarm.name === "pollCampusAlerts") {
    const newAlerts = await pollCampusAlerts().catch(() => [] as CampusAlert[]);
    // If any new HIGH or CRITICAL alerts, whisper toast to active tab
    const urgent = newAlerts.filter(
      a => a.severity === "high" || a.severity === "critical"
    );
    if (urgent.length > 0) {
      const topAlert = urgent[0];
      chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
        const tabId = tabs[0]?.id;
        if (tabId) {
          chrome.tabs.sendMessage(tabId, {
            type: "SHOW_CAMPUS_ALERT",
            alert: topAlert,
          }).catch(() => { });
        }
      });
    }
  }
});

// ─── Message router ───────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  // ── Inspector: auto context from content script ───────────────────────────
  if (message.type === "PAGE_CONTEXT") {
    const tabId = sender.tab?.id;
    if (!tabId) return true;

    const ctx = message.ctx as PageContext;
    try {
      const report = runInspectorPipeline(ctx);
      inspectorCache.set(tabId, report);
      updateInspectorBadge(tabId, report);
      maybeShowWhisperToast(tabId, report);
    } catch { /* never crash on inspection error */ }

    sendResponse({ ok: true });
    return true;
  }

  // ── Inspector: popup fetching cached report ───────────────────────────────
  if (message.type === "GET_INSPECTOR_REPORT") {
    const tabId = message.tabId ?? sender.tab?.id;
    if (tabId) {
      sendResponse({ report: inspectorCache.get(tabId) ?? null });
    } else {
      sendResponse({ report: null });
    }
    return true;
  }

  // ── Legacy: popup fetching threat scan result ─────────────────────────────
  if (message.type === "GET_SCAN_RESULT") {
    const tabId = message.tabId ?? sender.tab?.id;
    if (tabId) {
      sendResponse({ result: tabScanCache.get(tabId) ?? null });
    } else {
      sendResponse({ result: null });
    }
    return true;
  }

  if (message.type === "REQUEST_SCAN") {
    // Popup requesting a force scan (fallback)
    const { tabId, url } = message;
    if (tabId && url) {
      performScan(tabId, url).then(() => {
        sendResponse({ result: tabScanCache.get(tabId) ?? null });
      });
    } else {
      sendResponse({ result: null });
    }
    return true;
  }

  if (message.type === "SCAN_URL") {
    // Manual scan from popup (for arbitrary text/url input if needed)
    const { url, ctx } = message;
    const result = analyzeThreats(url, ctx ?? {});
    sendResponse({ result });
    return true;
  }

  if (message.type === "GET_CURRENT_TAB_ID") {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      sendResponse({ tabId: tabs[0]?.id });
    });
    return true;
  }

  if (message.type === "CHECK_FORM_SUBMIT") {
    // Called by contentEnhanced.ts when a password form is about to submit
    const { action, origin } = message;
    try {
      const actionHost = new URL(action).hostname;
      const originHost = new URL(origin).hostname;
      const safe = actionHost === originHost ||
        actionHost.endsWith("." + originHost) ||
        originHost.endsWith("." + actionHost);
      sendResponse({ safe, reason: safe ? undefined : `Form submits to ${actionHost}, not ${originHost}` });
    } catch {
      sendResponse({ safe: false, reason: "Could not verify form destination." });
    }
    return true;
  }

  if (message.type === "THREAT_DETECTED") {
    // Real-time threat from contentEnhanced monitors (clipboard hijack, hidden crypto)
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      const tabId = tabs[0]?.id;
      if (!tabId) return;
      const cached = tabScanCache.get(tabId);
      if (cached) {
        const upgraded: ThreatReport = {
          ...cached,
          overallSeverity: "critical",
          headline: `Real-time alert: ${message.detail}`,
          friendlyHeadline: `Heads up — I just caught something on this page: ${message.detail}`,
          score: Math.min((cached.score ?? 0) + 50, 100)
        };
        tabScanCache.set(tabId, upgraded);
        updateBadge(tabId, upgraded);
      }
    });
    return true;
  }

  // ── Campus Pulse: popup fetching cached campus alerts ───────────────────
  if (message.type === "GET_CAMPUS_ALERTS") {
    getCampusAlerts().then(alerts => {
      sendResponse({ alerts });
    });
    return true;
  }

  // OPEN_POPUP — triggered when student taps whisper toast
  if (message.type === "OPEN_POPUP") {
    // chrome.action.openPopup() is only available in MV3 with user gesture
    // We respond successfully; the toast handles its own click
    sendResponse({ ok: true });
    return true;
  }
});
