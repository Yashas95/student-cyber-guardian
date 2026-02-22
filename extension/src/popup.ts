/**
 * popup.ts — Student Cyber Guardian popup controller (v1.2)
 *
 * Architecture (reliable, no race condition):
 * 1. Popup opens → asks background for cached InspectorReport for active tab
 * 2. If found → render instantly
 * 3. If NOT found (service worker restarted, or page just loaded) →
 *    use chrome.scripting.executeScript to run extractPageContext() in the tab,
 *    then call runInspectorPipeline() right here in popup context,
 *    and render results — no background needed as fallback.
 */

import { getSettings, saveSettings, getLocalStats, clearAllData } from "./storage.js";
import { runInspectorPipeline } from "./pageInspector.js";
import type { InspectorReport } from "./pageInspector.js";
import {
  getCampusId,
  setCampusId,
  getCampusAlerts,
  CAMPUS_LIST,
} from "./campusPulse.js";
import type { CampusAlert } from "./campusPulse.js";

// ─── Tab switching ─────────────────────────────────────────────────────────────

document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    const target = (tab as HTMLElement).dataset.tab!;
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(t => t.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById(`tab-${target}`)?.classList.add("active");
    if (target === "guardian") loadStats();
    if (target === "pulse") loadCampusPulse();
  });
});

// ─── Accordion helpers ─────────────────────────────────────────────────────────

function setupAccordion(headerId: string, bodyId: string): void {
  const header = document.getElementById(headerId)!;
  const body = document.getElementById(bodyId)!;
  header.addEventListener("click", () => {
    const isOpen = body.classList.contains("open");
    header.classList.toggle("open", !isOpen);
    body.classList.toggle("open", !isOpen);
  });
}

setupAccordion("acc-tech-header", "acc-tech-body");
setupAccordion("acc-sec-header", "acc-sec-body");
setupAccordion("acc-track-header", "acc-track-body");

// ─── Page context extractor (runs inside tab via scripting.executeScript) ──────
// This function is serialised and injected — must be self-contained.

function extractPageContextInTab(): object {
  const scripts = [...document.querySelectorAll("script")];
  const scriptSrcs = scripts.map(s => s.src).filter(Boolean);
  const scriptInlineHints = scripts
    .filter(s => !s.src && s.textContent?.trim())
    .map(s => (s.textContent ?? "").slice(0, 300))
    .slice(0, 20);

  const GLOBALS_TO_CHECK = [
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
    "ytcfg", "ytInitialData", "yt", "ytInitialPlayerResponse",
    "Polymer",
    // AMP
    "AMP", "__AMP_SERVICES", "AMP_CONFIG",
  ];
  const windowGlobals: string[] = [];
  for (const g of GLOBALS_TO_CHECK) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      if ((window as any)[g] !== undefined) windowGlobals.push(g);
    } catch { /* ignore */ }
  }

  const metaTags = [...document.querySelectorAll("meta")]
    .map(m => ({ name: m.getAttribute("name") ?? m.getAttribute("http-equiv") ?? "", content: m.getAttribute("content") ?? "" }))
    .filter(m => m.name && m.content)
    .slice(0, 30);

  const formActions = [...document.querySelectorAll("form")]
    .map(f => f.action)
    .filter(Boolean);

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

  const cookieCount = document.cookie ? document.cookie.split(";").length : 0;
  const hostname = location.hostname;
  const thirdPartyDomains = [...new Set(
    scriptSrcs
      .map(src => { try { return new URL(src).hostname; } catch { return ""; } })
      .filter(h => h && h !== hostname && !h.endsWith("." + hostname))
  )].slice(0, 40);

  const hasCSP = document.querySelector('meta[http-equiv="Content-Security-Policy"]') !== null;
  const hasMixedContent = location.protocol === "https:" && (
    [...document.querySelectorAll("img, script, link, iframe")].some(el => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const src = (el as any).src ?? (el as any).href ?? "";
      return typeof src === "string" && src.startsWith("http://");
    })
  );
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

// ─── Render Inspector Report ───────────────────────────────────────────────────

function renderInspectorReport(report: InspectorReport): void {
  // Header domain + time
  const domainEl = document.getElementById("header-domain")!;
  const timeEl = document.getElementById("check-time")!;
  domainEl.textContent = report.hostname;
  const ago = Math.round((Date.now() - report.timestamp) / 1000);
  timeEl.textContent = ago < 5 ? "Checked just now" : ago < 60 ? `${ago}s ago` : "Checked recently";

  // Friend summary
  const loading = document.getElementById("summary-loading")!;
  const summaryText = document.getElementById("summary-text")!;
  loading.style.display = "none";
  summaryText.style.display = "block";
  summaryText.textContent = `"${report.friendSummary}"`;

  // Stats bar
  const statsBar = document.getElementById("stats-bar")!;
  statsBar.style.display = "flex";
  const gradeEl = document.getElementById("stat-grade")!;
  gradeEl.textContent = report.gradeLabel;
  gradeEl.className = `stat-num grade-${report.grade}`;
  document.getElementById("stat-trackers")!.textContent = String(report.trackerCount);
  const topTech = report.techStack[0];
  document.getElementById("stat-tech")!.textContent = topTech ? topTech.emoji : "–";

  // Tech accordion
  const techAccordion = document.getElementById("accordion-tech")!;
  if (report.techStack.length > 0) {
    techAccordion.style.display = "block";
    document.getElementById("acc-tech-summary")!.textContent =
      report.techStack.slice(0, 3).map(t => t.name).join(" · ") +
      (report.techStack.length > 3 ? ` +${report.techStack.length - 3} more` : "");
    document.getElementById("acc-tech-body")!.innerHTML = report.techStack.map(renderTechItem).join("");
  } else {
    techAccordion.style.display = "none";
  }

  // Security accordion
  document.getElementById("acc-sec-summary")!.textContent = buildSecuritySummary(report);
  document.getElementById("acc-sec-body")!.innerHTML = report.securityChecks.map(renderSecurityCheck).join("");

  // Trackers accordion
  const trackAccordion = document.getElementById("accordion-trackers")!;
  if (report.trackerCount > 0) {
    trackAccordion.style.display = "block";
    const topNames = report.trackers.slice(0, 2).map(t => t.name).join(" · ");
    const extra = report.trackerCount > 2 ? ` +${report.trackerCount - 2} more` : "";
    document.getElementById("acc-track-summary")!.textContent = topNames + extra;
    document.getElementById("acc-track-body")!.innerHTML = report.trackers.map(renderTrackerItem).join("");
  } else {
    trackAccordion.style.display = "none";
  }

  // Lesson
  const lessonCard = document.getElementById("lesson-card")!;
  if (report.lesson) {
    lessonCard.style.display = "block";
    document.getElementById("lesson-emoji")!.textContent = report.lessonEmoji;
    document.getElementById("lesson-text")!.textContent = report.lesson;
  }
}

function buildSecuritySummary(report: InspectorReport): string {
  const passed = report.securityChecks.filter(c => c.passed).length;
  const total = report.securityChecks.length;
  const https = report.securityChecks.find(c => c.id === "https");
  if (https && !https.passed) return "⚠️ No HTTPS — take care on this page";
  if (passed === total) return `✅ ${passed}/${total} checks passed`;
  return `⚠️ ${passed}/${total} checks passed`;
}

function renderTechItem(tech: InspectorReport["techStack"][number]): string {
  return `
    <div class="tech-item">
      <span class="tech-emoji">${tech.emoji}</span>
      <div class="tech-info">
        <div class="tech-name">${tech.name}</div>
        <div class="tech-desc">${tech.description}</div>
        <div class="tech-long-desc">${tech.longDescription}</div>
      </div>
      <div class="category-pill cat-${tech.category}">${tech.category}</div>
    </div>
  `;
}

function renderTrackerItem(tracker: InspectorReport["trackers"][number]): string {
  return `
    <div class="tracker-item">
      <span class="tracker-emoji">${tracker.emoji}</span>
      <div class="tracker-info">
        <div class="tracker-name">${tracker.name}</div>
        <div class="tracker-desc">${tracker.description}</div>
        <div class="tracker-long-desc">${tracker.longDescription}</div>
      </div>
      <div class="risk-pill risk-${tracker.risk}">${tracker.category}</div>
    </div>
  `;
}

function renderSecurityCheck(check: InspectorReport["securityChecks"][number]): string {
  return `
    <div class="security-item">
      <span class="security-emoji">${check.emoji}</span>
      <div class="security-info">
        <div class="security-label">${check.label}</div>
        <div class="security-explanation">${check.explanation}</div>
      </div>
    </div>
  `;
}

function showError(msg: string): void {
  document.getElementById("summary-loading")!.innerHTML =
    `<span style="font-size:12px;color:#64748b;">${msg}</span>`;
}

// ─── Trust Stats (My Guardian tab) ────────────────────────────────────────────

async function loadStats(): Promise<void> {
  const stats = await getLocalStats();
  const total = (stats.safe ?? 0) + (stats.suspicious ?? 0) + (stats.dangerous ?? 0);

  (document.getElementById("stat-safe") as HTMLElement).textContent = String(stats.safe ?? 0);
  (document.getElementById("stat-sus") as HTMLElement).textContent = String(stats.suspicious ?? 0);
  (document.getElementById("stat-danger") as HTMLElement).textContent = String(stats.dangerous ?? 0);

  const perfMsg = document.getElementById("guardian-perf-msg");
  if (perfMsg) {
    if (total === 0) {
      perfMsg.textContent = "I haven't checked anything yet — just browsing around?";
    } else if (stats.dangerous === 0 && stats.suspicious === 0) {
      perfMsg.textContent = `Looking good! I've checked ${total} site${total !== 1 ? "s" : ""} and kept you safe the whole time. 🙌`;
    } else if (stats.dangerous > 0) {
      perfMsg.textContent = `I stepped in on ${stats.dangerous} concerning site${stats.dangerous !== 1 ? "s" : ""} out of ${total} I checked. 🛡️`;
    } else {
      perfMsg.textContent = `I flagged ${stats.suspicious} site${stats.suspicious !== 1 ? "s" : ""} while keeping you safe on the rest.`;
    }
  }
}

document.getElementById("clear-btn")?.addEventListener("click", async () => {
  await clearAllData();
  await loadStats();
});

// ─── Settings tab ──────────────────────────────────────────────────────────────

async function loadSettings(): Promise<void> {
  const s = await getSettings();
  (document.getElementById("toggle-scan") as HTMLInputElement).checked = s.scanOnNavigate;
  (document.getElementById("toggle-badge") as HTMLInputElement).checked = s.showBadge;
  (document.getElementById("toggle-telemetry") as HTMLInputElement).checked = s.telemetryEnabled;
}

["scan", "badge", "telemetry"].forEach(key => {
  document.getElementById(`toggle-${key}`)?.addEventListener("change", async e => {
    const checked = (e.target as HTMLInputElement).checked;
    const map: Record<string, string> = {
      scan: "scanOnNavigate",
      badge: "showBadge",
      telemetry: "telemetryEnabled"
    };
    await saveSettings({ [map[key]]: checked });
  });
});

// ─── Main init ─────────────────────────────────────────────────────────────────

async function init(): Promise<void> {
  loadSettings();

  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const tab = tabs[0];
  if (!tab?.id || !tab.url) {
    showError("Couldn't identify the active tab.");
    return;
  }

  // Skip non-inspectable pages
  if (
    tab.url.startsWith("chrome://") ||
    tab.url.startsWith("chrome-extension://") ||
    tab.url.startsWith("about:") ||
    tab.url.startsWith("edge://")
  ) {
    document.getElementById("header-domain")!.textContent = "browser page";
    showError("Guardian doesn't inspect browser pages.");
    return;
  }

  // Update domain header immediately
  try {
    document.getElementById("header-domain")!.textContent = new URL(tab.url).hostname;
  } catch { /**/ }

  // Step 1: Try background cache first (fastest path — already computed)
  try {
    const cached = await new Promise<{ report: InspectorReport | null }>(resolve => {
      chrome.runtime.sendMessage(
        { type: "GET_INSPECTOR_REPORT", tabId: tab.id },
        (response) => {
          if (chrome.runtime.lastError) resolve({ report: null });
          else resolve(response ?? { report: null });
        }
      );
    });

    if (cached?.report) {
      renderInspectorReport(cached.report);
      return; // done — instant result from background
    }
  } catch { /**/ }

  // Step 2: Background cache empty (service worker restarted or first visit).
  // Run inspection right here in popup context using scripting.executeScript.
  // CRITICAL: world:"MAIN" lets us see actual page window.* globals (React, ytcfg, etc.)
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId: tab.id! },
      func: extractPageContextInTab,
      world: "MAIN",   // ← runs in page's real JS context, not isolated world
    });

    const ctx = results?.[0]?.result;
    if (!ctx) {
      showError("Couldn't read this page. Try reloading it.");
      return;
    }

    // Run the full inspector pipeline in popup context
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const report = runInspectorPipeline(ctx as any);
    renderInspectorReport(report);

    // Also tell background to cache it and update the badge
    chrome.runtime.sendMessage({ type: "PAGE_CONTEXT", ctx }).catch(() => { });

  } catch (err) {
    showError("Couldn't inspect this page — it may have restricted permissions.");
    console.error("[Guardian] scripting.executeScript failed:", err);
  }
}

init();

// ─── Campus Pulse tab logic ──────────────────────────────────────────────────

async function loadCampusPulse(): Promise<void> {
  const campusId = await getCampusId();
  const setupEl = document.getElementById("pulse-setup")!;
  const contentEl = document.getElementById("pulse-content")!;

  if (!campusId) {
    // Show campus setup
    setupEl.style.display = "";
    contentEl.style.display = "none";
    initCampusSetup();
    return;
  }

  setupEl.style.display = "none";
  contentEl.style.display = "";

  // Fetch cached alerts from background
  let alerts: CampusAlert[] = [];
  try {
    const resp = await new Promise<{ alerts: CampusAlert[] }>(resolve => {
      chrome.runtime.sendMessage({ type: "GET_CAMPUS_ALERTS" }, (r) => {
        if (chrome.runtime.lastError) resolve({ alerts: [] });
        else resolve(r ?? { alerts: [] });
      });
    });
    alerts = resp.alerts ?? [];
  } catch {
    alerts = await getCampusAlerts();
  }

  const activeAlerts = alerts.filter(a => a.active);
  const statusCard = document.getElementById("pulse-status-card")!;
  const dot = document.getElementById("pulse-dot")!;
  const label = document.getElementById("pulse-status-label")!;
  const body = document.getElementById("pulse-status-body")!;
  const alertsContainer = document.getElementById("pulse-alerts-container")!;
  const tabDot = document.getElementById("tab-pulse-dot");

  if (activeAlerts.length === 0) {
    // All clear
    statusCard.className = "pulse-status-card all-clear";
    dot.className = "pulse-dot green";
    label.className = "pulse-status-label green";
    label.textContent = "All Clear";
    body.innerHTML = `<div class="pulse-msg">"All clear at your campus right now. No active threats detected. I'm monitoring in the background."</div>`;
    alertsContainer.innerHTML = "";
    if (tabDot) tabDot.className = "tab-pulse-dot";
  } else {
    // Active alerts
    statusCard.className = "pulse-status-card alert-active";
    dot.className = "pulse-dot red";
    label.className = "pulse-status-label red";
    label.textContent = `${activeAlerts.length} Active Alert${activeAlerts.length > 1 ? "s" : ""}`;
    body.innerHTML = "";
    if (tabDot) tabDot.className = "tab-pulse-dot alert";

    alertsContainer.innerHTML = activeAlerts.map(a => {
      const adviceHtml = (a.advice ?? []).map(
        tip => `<div class="pulse-advice-item">${escHtml(tip)}</div>`
      ).join("");

      const timeAgo = getTimeAgo(a.last_seen);

      return `
        <div class="pulse-status-card alert-active" style="margin-top:8px;">
          <div class="pulse-alert-msg">${escHtml(a.friendly_message)}</div>
          ${adviceHtml ? `
            <div class="pulse-advice-box">
              <div class="pulse-advice-title">What to do</div>
              ${adviceHtml}
            </div>` : ""}
          <div class="pulse-alert-time">${a.signal_count} reports · ${timeAgo}</div>
        </div>
      `;
    }).join("");
  }

  // Weekly stats
  const weeklyText = document.getElementById("pulse-weekly-text")!;
  weeklyText.innerHTML = activeAlerts.length > 0
    ? `Your campus is currently experiencing <strong>${activeAlerts.length} active threat${activeAlerts.length > 1 ? "s" : ""}</strong>. Stay alert.`
    : `I'm watching over your campus in the background. You're good!`;
}

function initCampusSetup(): void {
  const searchInput = document.getElementById("campus-search") as HTMLInputElement;
  const listEl = document.getElementById("campus-list")!;
  const skipBtn = document.getElementById("campus-skip-btn")!;

  function renderList(filter: string): void {
    const q = filter.toLowerCase().trim();
    const filtered = q
      ? CAMPUS_LIST.filter(c => c.name.toLowerCase().includes(q) || c.id.includes(q))
      : CAMPUS_LIST;

    listEl.innerHTML = filtered.map(c =>
      `<div class="campus-list-item" data-campus-id="${c.id}">${escHtml(c.name)}</div>`
    ).join("");

    listEl.querySelectorAll(".campus-list-item").forEach(item => {
      item.addEventListener("click", async () => {
        const id = (item as HTMLElement).dataset.campusId!;
        await setCampusId(id);
        loadCampusPulse();
      });
    });
  }

  renderList("");
  searchInput.addEventListener("input", () => renderList(searchInput.value));
  skipBtn.addEventListener("click", () => {
    // Switch back to inspector tab
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(t => t.classList.remove("active"));
    document.querySelector('[data-tab="inspector"]')?.classList.add("active");
    document.getElementById("tab-inspector")?.classList.add("active");
  });
}

function escHtml(str: string): string {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function getTimeAgo(ts: number): string {
  const diff = Date.now() - ts;
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}
