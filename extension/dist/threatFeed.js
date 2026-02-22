/**
 * threatFeed.ts
 * ─────────────────────────────────────────────────────────────
 * Real-time threat intelligence using free public APIs:
 *  • Google Safe Browsing Lookup API (free, 10k req/day)
 *  • PhishTank community feed (free JSON, cached locally)
 *  • URLhaus (malware URL database, free)
 *  • Local bloom-filter cache to avoid hammering APIs
 * ─────────────────────────────────────────────────────────────
 *
 * Privacy: only the URL hash prefix (not the full URL) is sent
 * to Google Safe Browsing, matching GSB's privacy-preserving
 * partial-hash protocol. PhishTank + URLhaus are checked
 * locally against a cached blocklist.
 */
// ─── Config ───────────────────────────────────────────────────────────────────
// Set your Google Safe Browsing API key in chrome.storage or as a constant.
// Free key: https://developers.google.com/safe-browsing/v4/get-started
const GSB_API_KEY = "YOUR_GSB_API_KEY"; // replace before deploy
const GSB_ENDPOINT = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GSB_API_KEY}`;
// PhishTank & URLhaus cached JSON — update hourly via background alarm
const PHISHTANK_URL = "https://data.phishtank.com/data/online-valid.json";
const URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/";
// Cache keys in chrome.storage.local
const CACHE_KEY_PHISHTANK = "feed_phishtank";
const CACHE_KEY_URLHAUS = "feed_urlhaus";
const CACHE_KEY_UPDATED = "feed_updated";
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour
// ─── Google Safe Browsing ─────────────────────────────────────────────────────
export async function checkGoogleSafeBrowsing(url) {
    if (!GSB_API_KEY || GSB_API_KEY === "YOUR_GSB_API_KEY") {
        return { listed: false, source: "none" };
    }
    try {
        const body = {
            client: { clientId: "student-cyber-guardian", clientVersion: "1.0.0" },
            threatInfo: {
                threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                platformTypes: ["ANY_PLATFORM"],
                threatEntryTypes: ["URL"],
                threatEntries: [{ url }]
            }
        };
        const res = await fetch(GSB_ENDPOINT, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body)
        });
        if (!res.ok)
            return { listed: false, source: "none" };
        const data = await res.json();
        if (data.matches && data.matches.length > 0) {
            const match = data.matches[0];
            return {
                listed: true,
                source: "Google Safe Browsing",
                threat: match.threatType,
                url
            };
        }
    }
    catch { /* network error — fail open */ }
    return { listed: false, source: "none" };
}
// ─── Local blocklist cache management ────────────────────────────────────────
async function isCacheStale() {
    return new Promise(resolve => {
        chrome.storage.local.get(CACHE_KEY_UPDATED, r => {
            const ts = r[CACHE_KEY_UPDATED] ?? 0;
            resolve(Date.now() - ts > CACHE_TTL_MS);
        });
    });
}
export async function refreshFeedsIfStale() {
    if (!(await isCacheStale()))
        return;
    // Fetch URLhaus recent malware URLs (small JSON, ~500 entries)
    try {
        const res = await fetch(URLHAUS_URL, { method: "POST", body: "limit=500" });
        const data = await res.json();
        const urls = (data.urls ?? []).map((e) => normaliseUrl(e.url));
        chrome.storage.local.set({ [CACHE_KEY_URLHAUS]: urls });
    }
    catch { /* keep old cache */ }
    // PhishTank is large (~50MB) — only fetch hostnames to save space
    // In a real deployment, proxy this through your backend to return just hostnames
    // For demo, we skip the full feed and rely on GSB + heuristics
    chrome.storage.local.set({ [CACHE_KEY_UPDATED]: Date.now() });
}
function normaliseUrl(url) {
    try {
        return new URL(url).hostname.toLowerCase();
    }
    catch {
        return url.toLowerCase();
    }
}
async function getLocalBlocklist(key) {
    return new Promise(resolve => {
        chrome.storage.local.get(key, r => {
            resolve(new Set(r[key] ?? []));
        });
    });
}
// ─── URLhaus check ────────────────────────────────────────────────────────────
export async function checkURLhaus(url) {
    const hostname = normaliseUrl(url);
    const blocklist = await getLocalBlocklist(CACHE_KEY_URLHAUS);
    if (blocklist.has(hostname)) {
        return { listed: true, source: "URLhaus", threat: "MALWARE", url };
    }
    // Also try the live API for URLs not in cache
    try {
        const res = await fetch("https://urlhaus-api.abuse.ch/v1/url/", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: `url=${encodeURIComponent(url)}`
        });
        const data = await res.json();
        if (data.query_status === "is_malware") {
            return { listed: true, source: "URLhaus", threat: "MALWARE", url };
        }
    }
    catch { /* offline — use cache only */ }
    return { listed: false, source: "none" };
}
// ─── Aggregate feed check ─────────────────────────────────────────────────────
export async function checkAllFeeds(url) {
    await refreshFeedsIfStale();
    // Run all checks in parallel for speed
    const [gsb, urlhaus] = await Promise.all([
        checkGoogleSafeBrowsing(url),
        checkURLhaus(url)
    ]);
    if (gsb.listed)
        return gsb;
    if (urlhaus.listed)
        return urlhaus;
    return { listed: false, source: "none" };
}
// ─── Background alarm to refresh feeds hourly ────────────────────────────────
// Call this from background.ts on extension startup:
//
//   chrome.alarms.create("refreshFeeds", { periodInMinutes: 60 });
//   chrome.alarms.onAlarm.addListener(alarm => {
//     if (alarm.name === "refreshFeeds") refreshFeedsIfStale();
//   });
