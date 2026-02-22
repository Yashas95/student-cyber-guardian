/**
 * campusPulse.ts — Campus Threat Pulse
 * ─────────────────────────────────────────────────────────────
 * When one student gets protected, every student on campus
 * gets smarter — instantly, anonymously, automatically.
 *
 * PRIVACY RULES (non-negotiable):
 *   ✅ Sent: threat_category, domain_hash (8 chars), campus_id,
 *      timestamp (rounded to hour), session_token (24h rotating UUID)
 *   ❌ Never sent: full URL, student name, email, IP, browsing history,
 *      device fingerprint, or any personally identifiable information
 *
 * THRESHOLD: 3 independent signals → campus alert (prevents false positives)
 * ─────────────────────────────────────────────────────────────
 */
// ─── Server config ──────────────────────────────────────────────────────────
const PULSE_SERVER = "http://localhost:8000";
// ─── Helpers — privacy-preserving transforms ────────────────────────────────
/**
 * SHA-256 hash a hostname and return only the first 8 hex characters.
 * The full hash is never stored or transmitted.
 */
async function hashHostname(hostname) {
    const encoder = new TextEncoder();
    const data = encoder.encode(hostname.toLowerCase());
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
    return hashHex.slice(0, 8); // only first 8 chars — irreversible
}
/**
 * Round a timestamp DOWN to the nearest hour.
 * e.g. 9:47am becomes 9:00am — prevents timing fingerprinting.
 */
function roundToHour(ts) {
    return Math.floor(ts / 3_600_000) * 3_600_000;
}
// ─── Session token — rotates every 24 hours, not linked to identity ─────────
export async function getOrCreateSessionToken() {
    return new Promise(resolve => {
        chrome.storage.local.get("pulseSessionMeta", result => {
            const meta = result.pulseSessionMeta;
            const now = Date.now();
            if (meta && now - meta.createdAt < 86_400_000) {
                resolve(meta.token);
            }
            else {
                const newToken = crypto.randomUUID();
                chrome.storage.local.set({ pulseSessionMeta: { token: newToken, createdAt: now } }, () => resolve(newToken));
            }
        });
    });
}
// ─── Campus ID — set once during onboarding, stored locally ─────────────────
export async function getCampusId() {
    return new Promise(resolve => {
        chrome.storage.local.get("campus_id", result => {
            resolve(result.campus_id ?? null);
        });
    });
}
export async function setCampusId(campusId) {
    return new Promise(resolve => {
        chrome.storage.local.set({ campus_id: campusId }, resolve);
    });
}
// ─── Send anonymous threat signal ───────────────────────────────────────────
/**
 * Map a threat scanner severity/type to a pulse category.
 * Only called when a real threat is detected.
 */
export function mapThreatCategory(primaryThreat, overallSeverity) {
    // Only send signals for genuinely dangerous/suspicious detections
    if (overallSeverity !== "high" && overallSeverity !== "critical")
        return null;
    const mapping = {
        phishing: "phishing",
        malware: "malware",
        scam: "scam",
        fake_login: "fake_login",
        credential_theft: "fake_login",
        impersonation: "phishing",
    };
    return mapping[primaryThreat] ?? "phishing";
}
/**
 * Send an anonymous threat signal to the campus pulse server.
 * Fire-and-forget: never retries, never blocks, never stores locally.
 */
export async function sendThreatSignal(url, threatCategory) {
    try {
        const campusId = await getCampusId();
        if (!campusId)
            return; // student hasn't set up campus yet — silently skip
        const hostname = new URL(url).hostname;
        const domainHash = await hashHostname(hostname);
        const sessionToken = await getOrCreateSessionToken();
        const signal = {
            campus_id: campusId,
            threat_category: threatCategory,
            domain_hash: domainHash,
            timestamp: roundToHour(Date.now()),
            session_token: sessionToken,
        };
        // Best-effort POST — never retry, never await in caller
        await fetch(`${PULSE_SERVER}/pulse/signal`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(signal),
        });
        // Signal is never stored locally after sending
    }
    catch {
        // Silently fail — campus pulse is best-effort, never impacts core extension
    }
}
// ─── Poll campus alerts ─────────────────────────────────────────────────────
/**
 * Fetch active alerts for the student's campus.
 * Returns list of NEW alerts (not previously seen) for toast notifications.
 */
export async function pollCampusAlerts() {
    try {
        const campusId = await getCampusId();
        if (!campusId)
            return [];
        const response = await fetch(`${PULSE_SERVER}/pulse/alerts?campus=${encodeURIComponent(campusId)}`);
        if (!response.ok)
            return [];
        const alerts = await response.json();
        // Get previously seen alert IDs
        const prevAlertIds = await new Promise(resolve => {
            chrome.storage.local.get("campus_alert_ids", result => {
                resolve(result.campus_alert_ids ?? []);
            });
        });
        // Identify genuinely new alerts
        const prevSet = new Set(prevAlertIds);
        const newAlerts = alerts.filter(a => a.active && !prevSet.has(a.alert_id));
        // Store current alerts & their IDs
        const currentIds = alerts.filter(a => a.active).map(a => a.alert_id);
        await new Promise(resolve => {
            chrome.storage.local.set({
                campus_alerts: alerts.filter(a => a.active),
                campus_alert_ids: currentIds,
            }, resolve);
        });
        return newAlerts;
    }
    catch {
        return []; // silently fail — best-effort
    }
}
// ─── Read cached alerts (for popup) ─────────────────────────────────────────
export async function getCampusAlerts() {
    return new Promise(resolve => {
        chrome.storage.local.get("campus_alerts", result => {
            resolve(result.campus_alerts ?? []);
        });
    });
}
// ─── Campus list for onboarding ─────────────────────────────────────────────
export const CAMPUS_LIST = [
    { id: "mit", name: "Massachusetts Institute of Technology" },
    { id: "stanford", name: "Stanford University" },
    { id: "harvard", name: "Harvard University" },
    { id: "caltech", name: "California Institute of Technology" },
    { id: "cmu", name: "Carnegie Mellon University" },
    { id: "ucberkeley", name: "UC Berkeley" },
    { id: "umich", name: "University of Michigan" },
    { id: "gatech", name: "Georgia Institute of Technology" },
    { id: "uiuc", name: "University of Illinois Urbana-Champaign" },
    { id: "utaustin", name: "University of Texas at Austin" },
    { id: "cornell", name: "Cornell University" },
    { id: "princeton", name: "Princeton University" },
    { id: "columbia", name: "Columbia University" },
    { id: "upenn", name: "University of Pennsylvania" },
    { id: "yale", name: "Yale University" },
    { id: "nyu", name: "New York University" },
    { id: "ucla", name: "UCLA" },
    { id: "usc", name: "University of Southern California" },
    { id: "uw", name: "University of Washington" },
    { id: "purdue", name: "Purdue University" },
    { id: "osu", name: "Ohio State University" },
    { id: "psu", name: "Penn State University" },
    { id: "ufl", name: "University of Florida" },
    { id: "unc", name: "University of North Carolina" },
    { id: "uva", name: "University of Virginia" },
    { id: "duke", name: "Duke University" },
    { id: "northwestern", name: "Northwestern University" },
    { id: "brown", name: "Brown University" },
    { id: "rice", name: "Rice University" },
    { id: "vanderbilt", name: "Vanderbilt University" },
    { id: "iit-bombay", name: "IIT Bombay" },
    { id: "iit-delhi", name: "IIT Delhi" },
    { id: "iit-madras", name: "IIT Madras" },
    { id: "iit-kanpur", name: "IIT Kanpur" },
    { id: "iit-kharagpur", name: "IIT Kharagpur" },
    { id: "bits-pilani", name: "BITS Pilani" },
    { id: "oxford", name: "University of Oxford" },
    { id: "cambridge", name: "University of Cambridge" },
    { id: "imperial", name: "Imperial College London" },
    { id: "ucl", name: "University College London" },
    { id: "eth-zurich", name: "ETH Zurich" },
    { id: "nus", name: "National University of Singapore" },
    { id: "ntu", name: "Nanyang Technological University" },
    { id: "utokyo", name: "University of Tokyo" },
    { id: "tsinghua", name: "Tsinghua University" },
    { id: "kaist", name: "KAIST" },
    { id: "umelbourne", name: "University of Melbourne" },
    { id: "usyd", name: "University of Sydney" },
    { id: "utoronto", name: "University of Toronto" },
    { id: "ubc", name: "University of British Columbia" },
];
