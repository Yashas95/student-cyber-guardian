/**
 * riskScorer.ts
 * Core URL + page content risk scoring engine.
 * Runs entirely client-side — no raw URLs or page content leave the device.
 */

export type RiskLevel = "safe" | "suspicious" | "dangerous";

export interface RiskFactor {
  id: string;
  label: string;
  weight: number; // 0–100
  triggered: boolean;
  detail?: string;
}

export interface ScanResult {
  url: string;
  riskLevel: RiskLevel;
  score: number; // 0–100
  explanation: string;
  factors: RiskFactor[];
  tips: string[];
  timestamp: number;
}

// ─── Suspicious TLD list ─────────────────────────────────────────────────────
const SUSPICIOUS_TLDS = new Set([
  "xyz", "tk", "ml", "ga", "cf", "gq", "top", "click", "download",
  "zip", "review", "country", "kim", "cricket", "science", "work",
  "party", "gdn", "loan", "win", "bid", "trade", "date", "racing"
]);

// ─── Common brand keywords to detect impersonation ───────────────────────────
const BRAND_KEYWORDS = [
  "paypal", "amazon", "google", "apple", "microsoft", "netflix", "facebook",
  "instagram", "twitter", "bank", "chase", "wellsfargo", "citibank",
  "coinbase", "binance", "metamask", "irs", "fedex", "ups", "dhl",
  "whatsapp", "telegram", "discord", "steam"
];

// ─── Phishing path/query patterns ────────────────────────────────────────────
const PHISHING_PATH_PATTERNS = [
  /verify.*account/i, /confirm.*identity/i, /update.*payment/i,
  /suspended.*account/i, /unlock.*account/i, /login.*reset/i,
  /secure.*signin/i, /signin.*secure/i
];

const URGENCY_KEYWORDS = [
  "urgent", "immediately", "account suspended", "verify now", "limited time",
  "act now", "expires today", "click here to avoid", "your account will be",
  "unusual activity", "unauthorized access"
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function parseUrl(rawUrl: string): URL | null {
  try {
    return new URL(rawUrl.startsWith("http") ? rawUrl : `https://${rawUrl}`);
  } catch {
    return null;
  }
}

function getSubdomainDepth(hostname: string): number {
  return hostname.split(".").length - 2;
}

function hasBrandInSubdomain(hostname: string): string | null {
  const parts = hostname.split(".");
  const tld = parts[parts.length - 1];
  const sld = parts[parts.length - 2];
  const subdomains = parts.slice(0, -2).join(".");
  for (const brand of BRAND_KEYWORDS) {
    if (subdomains.includes(brand) && !sld.includes(brand)) {
      return brand;
    }
  }
  return null;
}

function levenshtein(a: string, b: string): number {
  const m = a.length, n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
  return dp[m][n];
}

function detectTyposquatting(hostname: string): string | null {
  const sld = hostname.split(".").slice(-2, -1)[0] ?? "";
  for (const brand of BRAND_KEYWORDS) {
    if (sld === brand) continue; // exact match = legit SLD
    const dist = levenshtein(sld, brand);
    if (dist > 0 && dist <= 2 && sld.length > 3) return brand;
  }
  return null;
}

// ─── Feature extraction ───────────────────────────────────────────────────────

export function extractFeatures(url: string, pageText: string, pageTitle: string): RiskFactor[] {
  const parsed = parseUrl(url);
  const hostname = parsed?.hostname ?? "";
  const tld = hostname.split(".").pop() ?? "";
  const path = parsed?.pathname ?? "";
  const isHttps = parsed?.protocol === "https:";
  const factors: RiskFactor[] = [];

  // 1. No HTTPS
  factors.push({
    id: "no_https",
    label: "No HTTPS encryption",
    weight: 30,
    triggered: !isHttps,
    detail: "The site doesn't use a secure connection (HTTPS). Your data could be intercepted."
  });

  // 2. Suspicious TLD
  factors.push({
    id: "suspicious_tld",
    label: "Suspicious domain extension",
    weight: 25,
    triggered: SUSPICIOUS_TLDS.has(tld),
    detail: `.${tld} domains are commonly used in spam and phishing campaigns.`
  });

  // 3. Brand in subdomain (impersonation)
  const brandSubdomain = hasBrandInSubdomain(hostname);
  factors.push({
    id: "brand_subdomain",
    label: "Brand name used as subdomain (possible impersonation)",
    weight: 50,
    triggered: brandSubdomain !== null,
    detail: brandSubdomain
      ? `"${brandSubdomain}" appears as a subdomain — attackers do this to fake legitimacy while the real domain is different.`
      : undefined
  });

  // 4. Typosquatting
  const typoTarget = detectTyposquatting(hostname);
  factors.push({
    id: "typosquatting",
    label: "Domain looks like a misspelling of a real brand",
    weight: 55,
    triggered: typoTarget !== null,
    detail: typoTarget
      ? `This domain closely resembles "${typoTarget}" but isn't the real site.`
      : undefined
  });

  // 5. Excessive subdomain depth
  const subDepth = getSubdomainDepth(hostname);
  factors.push({
    id: "deep_subdomains",
    label: "Unusually deep subdomain structure",
    weight: 20,
    triggered: subDepth >= 3,
    detail: `${subDepth} levels of subdomains — legitimate sites rarely need this.`
  });

  // 6. Phishing path patterns
  const phishPath = PHISHING_PATH_PATTERNS.some(p => p.test(path + pageText));
  factors.push({
    id: "phishing_path",
    label: "URL or page contains phishing language",
    weight: 40,
    triggered: phishPath,
    detail: "The URL path or page content uses language common in phishing attacks (e.g., 'verify account', 'confirm identity')."
  });

  // 7. Urgency language in page
  const urgencyFound = URGENCY_KEYWORDS.filter(kw =>
    pageText.toLowerCase().includes(kw.toLowerCase())
  );
  factors.push({
    id: "urgency_language",
    label: "High-pressure / urgency language detected",
    weight: 35,
    triggered: urgencyFound.length >= 2,
    detail: urgencyFound.length
      ? `Phrases like "${urgencyFound[0]}" are used to pressure you into acting without thinking.`
      : undefined
  });

  // 8. IP address as host
  const isIpHost = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
  factors.push({
    id: "ip_host",
    label: "Uses an IP address instead of a domain name",
    weight: 45,
    triggered: isIpHost,
    detail: "Legitimate websites almost always use domain names, not raw IP addresses."
  });

  // 9. Excessive URL length
  factors.push({
    id: "long_url",
    label: "Unusually long URL",
    weight: 15,
    triggered: url.length > 150,
    detail: "Very long URLs can be designed to hide the real destination."
  });

  // 10. Lots of special chars/numbers in domain
  const specialCharRatio = (hostname.match(/[-_0-9]/g) ?? []).length / hostname.length;
  factors.push({
    id: "special_chars_domain",
    label: "Domain contains many numbers or special characters",
    weight: 20,
    triggered: specialCharRatio > 0.35,
    detail: "Randomly-looking domains with lots of numbers are a hallmark of auto-generated phishing domains."
  });

  return factors;
}

// ─── Scoring ──────────────────────────────────────────────────────────────────

function computeScore(factors: RiskFactor[]): number {
  let score = 0;
  for (const f of factors) {
    if (f.triggered) score += f.weight;
  }
  return Math.min(score, 100);
}

function scoreToLevel(score: number): RiskLevel {
  if (score >= 60) return "dangerous";
  if (score >= 25) return "suspicious";
  return "safe";
}

// ─── Explanation generation ───────────────────────────────────────────────────

const TIPS: Record<RiskLevel, string[]> = {
  safe: [
    "Always double-check the URL before entering passwords.",
    "Look for the padlock icon in the address bar — it means the connection is encrypted.",
    "Be cautious even on 'safe' sites: only download files you were expecting."
  ],
  suspicious: [
    "Do NOT enter any passwords or personal info on this page until you verify it's legitimate.",
    "Check the domain carefully — attackers often use slight misspellings like 'paypa1.com'.",
    "When in doubt, navigate directly to the official site by typing the known address yourself."
  ],
  dangerous: [
    "Close this tab immediately — this page shows multiple signs of being a phishing attack.",
    "If you entered any information, change your passwords for those accounts right away.",
    "Report this site using your browser's 'Report phishing' option to protect others."
  ]
};

function buildExplanation(level: RiskLevel, factors: RiskFactor[], hostname: string): string {
  const triggered = factors.filter(f => f.triggered);
  if (triggered.length === 0) {
    return `This site (${hostname}) passes basic safety checks. Always stay alert.`;
  }
  const topFactors = triggered
    .sort((a, b) => b.weight - a.weight)
    .slice(0, 2)
    .map(f => f.label.toLowerCase());

  if (level === "dangerous") {
    return `⚠️ This page is likely dangerous. It triggered ${triggered.length} risk indicators including: ${topFactors.join(" and ")}. Do not enter any personal information.`;
  }
  if (level === "suspicious") {
    return `🟡 This page looks suspicious. It shows signs of ${topFactors.join(" and ")}. Proceed with caution.`;
  }
  return `✅ This page looks safe, though it triggered a minor flag: ${topFactors[0]}.`;
}

// ─── Main export ──────────────────────────────────────────────────────────────

export function scanPage(
  url: string,
  pageText: string = "",
  pageTitle: string = ""
): ScanResult {
  const parsed = parseUrl(url);
  const hostname = parsed?.hostname ?? url;
  const factors = extractFeatures(url, pageText, pageTitle);
  const score = computeScore(factors);
  const riskLevel = scoreToLevel(score);

  return {
    url,
    riskLevel,
    score,
    explanation: buildExplanation(riskLevel, factors, hostname),
    factors,
    tips: TIPS[riskLevel],
    timestamp: Date.now()
  };
}
