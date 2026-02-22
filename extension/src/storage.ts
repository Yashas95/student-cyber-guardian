/**
 * storage.ts
 * Privacy-first local storage + opt-in anonymised telemetry.
 *
 * DATA PRINCIPLES:
 *  - Raw URLs are NEVER sent to any server.
 *  - Only aggregated risk-level counts are sent (if user opts in).
 *  - All scan history is stored locally in chrome.storage.local.
 *  - User can wipe all data at any time.
 */

export interface LocalScanRecord {
  id: string;             // random UUID
  riskLevel: string;      // "safe" | "suspicious" | "dangerous"
  domain: string;         // just the hostname, not the full URL
  timestamp: number;
  factorIds: string[];    // which factors triggered (no URL, no page text)
}

export interface TelemetryPayload {
  sessionId: string;      // random, rotates every 24h — not linked to user identity
  periodStart: number;
  periodEnd: number;
  counts: {
    safe: number;
    suspicious: number;
    dangerous: number;
  };
  topFactors: string[];   // most common triggered factor IDs only
}

export interface AppSettings {
  telemetryEnabled: boolean;
  scanOnNavigate: boolean;
  showBadge: boolean;
}

// ─── Settings ──────────────────────────────────────────────────────────────────

const DEFAULT_SETTINGS: AppSettings = {
  telemetryEnabled: false,  // OFF by default — user must actively opt in
  scanOnNavigate: true,
  showBadge: true
};

export async function getSettings(): Promise<AppSettings> {
  return new Promise(resolve => {
    chrome.storage.local.get("settings", result => {
      resolve({ ...DEFAULT_SETTINGS, ...(result.settings ?? {}) });
    });
  });
}

export async function saveSettings(partial: Partial<AppSettings>): Promise<void> {
  const current = await getSettings();
  return new Promise(resolve => {
    chrome.storage.local.set({ settings: { ...current, ...partial } }, resolve);
  });
}

// ─── Scan history ─────────────────────────────────────────────────────────────

export async function saveScanRecord(record: LocalScanRecord): Promise<void> {
  return new Promise(resolve => {
    chrome.storage.local.get("scanHistory", result => {
      const history: LocalScanRecord[] = result.scanHistory ?? [];
      // Keep last 500 records max
      history.push(record);
      const trimmed = history.slice(-500);
      chrome.storage.local.set({ scanHistory: trimmed }, resolve);
    });
  });
}

export async function getScanHistory(): Promise<LocalScanRecord[]> {
  return new Promise(resolve => {
    chrome.storage.local.get("scanHistory", result => {
      resolve(result.scanHistory ?? []);
    });
  });
}

export async function clearAllData(): Promise<void> {
  return new Promise(resolve => {
    chrome.storage.local.clear(resolve);
  });
}

// ─── Session ID (rotates every 24 hours, not tied to identity) ────────────────

async function getSessionId(): Promise<string> {
  return new Promise(resolve => {
    chrome.storage.local.get("sessionMeta", result => {
      const meta = result.sessionMeta;
      const now = Date.now();
      if (meta && now - meta.createdAt < 86_400_000) {
        resolve(meta.id);
      } else {
        const newId = crypto.randomUUID();
        chrome.storage.local.set({ sessionMeta: { id: newId, createdAt: now } }, () => {
          resolve(newId);
        });
      }
    });
  });
}

// ─── Telemetry (opt-in only) ──────────────────────────────────────────────────

const TELEMETRY_ENDPOINT = "https://your-backend.fly.dev/telemetry"; // replace before deploy

export async function maybeFlushTelemetry(): Promise<void> {
  const settings = await getSettings();
  if (!settings.telemetryEnabled) return;

  const history = await getScanHistory();
  if (history.length === 0) return;

  const counts = { safe: 0, suspicious: 0, dangerous: 0 };
  const factorCounts: Record<string, number> = {};

  for (const record of history) {
    counts[record.riskLevel as keyof typeof counts]++;
    for (const fid of record.factorIds) {
      factorCounts[fid] = (factorCounts[fid] ?? 0) + 1;
    }
  }

  const topFactors = Object.entries(factorCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([id]) => id);

  const payload: TelemetryPayload = {
    sessionId: await getSessionId(),
    periodStart: history[0].timestamp,
    periodEnd: history[history.length - 1].timestamp,
    counts,
    topFactors
    // NOTICE: no URLs, no domains, no page text, no personal data
  };

  try {
    await fetch(TELEMETRY_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    // Clear history after successful flush so we don't resend
    await chrome.storage.local.remove("scanHistory");
  } catch {
    // Silently fail — telemetry is best-effort
  }
}

// ─── Stats for popup dashboard ────────────────────────────────────────────────

export async function getLocalStats() {
  const history = await getScanHistory();
  return {
    total: history.length,
    safe: history.filter(h => h.riskLevel === "safe").length,
    suspicious: history.filter(h => h.riskLevel === "suspicious").length,
    dangerous: history.filter(h => h.riskLevel === "dangerous").length
  };
}
