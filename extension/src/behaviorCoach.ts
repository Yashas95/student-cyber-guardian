/**
 * behaviorCoach.ts
 * ─────────────────────────────────────────────────────────────
 * User behaviour coaching layer:
 *  • Password strength analysis (client-side only)
 *  • HaveIBeenPwned k-anonymity breach check
 *    (only first 5 chars of SHA-1 hash sent — password never leaves device)
 *  • Password reuse warning (tracks hashes of previously seen passwords)
 *  • Autofill on suspicious domain warning
 *  • HTTP form submission interception
 * ─────────────────────────────────────────────────────────────
 */

export interface PasswordAnalysis {
  strength: "very_weak" | "weak" | "fair" | "strong" | "very_strong";
  score: number;          // 0–100
  breached: boolean;
  breachCount: number;    // times seen in known data breaches
  reused: boolean;        // seen on another domain in this session
  suggestions: string[];
}

// ─── Password strength scoring ────────────────────────────────────────────────

export function analysePasswordStrength(password: string): Omit<PasswordAnalysis, "breached" | "breachCount" | "reused"> {
  let score = 0;
  const suggestions: string[] = [];

  if (password.length >= 8)  score += 10;
  if (password.length >= 12) score += 15;
  if (password.length >= 16) score += 10;
  if (password.length < 8) suggestions.push("Use at least 8 characters (12+ is better).");

  if (/[a-z]/.test(password)) score += 10;
  if (/[A-Z]/.test(password)) score += 10;
  else suggestions.push("Add uppercase letters.");

  if (/[0-9]/.test(password)) score += 15;
  else suggestions.push("Add numbers.");

  if (/[^a-zA-Z0-9]/.test(password)) score += 20;
  else suggestions.push("Add symbols like !@#$ to make it much stronger.");

  // Penalise common patterns
  if (/^[a-zA-Z]+\d{1,4}$/.test(password)) { score -= 15; suggestions.push("Don't just add numbers at the end."); }
  if (/(.)\1{2,}/.test(password))            { score -= 10; suggestions.push("Avoid repeating characters."); }
  if (/^(password|qwerty|abc|letmein|admin|welcome)/i.test(password)) {
    score = Math.min(score, 10);
    suggestions.push("This is one of the most commonly guessed passwords — change it immediately.");
  }

  score = Math.max(0, Math.min(100, score));

  const strength =
    score < 20 ? "very_weak" :
    score < 40 ? "weak" :
    score < 60 ? "fair" :
    score < 80 ? "strong" : "very_strong";

  if (suggestions.length === 0) suggestions.push("Good password! Consider using a password manager to remember it.");

  return { score, strength, suggestions };
}

// ─── HaveIBeenPwned k-anonymity API ──────────────────────────────────────────
// Privacy: only the first 5 hex characters of the SHA-1 hash are sent.
// The full hash NEVER leaves the device.

async function sha1(text: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest("SHA-1", data);
  return [...new Uint8Array(hashBuffer)].map(b => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

export async function checkBreached(password: string): Promise<{ breached: boolean; count: number }> {
  try {
    const hash = await sha1(password);
    const prefix = hash.slice(0, 5);   // only 5 chars sent to HIBP
    const suffix = hash.slice(5);

    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { "Add-Padding": "true" }  // prevents traffic analysis
    });

    if (!res.ok) return { breached: false, count: 0 };

    const text = await res.text();
    const lines = text.split("\n");

    for (const line of lines) {
      const [lineSuffix, countStr] = line.trim().split(":");
      if (lineSuffix === suffix) {
        return { breached: true, count: parseInt(countStr, 10) };
      }
    }
  } catch { /* offline or API error */ }

  return { breached: false, count: 0 };
}

// ─── Password reuse tracking ──────────────────────────────────────────────────
// Stores SHA-256 hashes of passwords seen on other domains (NOT the passwords themselves)

const seenPasswordHashes = new Map<string, string>(); // hash → domain

async function sha256(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const buf  = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}

export async function checkPasswordReuse(
  password: string,
  currentDomain: string
): Promise<{ reused: boolean; previousDomain?: string }> {
  const hash = await sha256(password);
  const prev = seenPasswordHashes.get(hash);
  if (prev && prev !== currentDomain) {
    return { reused: true, previousDomain: prev };
  }
  seenPasswordHashes.set(hash, currentDomain);
  return { reused: false };
}

// ─── Full password analysis ───────────────────────────────────────────────────

export async function fullPasswordAnalysis(
  password: string,
  domain: string
): Promise<PasswordAnalysis> {
  const strength = analysePasswordStrength(password);
  const [breach, reuse] = await Promise.all([
    checkBreached(password),
    checkPasswordReuse(password, domain)
  ]);

  const suggestions = [...strength.suggestions];

  if (breach.breached) {
    suggestions.unshift(
      `🚨 This password has appeared in ${breach.count.toLocaleString()} data breaches. Change it immediately!`
    );
  }
  if (reuse.reused) {
    suggestions.unshift(
      `♻️ You used this same password on ${reuse.previousDomain}. Using unique passwords for every site protects you if one gets hacked.`
    );
  }

  return {
    ...strength,
    breached: breach.breached,
    breachCount: breach.count,
    reused: reuse.reused,
    suggestions
  };
}

// ─── Autofill safety check ────────────────────────────────────────────────────

export interface AutofillRisk {
  safe: boolean;
  reason?: string;
}

export function checkAutofillSafety(
  fieldDomain: string,
  storedCredentialDomain: string
): AutofillRisk {
  if (fieldDomain === storedCredentialDomain) {
    return { safe: true };
  }

  // Allow www prefix mismatch
  const strip = (d: string) => d.replace(/^www\./, "");
  if (strip(fieldDomain) === strip(storedCredentialDomain)) {
    return { safe: true };
  }

  return {
    safe: false,
    reason: `Your saved password is for "${storedCredentialDomain}" but this page is "${fieldDomain}". Autofill blocked to prevent credential theft.`
  };
}

// ─── Coaching messages by context ────────────────────────────────────────────

export const COACHING_TIPS = {
  passwordManager: "Use a password manager (Bitwarden is free & open-source) to generate and store unique passwords for every site.",
  twoFactor: "Enable two-factor authentication (2FA) on this account — even a stolen password won't let attackers in.",
  httpForm: "⚠️ You're about to submit a password over an unencrypted HTTP connection. Anyone on your network could intercept it.",
  publicWifi: "You appear to be on public Wi-Fi. Avoid logging into sensitive accounts without a VPN.",
  oldPassword: "Consider changing this password regularly, especially for financial or email accounts.",
};
