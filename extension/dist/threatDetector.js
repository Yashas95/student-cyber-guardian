/**
 * threatDetector.ts
 * ─────────────────────────────────────────────────────────────
 * Enhanced threat detection engine — extends riskScorer.ts with:
 *  • Malware / drive-by download detection
 *  • Cryptojacking detection (hidden miners)
 *  • Fake login form fingerprinting
 *  • Data exfiltration pattern detection
 *  • IDN homograph attack detection (ɑmаzon.com using Cyrillic chars)
 *  • Redirect chain abuse
 *  • Content Security Policy absence
 *  • Mixed content detection
 * ─────────────────────────────────────────────────────────────
 */
// ─── Cryptomining script patterns ─────────────────────────────────────────────
const CRYPTO_SCRIPT_PATTERNS = [
    /coinhive/i, /cryptonight/i, /minero/i, /webmr\.js/i,
    /coin-hive/i, /jsecoin/i, /coinblind/i, /deepminer/i,
    /cryptoloot/i, /monerominer/i, /authedmine/i,
    /\.mine\(/, /startMining\(/, /CoinHive\.Anonymous/
];
// ─── Malware / drive-by download indicators ───────────────────────────────────
const MALWARE_EXTENSIONS = new Set([
    "exe", "msi", "bat", "cmd", "ps1", "vbs", "js", "jar",
    "scr", "pif", "com", "reg", "hta", "wsf", "wsh"
]);
const MALWARE_PATH_PATTERNS = [
    /\/download\/.*\.(exe|msi|bat|cmd|ps1)/i,
    /auto[-_]?download/i,
    /forced[-_]?download/i,
    /update[-_]?required/i,
    /install[-_]?now/i,
    /your[-_]?browser[-_]?is[-_]?out/i,
    /flash[-_]?player[-_]?update/i,
    /java[-_]?update/i,
];
// ─── Fake login fingerprints ───────────────────────────────────────────────────
const FAKE_LOGIN_PATTERNS = [
    /signin.*\.php/i, /login.*\.php/i, /account.*verify.*\.php/i,
    /wp-login.*\.php/i, /portal.*login/i,
];
// ─── Data exfiltration patterns (look for suspicious form targets) ────────────
const EXFIL_PATTERNS = [
    /action=['"](https?:\/\/(?!(?:www\.)?(?:google|microsoft|apple|amazon)\.com))[^'"]+['"]/i,
    /formsubmit\.co/i,
    /getform\.io/i,
    /formspree\.io.*phish/i,
];
// ─── IDN homograph detection ───────────────────────────────────────────────────
// Detects Punycode (xn--) or mixed-script domains that impersonate brands
const PUNYCODE_RE = /xn--/i;
function hasHomographIndicators(hostname) {
    if (PUNYCODE_RE.test(hostname))
        return true;
    // Detect lookalike characters: Cyrillic а (U+0430) vs Latin a, etc.
    const suspiciousCodePoints = [...hostname].filter(ch => {
        const cp = ch.codePointAt(0) ?? 0;
        return (cp > 127 && cp < 65536); // non-ASCII in domain
    });
    return suspiciousCodePoints.length > 0;
}
// ─── Redirect chain abuse ─────────────────────────────────────────────────────
function isRedirectAbuse(redirectCount) {
    return redirectCount > 2;
}
// ─── Main threat analysis ─────────────────────────────────────────────────────
export function analyzeThreats(url, ctx, redirectCount = 0) {
    const parsed = safeParseUrl(url);
    const hostname = parsed?.hostname ?? "";
    const path = parsed?.pathname ?? "";
    const pageText = ctx.pageText ?? "";
    const scriptSrcs = ctx.scriptSrcs ?? [];
    const signals = [];
    // ── Cryptojacking ────────────────────────────────────────────────────────────
    const cryptoInScripts = scriptSrcs.some(src => CRYPTO_SCRIPT_PATTERNS.some(p => p.test(src)));
    const cryptoInText = CRYPTO_SCRIPT_PATTERNS.some(p => p.test(pageText));
    signals.push({
        id: "cryptojacking_script",
        category: "cryptojacking",
        severity: "critical",
        label: "Hidden crypto miner",
        triggered: cryptoInScripts || cryptoInText,
        detail: "This page is running a script that uses your CPU to mine cryptocurrency without your knowledge.",
        friendlyExplanation: "This page was secretly using your laptop's power to make money for someone else — kind of like a parasite. I stepped in and blocked it."
    });
    // ── Malware: drive-by download lure ──────────────────────────────────────────
    const malwarePath = MALWARE_PATH_PATTERNS.some(p => p.test(path + pageText));
    const executableInUrl = MALWARE_EXTENSIONS.has((path.split(".").pop() ?? "").toLowerCase());
    signals.push({
        id: "malware_download_lure",
        category: "malware",
        severity: "critical",
        label: "Fake 'update' download trick",
        triggered: malwarePath || executableInUrl,
        detail: executableInUrl
            ? `The URL points directly to an executable file (.${path.split(".").pop()}). Legitimate sites don't force-download programs.`
            : "The page is trying to trick you into downloading software under a fake pretext.",
        friendlyExplanation: "Scammers pretend to be a software update, then sneak a virus onto your device. Real updates come from the official app — not a random website. I blocked the attempt."
    });
    // ── Fake login form ───────────────────────────────────────────────────────────
    const fakeLoginPath = FAKE_LOGIN_PATTERNS.some(p => p.test(path));
    const passwordOnSuspiciousDomain = (ctx.hasPasswordField ?? false) && isSuspiciousDomain(hostname);
    signals.push({
        id: "fake_login_form",
        category: "fake_login",
        severity: "high",
        label: "Fake login form",
        triggered: fakeLoginPath || passwordOnSuspiciousDomain,
        detail: "This page has a password field but the domain doesn't look like a legitimate login page.",
        friendlyExplanation: "This page looks like a login screen, but the web address is fake. If you typed your password here, scammers would get it. Think of it as a fake door on a fake building."
    });
    // ── Data exfiltration: form posts to external collector ───────────────────────
    const exfilTargets = ctx.externalFormTargets ?? [];
    signals.push({
        id: "data_exfiltration",
        category: "data_exfiltration",
        severity: "high",
        label: "Form secretly sends data elsewhere",
        triggered: exfilTargets.length > 0 || EXFIL_PATTERNS.some(p => p.test(pageText)),
        detail: exfilTargets.length > 0
            ? `This page's form submits to: ${exfilTargets[0]} — not to the site you can see.`
            : "The form on this page sends your data to a third-party collector.",
        friendlyExplanation: "Imagine dropping a letter in a mailbox that secretly reroutes your mail to a stranger. That's what this form was doing with your info. I flagged it before you could submit."
    });
    // ── IDN Homograph attack ──────────────────────────────────────────────────────
    signals.push({
        id: "homograph_attack",
        category: "homograph",
        severity: "critical",
        label: "Copycat website address",
        triggered: hasHomographIndicators(hostname),
        detail: `The domain "${hostname}" may use characters that look identical to a real brand's domain but aren't — a sophisticated phishing technique.`,
        friendlyExplanation: "The web address uses fake look-alike letters (e.g. a Cyrillic 'а' instead of a Latin 'a'). It's designed to fool your eyes into thinking you're at a real site. Very sneaky — but I caught it."
    });
    // ── Hidden iframes ────────────────────────────────────────────────────────────
    const hiddenIframes = ctx.hasHiddenIframes ?? 0;
    signals.push({
        id: "hidden_iframes",
        category: "malware",
        severity: "high",
        label: "Hidden invisible frames",
        triggered: hiddenIframes > 0,
        detail: `${hiddenIframes} hidden iframe(s) found. These can silently load malicious content or perform clickjacking.`,
        friendlyExplanation: "Hidden frames are invisible windows-within-windows on the page. They're sometimes used to trick you into 'clicking' on something you can't see — like an invisible 'buy' button under your cursor."
    });
    // ── Mixed content (HTTPS page loading HTTP resources) ─────────────────────────
    signals.push({
        id: "mixed_content",
        category: "phishing",
        severity: "medium",
        label: "Some parts of the page aren't encrypted",
        triggered: ctx.hasMixedContent ?? false,
        detail: "This HTTPS page loads some resources over HTTP, which can be intercepted or replaced by an attacker.",
        friendlyExplanation: "The page itself is secure (like a locked room), but it's bringing in things from outside that aren't locked. That gap could let someone sneak in modified content."
    });
    // ── No Content Security Policy ────────────────────────────────────────────────
    signals.push({
        id: "no_csp",
        category: "phishing",
        severity: "low",
        label: "Site has weaker security settings",
        triggered: !(ctx.hasCSP ?? true),
        detail: "This site hasn't set a CSP header, making it easier for injected scripts to run.",
        friendlyExplanation: "This site is missing a special security setting that tells browsers which scripts are allowed to run. It's a minor gap, but worth knowing about."
    });
    // ── Excessive inline scripts (XSS risk indicator) ─────────────────────────────
    const inlineScripts = ctx.inlineScripts ?? 0;
    signals.push({
        id: "excessive_inline_scripts",
        category: "malware",
        severity: "medium",
        label: "Suspiciously many embedded scripts",
        triggered: inlineScripts > 10,
        detail: `${inlineScripts} inline <script> blocks found. Legitimate sites rarely need this many.`,
        friendlyExplanation: `This page has ${inlineScripts} embedded programs running inside it. Legitimate websites rarely need that many — it can be a sign someone stuffed extra code in there.`
    });
    // ── Redirect chain abuse ──────────────────────────────────────────────────────
    signals.push({
        id: "redirect_chain",
        category: "phishing",
        severity: "medium",
        label: "Took a suspicious detour to get here",
        triggered: isRedirectAbuse(redirectCount),
        detail: `This page was reached through ${redirectCount} redirects. Attackers chain redirects to bypass URL filters.`,
        friendlyExplanation: `You were bounced through ${redirectCount} different addresses before landing here. Scammers do this to hide where they're really sending you — like making a package go through 4 warehouses before delivery.`
    });
    // ─── Score + classify ─────────────────────────────────────────────────────────
    const SEVERITY_WEIGHTS = { low: 10, medium: 25, high: 45, critical: 70 };
    const score = Math.min(signals.filter(s => s.triggered).reduce((sum, s) => sum + SEVERITY_WEIGHTS[s.severity], 0), 100);
    const triggered = signals.filter(s => s.triggered);
    const primaryThreat = getPrimaryThreat(triggered);
    const overallSeverity = getOverallSeverity(score);
    return {
        url,
        primaryThreat,
        overallSeverity,
        score,
        signals,
        headline: buildHeadline(primaryThreat, overallSeverity, triggered.length),
        friendlyHeadline: buildFriendlyHeadline(primaryThreat, overallSeverity, triggered.length),
        advice: getAdvice(primaryThreat, overallSeverity),
        timestamp: Date.now()
    };
}
// ─── Helpers ──────────────────────────────────────────────────────────────────
function safeParseUrl(url) {
    try {
        return new URL(url.startsWith("http") ? url : `https://${url}`);
    }
    catch {
        return null;
    }
}
const SUSPICIOUS_TLDS = new Set(["tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "win", "bid"]);
function isSuspiciousDomain(hostname) {
    const tld = hostname.split(".").pop() ?? "";
    return SUSPICIOUS_TLDS.has(tld) || hostname.split(".").length > 4;
}
function getPrimaryThreat(triggered) {
    if (triggered.length === 0)
        return "clean";
    const priority = [
        "cryptojacking", "malware", "homograph", "fake_login",
        "data_exfiltration", "phishing", "scam"
    ];
    for (const cat of priority) {
        if (triggered.some(s => s.category === cat))
            return cat;
    }
    return triggered[0].category;
}
function getOverallSeverity(score) {
    if (score === 0)
        return "clean";
    if (score < 20)
        return "low";
    if (score < 45)
        return "medium";
    if (score < 70)
        return "high";
    return "critical";
}
const HEADLINES = {
    cryptojacking: "🪙 This page is mining cryptocurrency using your computer without permission.",
    malware: "☣️  This page is trying to install malicious software on your device.",
    fake_login: "🎣 This page has a fake login form designed to steal your password.",
    data_exfiltration: "📤 This page's form sends your data to a third-party collector.",
    homograph: "🔤 This domain uses lookalike characters to impersonate a real site.",
    phishing: "⚠️  This page shows multiple signs of being a phishing attack.",
    scam: "💸 This page shows signs of being a scam.",
    clean: "✅ No threats detected on this page."
};
// Friend-voice headlines — warm, first-person, non-alarmist
const FRIENDLY_HEADLINES = {
    cryptojacking: "Heads up — I blocked something sneaky on this page. 🪙",
    malware: "I stopped a fake download trick on this page. 🛡️",
    fake_login: "This looks like a fake login page — I've got your back. 🎣",
    data_exfiltration: "I noticed this form was trying to send your data somewhere shady. 📤",
    homograph: "The web address here is a sneaky copycat of a real site. 🔤",
    phishing: "Something felt off about this page, so I took a closer look. 🔍",
    scam: "This page has some classic scam red-flags. 💸",
    clean: "All clear! This site looks good to me. ✅"
};
function buildHeadline(cat, severity, count) {
    const base = HEADLINES[cat];
    if (severity === "clean")
        return base;
    return `${base} (${count} threat signal${count !== 1 ? "s" : ""} detected)`;
}
function buildFriendlyHeadline(cat, severity, _count) {
    return FRIENDLY_HEADLINES[cat] ?? FRIENDLY_HEADLINES.clean;
}
const ADVICE = {
    cryptojacking: [
        "Safe move: just close this tab. Your computer will thank you for it.",
        "You can double-check by opening Task Manager — your CPU usage should drop right after closing.",
        "A browser extension like uBlock Origin can help stop these scripts in the future."
    ],
    malware: [
        "Real browser updates happen automatically or through your browser's settings menu — never via a pop-up on a random site.",
        "If you already downloaded a file from here, just delete it without opening it and you'll be fine.",
        "When in doubt, go directly to the official site (e.g. google.com/chrome) to check for updates."
    ],
    fake_login: [
        "The real login page for any service will always be at its official domain (e.g. accounts.google.com). Check the address bar!",
        "If you already entered your password here, head to the real site now and change it — better safe than sorry.",
        "Bookmarking your frequently used login pages is a great habit to avoid fakes."
    ],
    data_exfiltration: [
        "Take a peek at the address bar — does the URL match the service you meant to use?",
        "If you need to contact this company, find their real website by searching for them directly.",
        "Trusted sites always handle your data themselves. They don't send it through random third parties."
    ],
    homograph: [
        "The safest move is to close this tab. Try reaching the real site by typing the address yourself.",
        "Saving important sites as bookmarks is the best defence against this kind of trick — your bookmark always points to the real address.",
        "Real companies stick to plain, simple domain names. Non-standard characters in a web address are a big red flag."
    ],
    phishing: [
        "Something felt off about this page. It's safest to close it and revisit the real site directly.",
        "You can report phishing pages right from your browser: look for 'Help' or 'Report' in the menu.",
        "Remember: real organisations won't ask you to verify personal info via a random link."
    ],
    scam: [
        "If an offer seems too good to be true, it usually is. Legitimate prizes don't require your info on a random page.",
        "Close this tab — your details are far too valuable to give away here.",
        "Feel free to report it via your browser's safety menu to help others stay safe too."
    ],
    clean: [
        "You're good! Just a friendly reminder: always glance at the address bar before typing a password.",
        "The little padlock icon on the left of the address bar means your connection is private and encrypted.",
        "Even on safe sites, only download files you were specifically expecting to receive."
    ]
};
function getAdvice(cat, severity) {
    return severity === "clean" ? ADVICE.clean : ADVICE[cat];
}
