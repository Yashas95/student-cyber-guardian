/**
 * permissionCoach.ts
 * Classifies browser/app permission requests and explains them in plain English.
 */

export type PermissionRisk = "low" | "medium" | "high";

export interface PermissionAnalysis {
  permission: string;
  riskLevel: PermissionRisk;
  explanation: string;
  isReasonable: boolean;
  siteType: string;
  tip: string;
}

type SiteCategory =
  | "video-call"
  | "social"
  | "news"
  | "shopping"
  | "banking"
  | "gaming"
  | "unknown";

const SITE_KEYWORDS: Record<SiteCategory, string[]> = {
  "video-call": ["zoom", "meet", "teams", "webex", "skype", "whereby"],
  social: ["facebook", "instagram", "twitter", "tiktok", "snapchat", "discord"],
  news: ["cnn", "bbc", "nytimes", "reuters", "theguardian", "huffpost"],
  shopping: ["amazon", "ebay", "etsy", "shopify", "walmart", "target"],
  banking: ["bank", "chase", "wellsfargo", "citibank", "paypal", "venmo"],
  gaming: ["steam", "epicgames", "roblox", "twitch", "itch.io"],
  unknown: []
};

export function classifySite(hostname: string): SiteCategory {
  const h = hostname.toLowerCase();
  for (const [cat, keywords] of Object.entries(SITE_KEYWORDS)) {
    if (keywords.some(kw => h.includes(kw))) return cat as SiteCategory;
  }
  return "unknown";
}

interface PermissionRule {
  riskLevel: PermissionRisk;
  explanation: string;
  reasonableFor: SiteCategory[];
  tip: string;
}

const PERMISSION_RULES: Record<string, PermissionRule> = {
  camera: {
    riskLevel: "high",
    explanation: "This site wants to access your webcam. It could see everything in front of your camera.",
    reasonableFor: ["video-call", "social"],
    tip: "Only allow camera access for video calls or profile photo uploads. Deny it on news, shopping, or unfamiliar sites."
  },
  microphone: {
    riskLevel: "high",
    explanation: "This site wants to listen through your microphone. It could record your voice.",
    reasonableFor: ["video-call", "social"],
    tip: "Only allow mic access for voice/video calls. If a random website asks for your mic, that's a red flag."
  },
  geolocation: {
    riskLevel: "medium",
    explanation: "This site wants to know your physical location (from GPS or Wi-Fi).",
    reasonableFor: ["shopping", "news", "unknown"],
    tip: "Location can be useful for local results, but be careful — sharing it with unknown sites can reveal where you live or study."
  },
  notifications: {
    riskLevel: "low",
    explanation: "This site wants to send you pop-up notifications, even when the tab is closed.",
    reasonableFor: ["social", "news", "gaming"],
    tip: "Only allow notifications for sites you use daily. Malicious sites use notifications to spam ads or fake alerts."
  },
  clipboard: {
    riskLevel: "medium",
    explanation: "This site wants to read what you've recently copied (your clipboard). This could include passwords or personal info.",
    reasonableFor: [],
    tip: "Very few legitimate sites need clipboard access. If you didn't paste anything, deny this request."
  },
  storage: {
    riskLevel: "low",
    explanation: "This site wants to save data in your browser (cookies, local storage). Most sites do this for login sessions.",
    reasonableFor: ["social", "shopping", "banking", "gaming", "news", "video-call", "unknown"],
    tip: "This is normal for websites — it helps them remember your login and preferences. But clear cookies for sites you don't trust."
  },
  usb: {
    riskLevel: "high",
    explanation: "This site wants to connect to USB devices plugged into your computer.",
    reasonableFor: [],
    tip: "Almost no regular website needs USB access. This is a very unusual request — deny it unless you know exactly why it's needed."
  },
  bluetooth: {
    riskLevel: "high",
    explanation: "This site wants to scan for and connect to Bluetooth devices near you.",
    reasonableFor: [],
    tip: "Only allow Bluetooth access for dedicated IoT or device-pairing tools, never for general websites."
  }
};

export function analyzePermission(
  permission: string,
  hostname: string
): PermissionAnalysis {
  const siteType = classifySite(hostname);
  const rule = PERMISSION_RULES[permission.toLowerCase()];

  if (!rule) {
    return {
      permission,
      riskLevel: "medium",
      explanation: `This site is requesting the "${permission}" permission. We don't have details on this specific permission.`,
      isReasonable: false,
      siteType,
      tip: "When in doubt, deny the permission and see if the site still works for your needs."
    };
  }

  const isReasonable = rule.reasonableFor.includes(siteType);

  return {
    permission,
    riskLevel: rule.riskLevel,
    explanation: rule.explanation,
    isReasonable,
    siteType,
    tip: rule.tip
  };
}
