/**
 * pageInspector.ts — Student Cyber Guardian Page Inspector Engine
 * Runs in background.ts context (no DOM access — data supplied by content script).
 * Detects: tech stack, trackers, security posture.
 * Generates: grade, friend summary, lesson of the page.
 * 100% client-side. No network calls. No external data.
 */

// ─── Interfaces ──────────────────────────────────────────────────────────────

/** Raw page context collected by content script */
export interface PageContext {
    url: string;
    hostname: string;
    protocol: string;                // "https:" | "http:"
    scriptSrcs: string[];            // All <script src="..."> values
    scriptInlineHints: string[];     // Short snippets from inline scripts (first 200 chars each)
    windowGlobals: string[];         // Detected window.* property names hinting at frameworks
    metaTags: { name: string; content: string }[];
    formActions: string[];           // form.action values
    iframeCount: number;
    hiddenIframeCount: number;
    hasPasswordField: boolean;
    hasCSP: boolean;
    hasMixedContent: boolean;
    cookieCount: number;             // rough cookie count from document.cookie
    thirdPartyDomains: string[];     // unique script domains ≠ page hostname
    pageTitle: string;
}

/** A detected technology */
export interface TechItem {
    id: string;
    name: string;
    emoji: string;
    category: "Frontend" | "Framework" | "CMS" | "Ecommerce" | "CDN" | "Infra" | "Analytics" | "Tracking" | "Payment" | "Support" | "Auth";
    description: string;             // 1-line educational blurb
    longDescription: string;         // expandable educational paragraph
}

/** A detected tracker */
export interface TrackerItem {
    id: string;
    name: string;
    emoji: string;
    domain: string;
    category: "Analytics" | "Advertising" | "SessionReplay" | "Marketing" | "Social";
    risk: "low" | "medium" | "high";
    description: string;
    longDescription: string;
}

/** Security check result */
export interface SecurityCheck {
    id: string;
    label: string;
    passed: boolean;
    emoji: string;
    explanation: string;
}

/** Full inspector report cached per tab */
export interface InspectorReport {
    url: string;
    hostname: string;
    grade: "A" | "B" | "C" | "D" | "F";
    gradeLabel: string;              // e.g. "B+"
    techStack: TechItem[];
    trackers: TrackerItem[];
    securityChecks: SecurityCheck[];
    friendSummary: string;
    lesson: string;
    lessonEmoji: string;
    trackerCount: number;
    timestamp: number;
}

// ─── Tech Library ─────────────────────────────────────────────────────────────

interface TechRule {
    id: string;
    name: string;
    emoji: string;
    category: TechItem["category"];
    description: string;
    longDescription: string;
    // Detection: any of these must match
    globalHints?: string[];          // window.* property names
    scriptPatterns?: RegExp[];       // script src patterns
    metaHints?: { name: string; pattern: RegExp }[];
    inlineHints?: RegExp[];          // inline script content patterns
}

const TECH_RULES: TechRule[] = [
    {
        id: "react",
        name: "React",
        emoji: "⚛️",
        category: "Frontend",
        description: "Made by Meta. Powers Instagram, Netflix, Airbnb.",
        longDescription: "React was invented by a Facebook engineer in 2011 to make Facebook's newsfeed update in real time without reloading the page. Now it powers thousands of apps you use every day — Instagram, Netflix, Airbnb, and more.",
        globalHints: ["__REACT_DEVTOOLS_GLOBAL_HOOK__", "React"],
        scriptPatterns: [/react(\.min)?\.js/, /react-dom/],
        inlineHints: [/ReactDOM\.render/, /__REACT_FIBER__/],
    },
    {
        id: "nextjs",
        name: "Next.js",
        emoji: "▲",
        category: "Framework",
        description: "Built on React. Makes pages load faster by pre-rendering on the server.",
        longDescription: "Next.js is built on top of React. It prepares pages on the server before sending them to your browser, making sites load faster. Used by TikTok, Notion, and many big company websites.",
        globalHints: ["__NEXT_DATA__", "__next"],
        scriptPatterns: [/_next\/static/, /next\/dist/],
    },
    {
        id: "vue",
        name: "Vue.js",
        emoji: "💚",
        category: "Frontend",
        description: "A popular alternative to React. Powers Alibaba and many apps.",
        longDescription: "Vue.js was created by a Google engineer in 2014 as a simpler, lighter alternative to React. It's especially popular in Asia and in startups. Used by Alibaba, Xiaomi, and Nintendo.",
        globalHints: ["Vue", "__VUE__", "__vue_app__"],
        scriptPatterns: [/vue(\.min)?\.js/, /vue@\d/, /\/vue\//],
    },
    {
        id: "angular",
        name: "Angular",
        emoji: "🔴",
        category: "Framework",
        description: "Made by Google. Enterprise-grade framework for large apps.",
        longDescription: "Angular is Google's main web framework. It's the go-to choice for large enterprise applications because it includes everything you need in one package — routing, forms, HTTP handling. Used by Google, Microsoft, and thousands of companies.",
        globalHints: ["angular", "ng"],
        scriptPatterns: [/angular(\.min)?\.js/, /angular\/core/, /@angular\/core/],
        inlineHints: [/ng-version=/, /ng\.probe/],
    },
    {
        id: "svelte",
        name: "Svelte",
        emoji: "🧡",
        category: "Frontend",
        description: "A fast-rising modern alternative to React. Compiles away at build time.",
        longDescription: "Svelte is exciting because it doesn't send a framework to your browser — it converts your code into plain JavaScript at build time. This makes pages smaller and faster. It's one of the most loved frameworks among developers, growing rapidly since 2019.",
        globalHints: ["__svelte"],
        scriptPatterns: [/svelte/, /_svelte\//],
        inlineHints: [/__svelte_component__/],
    },
    {
        id: "wordpress",
        name: "WordPress",
        emoji: "📝",
        category: "CMS",
        description: "Powers 40% of all websites on the internet.",
        longDescription: "WordPress started as a blogging tool in 2003. Today about 40% of every website on the internet runs on it. It's used by The New York Times, BBC, Sony, and millions of small blogs worldwide. If you ever build a website, you'll probably encounter WordPress.",
        globalHints: ["wp", "wpApiSettings"],
        scriptPatterns: [/wp-content/, /wp-includes/, /wp-json/],
        metaHints: [{ name: "generator", pattern: /WordPress/ }],
        inlineHints: [/wp\.ajax/, /"siteurl":/],
    },
    {
        id: "shopify",
        name: "Shopify",
        emoji: "🛍️",
        category: "Ecommerce",
        description: "The world's largest e-commerce platform for online stores.",
        longDescription: "Shopify powers over a million online stores worldwide, from tiny side-hustles to huge brands like Gymshark, Fashion Nova, and Kylie Cosmetics. It makes it easy for anyone to sell things online without knowing how to code.",
        globalHints: ["Shopify", "ShopifyAnalytics"],
        scriptPatterns: [/cdn\.shopify\.com/, /shopify\.com\/s\/files/],
        metaHints: [{ name: "generator", pattern: /Shopify/ }],
    },
    {
        id: "wix",
        name: "Wix",
        emoji: "🔷",
        category: "CMS",
        description: "Drag-and-drop website builder. Powers millions of small business sites.",
        longDescription: "Wix is a website builder that lets you drag and drop things to build a website without any coding. It powers over 200 million websites. If you see this, the site owner probably built it without a developer.",
        globalHints: ["wixBiSession", "rendererModel"],
        scriptPatterns: [/static\.wixstatic\.com/, /wix\.com/],
        metaHints: [{ name: "generator", pattern: /Wix/ }],
    },
    {
        id: "squarespace",
        name: "Squarespace",
        emoji: "⬛",
        category: "CMS",
        description: "Premium drag-and-drop website builder known for beautiful designs.",
        longDescription: "Squarespace is popular for its sleek, professional-looking templates. Many artists, photographers, and small businesses use it. Less flexible than WordPress but much simpler to use.",
        globalHints: ["Static.SQUARESPACE_CONTEXT"],
        scriptPatterns: [/squarespace\.com/, /sqspcdn\.com/],
        metaHints: [{ name: "generator", pattern: /Squarespace/ }],
    },
    {
        id: "cloudflare",
        name: "Cloudflare",
        emoji: "🟠",
        category: "CDN",
        description: "Acts as a security shield and speed booster for websites.",
        longDescription: "Cloudflare sits between your browser and the website like an invisible shield. It blocks millions of cyberattacks every day, including DDoS attacks that try to flood websites with fake traffic. It also delivers pages faster by storing copies near you. It protects about 20% of the internet.",
        scriptPatterns: [/cloudflare\.com/, /cf-beacon/, /challenges\.cloudflare/],
        inlineHints: [/cf_clearance/, /cloudflare/i],
    },
    {
        id: "vercel",
        name: "Vercel",
        emoji: "▲",
        category: "Infra",
        description: "The platform Next.js is built on. Used by many modern web apps.",
        longDescription: "Vercel is a cloud platform that makes it easy for developers to deploy web applications instantly. It was created by the team behind Next.js. If a site uses Vercel, it's probably a modern, well-engineered app.",
        scriptPatterns: [/vercel\.app/, /vercel\.live/],
        inlineHints: [/__VERCEL_/],
    },
    {
        id: "firebase",
        name: "Firebase",
        emoji: "🔥",
        category: "Infra",
        description: "Google's real-time database and app platform.",
        longDescription: "Firebase is a set of tools made by Google that helps developers build apps faster. It provides a real-time database (data updates instantly without refreshing), authentication, and cloud storage. Used by millions of apps, from small startups to big companies.",
        globalHints: ["firebase", "__FIREBASE_DEFAULTS__"],
        scriptPatterns: [/firebase-app/, /firebaseapp\.com/, /gstatic\.com\/firebasejs/],
    },
    {
        id: "netlify",
        name: "Netlify",
        emoji: "🌿",
        category: "Infra",
        description: "A platform for deploying websites from code repositories.",
        longDescription: "Netlify makes it incredibly easy to publish a website from code. Developers push their code to GitHub, and Netlify automatically builds and publishes it. Used by many developers and open-source projects.",
        scriptPatterns: [/netlify\.com/, /netlify-identity/],
        inlineHints: [/netlifyIdentity/],
    },
    {
        id: "stripe",
        name: "Stripe",
        emoji: "💳",
        category: "Payment",
        description: "One of the most secure and trusted payment processors in the world.",
        longDescription: "Stripe is the payment system trusted by millions of businesses including Amazon, Google, Lyft, and Shopify. If you're paying on a site that uses Stripe, your card details are very well protected — Stripe has some of the best security in the industry.",
        globalHints: ["Stripe"],
        scriptPatterns: [/js\.stripe\.com/, /stripe\.js/],
    },
    {
        id: "paypal",
        name: "PayPal",
        emoji: "🔵",
        category: "Payment",
        description: "The world's most recognisable online payment service.",
        longDescription: "PayPal has been processing online payments since 1998 and now handles over $1 trillion in transactions every year. If this site accepts PayPal, it means they've been vetted by PayPal's merchant programme.",
        scriptPatterns: [/paypal\.com\/sdk/, /paypalobjects\.com/],
        globalHints: ["paypal", "PAYPAL"],
    },
    {
        id: "intercom",
        name: "Intercom",
        emoji: "💬",
        category: "Support",
        description: "That little chat bubble in the corner. Connects you to support.",
        longDescription: "Intercom is the chat widget you see in the corner of many websites. It lets companies talk to users in real time, send automated messages, and track who's visiting. Your browsing and account activity may be recorded to personalise messages.",
        globalHints: ["Intercom"],
        scriptPatterns: [/intercom\.io/, /intercomcdn\.com/],
    },
    {
        id: "zendesk",
        name: "Zendesk",
        emoji: "☀️",
        category: "Support",
        description: "Customer support chat and ticketing platform.",
        longDescription: "Zendesk is used by thousands of companies to manage customer support. If you chat with a website's support team, there's a good chance it's powered by Zendesk. It tracks your support history and may record chat sessions.",
        globalHints: ["zE", "zESettings"],
        scriptPatterns: [/zendesk\.com/, /zdassets\.com/],
    },
    {
        id: "jquery",
        name: "jQuery",
        emoji: "🔰",
        category: "Frontend",
        description: "The original JavaScript library. Still on millions of older sites.",
        longDescription: "jQuery was created in 2006 and was so useful it ended up being used on a huge proportion of websites. Modern frameworks like React have mostly replaced it, but it's still found on many older sites. If a site uses jQuery, it was probably built before 2015 or is using an older CMS.",
        globalHints: ["jQuery", "$"],
        scriptPatterns: [/jquery(\.min)?\.js/, /jquery@\d/],
    },
    {
        id: "youtube",
        name: "YouTube / Polymer",
        emoji: "▶️",
        category: "Frontend",
        description: "Google's own Polymer web components framework. Powers YouTube.",
        longDescription: "YouTube is built on Polymer — Google's custom web components framework — and LitElement. It's one of the most visited sites on Earth, serving over 500 hours of video uploaded every minute. Behind the scenes, YouTube uses a complex system of microservices, its own video codec (AV1), and machine learning to power recommendations.",
        globalHints: ["ytcfg", "ytInitialData", "yt", "ytInitialPlayerResponse", "Polymer"],
        scriptPatterns: [/yt\.www\.watch/, /youtube\.com\/s\/desktop/, /googlevideo\.com/, /youtubei\/v1/, /yt\/polymer/, /youtube\/www/],
        inlineHints: [/ytcfg\.set/, /ytInitialData/, /INNERTUBE_CONTEXT/],
    },
    {
        id: "polymer",
        name: "Polymer / LitElement",
        emoji: "🧩",
        category: "Frontend",
        description: "Google's web components library. Used for custom HTML elements.",
        longDescription: "Polymer and its successor LitElement are Google's libraries for building modular, reusable web components. Web components let developers create custom HTML tags that work like built-in browser elements. This approach makes large apps easier to maintain and faster to load.",
        globalHints: ["Polymer", "customElements"],
        scriptPatterns: [/polymer\/polymer/, /lit-element/, /lit-html/, /lit\.dev/],
        inlineHints: [/customElements\.define/, /LitElement/],
    },
    {
        id: "amp",
        name: "AMP",
        emoji: "⚡",
        category: "Framework",
        description: "Google's framework for ultra-fast mobile web pages.",
        longDescription: "AMP (Accelerated Mobile Pages) is a project by Google to make web pages load near-instantly on mobile. AMP pages are cached by Google's servers and appear at the top of search results with a lightning bolt icon. They sacrifice some flexibility for speed.",
        globalHints: ["AMP", "__AMP_SERVICES", "AMP_CONFIG"],
        scriptPatterns: [/cdn\.ampproject\.org/],
        metaHints: [{ name: "amp", pattern: /./ }],
        inlineHints: [/"@context":"http:\/\/schema\.org\//, /AMP/],
    },
    {
        id: "instagram",
        name: "Instagram / Meta",
        emoji: "📸",
        category: "Frontend",
        description: "Meta's custom React app with their own module system (Relay + Docblock).",
        longDescription: "Instagram's web app is built entirely with React, Meta's own GraphQL client Relay, and an in-house JavaScript module system called Docblock (window.__d / requireLazy). It's one of the most complex React apps in the world, serving over 2 billion users. Meta's engineers wrote many of the open-source tools that power it.",
        globalHints: ["instagramReadyCallbacks", "__instagram", "_sharedData", "IgCoreAnalytics", "requireLazy", "__d"],
        scriptPatterns: [/instagram\.com\/static/, /cdninstagram\.com/, /instagram\.com\/ajax/],
        inlineHints: [/requireLazy\(/, /__d\(\"/, /instagramReadyCallbacks/],
    },
    {
        id: "tiktok",
        name: "TikTok",
        emoji: "🎵",
        category: "Frontend",
        description: "ByteDance's video platform. Uses its own custom web framework.",
        longDescription: "TikTok (owned by ByteDance) built its web app with a custom internal framework. It's notable for its extremely aggressive data collection, including device fingerprinting. Its recommendation algorithm is considered one of the most powerful in the world, trained on billions of interactions.",
        globalHints: ["byted_acrawler", "TIKTOK_WEB_DATA"],
        scriptPatterns: [/tiktok\.com\/tiktok\/webapp/, /sf16-website-login\.neutral\./, /tiktokcdn\.com/],
        inlineHints: [/byted_acrawler/, /TIKTOK/],
    },
    {
        id: "twitter",
        name: "Twitter / X",
        emoji: "🐦",
        category: "Frontend",
        description: "Built with React, GraphQL, and Twitter's own design system.",
        longDescription: "Twitter (now X) rebuilt its web app in 2019 as a Progressive Web App using React and GraphQL. It became a landmark example of a high-performance PWA — installable, fast-loading, and offline-capable. The new architecture made Twitter's website feel like a native app for the first time.",
        globalHints: ["twttr", "__INITIAL_STATE__"],
        scriptPatterns: [/abs\.twimg\.com/, /pbs\.twimg\.com\/profile/, /twitter\.com\/i\/js/],
        inlineHints: [/TWEETDECK/, /twttr\.init/],
    },
    {
        id: "reddit",
        name: "Reddit",
        emoji: "👽",
        category: "Frontend",
        description: "Rebuilt with React and their own design system (Snooify).",
        longDescription: "Reddit rebuilt its entire web app in 2018 using React and a custom design system. The new version is a Progressive Web App. Reddit's backend is a massive Python/Go microservices system, but the frontend you see is a modern React single-page app that loads comments and posts dynamically.",
        globalHints: ["r", "reddit"],
        scriptPatterns: [/redd\.it\//, /redditmedia\.com/, /reddit\.com\/static\/bundles/],
        inlineHints: [/reddit\.models/, /snooify/],
    },
];

// ─── Tracker Library ──────────────────────────────────────────────────────────

interface TrackerRule {
    id: string;
    name: string;
    emoji: string;
    domains: string[];               // domains to match in script srcs
    category: TrackerItem["category"];
    risk: TrackerItem["risk"];
    description: string;
    longDescription: string;
}

const TRACKER_RULES: TrackerRule[] = [
    {
        id: "google-analytics",
        name: "Google Analytics",
        emoji: "📊",
        domains: ["google-analytics.com", "analytics.google.com"],
        category: "Analytics",
        risk: "low",
        description: "Tracks which pages you visit and how long you stay.",
        longDescription: "Google Analytics tells website owners how many people visited their site, which pages they looked at, how long they stayed, and where they came from. This data goes to Google. It's anonymous by default, but Google may combine it with your Google account data.",
    },
    {
        id: "gtm",
        name: "Google Tag Manager",
        emoji: "🏷️",
        domains: ["googletagmanager.com"],
        category: "Analytics",
        risk: "low",
        description: "A tool that manages all other tracking scripts on this page.",
        longDescription: "Google Tag Manager is like a remote control for tracking scripts. Instead of adding tracking code directly, developers add Tag Manager and then configure all other trackers through Google's dashboard. If you see this, there may be other trackers loaded through it that aren't visible in the page source.",
    },
    {
        id: "meta-pixel",
        name: "Meta Pixel",
        emoji: "👤",
        domains: ["facebook.net", "connect.facebook.net"],
        category: "Advertising",
        risk: "medium",
        description: "Tells Facebook you visited this page. Used to target you with ads.",
        longDescription: "The Meta Pixel (formerly Facebook Pixel) is a tiny invisible image that tells Facebook when you've visited a website, what you looked at, and if you bought anything. Facebook uses this to show you targeted ads. Even if you're not logged into Facebook, this tracks your visit.",
    },
    {
        id: "doubleclick",
        name: "DoubleClick",
        emoji: "🎯",
        domains: ["doubleclick.net", "googlesyndication.com"],
        category: "Advertising",
        risk: "high",
        description: "Follows you across thousands of websites to build an ad profile.",
        longDescription: "DoubleClick (now Google Ads) is one of the most pervasive tracking systems on the internet. It follows you across millions of websites to build a detailed profile of your interests, behaviours, and demographics. This profile is used to show you targeted ads wherever you go online.",
    },
    {
        id: "hotjar",
        name: "Hotjar",
        emoji: "🌡️",
        domains: ["hotjar.com", "static.hotjar.com"],
        category: "SessionReplay",
        risk: "medium",
        description: "Records your mouse movements like a video. Website owners watch these.",
        longDescription: "Hotjar records your mouse movements, scrolls, and clicks like a video replay. Website owners watch these recordings to see where people get confused or stuck on their pages. It's anonymised — your personal details are hidden — but your entire browsing session on this site is being recorded.",
    },
    {
        id: "clarity",
        name: "Microsoft Clarity",
        emoji: "🔭",
        domains: ["clarity.ms"],
        category: "SessionReplay",
        risk: "medium",
        description: "Microsoft's session recording tool. Similar to Hotjar.",
        longDescription: "Microsoft Clarity is Microsoft's free version of tools like Hotjar. It records mouse movements, clicks, and scrolls to help website owners understand how people use their site. It shows heatmaps of where people click most. Microsoft uses this anonymised data to improve their own analytics products.",
    },
    {
        id: "mixpanel",
        name: "Mixpanel",
        emoji: "📈",
        domains: ["mixpanel.com", "cdn.mxpnl.com"],
        category: "Analytics",
        risk: "low",
        description: "Tracks detailed user actions like button clicks and feature usage.",
        longDescription: "Mixpanel is different from Google Analytics — instead of just tracking page views, it tracks specific actions like which buttons you clicked, which features you used, and how far you got in a sign-up flow. Used to improve app design and understand user behaviour.",
    },
    {
        id: "segment",
        name: "Segment",
        emoji: "🔗",
        domains: ["segment.com", "cdn.segment.com", "segment.io"],
        category: "Marketing",
        risk: "low",
        description: "A data pipeline that routes your activity to other trackers.",
        longDescription: "Segment is like a central hub for tracking data. Instead of adding 10 different trackers, a company adds Segment once and routes data to tools like Mixpanel, Salesforce, and more. If you see Segment, your data is probably going to multiple places.",
    },
    {
        id: "amplitude",
        name: "Amplitude",
        emoji: "📉",
        domains: ["amplitude.com", "cdn.amplitude.com"],
        category: "Analytics",
        risk: "low",
        description: "Deep analytics on how users interact with products.",
        longDescription: "Amplitude is a product analytics tool used by companies like Dropbox, Twitter, and Coursera. It tracks detailed user journeys — what you did, in what order, and whether you came back. It's focused on understanding product usage rather than advertising.",
    },
    {
        id: "heap",
        name: "Heap",
        emoji: "🗃️",
        domains: ["heap.io", "heapanalytics.com"],
        category: "Analytics",
        risk: "low",
        description: "Automatically records every interaction on the page — clicks, scrolls, inputs.",
        longDescription: "Heap is unusual because it automatically captures every single interaction — every click, form fill, and scroll — without the developer needing to set up anything special. This means a very detailed record of your actions is sent to Heap's servers.",
    },
    {
        id: "intercom-track",
        name: "Intercom",
        emoji: "💬",
        domains: ["intercom.io", "intercomcdn.com", "widget.intercom.io"],
        category: "Marketing",
        risk: "low",
        description: "Chat and messaging platform. May track your activity to personalise messages.",
        longDescription: "When Intercom tracking is loaded, it can track your page visits, actions, and potentially your identity if you're logged in. This helps support teams understand who they're talking to, but it does mean your browsing on this site is being recorded.",
    },
    {
        id: "hubspot",
        name: "HubSpot",
        emoji: "🧲",
        domains: ["hubspot.com", "hs-analytics.net", "hscollectedforms.net"],
        category: "Marketing",
        risk: "low",
        description: "Marketing and lead tracking platform. May track your email and actions.",
        longDescription: "HubSpot is a marketing platform that tracks visitors to see if they turn into customers. If you ever fill in a form on a HubSpot site, your email is connected to all your future visits — the company can see every page you visited before and after.",
    },
    {
        id: "twitter-ads",
        name: "X/Twitter Ads",
        emoji: "🐦",
        domains: ["platform.twitter.com", "static.ads-twitter.com"],
        category: "Advertising",
        risk: "medium",
        description: "Twitter's ad tracking pixel. Tells Twitter you visited this page.",
        longDescription: "Twitter's advertising tracker tells Twitter when you've visited this website, so Twitter can show you ads about it. Even if you don't have a Twitter account, your visits are tracked and connected to your browser fingerprint.",
    },
    {
        id: "linkedin-ads",
        name: "LinkedIn Insight",
        emoji: "💼",
        domains: ["snap.licdn.com", "linkedin.com/px"],
        category: "Advertising",
        risk: "medium",
        description: "LinkedIn's ad tracker. Shows this site to LinkedIn users who visited.",
        longDescription: "LinkedIn's Insight Tag lets companies see which LinkedIn users visited their website. If you're logged into LinkedIn and visit this site, LinkedIn (and the company) know you were here. It's used to retarget you with LinkedIn ads.",
    },
    {
        id: "criteo",
        name: "Criteo",
        emoji: "🛒",
        domains: ["criteo.com", "static.criteo.net"],
        category: "Advertising",
        risk: "high",
        description: "Cross-site ad retargeting. Follows you across the web to show repeated ads.",
        longDescription: "Criteo is a retargeting company — its job is to show you ads for things you looked at on other websites. If you browse a pair of shoes and then see ads for those same shoes everywhere you go, that's often Criteo at work. It tracks you across many different websites.",
    },
    {
        id: "taboola",
        name: "Taboola",
        emoji: "📰",
        domains: ["taboola.com", "trc.taboola.com"],
        category: "Advertising",
        risk: "medium",
        description: "The 'recommended content' ads at the bottom of news articles.",
        longDescription: "Taboola is the company behind most of the 'You Won't Believe What Happened Next!' ads you see at the bottom of news sites. It uses tracking to decide which clickbait to show you based on your browsing history.",
    },
    {
        id: "snapchat",
        name: "Snapchat Pixel",
        emoji: "👻",
        domains: ["sc-static.net", "snapchat.com/privacy"],
        category: "Advertising",
        risk: "medium",
        description: "Snapchat's ad tracker. Links your web visits to your Snap account.",
        longDescription: "Snapchat's Pixel works like Facebook's — it tells Snapchat when you've visited this website, so Snapchat can show you ads from this company. If you use Snapchat, this connects your real identity to your web browsing on this site.",
    },
    {
        id: "tiktok",
        name: "TikTok Pixel",
        emoji: "🎵",
        domains: ["analytics.tiktok.com", "sf16-scmcdn-sg.ibytedtos.com"],
        category: "Advertising",
        risk: "medium",
        description: "TikTok's ad tracker. Used to target you with ads on TikTok.",
        longDescription: "TikTok's advertising pixel tells TikTok when you visit websites that are advertising on the platform. This data is used to show you relevant ads on TikTok. Due to TikTok's ownership structure, this data may be stored on servers in China, which has raised privacy concerns in many countries.",
    },
];

// ─── Detection Functions ──────────────────────────────────────────────────────

function normaliseDomain(src: string): string {
    try {
        return new URL(src.startsWith("//") ? "https:" + src : src).hostname;
    } catch {
        return src;
    }
}

export function detectTechStack(ctx: PageContext): TechItem[] {
    const found: TechItem[] = [];

    for (const rule of TECH_RULES) {
        let matched = false;

        // Check window globals hints
        if (!matched && rule.globalHints) {
            matched = rule.globalHints.some(g => ctx.windowGlobals.includes(g));
        }

        // Check script src patterns
        if (!matched && rule.scriptPatterns) {
            matched = rule.scriptPatterns.some(pattern =>
                ctx.scriptSrcs.some(src => pattern.test(src))
            );
        }

        // Check meta tag hints
        if (!matched && rule.metaHints) {
            matched = rule.metaHints.some(hint =>
                ctx.metaTags.some(m => m.name.toLowerCase() === hint.name && hint.pattern.test(m.content))
            );
        }

        // Check inline script hints
        if (!matched && rule.inlineHints) {
            matched = rule.inlineHints.some(pattern =>
                ctx.scriptInlineHints.some(src => pattern.test(src))
            );
        }

        if (matched) {
            found.push({
                id: rule.id,
                name: rule.name,
                emoji: rule.emoji,
                category: rule.category,
                description: rule.description,
                longDescription: rule.longDescription,
            });
        }
    }

    return found;
}

export function detectTrackers(ctx: PageContext): TrackerItem[] {
    const found: TrackerItem[] = [];
    const scriptDomains = ctx.scriptSrcs.map(normaliseDomain);
    const allDomains = [...scriptDomains, ...ctx.thirdPartyDomains];

    for (const rule of TRACKER_RULES) {
        const matched = rule.domains.some(d =>
            allDomains.some(domain => domain === d || domain.endsWith("." + d))
        );
        if (matched) {
            found.push({
                id: rule.id,
                name: rule.name,
                emoji: rule.emoji,
                domain: rule.domains[0],
                category: rule.category,
                risk: rule.risk,
                description: rule.description,
                longDescription: rule.longDescription,
            });
        }
    }

    return found;
}

export function calculateSecurityChecks(ctx: PageContext): SecurityCheck[] {
    const checks: SecurityCheck[] = [];

    // HTTPS
    const isHttps = ctx.protocol === "https:";
    checks.push({
        id: "https",
        label: "HTTPS Encrypted",
        passed: isHttps,
        emoji: isHttps ? "✅" : "⚠️",
        explanation: isHttps
            ? "Connection is encrypted. Nobody on your WiFi can see what you send or receive."
            : "This page isn't encrypted. Avoid entering passwords or card numbers here.",
    });

    // CSP
    checks.push({
        id: "csp",
        label: "Content Security Policy",
        passed: ctx.hasCSP,
        emoji: ctx.hasCSP ? "✅" : "ℹ️",
        explanation: ctx.hasCSP
            ? "This page has a Content Security Policy. Only approved scripts are allowed to run — hackers can't easily inject code."
            : "No Content Security Policy (CSP) detected via HTTP headers or meta tags. Without it, injected scripts could run if the site were ever hacked. Many major sites do use CSP — your browser's Network tab is the most reliable way to confirm.",
    });

    // Mixed content
    checks.push({
        id: "mixed",
        label: "No Mixed Content",
        passed: !ctx.hasMixedContent,
        emoji: ctx.hasMixedContent ? "⚠️" : "✅",
        explanation: ctx.hasMixedContent
            ? "This HTTPS page loads some resources over plain HTTP. Those resources could be intercepted."
            : "All resources are loaded securely.",
    });

    // Hidden iframes
    const hasHiddenIframes = ctx.hiddenIframeCount > 0;
    checks.push({
        id: "iframes",
        label: "No Hidden iFrames",
        passed: !hasHiddenIframes,
        emoji: hasHiddenIframes ? "⚠️" : "✅",
        explanation: hasHiddenIframes
            ? `${ctx.hiddenIframeCount} hidden iframe(s) found. These invisible frames are sometimes used to load content without your knowledge.`
            : "No hidden iframes detected.",
    });

    // External form targets
    const hasExternalForms = ctx.formActions.some(action => {
        try {
            return new URL(action).hostname !== ctx.hostname;
        } catch {
            return false;
        }
    });
    if (ctx.hasPasswordField) {
        checks.push({
            id: "form",
            label: "Password Form Destination",
            passed: !hasExternalForms,
            emoji: hasExternalForms ? "⚠️" : "✅",
            explanation: hasExternalForms
                ? "I found a password form that posts to a different domain. This is worth investigating — could be a phishing attempt."
                : "The password form on this page sends data to the same domain — that's expected and fine.",
        });
    }

    // Cookie count
    const manyCookies = ctx.cookieCount > 10;
    if (manyCookies) {
        checks.push({
            id: "cookies",
            label: "Cookie Count",
            passed: false,
            emoji: "ℹ️",
            explanation: `This page has ${ctx.cookieCount} cookies. Cookies are small files websites store on your device. A high number can indicate extensive tracking.`,
        });
    }

    return checks;
}

// ─── Grading ──────────────────────────────────────────────────────────────────

export function calculateGrade(
    checks: SecurityCheck[],
    trackers: TrackerItem[]
): { grade: "A" | "B" | "C" | "D" | "F"; gradeLabel: string } {
    let score = 100;

    // HTTPS failure is major
    const httpsCheck = checks.find(c => c.id === "https");
    if (httpsCheck && !httpsCheck.passed) score -= 30;

    // External form with password
    const formCheck = checks.find(c => c.id === "form");
    if (formCheck && !formCheck.passed) score -= 25;

    // Mixed content
    const mixedCheck = checks.find(c => c.id === "mixed");
    if (mixedCheck && !mixedCheck.passed) score -= 15;

    // Hidden iframes
    const iframeCheck = checks.find(c => c.id === "iframes");
    if (iframeCheck && !iframeCheck.passed) score -= 10;

    // No CSP (minor)
    const cspCheck = checks.find(c => c.id === "csp");
    if (cspCheck && !cspCheck.passed) score -= 5;

    // High-risk trackers
    const highRisk = trackers.filter(t => t.risk === "high").length;
    const medRisk = trackers.filter(t => t.risk === "medium").length;
    score -= highRisk * 8;
    score -= medRisk * 3;

    // Many trackers
    if (trackers.length > 8) score -= 5;

    score = Math.max(0, score);

    let grade: "A" | "B" | "C" | "D" | "F";
    let gradeLabel: string;

    if (score >= 90) { grade = "A"; gradeLabel = "A"; }
    else if (score >= 80) { grade = "A"; gradeLabel = "A−"; }
    else if (score >= 72) { grade = "B"; gradeLabel = "B+"; }
    else if (score >= 65) { grade = "B"; gradeLabel = "B"; }
    else if (score >= 58) { grade = "B"; gradeLabel = "B−"; }
    else if (score >= 50) { grade = "C"; gradeLabel = "C"; }
    else if (score >= 40) { grade = "D"; gradeLabel = "D"; }
    else { grade = "F"; gradeLabel = "F"; }

    return { grade, gradeLabel };
}

// ─── Friend Summary ───────────────────────────────────────────────────────────

export function buildFriendSummary(
    hostname: string,
    grade: string,
    techStack: TechItem[],
    trackers: TrackerItem[],
    checks: SecurityCheck[]
): string {
    const isHttps = checks.find(c => c.id === "https")?.passed ?? true;
    const hasBadForm = checks.find(c => c.id === "form")?.passed === false;
    const trackerCount = trackers.length;
    const hasCloudflare = techStack.some(t => t.id === "cloudflare");
    const hasStripe = techStack.some(t => t.id === "stripe");
    const hasShopify = techStack.some(t => t.id === "shopify");
    const primaryFrontend = techStack.find(t =>
        ["react", "vue", "angular", "svelte", "nextjs"].includes(t.id)
    );

    let line1: string;
    let line2: string;

    // Line 1 — overall security posture
    if (!isHttps) {
        line1 = "I found something worth flagging — this page isn't using a secure (HTTPS) connection.";
    } else if (hasBadForm) {
        line1 = "I noticed a form on this page that sends data to a different domain — that's unusual and worth your attention.";
    } else if (hasCloudflare && (grade === "A" || grade === "B")) {
        line1 = `This page is well-built and secure — HTTPS is active and Cloudflare is protecting it.`;
    } else if (hasShopify && hasStripe) {
        line1 = "This is a professional Shopify store with Stripe handling payments — both are very trustworthy.";
    } else if (grade === "A" || grade === "B") {
        line1 = `This page looks good — it's using a secure connection${hasStripe ? " and has a trusted payment processor" : ""}.`;
    } else if (grade === "C") {
        line1 = "This page is okay but I spotted a few things worth knowing about.";
    } else {
        line1 = "I found a few things worth flagging on this page — I'm keeping a close eye on it for you.";
    }

    // Line 2 — trackers / tech insight
    if (trackerCount === 0) {
        line2 = primaryFrontend
            ? `This site is built with ${primaryFrontend.name} and I spotted no trackers at all — quite clean.`
            : "I spotted no trackers on this page at all — that's quite clean.";
    } else if (trackerCount === 1) {
        line2 = `I spotted 1 tracker watching your visit — ${trackers[0].name}. Low-key, just so you know.`;
    } else if (trackerCount <= 4) {
        line2 = `I spotted ${trackerCount} trackers watching your visit — worth knowing, though it's pretty normal for most sites.`;
    } else if (trackerCount <= 7) {
        line2 = `I spotted ${trackerCount} trackers on this page. That's on the busier side, but normal for large sites.`;
    } else {
        line2 = `I spotted ${trackerCount} trackers on this page — quite a few are watching your visit.`;
    }

    return `${line1} ${line2}`;
}

// ─── Lesson of the Page ───────────────────────────────────────────────────────

export function generateLesson(
    techStack: TechItem[],
    trackers: TrackerItem[],
    checks: SecurityCheck[]
): { text: string; emoji: string } {
    // Priority order: interesting tech > notable tracker > security issue

    // Specific tech lessons (most educational first)
    const interestingTech = ["svelte", "nextjs", "react", "firebase", "cloudflare", "wordpress", "shopify", "stripe"];
    for (const id of interestingTech) {
        const tech = techStack.find(t => t.id === id);
        if (tech) {
            return { text: tech.longDescription, emoji: tech.emoji };
        }
    }

    // Session replay is very interesting to explain
    const sessionReplay = trackers.find(t => t.category === "SessionReplay");
    if (sessionReplay) {
        return { text: sessionReplay.longDescription, emoji: sessionReplay.emoji };
    }

    // High-risk tracker
    const highRiskTracker = trackers.find(t => t.risk === "high");
    if (highRiskTracker) {
        return { text: highRiskTracker.longDescription, emoji: highRiskTracker.emoji };
    }

    // No CSP explanation
    const cspCheck = checks.find(c => c.id === "csp" && !c.passed);
    if (cspCheck) {
        return {
            text: "This page has no Content Security Policy (CSP). CSP is like a bouncer that only lets approved scripts run. Without it, if a hacker ever got into this site's code, they could make your browser run anything.",
            emoji: "🔒",
        };
    }

    // No HTTPS
    const httpsCheck = checks.find(c => c.id === "https" && !c.passed);
    if (httpsCheck) {
        return {
            text: "HTTPS encrypts the connection between you and a website, so nobody on your WiFi network can read what you send or receive. The padlock in your browser's address bar means HTTPS is active. Always look for it before entering personal information.",
            emoji: "🔐",
        };
    }

    // General tracker lesson
    if (trackers.length > 0) {
        const t = trackers[0];
        return { text: t.longDescription, emoji: t.emoji };
    }

    // Default
    return {
        text: "HTTPS encrypts your connection to websites, making it impossible for others on your WiFi to spy on your browsing. The little padlock in your browser's address bar is your signal that the connection is secure.",
        emoji: "🛡️",
    };
}

// ─── Full Inspection Pipeline ──────────────────────────────────────────────────

export function runInspectorPipeline(ctx: PageContext): InspectorReport {
    const techStack = detectTechStack(ctx);
    const trackers = detectTrackers(ctx);
    const securityChecks = calculateSecurityChecks(ctx);
    const { grade, gradeLabel } = calculateGrade(securityChecks, trackers);
    const friendSummary = buildFriendSummary(ctx.hostname, grade, techStack, trackers, securityChecks);
    const { text: lesson, emoji: lessonEmoji } = generateLesson(techStack, trackers, securityChecks);

    return {
        url: ctx.url,
        hostname: ctx.hostname,
        grade,
        gradeLabel,
        techStack,
        trackers,
        securityChecks,
        friendSummary,
        lesson,
        lessonEmoji,
        trackerCount: trackers.length,
        timestamp: Date.now(),
    };
}
