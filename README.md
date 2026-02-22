# 🛡️ Student Cyber Guardian

> **Privacy-first, community-powered threat detection for students.**  
> Turns every phishing link, scam site, and dark pattern into a teaching moment — anonymously.

---

## ⚡ Install the Extension (Judges — Start Here!)

> **No `npm`, no terminal, no build step needed. Just download and load.**

### Step 1 — Download the Extension

<div align="center">

**[⬇️ Download StudentCyberGuardian-extension.zip](https://github.com/Yashas95/student-cyber-guardian/raw/main/StudentCyberGuardian-extension.zip)**

</div>

> This is a pre-built zip. Just download it — no cloning required.

---

### Step 2 — Unzip It

Right-click the downloaded `.zip` file → **Extract All** → choose any folder (e.g. your Desktop).

You'll get a folder called something like `StudentCyberGuardian-extension` containing files like `manifest.json`, `popup.html`, etc.

---

### Step 3 — Load in Chrome

1. Open Chrome and go to **`chrome://extensions/`**
2. Toggle **Developer mode** ON (top-right corner)
3. Click **"Load unpacked"**
4. Select the **unzipped folder** (the one containing `manifest.json`)
5. ✅ Done! The Guardian shield icon appears in your toolbar.

---

### 🎯 What to Try First

| Action | What to Look For |
|---|---|
| Visit a known phishing site (e.g. `http://phishing.test`) | 🚨 Guardian popup with risk score |
| Visit [Campus Pulse Dashboard](https://yashas95.github.io/campus-pulse-dashboard/?campus=mit) | 📊 Live threat map |
| Change `?campus=` to `stanford`, `iit-bombay`, etc. | 🌍 Campus-specific alerts |
| Watch for the animated **whisper toast** | 🔔 Community threat notification |

---

## 🏗️ Architecture Overview

```
Student Cyber Guardian
├── Chrome Extension (TypeScript → pre-built dist/)
│   ├── Threat Detection (ML + heuristics)
│   ├── Campus Pulse (anonymous community reporting)
│   ├── Whisper Toast (real-time alerts)
│   └── Guardian Popup (risk score + advice)
├── FastAPI Backend (Python, deployed on Render)
│   └── Escalation engine (3-student threshold → campus alert)
└── Dashboard (GitHub Pages, live)
    └── IT Admin view — zero student PII
```

## 🔒 Privacy by Design

- **No PII ever collected** — no names, emails, or IPs
- **SHA-256 hostname hashing** — only the first 8 characters transmitted
- **Hourly timestamp rounding** — prevents timing-based identification
- **24-hour rotating session tokens**

## 🛠️ Stack

| Layer | Tech |
|---|---|
| Extension | TypeScript, Chrome MV3, Vanilla CSS |
| Backend | FastAPI, Pydantic, Uvicorn |
| Dashboard | GitHub Pages |
| Deployment | Render (API) |

---

## 📖 Full Judge Guide

See [JUDGE_GUIDE.md](./JUDGE_GUIDE.md) for a detailed walkthrough of all features and what to evaluate.

## 🏛️ Privacy Architecture

See [PRIVACY_ARCHITECTURE.md](./PRIVACY_ARCHITECTURE.md) for a deep dive into our zero-PII design.

---

<div align="center">
  Made with ❤️ for students, by students.
</div>
