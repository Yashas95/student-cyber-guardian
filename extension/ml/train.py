"""
ml/train.py
───────────────────────────────────────────────────────────────────────────────
Student Cyber Guardian — ML Training Pipeline
Trains a GradientBoostingClassifier on PhishTank + Tranco data.
The same 17-feature vector used by the extension's heuristic engine.

Usage:
  pip install -r requirements.txt
  python train.py

Output:
  model.pkl   — trained model (load with joblib.load)
  scaler.pkl  — fitted StandardScaler

To use in backend (main.py):
  Replace compute_score() with:
    features = extract_features_vector(url)
    prob = model.predict_proba([features])[0][1]   # phishing probability
    score = int(prob * 100)
───────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import hashlib
import io
import re
import zipfile
from pathlib import Path
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd
import requests
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# ─── Config ───────────────────────────────────────────────────────────────────

DATA_DIR   = Path(__file__).parent / "data"
MODEL_PATH = Path(__file__).parent / "model.pkl"
SCALER_PATH = Path(__file__).parent / "scaler.pkl"

PHISHTANK_URL = "http://data.phishtank.com/data/online-valid.csv"
TRANCO_URL    = "https://tranco-list.eu/top-1m.csv.zip"

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "download",
    "zip", "review", "country", "kim", "cricket", "science", "work",
    "party", "gdn", "loan", "win", "bid", "trade", "date", "racing"
}

BRAND_KEYWORDS = [
    "paypal", "amazon", "google", "apple", "microsoft", "netflix", "facebook",
    "instagram", "twitter", "bank", "chase", "wellsfargo", "citibank",
    "coinbase", "binance", "metamask", "irs", "fedex", "ups", "dhl",
    "whatsapp", "telegram", "discord", "steam"
]

PHISHING_PATH_PATTERNS = [
    re.compile(p, re.I) for p in [
        r"verify.*account", r"confirm.*identity", r"update.*payment",
        r"suspended.*account", r"unlock.*account", r"login.*reset",
        r"secure.*signin", r"signin.*secure"
    ]
]

# ─── Data download ────────────────────────────────────────────────────────────

def download_phishtank(path: Path) -> pd.DataFrame:
    print("Downloading PhishTank feed...")
    DATA_DIR.mkdir(exist_ok=True)
    try:
        r = requests.get(PHISHTANK_URL, timeout=60,
                         headers={"User-Agent": "student-cyber-guardian-research/1.0"})
        r.raise_for_status()
        df = pd.read_csv(io.StringIO(r.text))
        df = df[["url"]].dropna()
        df["label"] = 1   # phishing
        df.to_csv(path, index=False)
        print(f"  PhishTank: {len(df)} phishing URLs")
        return df
    except Exception as e:
        print(f"  PhishTank download failed: {e}. Using cached if available.")
        if path.exists():
            return pd.read_csv(path)
        raise


def download_tranco(path: Path, n: int = 50_000) -> pd.DataFrame:
    print("Downloading Tranco top-1M (legitimate URLs)...")
    DATA_DIR.mkdir(exist_ok=True)
    try:
        r = requests.get(TRANCO_URL, timeout=120)
        r.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            with z.open("top-1m.csv") as f:
                df = pd.read_csv(f, header=None, names=["rank", "domain"])
        df = df.head(n).copy()
        df["url"] = "https://" + df["domain"]
        df = df[["url"]]
        df["label"] = 0   # legitimate
        df.to_csv(path, index=False)
        print(f"  Tranco: {len(df)} legitimate URLs")
        return df
    except Exception as e:
        print(f"  Tranco download failed: {e}. Using cached if available.")
        if path.exists():
            return pd.read_csv(path)
        raise

# ─── Feature extraction (17 features — mirrors the extension's heuristics) ────

def levenshtein(a: str, b: str) -> int:
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[:]
        dp[0] = i
        for j in range(1, n + 1):
            dp[j] = prev[j - 1] if a[i-1] == b[j-1] else 1 + min(prev[j], dp[j-1], prev[j-1])
    return dp[n]


def extract_features_vector(url: str) -> list[float]:
    """
    Returns a 17-element feature vector matching the extension's heuristic checks.
    All features are numeric (0/1 flags or continuous values).
    """
    try:
        parsed = urlparse(url if url.startswith("http") else f"https://{url}")
    except Exception:
        return [0.0] * 17

    hostname = parsed.hostname or ""
    path     = parsed.path or ""
    tld      = hostname.split(".")[-1] if "." in hostname else ""
    parts    = hostname.split(".")
    sld      = parts[-2] if len(parts) >= 2 else ""
    subdomains = ".".join(parts[:-2])

    # 1. No HTTPS
    f1 = float(parsed.scheme != "https")

    # 2. Suspicious TLD
    f2 = float(tld in SUSPICIOUS_TLDS)

    # 3. Brand in subdomain (impersonation)
    f3 = float(any(b in subdomains and b not in sld for b in BRAND_KEYWORDS))

    # 4. Typosquatting (Levenshtein ≤ 2 to a brand keyword)
    f4 = float(any(
        0 < levenshtein(sld, b) <= 2 and len(sld) > 3
        for b in BRAND_KEYWORDS if sld != b
    ))

    # 5. Subdomain depth ≥ 3
    f5 = float(len(parts) - 2 >= 3)

    # 6. Phishing path patterns
    f6 = float(any(p.search(path) for p in PHISHING_PATH_PATTERNS))

    # 7. IP address as host
    f7 = float(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname)))

    # 8. URL length > 150
    f8 = float(len(url) > 150)

    # 9. Special char ratio in domain > 0.35
    special = len(re.findall(r"[-_0-9]", hostname))
    f9 = float((special / len(hostname)) > 0.35 if hostname else 0)

    # 10. Punycode / IDN homograph
    f10 = float("xn--" in hostname.lower())

    # 11. Non-ASCII chars in hostname
    f11 = float(any(ord(c) > 127 for c in hostname))

    # 12. Fake login path pattern
    f12 = float(bool(re.search(r"(signin|login|account.*verify).*\.php", path, re.I)))

    # 13. Executable file extension in path
    ext = path.split(".")[-1].lower() if "." in path else ""
    f13 = float(ext in {"exe", "msi", "bat", "cmd", "ps1", "vbs", "jar", "scr"})

    # 14. Malware download lure in path
    f14 = float(bool(re.search(
        r"(auto[-_]?download|forced[-_]?download|update[-_]?required|install[-_]?now)", path, re.I
    )))

    # 15. Redirect indicator in URL (multiple http in path)
    f15 = float(path.lower().count("http") > 1)

    # 16. Query string length > 100
    f16 = float(len(parsed.query or "") > 100)

    # 17. Number of dots in hostname > 4
    f17 = float(hostname.count(".") > 4)

    return [f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12, f13, f14, f15, f16, f17]


FEATURE_NAMES = [
    "no_https", "suspicious_tld", "brand_subdomain", "typosquatting",
    "deep_subdomains", "phishing_path", "ip_host", "long_url",
    "special_chars_domain", "punycode", "non_ascii_host",
    "fake_login_path", "executable_ext", "malware_lure",
    "redirect_in_path", "long_query", "many_dots"
]

# ─── Training ─────────────────────────────────────────────────────────────────

def build_dataset() -> pd.DataFrame:
    phish_path  = DATA_DIR / "phishtank.csv"
    tranco_path = DATA_DIR / "tranco.csv"

    phish  = download_phishtank(phish_path)
    tranco = download_tranco(tranco_path)

    df = pd.concat([phish, tranco], ignore_index=True).sample(frac=1, random_state=42)
    return df


def train(df: pd.DataFrame):
    print("\nExtracting features...")
    X_raw = df["url"].apply(extract_features_vector).tolist()
    X = np.array(X_raw, dtype=np.float32)
    y = df["label"].values

    print(f"Dataset: {len(y)} samples | phishing={y.sum()} | legit={(y==0).sum()}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test  = scaler.transform(X_test)

    print("\nTraining GradientBoostingClassifier...")
    model = GradientBoostingClassifier(
        n_estimators=300,
        max_depth=4,
        learning_rate=0.05,
        subsample=0.8,
        random_state=42,
        verbose=1
    )
    model.fit(X_train, y_train)

    y_prob = model.predict_proba(X_test)[:, 1]
    y_pred = model.predict(X_test)

    auc = roc_auc_score(y_test, y_prob)
    print(f"\nROC-AUC: {auc:.4f}")
    print(classification_report(y_test, y_pred, target_names=["legitimate", "phishing"]))

    # Feature importances
    importances = sorted(
        zip(FEATURE_NAMES, model.feature_importances_),
        key=lambda x: x[1], reverse=True
    )
    print("\nTop feature importances:")
    for name, imp in importances[:10]:
        print(f"  {name:<25} {imp:.4f}")

    # Save
    joblib.dump(model,  MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    print(f"\nSaved model  → {MODEL_PATH}")
    print(f"Saved scaler → {SCALER_PATH}")

    return model, scaler


# ─── Entrypoint ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    df = build_dataset()
    train(df)
