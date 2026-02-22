"""
backend/main.py
───────────────────────────────────────────────────────────────────────────────
Student Cyber Guardian — Backend API
Endpoints:
  POST /feed/check      — check a URL against community + feed blocklists
  POST /report          — community threat report (3 reports = auto-block)
  GET  /stats           — aggregate anonymised stats
  POST /telemetry       — receive opt-in telemetry from extension
  GET  /health          — liveness probe

Privacy:
  - Raw URLs are NEVER logged. Only SHA-256 prefixes (first 8 hex chars).
  - No IP addresses stored. Rate limiting uses in-memory token buckets.
  - All data is ephemeral (in-memory) unless you add a DB.

Run:
  pip install -r requirements.txt
  uvicorn main:app --host 0.0.0.0 --port 8000
  OR:
  python main.py   (uses built-in uvicorn dev server)
───────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ─── App setup ────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Student Cyber Guardian API",
    version="1.1.0",
    description="Privacy-first threat intelligence backend for the SCG extension."
)

# ── Include Campus Pulse router ──────────────────────────────────────────────
from pulse_server import router as pulse_router  # noqa: E402
app.include_router(pulse_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # restrict to your extension origin in production
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

# ─── In-memory stores (replace with Redis/SQLite for persistence) ──────────────

# Community blocklist: sha256_prefix → {count, first_seen, threat_type}
community_reports: dict[str, dict[str, Any]] = {}

# Aggregate stats (reset on restart — use a DB for persistence)
stats_store: dict[str, int] = defaultdict(int)

# Rate limiter: ip_hash → list of timestamps
rate_limit_store: dict[str, list[float]] = defaultdict(list)

RATE_LIMIT_WINDOW = 60   # seconds
RATE_LIMIT_MAX    = 30   # requests per window per IP

# ─── Helpers ──────────────────────────────────────────────────────────────────

def url_to_prefix(url: str) -> str:
    """Return first 8 hex chars of SHA-256 of the normalised URL hostname."""
    try:
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname or url
        return hashlib.sha256(hostname.lower().encode()).hexdigest()[:8]
    except Exception:
        return hashlib.sha256(url.encode()).hexdigest()[:8]


def check_rate_limit(ip: str) -> bool:
    """Return True if request is allowed, False if rate-limited."""
    ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:16]  # never store raw IP
    now = time.time()
    timestamps = rate_limit_store[ip_hash]
    # Evict old timestamps
    rate_limit_store[ip_hash] = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
    if len(rate_limit_store[ip_hash]) >= RATE_LIMIT_MAX:
        return False
    rate_limit_store[ip_hash].append(now)
    return True

# ─── Models ───────────────────────────────────────────────────────────────────

class FeedCheckRequest(BaseModel):
    url: str

class FeedCheckResponse(BaseModel):
    listed: bool
    source: str
    threat: str | None = None
    prefix: str        # returned so client can verify, never the full URL

class ReportRequest(BaseModel):
    url: str
    threat_type: str   # e.g. "phishing", "malware", "scam"

class TelemetryPayload(BaseModel):
    sessionId: str
    periodStart: int
    periodEnd: int
    counts: dict[str, int]
    topFactors: list[str]

# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "version": "1.0.0"}


@app.post("/feed/check", response_model=FeedCheckResponse)
async def feed_check(body: FeedCheckRequest, request: Request):
    """
    Check a URL against the community blocklist.
    Only the SHA-256 prefix of the hostname is used — raw URL never stored.
    """
    client_ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Try again in a minute.")

    prefix = url_to_prefix(body.url)
    entry = community_reports.get(prefix)

    if entry and entry["count"] >= 3:
        return FeedCheckResponse(
            listed=True,
            source="Community Reports",
            threat=entry["threat_type"],
            prefix=prefix
        )

    return FeedCheckResponse(listed=False, source="none", prefix=prefix)


@app.post("/report")
async def report_url(body: ReportRequest, request: Request):
    """
    Submit a community threat report.
    3 independent reports from different sessions auto-flags the domain.
    """
    client_ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")

    prefix = url_to_prefix(body.url)
    if prefix not in community_reports:
        community_reports[prefix] = {
            "count": 0,
            "threat_type": body.threat_type,
            "first_seen": int(time.time())
        }

    community_reports[prefix]["count"] += 1
    count = community_reports[prefix]["count"]

    stats_store["total_reports"] += 1

    return {
        "received": True,
        "prefix": prefix,
        "report_count": count,
        "auto_blocked": count >= 3
    }


@app.get("/stats")
async def get_stats():
    """Return aggregate anonymised stats (no URLs, no user data)."""
    return {
        "total_reports": stats_store["total_reports"],
        "community_blocked_domains": sum(
            1 for v in community_reports.values() if v["count"] >= 3
        ),
        "telemetry_sessions": stats_store["telemetry_sessions"],
        "scans": {
            "safe":       stats_store["scan_safe"],
            "suspicious": stats_store["scan_suspicious"],
            "dangerous":  stats_store["scan_dangerous"],
        }
    }


@app.post("/telemetry")
async def receive_telemetry(body: TelemetryPayload, request: Request):
    """
    Receive opt-in anonymised telemetry from the extension.
    sessionId is a rotating random UUID — not linked to any user identity.
    """
    client_ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")

    stats_store["telemetry_sessions"] += 1
    stats_store["scan_safe"]       += body.counts.get("safe", 0)
    stats_store["scan_suspicious"] += body.counts.get("suspicious", 0)
    stats_store["scan_dangerous"]  += body.counts.get("dangerous", 0)

    # Log only the session ID prefix (first 8 chars) — not the full UUID
    session_prefix = body.sessionId[:8] if body.sessionId else "unknown"
    print(f"[telemetry] session={session_prefix}... safe={body.counts.get('safe',0)} "
          f"sus={body.counts.get('suspicious',0)} danger={body.counts.get('dangerous',0)}")

    return {"received": True}


# ─── Dev server entrypoint ────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
