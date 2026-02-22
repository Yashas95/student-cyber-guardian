"""
pulse_server.py — Campus Threat Pulse API
══════════════════════════════════════════════════════════════════
Anonymous, aggregated threat intelligence for campus communities.

PRIVACY RULES (non-negotiable):
  ✅ Received: campus_id, threat_category, domain_hash (8 chars),
     timestamp (rounded), session_token (rotating UUID)
  ❌ Never logged: IP, full domain, student identity, browsing data
  ✅ Logged: timestamp (hourly), campus_id, threat_category, signal_count
  
THRESHOLD: 3 independent signals → campus alert
══════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import time
import uuid
from collections import defaultdict
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

# ─── Router ──────────────────────────────────────────────────────────────────

router = APIRouter(prefix="/pulse", tags=["Campus Pulse"])

# ─── Models ──────────────────────────────────────────────────────────────────

class ThreatSignal(BaseModel):
    campus_id: str = Field(..., min_length=1, max_length=64)
    threat_category: str = Field(..., pattern=r"^(phishing|malware|scam|fake_login)$")
    domain_hash: str = Field(..., min_length=8, max_length=8)
    timestamp: int = Field(..., gt=0)
    session_token: str = Field(..., min_length=1, max_length=128)


class CampusAlert(BaseModel):
    alert_id: str
    campus_id: str
    threat_category: str
    severity: str
    signal_count: int
    first_seen: float
    last_seen: float
    friendly_message: str
    advice: list[str]
    active: bool


# ─── In-memory stores (swap for Redis in production) ─────────────────────────

# pending_signals[campus_id][category+domain_hash] = { tokens: set, first_seen, last_seen }
pending_signals: dict[str, dict[str, dict]] = defaultdict(dict)

# active_alerts[campus_id] = [CampusAlert, ...]
active_alerts: dict[str, list[CampusAlert]] = defaultdict(list)

# Rate limiting: token_counts[session_token] = { count, window_start }
token_rate: dict[str, dict] = {}

# campus_rate[campus_id] = { count, window_start }
campus_rate: dict[str, dict] = {}

ALERT_THRESHOLD = 3      # signals from unique tokens → alert
ALERT_TTL = 86_400        # 24 hours in seconds
MAX_SIGNALS_PER_TOKEN = 10   # per hour
MAX_SIGNALS_PER_CAMPUS = 100  # per minute


# ─── Friendly message templates ──────────────────────────────────────────────

FRIENDLY_MESSAGES = {
    "phishing": "I've noticed several students at your campus encountering phishing attempts. Someone's trying to trick people — be extra careful with links today.",
    "malware": "A malware threat has been detected across your campus. Some websites are trying to install harmful software. I'm keeping watch.",
    "scam": "Scam pages are circulating at your campus right now. If something seems too good to be true, trust your gut.",
    "fake_login": "Fake login pages are active at your campus. Always double-check the URL before entering your credentials.",
}

ADVICE = {
    "phishing": [
        "Don't click links in unexpected emails or messages",
        "Check the URL carefully before entering any info",
        "When in doubt, go directly to the website by typing the address",
    ],
    "malware": [
        "Avoid downloading files from unfamiliar sites",
        "Keep your browser and OS up to date",
        "If a site asks to install something unexpected, close the tab",
    ],
    "scam": [
        "Free offers that seem too good to be true usually are",
        "Never pay upfront for prizes or scholarships",
        "Check official university channels for legitimate offers",
    ],
    "fake_login": [
        "Always check the URL bar — look for your university's real domain",
        "Use a password manager (it won't autofill on fake domains)",
        "Enable two-factor authentication on all accounts",
    ],
}

SEVERITY_MAP = {
    "phishing": "high",
    "malware": "critical",
    "scam": "medium",
    "fake_login": "high",
}


# ─── Rate limiting helpers ───────────────────────────────────────────────────

def _check_token_rate(token: str) -> bool:
    """Returns True if within rate limit."""
    now = time.time()
    entry = token_rate.get(token)
    if not entry or now - entry["window_start"] > 3600:
        token_rate[token] = {"count": 1, "window_start": now}
        return True
    if entry["count"] >= MAX_SIGNALS_PER_TOKEN:
        return False
    entry["count"] += 1
    return True


def _check_campus_rate(campus_id: str) -> bool:
    """Returns True if within rate limit."""
    now = time.time()
    entry = campus_rate.get(campus_id)
    if not entry or now - entry["window_start"] > 60:
        campus_rate[campus_id] = {"count": 1, "window_start": now}
        return True
    if entry["count"] >= MAX_SIGNALS_PER_CAMPUS:
        return False
    entry["count"] += 1
    return True


# ─── Alert management ───────────────────────────────────────────────────────

def _maybe_create_alert(campus_id: str, category: str, domain_hash: str) -> None:
    """Elevate pending signals to a CampusAlert if threshold is met."""
    key = f"{category}:{domain_hash}"
    pending = pending_signals[campus_id].get(key)
    if not pending:
        return

    if len(pending["tokens"]) >= ALERT_THRESHOLD:
        # Check if alert already exists for this key
        existing = [a for a in active_alerts[campus_id] if a.alert_id.endswith(key)]
        if existing:
            # Update existing alert
            existing[0].signal_count = len(pending["tokens"])
            existing[0].last_seen = pending["last_seen"]
            existing[0].active = True
            return

        alert = CampusAlert(
            alert_id=f"{campus_id}:{key}",
            campus_id=campus_id,
            threat_category=category,
            severity=SEVERITY_MAP.get(category, "medium"),
            signal_count=len(pending["tokens"]),
            first_seen=pending["first_seen"],
            last_seen=pending["last_seen"],
            friendly_message=FRIENDLY_MESSAGES.get(category, "A threat has been detected at your campus."),
            advice=ADVICE.get(category, ["Stay cautious online."]),
            active=True,
        )
        active_alerts[campus_id].append(alert)


def _expire_old_alerts() -> None:
    """Deactivate alerts older than ALERT_TTL."""
    now = time.time()
    for campus_id in list(active_alerts.keys()):
        for alert in active_alerts[campus_id]:
            if now - alert.last_seen > ALERT_TTL:
                alert.active = False
        # Keep only last 50 alerts per campus
        active_alerts[campus_id] = active_alerts[campus_id][-50:]


# ─── Endpoints ───────────────────────────────────────────────────────────────

@router.post("/signal")
async def receive_signal(signal: ThreatSignal, request: Request):
    """
    Receive an anonymous threat signal.
    Never logs individual signals — only increments aggregate counters.
    """
    # Rate limiting
    if not _check_token_rate(signal.session_token):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    if not _check_campus_rate(signal.campus_id):
        raise HTTPException(status_code=429, detail="Campus rate limit exceeded")

    key = f"{signal.threat_category}:{signal.domain_hash}"
    now = time.time()

    if key not in pending_signals[signal.campus_id]:
        pending_signals[signal.campus_id][key] = {
            "tokens": set(),
            "first_seen": now,
            "last_seen": now,
        }

    entry = pending_signals[signal.campus_id][key]
    entry["tokens"].add(signal.session_token)
    entry["last_seen"] = now

    # Check if threshold met → create alert
    _maybe_create_alert(signal.campus_id, signal.threat_category, signal.domain_hash)

    # Expire old alerts periodically
    _expire_old_alerts()

    return {"status": "received"}


@router.get("/alerts")
async def get_alerts(campus: str):
    """
    Return active campus alerts. No auth required — alerts contain no PII.
    """
    if not campus:
        raise HTTPException(status_code=400, detail="campus query param required")

    _expire_old_alerts()

    alerts = [a for a in active_alerts.get(campus, []) if a.active]
    return alerts


@router.get("/stats")
async def get_stats():
    """
    Public aggregate stats — never per-campus breakdowns.
    """
    _expire_old_alerts()

    total_active = sum(
        len([a for a in alerts if a.active])
        for alerts in active_alerts.values()
    )
    campuses_protected = len([
        c for c, alerts in active_alerts.items()
        if any(a.active for a in alerts)
    ])

    # Most common threat category across all active alerts
    category_counts: dict[str, int] = defaultdict(int)
    for alerts in active_alerts.values():
        for a in alerts:
            if a.active:
                category_counts[a.threat_category] += 1

    most_common = max(category_counts, key=category_counts.get, default=None) if category_counts else None  # type: ignore

    return {
        "total_active_alerts": total_active,
        "campuses_with_alerts": campuses_protected,
        "most_common_threat": most_common,
        "total_campuses_monitored": len(set(
            list(pending_signals.keys()) + list(active_alerts.keys())
        )),
    }


@router.get("/dashboard/{campus_id}")
async def get_dashboard(campus_id: str, days: int = 7):
    """
    IT admin dashboard data — last N days of alerts (aggregated).
    """
    _expire_old_alerts()

    cutoff = time.time() - (days * 86_400)
    all_alerts = active_alerts.get(campus_id, [])
    recent = [a for a in all_alerts if a.last_seen > cutoff]

    # Aggregate by category
    category_summary: dict[str, dict] = {}
    for a in recent:
        if a.threat_category not in category_summary:
            category_summary[a.threat_category] = {
                "category": a.threat_category,
                "total_alerts": 0,
                "total_signals": 0,
                "active": 0,
                "severity": a.severity,
            }
        cat = category_summary[a.threat_category]
        cat["total_alerts"] += 1
        cat["total_signals"] += a.signal_count
        if a.active:
            cat["active"] += 1

    return {
        "campus_id": campus_id,
        "period_days": days,
        "active_alerts": [a.model_dump() for a in recent if a.active],
        "category_summary": list(category_summary.values()),
        "total_alerts": len(recent),
        "total_active": len([a for a in recent if a.active]),
    }
