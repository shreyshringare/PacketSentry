"""Alert REST API endpoints.

GET  /api/alerts           — paginated alert list from DuckDB
GET  /api/alerts/:id       — single alert with full SHAP JSON
POST /api/alerts/:id/false_positive — mark as FP, adjust ensemble weights
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/alerts", tags=["alerts"])

_store = None
_arbiter = None


def set_dependencies(store, arbiter) -> None:
    """Called once at app startup to inject shared instances."""
    global _store, _arbiter
    _store = store
    _arbiter = arbiter


class AlertOut(BaseModel):
    alert_id: str
    timestamp: str
    src_ip: str
    dst_ip: str
    dst_port: int
    confidence: float
    severity: str
    shap_explanation: str
    rule: Optional[str] = None
    detectors: Optional[str] = None


@router.get("", response_model=list[AlertOut])
async def list_alerts(
    limit: int = Query(100, ge=1, le=1000),
    severity: Optional[str] = Query(None),
    since: Optional[float] = Query(None),
) -> list[AlertOut]:
    """Return recent alerts, newest first."""
    if _store is None:
        raise HTTPException(503, "Alert store not initialized")

    alerts = _store.get_recent_alerts(limit=limit)

    if severity:
        alerts = [a for a in alerts if a.get("severity") == severity.upper()]
    if since:
        alerts = [
            a for a in alerts
            if _ts_to_float(a.get("timestamp")) >= since
        ]

    return [AlertOut(**_normalize_alert(a)) for a in alerts]


@router.get("/{alert_id}", response_model=AlertOut)
async def get_alert(alert_id: str) -> AlertOut:
    """Return a single alert by ID."""
    if _store is None:
        raise HTTPException(503, "Alert store not initialized")

    alerts = _store.get_recent_alerts(limit=10000)
    match = next((a for a in alerts if a.get("alert_id") == alert_id), None)
    if match is None:
        raise HTTPException(404, f"Alert {alert_id!r} not found")
    return AlertOut(**_normalize_alert(match))


class FalsePositiveRequest(BaseModel):
    detectors: list[str]


@router.post("/{alert_id}/false_positive")
async def mark_false_positive(
    alert_id: str,
    body: FalsePositiveRequest,
) -> dict:
    """Mark an alert as a false positive and reduce detector weights."""
    if _arbiter is None:
        raise HTTPException(503, "Ensemble arbiter not initialized")

    for detector in body.detectors:
        _arbiter.feedback(detector, was_false_positive=True)
        logger.info("FP feedback recorded for detector: %s", detector)

    return {"ok": True, "detectors_penalized": body.detectors}


# ── Helpers ────────────────────────────────────────────────────────────────

def _ts_to_float(ts) -> float:
    if ts is None:
        return 0.0
    if isinstance(ts, (int, float)):
        return float(ts)
    try:
        return ts.timestamp()
    except AttributeError:
        return 0.0


def _normalize_alert(raw: dict) -> dict:
    return {
        "alert_id": str(raw.get("alert_id", "")),
        "timestamp": str(raw.get("timestamp", "")),
        "src_ip": str(raw.get("src_ip", "")),
        "dst_ip": str(raw.get("dst_ip", "")),
        "dst_port": int(raw.get("dst_port", 0) or 0),
        "confidence": float(raw.get("confidence", 0.0) or 0.0),
        "severity": str(raw.get("severity", "LOW")),
        "shap_explanation": str(raw.get("shap_explanation", "{}")),
        "rule": raw.get("rule"),
        "detectors": raw.get("detectors"),
    }
