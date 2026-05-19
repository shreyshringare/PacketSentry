# packetsentry-web/backend/routers/demo.py
"""Read-only demo endpoints — serve fixture data for demo JWT users."""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status

from dependencies import get_current_user

router = APIRouter(prefix="/api/demo", tags=["demo"])

_DEMO_DATA_PATH = Path(__file__).parent.parent / "data" / "demo_alerts.json"

# Cache at import time — file is static, no need to re-read per request
try:
    with open(_DEMO_DATA_PATH) as _f:
        _DEMO_ALERTS: list[dict] = json.load(_f)
except (FileNotFoundError, json.JSONDecodeError):
    _DEMO_ALERTS = []


def _load_demo_alerts() -> list[dict]:
    return _DEMO_ALERTS


def _require_demo_or_admin(user: dict = Depends(get_current_user)) -> dict:
    """Allow demo and admin roles."""
    if user.get("role") not in ("demo", "admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    return user


@router.get("/alerts")
def demo_alerts(_user: dict = Depends(_require_demo_or_admin)) -> list[dict]:
    """Return pre-recorded demo alerts."""
    return _load_demo_alerts()


@router.get("/stats")
def demo_stats(_user: dict = Depends(_require_demo_or_admin)) -> dict:
    """Return static demo statistics."""
    return {
        "packets": 48203,
        "completed_flows": 1247,
        "alerts": 5,
        "pps": 214.7,
        "ensemble_conf": 0.73,
        "active_flows": 23,
    }
