# packetsentry-web/backend/routers/admin.py
"""Admin-only endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from audit import get_recent_events
from dependencies import require_admin

router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.get("/audit")
def audit_log(
    limit: int = 100,
    _user: dict = Depends(require_admin),
) -> list[dict]:
    """Return recent auth events. Admin only."""
    return get_recent_events(limit=limit)
