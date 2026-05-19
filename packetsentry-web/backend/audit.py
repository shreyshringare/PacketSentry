# packetsentry-web/backend/audit.py
"""Audit log — records auth events to DuckDB for security visibility."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

import duckdb

logger = logging.getLogger(__name__)

_AUDIT_DB = Path("data/audit.duckdb")


def _get_conn() -> duckdb.DuckDBPyConnection:
    _AUDIT_DB.parent.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(_AUDIT_DB))
    con.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id        VARCHAR DEFAULT gen_random_uuid() PRIMARY KEY,
            ts        TIMESTAMP NOT NULL,
            event     VARCHAR NOT NULL,
            ip        VARCHAR,
            success   BOOLEAN NOT NULL,
            detail    VARCHAR
        )
    """)
    return con


def log_event(event: str, ip: str | None, success: bool, detail: str = "") -> None:
    """Write one audit record. Silently swallows errors — never crash the request."""
    try:
        con = _get_conn()
        con.execute(
            "INSERT INTO audit_log (ts, event, ip, success, detail) VALUES (?, ?, ?, ?, ?)",
            [datetime.now(timezone.utc), event, ip or "unknown", success, detail],
        )
        con.close()
        logger.info("audit_event", extra={"event": event, "ip": ip, "success": success})
    except Exception as exc:  # noqa: BLE001
        logger.warning("audit_log_failed", extra={"error": str(exc)})


def get_recent_events(limit: int = 100) -> list[dict]:
    """Return recent audit events newest-first."""
    try:
        con = _get_conn()
        rows = con.execute(
            "SELECT id, ts, event, ip, success, detail FROM audit_log ORDER BY ts DESC LIMIT ?",
            [limit],
        ).fetchall()
        con.close()
        keys = ["id", "ts", "event", "ip", "success", "detail"]
        return [dict(zip(keys, r)) for r in rows]
    except Exception:
        return []
