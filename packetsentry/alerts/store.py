"""DuckDB-backed structured storage for alerts.

Persists network intrusion alerts to a local DuckDB file for fast,
analytical queries needed by the dashboard (e.g. counting attacks by IP,
filtering by severity, paginating recent events).
"""

from __future__ import annotations

import logging
from typing import Any

import duckdb

logger = logging.getLogger(__name__)


class DuckDBAlertStore:
    """Stores structured alert metadata in DuckDB."""

    def __init__(self, db_path: str = "data/alerts.duckdb") -> None:
        """Initialize the DuckDB connection and schema.

        Args:
            db_path: Path to the database file. Defaults to `data/alerts.duckdb`.
                     Use `:memory:` for ephemeral testing.
        """
        self.db_path = db_path
        self.conn = duckdb.connect(db_path)
        self._init_db()

    def _init_db(self) -> None:
        """Create the alerts table if it doesn't exist."""
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id VARCHAR PRIMARY KEY,
                timestamp TIMESTAMP,
                src_ip VARCHAR,
                dst_ip VARCHAR,
                dst_port INTEGER,
                confidence DOUBLE,
                severity VARCHAR,
                shap_explanation VARCHAR
            )
        """)

    def insert_alert(self, alert: dict[str, Any]) -> None:
        """Insert a single alert into the database.

        Args:
            alert: Dictionary containing the alert fields.
        """
        try:
            self.conn.execute("""
                INSERT INTO alerts (
                    alert_id, timestamp, src_ip, dst_ip, dst_port,
                    confidence, severity, shap_explanation
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert["alert_id"],
                alert["timestamp"],
                alert["src_ip"],
                alert["dst_ip"],
                alert["dst_port"],
                alert["confidence"],
                alert["severity"],
                alert["shap_explanation"]
            ))
        except Exception as e:
            logger.error(f"Failed to insert alert {alert.get('alert_id')}: {e}")

    def get_recent_alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        """Fetch the most recent alerts.

        Args:
            limit: Maximum number of alerts to return.

        Returns:
            List of dictionaries representing the alerts.
        """
        try:
            df = self.conn.execute(
                "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?"
            , (limit,)).df()
            # Convert Pandas DataFrame to list of dicts
            return df.to_dict(orient="records")
        except Exception as e:
            logger.error(f"Failed to fetch recent alerts: {e}")
            return []

    def get_stats_by_ip(self, hours: int = 24) -> list[dict[str, Any]]:
        """Get attack counts aggregated by source IP over the last N hours.

        Args:
            hours: Number of hours to look back.

        Returns:
            List of dictionaries containing `src_ip` and `alert_count`,
            ordered descending by count.
        """
        try:
            df = self.conn.execute(f"""
                SELECT src_ip, COUNT(*) as alert_count
                FROM alerts
                WHERE timestamp >= current_timestamp - interval '{hours} hours'
                GROUP BY src_ip
                ORDER BY alert_count DESC
                LIMIT 100
            """).df()
            return df.to_dict(orient="records")
        except Exception as e:
            logger.error(f"Failed to fetch stats by IP: {e}")
            return []
