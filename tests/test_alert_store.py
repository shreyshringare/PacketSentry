"""Tests for DuckDBAlertStore."""

import json
from datetime import datetime

import pytest

from packetsentry.alerts.store import DuckDBAlertStore


class TestDuckDBAlertStore:
    @pytest.fixture
    def store(self):
        # Use in-memory DuckDB for tests
        return DuckDBAlertStore(db_path=":memory:")

    def test_init_creates_table(self, store) -> None:
        # If the table doesn't exist, this will throw an error
        result = store.conn.execute("SELECT count(*) FROM alerts").fetchone()
        assert result[0] == 0

    def test_insert_and_get_recent_alerts(self, store) -> None:
        now = datetime.now()
        
        alert1 = {
            "alert_id": "uuid-1",
            "timestamp": now,
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "dst_port": 80,
            "confidence": 0.95,
            "severity": "HIGH",
            "shap_explanation": json.dumps({"feature": "src_bytes", "value": 0.5})
        }
        
        alert2 = {
            "alert_id": "uuid-2",
            "timestamp": now,
            "src_ip": "1.1.1.2",
            "dst_ip": "2.2.2.2",
            "dst_port": 443,
            "confidence": 0.55,
            "severity": "MED",
            "shap_explanation": "{}"
        }

        store.insert_alert(alert1)
        store.insert_alert(alert2)

        results = store.get_recent_alerts(limit=10)
        assert len(results) == 2
        
        # Should be sorted by timestamp descending, but both are 'now'. 
        # Just check contents exist.
        ids = [r["alert_id"] for r in results]
        assert "uuid-1" in ids
        assert "uuid-2" in ids

    def test_get_stats_by_ip(self, store) -> None:
        now = datetime.now()
        
        # Insert 3 alerts from 1.1.1.1 and 1 from 2.2.2.2
        for i in range(3):
            store.insert_alert({
                "alert_id": f"uuid-{i}",
                "timestamp": now,
                "src_ip": "1.1.1.1",
                "dst_ip": "8.8.8.8",
                "dst_port": 53,
                "confidence": 0.9,
                "severity": "HIGH",
                "shap_explanation": "{}"
            })
            
        store.insert_alert({
            "alert_id": "uuid-other",
            "timestamp": now,
            "src_ip": "2.2.2.2",
            "dst_ip": "8.8.8.8",
            "dst_port": 53,
            "confidence": 0.9,
            "severity": "HIGH",
            "shap_explanation": "{}"
        })

        stats = store.get_stats_by_ip(hours=1)
        assert len(stats) == 2
        
        # Results should be ordered by count descending
        assert stats[0]["src_ip"] == "1.1.1.1"
        assert stats[0]["alert_count"] == 3
        
        assert stats[1]["src_ip"] == "2.2.2.2"
        assert stats[1]["alert_count"] == 1
