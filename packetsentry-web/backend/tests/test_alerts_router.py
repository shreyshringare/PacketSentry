"""Tests for alerts router."""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock


def _make_app(mock_alerts):
    from fastapi import FastAPI
    import sys
    sys.path.insert(0, "packetsentry-web/backend")
    from routers.alerts import router, set_dependencies

    mock_store = MagicMock()
    mock_store.get_recent_alerts.return_value = mock_alerts
    mock_arbiter = MagicMock()
    set_dependencies(mock_store, mock_arbiter)

    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_list_alerts_returns_list():
    _ALERTS = [{
        "alert_id": "abc123", "timestamp": "2026-01-01 00:00:00",
        "src_ip": "1.2.3.4", "dst_ip": "5.6.7.8", "dst_port": 80,
        "confidence": 0.91, "severity": "CRITICAL", "shap_explanation": "{}",
        "rule": "SYN flood", "detectors": '["xgboost","gnn_detector"]',
    }]
    client = _make_app(_ALERTS)
    resp = client.get("/api/alerts")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["alert_id"] == "abc123"


def test_get_alert_not_found():
    client = _make_app([])
    resp = client.get("/api/alerts/does-not-exist")
    assert resp.status_code == 404
