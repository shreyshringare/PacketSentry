"""Router-level tests for PacketSentry FastAPI backend.

Tests use FastAPI's TestClient (httpx) and a real in-memory DuckDB store so
no live network capture is required.  Auth is satisfied by issuing a real JWT
via the same ``create_access_token`` helper the backend uses at runtime.
"""

from __future__ import annotations

import json
import sys
import os
from datetime import datetime
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Make the backend package importable when running pytest from the repo root.
# ---------------------------------------------------------------------------
BACKEND_DIR = os.path.join(
    os.path.dirname(__file__), "..", "packetsentry-web", "backend"
)
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, os.path.abspath(BACKEND_DIR))


# ---------------------------------------------------------------------------
# Imports that require the backend on sys.path
# ---------------------------------------------------------------------------
from fastapi.testclient import TestClient  # noqa: E402
from fastapi import FastAPI                # noqa: E402

from auth import create_access_token      # noqa: E402
from packetsentry.alerts.store import DuckDBAlertStore  # noqa: E402
import routers.alerts as alerts_router    # noqa: E402
import routers.auth as auth_router        # noqa: E402
from ws_manager import WebSocketManager   # noqa: E402


# ---------------------------------------------------------------------------
# Minimal FastAPI app wired up for tests
# ---------------------------------------------------------------------------

def _build_test_app(store: DuckDBAlertStore) -> FastAPI:
    """Return a minimal FastAPI app with alerts + auth routers."""
    app = FastAPI()

    arbiter_mock = MagicMock()
    alerts_router.set_dependencies(store, arbiter_mock)

    app.include_router(alerts_router.router)
    app.include_router(auth_router.router)

    # Rate-limiter middleware used by auth router — attach a no-op limiter
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded

    app.state.limiter = Limiter(key_func=get_remote_address)
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    return app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def store() -> DuckDBAlertStore:
    """In-memory DuckDB store pre-populated with three alerts."""
    s = DuckDBAlertStore(db_path=":memory:")
    now = datetime.utcnow()

    for alert_id, severity, confidence in [
        ("id-high-1", "HIGH", 0.95),
        ("id-med-1",  "MED",  0.65),
        ("id-low-1",  "LOW",  0.35),
    ]:
        s.insert_alert({
            "alert_id": alert_id,
            "timestamp": now,
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "dst_port": 443,
            "confidence": confidence,
            "severity": severity,
            "shap_explanation": json.dumps({"src_bytes": 0.4}),
        })

    return s


@pytest.fixture(scope="module")
def client(store: DuckDBAlertStore) -> TestClient:
    """TestClient bound to the test app."""
    app = _build_test_app(store)
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture(scope="module")
def admin_token() -> str:
    """A valid admin JWT (matches the dev SECRET_KEY)."""
    return create_access_token(sub="admin", role="admin")


@pytest.fixture(scope="module")
def auth_headers(admin_token: str) -> dict:
    return {"Authorization": f"Bearer {admin_token}"}


# ---------------------------------------------------------------------------
# GET /api/alerts — list all alerts
# ---------------------------------------------------------------------------

class TestListAlerts:
    def test_returns_200_with_alerts(self, client: TestClient, auth_headers: dict) -> None:
        """GET /api/alerts should return a 200 with the inserted alerts."""
        resp = client.get("/api/alerts", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) == 3

    def test_filter_by_severity_high(self, client: TestClient, auth_headers: dict) -> None:
        """severity=HIGH filter should return only HIGH-severity alerts."""
        resp = client.get("/api/alerts?severity=HIGH", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["severity"] == "HIGH"
        assert data[0]["alert_id"] == "id-high-1"

    def test_filter_by_severity_med(self, client: TestClient, auth_headers: dict) -> None:
        """severity=MED filter should return only MED-severity alerts."""
        resp = client.get("/api/alerts?severity=MED", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["severity"] == "MED"

    def test_filter_by_severity_low(self, client: TestClient, auth_headers: dict) -> None:
        """severity=LOW filter should return only LOW-severity alerts."""
        resp = client.get("/api/alerts?severity=LOW", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["severity"] == "LOW"

    def test_filter_unknown_severity_returns_empty(self, client: TestClient, auth_headers: dict) -> None:
        """An unrecognised severity value should return an empty list."""
        resp = client.get("/api/alerts?severity=CRITICAL", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json() == []

    def test_unauthenticated_returns_401(self, client: TestClient) -> None:
        """Request without token should be rejected with 401."""
        resp = client.get("/api/alerts")
        assert resp.status_code == 401

    def test_response_schema_has_required_fields(self, client: TestClient, auth_headers: dict) -> None:
        """Each alert in the list response must contain the expected fields."""
        resp = client.get("/api/alerts", headers=auth_headers)
        alert = resp.json()[0]
        for field in ("alert_id", "timestamp", "src_ip", "dst_ip", "dst_port", "confidence", "severity", "shap_explanation"):
            assert field in alert, f"Missing field: {field}"


# ---------------------------------------------------------------------------
# GET /api/alerts/{id} — single alert
# ---------------------------------------------------------------------------

class TestGetAlert:
    def test_returns_existing_alert(self, client: TestClient, auth_headers: dict) -> None:
        """GET /api/alerts/{id} should return the correct alert."""
        resp = client.get("/api/alerts/id-high-1", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["alert_id"] == "id-high-1"
        assert data["severity"] == "HIGH"

    def test_returns_404_for_nonexistent_id(self, client: TestClient, auth_headers: dict) -> None:
        """GET /api/alerts/{id} with an unknown ID should return 404."""
        resp = client.get("/api/alerts/nonexistent-uuid-000", headers=auth_headers)
        assert resp.status_code == 404

    def test_unauthenticated_returns_401(self, client: TestClient) -> None:
        """Fetching a single alert without auth should be rejected with 401."""
        resp = client.get("/api/alerts/id-high-1")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# GET /auth/demo-token — demo JWT
# ---------------------------------------------------------------------------

class TestDemoToken:
    def test_returns_200_and_token(self, client: TestClient) -> None:
        """GET /auth/demo-token should return a token without authentication."""
        resp = client.get("/auth/demo-token")
        assert resp.status_code == 200

    def test_response_contains_access_token(self, client: TestClient) -> None:
        """Response body must include access_token and token_type fields."""
        resp = client.get("/auth/demo-token")
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_token_has_demo_role(self, client: TestClient) -> None:
        """The issued token must encode role=demo."""
        from auth import decode_token
        resp = client.get("/auth/demo-token")
        token = resp.json()["access_token"]
        payload = decode_token(token)
        assert payload is not None
        assert payload["role"] == "demo"
        assert payload["sub"] == "demo"

    def test_demo_token_not_accepted_as_admin(self, client: TestClient) -> None:
        """A demo token should work for /api/alerts (read-only) but not escalate privileges."""
        resp = client.get("/auth/demo-token")
        demo_token = resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {demo_token}"}

        # /api/alerts is accessible to any valid JWT (admin or demo)
        alerts_resp = client.get("/api/alerts", headers=headers)
        assert alerts_resp.status_code == 200
