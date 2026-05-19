"""PacketSentry FastAPI backend.

Mounts all routers and exposes the WebSocket hub at /ws.
All components are instantiated at startup and injected into routers.

Run:
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations

import logging
import os
import time as _time

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from ws_manager import WebSocketManager
from routers import alerts as alerts_router
from routers import auth as auth_router
from routers import capture as capture_router
from routers import demo as demo_router
from routers import stats as stats_router

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

_START_TIME = _time.time()

app = FastAPI(
    title="PacketSentry API",
    description="7-model ensemble NIDS — REST + WebSocket API",
    version="1.0.0",
)

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------------------------------------------------
# Shared singletons — created once at startup
# -----------------------------------------------------------------------
_ws_manager = WebSocketManager()
_pipeline = None
_store = None
_arbiter = None
_vector_store = None


@app.on_event("startup")
async def startup() -> None:
    """Instantiate all PacketSentry components and inject into routers."""
    global _pipeline, _store, _arbiter, _vector_store

    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

    from packetsentry.capture.pipeline import DetectionPipeline
    from packetsentry.alerts.store import DuckDBAlertStore
    from packetsentry.detection.ensemble import EnsembleArbiter
    from packetsentry.storage.vector_store import ChromaStore

    db_path = os.environ.get("DUCKDB_PATH", "data/alerts.duckdb")
    chroma_path = os.environ.get("CHROMA_PATH", "data/chroma")

    _store = DuckDBAlertStore(db_path=db_path)
    _arbiter = EnsembleArbiter()
    _vector_store = ChromaStore(persist_directory=chroma_path)

    def _alert_callback(result, features, src_ip, dst_ip, dst_port):
        """Called by DetectionPipeline on every alert — stores + broadcasts."""
        import asyncio
        import json
        import time
        import uuid

        alert_id = str(uuid.uuid4())
        conf = result.confidence
        severity = _severity(conf)

        # SHAP dict
        shap = {}
        if result.explanation is not None:
            try:
                shap = {k: float(v) for k, v in
                        zip(result.explanation.feature_names, result.explanation.shap_values)}
            except Exception:
                pass

        # Persist to DuckDB
        _store.insert_alert({
            "alert_id": alert_id,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "confidence": conf,
            "severity": severity,
            "shap_explanation": json.dumps(shap),
        })

        # Determine top detectors
        top_detectors = sorted(
            result.scores.items(), key=lambda kv: kv[1], reverse=True
        )
        fired = [k for k, v in top_detectors if v > 0.5]

        # Broadcast to WS clients
        alert_event = _ws_manager.make_alert_event(
            alert_id=alert_id,
            rule=_rule_from_scores(result.scores),
            severity=severity,
            confidence=conf,
            src_ip=src_ip,
            dst_ip=dst_ip,
            port=dst_port,
            detectors=fired,
            shap=shap,
        )
        asyncio.create_task(_ws_manager.broadcast(alert_event))

    _pipeline = DetectionPipeline(alert_callback=_alert_callback)

    # Inject into routers
    alerts_router.set_dependencies(_store, _arbiter)
    capture_router.set_dependencies(_pipeline, _ws_manager)
    stats_router.set_dependencies(_pipeline, _store, _vector_store)

    admin_password = os.environ.get("PACKETSENTRY_ADMIN_PASSWORD", "admin")
    auth_router.set_admin_password(admin_password)

    logger.info("PacketSentry API started — all components ready")


# -----------------------------------------------------------------------
# Health check
# -----------------------------------------------------------------------

@app.get("/health")
async def health() -> dict:
    """Health check — no auth required."""
    from packetsentry.alerts.store import DuckDBAlertStore
    try:
        store = DuckDBAlertStore()
        alert_count = len(store.get_recent_alerts(limit=1))
        db_status = "ok"
    except Exception:
        alert_count = 0
        db_status = "error"
    return {
        "status": "ok",
        "uptime_seconds": round(_time.time() - _START_TIME),
        "db": db_status,
    }


# -----------------------------------------------------------------------
# WebSocket endpoint
# -----------------------------------------------------------------------

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket) -> None:
    """Main WebSocket hub — clients connect here for live events."""
    await _ws_manager.connect(ws)
    try:
        while True:
            # Keep connection alive; clients send pings as needed
            data = await ws.receive_text()
            if data == "ping":
                await ws.send_text('{"type":"pong"}')
    except WebSocketDisconnect:
        _ws_manager.disconnect(ws)


# -----------------------------------------------------------------------
# Include routers
# -----------------------------------------------------------------------
app.include_router(alerts_router.router)
app.include_router(capture_router.router)
app.include_router(stats_router.router)
app.include_router(auth_router.router)
app.include_router(demo_router.router)


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

def _severity(conf: float) -> str:
    if conf >= 0.80:
        return "CRITICAL"
    if conf >= 0.60:
        return "HIGH"
    if conf >= 0.40:
        return "MED"
    return "LOW"


def _rule_from_scores(scores: dict[str, float]) -> str:
    """Derive a human-readable rule name from detector scores."""
    top = max(scores.items(), key=lambda kv: kv[1], default=("unknown", 0.0))
    rules = {
        "aho_corasick": "Signature Match",
        "xgboost": "ML Anomaly",
        "gnn_detector": "Topology Anomaly",
        "transformer_ae": "Temporal Anomaly",
        "isolation_forest": "Statistical Outlier",
        "zscore": "Z-Score Spike",
        "random_forest": "ML Anomaly",
    }
    return rules.get(top[0], "Unknown")
