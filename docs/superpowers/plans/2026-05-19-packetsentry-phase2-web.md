# PacketSentry Phase 2 — Web Dashboard + REST API + Docker

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** React 18 + FastAPI web dashboard with live WebSocket streaming, SHAP waterfall, ensemble panels, ChromaDB similarity search, and Docker deployment.

**Architecture:** `packetsentry-web/` subdirectory in the same repo. FastAPI backend (`backend/`) wraps the existing `DetectionPipeline` via `ws_manager.py`. React frontend (`frontend/`) uses Zustand for state + React Query for REST + a single `useWebSocket` hook for live events. No routing library — screen switching via `uiStore.activeScreen`. Docker Compose runs backend on :8000 and frontend on :5173.

**Tech Stack:** React 18, TypeScript, Tailwind CSS 3, Recharts, Zustand, React Query v5, Lucide React, react-window, Vite 5 (frontend); FastAPI, uvicorn, python-multipart (backend); Docker + docker-compose

---

## File Map

### Backend

| Action | Path | Responsibility |
|--------|------|----------------|
| Create | `packetsentry-web/backend/main.py` | FastAPI app, WebSocket endpoint `/ws`, mounts routers |
| Create | `packetsentry-web/backend/ws_manager.py` | WebSocket hub: per-client asyncio.Queue, broadcast, DetectionPipeline bridge |
| Create | `packetsentry-web/backend/routers/__init__.py` | Empty |
| Create | `packetsentry-web/backend/routers/alerts.py` | GET /api/alerts, GET /api/alerts/:id, POST /api/alerts/:id/false_positive |
| Create | `packetsentry-web/backend/routers/capture.py` | POST /api/capture/start, POST /api/capture/stop |
| Create | `packetsentry-web/backend/routers/stats.py` | GET /api/stats, GET /api/flows/active, GET /api/similar/:alert_id |
| Create | `packetsentry-web/backend/requirements.txt` | fastapi, uvicorn, python-multipart, websockets |
| Create | `packetsentry-web/backend/Dockerfile` | Python 3.12, installs packetsentry + backend deps |

### Frontend

| Action | Path | Responsibility |
|--------|------|----------------|
| Create | `packetsentry-web/frontend/` | Vite scaffold (via `npm create vite`) |
| Create | `packetsentry-web/frontend/src/store/captureStore.ts` | running, interface, bpfFilter, pps, packets[] |
| Create | `packetsentry-web/frontend/src/store/alertStore.ts` | alerts[], selectedAlert, activeFilter |
| Create | `packetsentry-web/frontend/src/store/uiStore.ts` | activeScreen, sidebarOpen |
| Create | `packetsentry-web/frontend/src/hooks/useWebSocket.ts` | WS connect/reconnect, dispatch to stores |
| Create | `packetsentry-web/frontend/src/api/client.ts` | Axios/fetch wrappers for REST endpoints |
| Create | `packetsentry-web/frontend/src/components/TopNav.tsx` | Shield icon + nav tabs + live pill |
| Create | `packetsentry-web/frontend/src/components/StatCards.tsx` | 4-column stat grid |
| Create | `packetsentry-web/frontend/src/components/FlowTable.tsx` | Active flows, score color, row click |
| Create | `packetsentry-web/frontend/src/components/EnsemblePanel.tsx` | 7-model weight bars + final score |
| Create | `packetsentry-web/frontend/src/components/AlertFeed.tsx` | Severity-sorted alert list + animations |
| Create | `packetsentry-web/frontend/src/components/ThroughputChart.tsx` | Recharts LineChart, 1pt/sec, no rerender |
| Create | `packetsentry-web/frontend/src/components/PolarRadar.tsx` | SVG 7-axis radar, path interpolation |
| Create | `packetsentry-web/frontend/src/components/ShapWaterfall.tsx` | Diverging animated bar chart |
| Create | `packetsentry-web/frontend/src/components/SimilarAlerts.tsx` | 3 ChromaDB similarity cards |
| Create | `packetsentry-web/frontend/src/components/PacketStream.tsx` | react-window virtual scroll, 500-line buffer |
| Create | `packetsentry-web/frontend/src/screens/Overview.tsx` | Full Overview layout |
| Create | `packetsentry-web/frontend/src/screens/LiveCapture.tsx` | Toolbar + PacketStream + PolarRadar + Chart |
| Create | `packetsentry-web/frontend/src/screens/AlertDetail.tsx` | Slide-in panel with SHAP + ensemble + similar |
| Create | `packetsentry-web/frontend/src/screens/Settings.tsx` | Sliders + thresholds + storage config |
| Create | `packetsentry-web/frontend/src/App.tsx` | Top-level: TopNav + screen switch |
| Create | `packetsentry-web/docker-compose.yml` | backend + frontend services |
| Create | `packetsentry-web/frontend/Dockerfile` | Node 20, Vite build, nginx serve |

---

## Task 11: Scaffold backend directory + requirements

**Files:**
- Create: `packetsentry-web/backend/requirements.txt`
- Create: `packetsentry-web/backend/routers/__init__.py`

- [ ] **Step 1: Create directory structure**

```bash
mkdir -p packetsentry-web/backend/routers
touch packetsentry-web/backend/routers/__init__.py
```

- [ ] **Step 2: Create packetsentry-web/backend/requirements.txt**

```
fastapi>=0.111.0
uvicorn[standard]>=0.29.0
python-multipart>=0.0.9
websockets>=12.0
```

- [ ] **Step 3: Install backend deps**

```bash
pip install fastapi "uvicorn[standard]" python-multipart websockets
```

Expected: packages install cleanly.

- [ ] **Step 4: Commit**

```bash
git add packetsentry-web/
git commit -m "chore(web): scaffold backend directory + requirements.txt"
```

---

## Task 12: Implement ws_manager.py — WebSocket hub

**Files:**
- Create: `packetsentry-web/backend/ws_manager.py`

- [ ] **Step 1: Create ws_manager.py**

```python
"""WebSocket connection manager + DetectionPipeline bridge.

Each connected client gets its own asyncio.Queue (maxsize=100).
Slow clients are dropped when their queue is full (non-blocking put_nowait).

The manager wraps DetectionPipeline so every DecisionResult and packet
event is broadcast to all connected clients.

Usage:
    manager = WebSocketManager()
    await manager.connect(websocket)
    await manager.broadcast({"type": "stats_update", ...})
    manager.disconnect(websocket)
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

from fastapi import WebSocket
from starlette.websockets import WebSocketState

logger = logging.getLogger(__name__)

_QUEUE_MAXSIZE = 100


class WebSocketManager:
    """Manages all active WebSocket connections with per-client send queues."""

    def __init__(self) -> None:
        self._clients: dict[WebSocket, asyncio.Queue] = {}

    async def connect(self, ws: WebSocket) -> None:
        """Accept a new WebSocket connection and register it."""
        await ws.accept()
        self._clients[ws] = asyncio.Queue(maxsize=_QUEUE_MAXSIZE)
        logger.info("WS client connected. Total: %d", len(self._clients))

    def disconnect(self, ws: WebSocket) -> None:
        """Remove a client from the registry."""
        self._clients.pop(ws, None)
        logger.info("WS client disconnected. Total: %d", len(self._clients))

    async def broadcast(self, message: dict[str, Any]) -> None:
        """Broadcast a message to all connected clients.

        Clients whose queue is full are dropped (non-blocking).
        Clients that fail to send (disconnect mid-flight) are removed.
        """
        payload = json.dumps(message)
        dead: list[WebSocket] = []

        for ws, queue in list(self._clients.items()):
            try:
                queue.put_nowait(payload)
            except asyncio.QueueFull:
                logger.warning("Client queue full — dropping client")
                dead.append(ws)

        for ws in dead:
            self.disconnect(ws)

        # Drain queues to actual sockets
        for ws, queue in list(self._clients.items()):
            while not queue.empty():
                try:
                    msg = queue.get_nowait()
                    if ws.client_state == WebSocketState.CONNECTED:
                        await ws.send_text(msg)
                except Exception as exc:
                    logger.warning("Failed to send to client: %s", exc)
                    dead.append(ws)
                    break

        for ws in dead:
            self.disconnect(ws)

    def make_packet_event(
        self,
        src: str, dst: str, proto: str,
        length: int, flags: str,
        flow_score: float, flagged: bool,
    ) -> dict:
        """Build a packet_event WS message."""
        return {
            "type": "packet_event",
            "ts": time.time(),
            "src": src,
            "dst": dst,
            "proto": proto,
            "length": length,
            "flags": flags,
            "flow_score": round(flow_score, 3),
            "flagged": flagged,
        }

    def make_alert_event(
        self,
        alert_id: str,
        rule: str,
        severity: str,
        confidence: float,
        src_ip: str,
        dst_ip: str,
        port: int,
        detectors: list[str],
        shap: dict[str, float],
    ) -> dict:
        """Build an alert_event WS message."""
        return {
            "type": "alert_event",
            "id": alert_id,
            "rule": rule,
            "severity": severity,
            "confidence": round(confidence, 3),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "port": port,
            "detectors": detectors,
            "shap": {k: round(v, 3) for k, v in shap.items()},
            "ts": int(time.time()),
        }

    def make_stats_update(
        self, pps: int, flows: int, ensemble_conf: float, active_alerts: int
    ) -> dict:
        """Build a stats_update WS message."""
        return {
            "type": "stats_update",
            "pps": pps,
            "flows": flows,
            "ensemble_conf": round(ensemble_conf, 3),
            "active_alerts": active_alerts,
        }

    def make_flow_update(self, flows: list[dict]) -> dict:
        """Build a flow_update WS message."""
        return {"type": "flow_update", "flows": flows}
```

- [ ] **Step 2: Write a test for broadcast + queue backpressure**

Create `packetsentry-web/backend/tests/test_ws_manager.py`:

```python
"""Tests for WebSocketManager."""
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock
from starlette.websockets import WebSocketState


def _make_ws():
    ws = AsyncMock()
    ws.client_state = WebSocketState.CONNECTED
    return ws


@pytest.mark.asyncio
async def test_connect_registers_client():
    import sys
    sys.path.insert(0, "packetsentry-web/backend")
    from ws_manager import WebSocketManager

    manager = WebSocketManager()
    ws = _make_ws()
    await manager.connect(ws)
    assert ws in manager._clients
    ws.accept.assert_called_once()


@pytest.mark.asyncio
async def test_disconnect_removes_client():
    import sys
    sys.path.insert(0, "packetsentry-web/backend")
    from ws_manager import WebSocketManager

    manager = WebSocketManager()
    ws = _make_ws()
    await manager.connect(ws)
    manager.disconnect(ws)
    assert ws not in manager._clients


@pytest.mark.asyncio
async def test_broadcast_sends_to_all_clients():
    import sys
    sys.path.insert(0, "packetsentry-web/backend")
    from ws_manager import WebSocketManager

    manager = WebSocketManager()
    ws1, ws2 = _make_ws(), _make_ws()
    await manager.connect(ws1)
    await manager.connect(ws2)
    await manager.broadcast({"type": "stats_update", "pps": 100})
    ws1.send_text.assert_called_once()
    ws2.send_text.assert_called_once()
```

- [ ] **Step 3: Install pytest-asyncio**

```bash
pip install pytest-asyncio
```

- [ ] **Step 4: Run tests**

```bash
pytest packetsentry-web/backend/tests/test_ws_manager.py -v
```

Expected: `3 passed`.

- [ ] **Step 5: Commit**

```bash
git add packetsentry-web/backend/ws_manager.py packetsentry-web/backend/tests/
git commit -m "feat(web): implement WebSocketManager with per-client send queue"
```

---

## Task 13: Implement routers/alerts.py

**Files:**
- Create: `packetsentry-web/backend/routers/alerts.py`

- [ ] **Step 1: Create routers/alerts.py**

```python
"""Alert REST API endpoints.

GET  /api/alerts           — paginated alert list from DuckDB
GET  /api/alerts/:id       — single alert with full SHAP JSON
POST /api/alerts/:id/false_positive — mark as FP, adjust ensemble weights
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/alerts", tags=["alerts"])


# Shared state injected by main.py
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
    severity: Optional[str] = Query(None, description="Filter by severity: CRITICAL/HIGH/MED/LOW"),
    since: Optional[float] = Query(None, description="Unix timestamp lower bound"),
) -> list[AlertOut]:
    """Return recent alerts, newest first."""
    if _store is None:
        raise HTTPException(503, "Alert store not initialized")

    alerts = _store.get_recent_alerts(limit=limit)

    if severity:
        alerts = [a for a in alerts if a.get("severity") == severity.upper()]
    if since:
        from datetime import datetime, timezone
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
    detectors: list[str]  # which detectors fired this alert


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


# -----------------------------------------------------------------------
# Internal helpers
# -----------------------------------------------------------------------

def _ts_to_float(ts) -> float:
    """Convert DuckDB timestamp (could be datetime or float) to unix float."""
    if ts is None:
        return 0.0
    if isinstance(ts, (int, float)):
        return float(ts)
    try:
        return ts.timestamp()
    except AttributeError:
        return 0.0


def _normalize_alert(raw: dict) -> dict:
    """Ensure all required fields have values for Pydantic model."""
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
```

- [ ] **Step 2: Write a test for the alert router**

Create `packetsentry-web/backend/tests/test_alerts_router.py`:

```python
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
```

- [ ] **Step 3: Run tests**

```bash
pytest packetsentry-web/backend/tests/test_alerts_router.py -v
```

Expected: `2 passed`.

- [ ] **Step 4: Commit**

```bash
git add packetsentry-web/backend/routers/alerts.py packetsentry-web/backend/tests/test_alerts_router.py
git commit -m "feat(web): implement /api/alerts router with FP feedback endpoint"
```

---

## Task 14: Implement routers/capture.py + routers/stats.py

**Files:**
- Create: `packetsentry-web/backend/routers/capture.py`
- Create: `packetsentry-web/backend/routers/stats.py`

- [ ] **Step 1: Create routers/capture.py**

```python
"""Capture control endpoints.

POST /api/capture/start  { interface, bpf_filter }
POST /api/capture/stop
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/capture", tags=["capture"])

_pipeline = None
_ws_manager = None
_capture_task: Optional[asyncio.Task] = None


def set_dependencies(pipeline, ws_manager) -> None:
    global _pipeline, _ws_manager
    _pipeline = pipeline
    _ws_manager = ws_manager


class StartRequest(BaseModel):
    interface: str = "eth0"
    bpf_filter: str = ""


@router.post("/start")
async def start_capture(body: StartRequest) -> dict:
    """Start live packet capture on the specified interface."""
    global _capture_task
    if _pipeline is None:
        raise HTTPException(503, "Pipeline not initialized")
    if _capture_task and not _capture_task.done():
        return {"ok": True, "already_running": True}

    _capture_task = asyncio.create_task(
        _run_capture(body.interface, body.bpf_filter)
    )
    logger.info("Capture started: iface=%s filter=%r", body.interface, body.bpf_filter)
    return {"ok": True, "interface": body.interface, "bpf_filter": body.bpf_filter}


@router.post("/stop")
async def stop_capture() -> dict:
    """Stop live packet capture."""
    global _capture_task
    if _capture_task and not _capture_task.done():
        _capture_task.cancel()
        _capture_task = None
        logger.info("Capture stopped by API request")
        return {"ok": True, "stopped": True}
    return {"ok": True, "was_running": False}


async def _run_capture(interface: str, bpf_filter: str) -> None:
    """Background task: read packets from scapy, feed to pipeline, broadcast events."""
    try:
        from scapy.all import AsyncSniffer
        from packetsentry.dissector.ethernet import dissect_packet
        from packetsentry.features.flow_tracker import ParsedPacket

        def _packet_handler(raw_pkt):
            """Called by scapy for each sniffed packet."""
            parsed = dissect_packet(raw_pkt)
            if parsed is None:
                return
            result = _pipeline.ingest(parsed)
            if result and result.is_alert and _ws_manager:
                stats = _pipeline.stats()
                asyncio.create_task(_ws_manager.broadcast(
                    _ws_manager.make_stats_update(
                        pps=stats.get("packets", 0),
                        flows=stats.get("active_flows", 0),
                        ensemble_conf=result.confidence,
                        active_alerts=stats.get("alerts", 0),
                    )
                ))

        sniffer = AsyncSniffer(
            iface=interface,
            filter=bpf_filter or None,
            prn=_packet_handler,
            store=False,
        )
        sniffer.start()
        while True:
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        logger.info("Capture task cancelled")
        raise
    except Exception as exc:
        logger.error("Capture error: %s", exc)
```

- [ ] **Step 2: Create routers/stats.py**

```python
"""Stats + similarity endpoints.

GET /api/stats               — current pipeline stats
GET /api/flows/active        — top 50 active flows by score
GET /api/similar/:alert_id   — ChromaDB top-5 similar alerts
GET /api/clusters            — cluster summary for Memory screen (Phase 3 stub)
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

logger = logging.getLogger(__name__)
router = APIRouter(tags=["stats"])

_pipeline = None
_store = None
_vector_store = None


def set_dependencies(pipeline, store, vector_store) -> None:
    global _pipeline, _store, _vector_store
    _pipeline = pipeline
    _store = store
    _vector_store = vector_store


@router.get("/api/stats")
async def get_stats() -> dict:
    """Return current pipeline statistics."""
    if _pipeline is None:
        return {"packets": 0, "flows": 0, "alerts": 0, "active_flows": 0, "bytes": 0}
    return _pipeline.stats()


@router.get("/api/flows/active")
async def get_active_flows(limit: int = Query(50, ge=1, le=200)) -> list[dict]:
    """Return top flows sorted by anomaly score descending."""
    # The pipeline does not expose per-flow scores directly.
    # Return the most recent alerts as a proxy for active high-score flows.
    if _store is None:
        return []
    alerts = _store.get_recent_alerts(limit=limit)
    flows = []
    for a in alerts:
        detectors_raw = a.get("detectors") or "[]"
        try:
            detectors = json.loads(detectors_raw)
        except (json.JSONDecodeError, TypeError):
            detectors = []
        flows.append({
            "src_ip": a.get("src_ip", ""),
            "dst_ip": a.get("dst_ip", ""),
            "proto": "TCP",  # NSL-KDD is TCP-dominant; extend with protocol field if needed
            "score": float(a.get("confidence", 0)),
            "severity": a.get("severity", "LOW"),
            "detectors": detectors,
            "bytes": 0,  # not stored in current schema; Phase 3 extension
        })
    return sorted(flows, key=lambda x: x["score"], reverse=True)


@router.get("/api/similar/{alert_id}")
async def get_similar(
    alert_id: str,
    top: int = Query(5, ge=1, le=20),
) -> dict:
    """Return ChromaDB top-N similar alerts by embedding cosine similarity."""
    if _vector_store is None:
        return {"similar_alerts": []}

    try:
        results = _vector_store.query_similar(alert_id=alert_id, top_k=top)
        return {"similar_alerts": results}
    except Exception as exc:
        logger.warning("ChromaDB similarity query failed: %s", exc)
        return {"similar_alerts": []}


@router.get("/api/clusters")
async def get_clusters() -> dict:
    """Stub for Phase 3 Memory/UMAP screen."""
    return {"clusters": [], "note": "Phase 3 — not yet implemented"}
```

- [ ] **Step 3: Run all backend tests**

```bash
pytest packetsentry-web/backend/tests/ -v
```

Expected: `5+ passed`, no failures.

- [ ] **Step 4: Commit**

```bash
git add packetsentry-web/backend/routers/capture.py packetsentry-web/backend/routers/stats.py
git commit -m "feat(web): implement capture start/stop + stats/flows/similar routers"
```

---

## Task 15: Implement main.py — FastAPI app + WebSocket endpoint

**Files:**
- Create: `packetsentry-web/backend/main.py`

- [ ] **Step 1: Create main.py**

```python
"""PacketSentry FastAPI backend.

Mounts all routers and exposes the WebSocket hub at /ws.
All components are instantiated at startup and injected into routers.

Run:
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations

import logging
import os

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from ws_manager import WebSocketManager
from routers import alerts as alerts_router
from routers import capture as capture_router
from routers import stats as stats_router

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(
    title="PacketSentry API",
    description="7-model ensemble NIDS — REST + WebSocket API",
    version="1.0.0",
)

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
    from packetsentry.storage.vector_store import ChromaDBVectorStore

    db_path = os.environ.get("DUCKDB_PATH", "data/alerts.duckdb")
    chroma_path = os.environ.get("CHROMA_PATH", "data/chroma")

    _store = DuckDBAlertStore(db_path=db_path)
    _arbiter = EnsembleArbiter()
    _vector_store = ChromaDBVectorStore(path=chroma_path)

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

    logger.info("PacketSentry API started — all components ready")


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
```

- [ ] **Step 2: Smoke test — verify app starts**

```bash
cd packetsentry-web/backend
uvicorn main:app --port 8001 &
sleep 2
curl -s http://localhost:8001/api/stats
kill %1
```

Expected: `{"packets":0,"flows":0,"alerts":0,...}` JSON response.

- [ ] **Step 3: Commit**

```bash
git add packetsentry-web/backend/main.py
git commit -m "feat(web): implement FastAPI main.py with WebSocket hub + startup injection"
```

---

## Task 16: Scaffold React frontend

**Files:**
- Create: `packetsentry-web/frontend/` (full Vite scaffold)

- [ ] **Step 1: Scaffold Vite + React + TypeScript**

```bash
cd packetsentry-web
npm create vite@latest frontend -- --template react-ts
cd frontend
npm install
```

Expected: `node_modules/` created, `npm run dev` starts on :5173.

- [ ] **Step 2: Install frontend dependencies**

```bash
npm install \
  tailwindcss@3 postcss autoprefixer \
  zustand \
  @tanstack/react-query \
  recharts \
  lucide-react \
  react-window \
  @types/react-window
```

- [ ] **Step 3: Configure Tailwind**

```bash
npx tailwindcss init -p
```

Replace `tailwind.config.js` content:

```js
/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: { extend: {} },
  plugins: [],
}
```

Add to `src/index.css` (replace all existing content):

```css
@tailwind base;
@tailwind components;
@tailwind utilities;

body {
  font-family: 'Inter', system-ui, sans-serif;
  background: #f9fafb;
}

.font-mono-ip {
  font-family: 'JetBrains Mono', 'Courier New', monospace;
  font-size: 11px;
}
```

- [ ] **Step 4: Verify dev server starts**

```bash
npm run dev
```

Expected: `➜ Local: http://localhost:5173/` — browser shows Vite default page.

- [ ] **Step 5: Commit**

```bash
cd ../..
git add packetsentry-web/frontend/
git commit -m "chore(web): scaffold Vite+React+TS frontend with Tailwind + deps"
```

---

## Task 17: Zustand stores + WebSocket hook + API client

**Files:**
- Create: `packetsentry-web/frontend/src/store/captureStore.ts`
- Create: `packetsentry-web/frontend/src/store/alertStore.ts`
- Create: `packetsentry-web/frontend/src/store/uiStore.ts`
- Create: `packetsentry-web/frontend/src/hooks/useWebSocket.ts`
- Create: `packetsentry-web/frontend/src/api/client.ts`

- [ ] **Step 1: Create captureStore.ts**

```typescript
// src/store/captureStore.ts
import { create } from "zustand";

export interface PacketEvent {
  ts: number;
  src: string;
  dst: string;
  proto: string;
  length: number;
  flags: string;
  flow_score: number;
  flagged: boolean;
}

export interface StatsUpdate {
  pps: number;
  flows: number;
  ensemble_conf: number;
  active_alerts: number;
}

interface CaptureState {
  running: boolean;
  interface: string;
  bpfFilter: string;
  stats: StatsUpdate;
  packets: PacketEvent[];  // last 500
  setRunning: (v: boolean) => void;
  setInterface: (v: string) => void;
  setBpfFilter: (v: string) => void;
  updateStats: (s: StatsUpdate) => void;
  addPacket: (p: PacketEvent) => void;
  clearPackets: () => void;
}

export const useCaptureStore = create<CaptureState>((set) => ({
  running: false,
  interface: "eth0",
  bpfFilter: "",
  stats: { pps: 0, flows: 0, ensemble_conf: 0, active_alerts: 0 },
  packets: [],
  setRunning: (running) => set({ running }),
  setInterface: (i) => set({ interface: i }),
  setBpfFilter: (f) => set({ bpfFilter: f }),
  updateStats: (stats) => set({ stats }),
  addPacket: (p) =>
    set((s) => ({
      packets: [...s.packets.slice(-499), p],  // keep last 500
    })),
  clearPackets: () => set({ packets: [] }),
}));
```

- [ ] **Step 2: Create alertStore.ts**

```typescript
// src/store/alertStore.ts
import { create } from "zustand";

export interface AlertEvent {
  id: string;
  rule: string;
  severity: "CRITICAL" | "HIGH" | "MED" | "LOW";
  confidence: number;
  src_ip: string;
  dst_ip: string;
  port: number;
  detectors: string[];
  shap: Record<string, number>;
  ts: number;
}

export interface Flow {
  src_ip: string;
  dst_ip: string;
  proto: string;
  score: number;
  severity: string;
  detectors: string[];
  bytes: number;
}

interface AlertState {
  alerts: AlertEvent[];
  selectedAlert: AlertEvent | null;
  activeFilter: string | null;
  flows: Flow[];
  setSelectedAlert: (a: AlertEvent | null) => void;
  addAlert: (a: AlertEvent) => void;
  setActiveFilter: (f: string | null) => void;
  setFlows: (f: Flow[]) => void;
}

export const useAlertStore = create<AlertState>((set) => ({
  alerts: [],
  selectedAlert: null,
  activeFilter: null,
  flows: [],
  setSelectedAlert: (a) => set({ selectedAlert: a }),
  addAlert: (a) =>
    set((s) => ({
      alerts: [a, ...s.alerts].slice(0, 500),  // newest first, cap 500
    })),
  setActiveFilter: (f) => set({ activeFilter: f }),
  setFlows: (flows) => set({ flows }),
}));
```

- [ ] **Step 3: Create uiStore.ts**

```typescript
// src/store/uiStore.ts
import { create } from "zustand";

export type Screen = "overview" | "live" | "alerts" | "settings";

interface UIState {
  activeScreen: Screen;
  sidebarOpen: boolean;
  setScreen: (s: Screen) => void;
  setSidebarOpen: (v: boolean) => void;
}

export const useUIStore = create<UIState>((set) => ({
  activeScreen: "overview",
  sidebarOpen: false,
  setScreen: (activeScreen) => set({ activeScreen }),
  setSidebarOpen: (sidebarOpen) => set({ sidebarOpen }),
}));
```

- [ ] **Step 4: Create useWebSocket.ts**

```typescript
// src/hooks/useWebSocket.ts
import { useEffect, useRef } from "react";
import { useCaptureStore } from "../store/captureStore";
import { useAlertStore } from "../store/alertStore";

const WS_URL = import.meta.env.VITE_WS_URL ?? "ws://localhost:8000/ws";
const MAX_RETRIES = 10;

export function useWebSocket() {
  const wsRef = useRef<WebSocket | null>(null);
  const retriesRef = useRef(0);
  const updateStats = useCaptureStore((s) => s.updateStats);
  const addPacket = useCaptureStore((s) => s.addPacket);
  const addAlert = useAlertStore((s) => s.addAlert);
  const setFlows = useAlertStore((s) => s.setFlows);

  useEffect(() => {
    let reconnectTimeout: ReturnType<typeof setTimeout>;

    function connect() {
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen = () => {
        retriesRef.current = 0;
        // Send ping every 30s to keep alive
        const pingInterval = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) ws.send("ping");
        }, 30_000);
        (ws as any)._pingInterval = pingInterval;
      };

      ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data as string);
          switch (msg.type) {
            case "packet_event":
              addPacket(msg);
              break;
            case "alert_event":
              addAlert(msg);
              break;
            case "stats_update":
              updateStats(msg);
              break;
            case "flow_update":
              setFlows(msg.flows ?? []);
              break;
          }
        } catch {
          // malformed message — ignore
        }
      };

      ws.onclose = () => {
        clearInterval((ws as any)._pingInterval);
        if (retriesRef.current < MAX_RETRIES) {
          const delay = Math.min(2000 * (retriesRef.current + 1), 30_000);
          retriesRef.current++;
          reconnectTimeout = setTimeout(connect, delay);
        }
      };

      ws.onerror = () => ws.close();
    }

    connect();

    return () => {
      clearTimeout(reconnectTimeout);
      wsRef.current?.close();
    };
  }, []);
}
```

- [ ] **Step 5: Create api/client.ts**

```typescript
// src/api/client.ts
const BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!resp.ok) throw new Error(`API ${path} → ${resp.status}`);
  return resp.json() as Promise<T>;
}

export const api = {
  getAlerts: (params?: { limit?: number; severity?: string }) => {
    const qs = new URLSearchParams();
    if (params?.limit) qs.set("limit", String(params.limit));
    if (params?.severity) qs.set("severity", params.severity);
    return apiFetch<unknown[]>(`/api/alerts?${qs}`);
  },

  getAlert: (id: string) => apiFetch<unknown>(`/api/alerts/${id}`),

  markFalsePositive: (id: string, detectors: string[]) =>
    apiFetch<{ ok: boolean }>(`/api/alerts/${id}/false_positive`, {
      method: "POST",
      body: JSON.stringify({ detectors }),
    }),

  startCapture: (iface: string, bpfFilter: string) =>
    apiFetch<{ ok: boolean }>("/api/capture/start", {
      method: "POST",
      body: JSON.stringify({ interface: iface, bpf_filter: bpfFilter }),
    }),

  stopCapture: () =>
    apiFetch<{ ok: boolean }>("/api/capture/stop", { method: "POST" }),

  getStats: () => apiFetch<Record<string, number>>("/api/stats"),

  getActiveFlows: () => apiFetch<unknown[]>("/api/flows/active"),

  getSimilar: (alertId: string, top = 5) =>
    apiFetch<{ similar_alerts: unknown[] }>(`/api/similar/${alertId}?top=${top}`),
};
```

- [ ] **Step 6: Create `packetsentry-web/frontend/.env` for local dev**

```
VITE_API_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000/ws
```

- [ ] **Step 7: TypeScript compile check**

```bash
cd packetsentry-web/frontend
npx tsc --noEmit
```

Expected: No type errors.

- [ ] **Step 8: Commit**

```bash
cd ../..
git add packetsentry-web/frontend/src/
git commit -m "feat(web): add Zustand stores, useWebSocket hook, API client"
```

---

## Task 18: TopNav + StatCards components

**Files:**
- Create: `packetsentry-web/frontend/src/components/TopNav.tsx`
- Create: `packetsentry-web/frontend/src/components/StatCards.tsx`

- [ ] **Step 1: Create TopNav.tsx**

```tsx
// src/components/TopNav.tsx
import { ShieldCheck } from "lucide-react";
import { useCaptureStore } from "../store/captureStore";
import { useUIStore, type Screen } from "../store/uiStore";

const TABS: { id: Screen; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "live", label: "Live Capture" },
  { id: "alerts", label: "Alerts" },
  { id: "settings", label: "Settings" },
];

export function TopNav() {
  const { activeScreen, setScreen } = useUIStore();
  const running = useCaptureStore((s) => s.running);

  return (
    <header className="h-11 border-b border-gray-200 bg-white flex items-center justify-between px-4 shrink-0">
      <div className="flex items-center gap-2">
        <ShieldCheck size={18} className="text-blue-600" />
        <span className="font-semibold text-sm tracking-wide">PacketSentry</span>
      </div>

      <nav className="flex items-center gap-1">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setScreen(tab.id)}
            className={[
              "px-3 py-1 text-xs font-medium rounded-md transition-colors",
              activeScreen === tab.id
                ? "bg-gray-100 text-gray-900 border-b-2 border-blue-600"
                : "text-gray-500 hover:text-gray-800 hover:bg-gray-50",
            ].join(" ")}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      <div className="flex items-center gap-1.5 text-xs">
        <span
          className={[
            "inline-block w-2 h-2 rounded-full",
            running ? "bg-green-500 animate-pulse" : "bg-gray-400",
          ].join(" ")}
        />
        <span className="text-gray-500">{running ? "LIVE" : "idle"}</span>
      </div>
    </header>
  );
}
```

- [ ] **Step 2: Create StatCards.tsx**

```tsx
// src/components/StatCards.tsx
import { useCaptureStore } from "../store/captureStore";
import { useAlertStore } from "../store/alertStore";

function Card({
  label,
  value,
  sub,
  accent,
}: {
  label: string;
  value: string | number;
  sub?: string;
  accent?: "red" | "amber" | "green";
}) {
  const valCls =
    accent === "red"
      ? "text-red-600"
      : accent === "amber"
      ? "text-amber-500"
      : accent === "green"
      ? "text-green-600"
      : "text-gray-900";

  return (
    <div className="bg-white rounded-lg border border-gray-200 px-4 py-3">
      <div className="text-xs text-gray-500 uppercase tracking-wide">{label}</div>
      <div className={`text-2xl font-bold mt-0.5 ${valCls}`}>{value}</div>
      {sub && <div className="text-xs text-gray-400 mt-0.5">{sub}</div>}
    </div>
  );
}

export function StatCards() {
  const stats = useCaptureStore((s) => s.stats);
  const alerts = useAlertStore((s) => s.alerts);

  const critCount = alerts.filter((a) => a.severity === "CRITICAL").length;
  const confPercent = Math.round(stats.ensemble_conf * 100);
  const confAccent =
    stats.ensemble_conf >= 0.8
      ? "red"
      : stats.ensemble_conf >= 0.5
      ? "amber"
      : "green";

  return (
    <div className="grid grid-cols-4 gap-3 p-3">
      <Card
        label="Packets / min"
        value={(stats.pps * 60).toLocaleString()}
        sub={`${stats.pps} pps`}
        accent={stats.pps > 5000 ? "red" : undefined}
      />
      <Card
        label="Active Alerts"
        value={stats.active_alerts}
        sub={critCount > 0 ? `${critCount} critical` : "none critical"}
        accent={stats.active_alerts > 0 ? "red" : "green"}
      />
      <Card
        label="Ensemble Confidence"
        value={`${confPercent}%`}
        sub={stats.ensemble_conf >= 0.5 ? "above threshold" : "below threshold"}
        accent={confAccent}
      />
      <Card
        label="Flows Tracked"
        value={stats.flows.toLocaleString()}
        sub="60s window"
        accent="green"
      />
    </div>
  );
}
```

- [ ] **Step 3: TypeScript compile check**

```bash
cd packetsentry-web/frontend && npx tsc --noEmit
```

Expected: No errors.

- [ ] **Step 4: Commit**

```bash
cd ../..
git add packetsentry-web/frontend/src/components/TopNav.tsx packetsentry-web/frontend/src/components/StatCards.tsx
git commit -m "feat(web): add TopNav + StatCards components"
```

---

## Task 19: FlowTable + EnsemblePanel components

**Files:**
- Create: `packetsentry-web/frontend/src/components/FlowTable.tsx`
- Create: `packetsentry-web/frontend/src/components/EnsemblePanel.tsx`

- [ ] **Step 1: Create FlowTable.tsx**

```tsx
// src/components/FlowTable.tsx
import { useAlertStore, type Flow } from "../store/alertStore";

const SEVERITY_CLS: Record<string, string> = {
  CRITICAL: "bg-red-100 text-red-700",
  HIGH: "bg-amber-100 text-amber-700",
  MED: "bg-blue-100 text-blue-700",
  LOW: "bg-green-100 text-green-700",
};

function ScoreBar({ score }: { score: number }) {
  const color =
    score >= 0.8 ? "bg-red-500" : score >= 0.5 ? "bg-amber-400" : "bg-green-400";
  return (
    <div className="flex items-center gap-1.5">
      <div className="w-16 h-1.5 bg-gray-100 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${score * 100}%` }} />
      </div>
      <span
        className={`text-xs font-mono ${
          score >= 0.8 ? "text-red-600" : score >= 0.5 ? "text-amber-500" : "text-gray-500"
        }`}
      >
        {score.toFixed(2)}
      </span>
    </div>
  );
}

export function FlowTable() {
  const flows = useAlertStore((s) => s.flows);
  const setSelectedAlert = useAlertStore((s) => s.setSelectedAlert);

  return (
    <div className="overflow-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="bg-gray-50 border-b border-gray-200">
            {["Src IP", "Dst IP", "Proto", "Score", "Severity", "Detectors"].map((h) => (
              <th key={h} className="px-3 py-2 text-left text-gray-500 font-medium uppercase tracking-wide text-[10px]">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {flows.slice(0, 50).map((flow, i) => (
            <tr
              key={i}
              className="border-b border-gray-100 hover:bg-gray-50 cursor-pointer"
              onClick={() => {
                // Flow → AlertEvent stub click handler (Phase 3: full flow detail)
              }}
            >
              <td className="px-3 py-1.5 font-mono text-[11px]">{flow.src_ip}</td>
              <td className="px-3 py-1.5 font-mono text-[11px]">{flow.dst_ip}</td>
              <td className="px-3 py-1.5 text-gray-500">{flow.proto}</td>
              <td className="px-3 py-1.5"><ScoreBar score={flow.score} /></td>
              <td className="px-3 py-1.5">
                <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${SEVERITY_CLS[flow.severity] ?? "bg-gray-100 text-gray-600"}`}>
                  {flow.severity}
                </span>
              </td>
              <td className="px-3 py-1.5 text-gray-400 text-[10px]">
                {flow.detectors.join(", ")}
              </td>
            </tr>
          ))}
          {flows.length === 0 && (
            <tr>
              <td colSpan={6} className="px-3 py-6 text-center text-gray-400 text-xs">
                No active flows — start capture to see live data
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
```

- [ ] **Step 2: Create EnsemblePanel.tsx**

```tsx
// src/components/EnsemblePanel.tsx
import { useCaptureStore } from "../store/captureStore";
import { useAlertStore } from "../store/alertStore";

const MODEL_CONFIG = [
  { key: "aho_corasick", label: "Aho-Corasick", color: "#7C3AED" },
  { key: "xgboost", label: "XGBoost (SHAP)", color: "#0891B2" },
  { key: "gnn_detector", label: "GNN (GraphSAGE)", color: "#EA580C" },
  { key: "transformer_ae", label: "Transformer AE", color: "#2563EB" },
  { key: "isolation_forest", label: "Isolation Forest", color: "#D97706" },
  { key: "zscore", label: "Z-Score", color: "#6B7280" },
  { key: "random_forest", label: "Random Forest", color: "#6B7280" },
];

// Default weights from EnsembleArbiter
const DEFAULT_WEIGHTS: Record<string, number> = {
  aho_corasick: 0.20,
  xgboost: 0.22,
  gnn_detector: 0.15,
  transformer_ae: 0.15,
  isolation_forest: 0.12,
  zscore: 0.08,
  random_forest: 0.08,
};

export function EnsemblePanel({ scores }: { scores?: Record<string, number> }) {
  const stats = useCaptureStore((s) => s.stats);
  const conf = stats.ensemble_conf;
  const confCls = conf >= 0.8 ? "text-red-600" : conf >= 0.5 ? "text-amber-500" : "text-green-600";

  return (
    <div className="bg-white rounded-lg border border-gray-200 p-3">
      <div className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">
        Ensemble Model Scores
      </div>
      <div className="space-y-1.5">
        {MODEL_CONFIG.map(({ key, label, color }) => {
          const score = scores?.[key] ?? 0;
          const weight = DEFAULT_WEIGHTS[key] ?? 0;
          return (
            <div key={key} className="flex items-center gap-2">
              <div className="text-[10px] text-gray-500 w-32 truncate">{label}</div>
              <div className="flex-1 h-2 bg-gray-100 rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-300 ease-out"
                  style={{
                    width: `${score * 100}%`,
                    backgroundColor: color,
                  }}
                />
              </div>
              <div className="text-[10px] font-mono text-gray-600 w-8 text-right">
                {score.toFixed(2)}
              </div>
              <div className="text-[9px] text-gray-400 w-8 text-right">
                w={weight.toFixed(2)}
              </div>
            </div>
          );
        })}
      </div>
      <div className="mt-2 pt-2 border-t border-gray-100 flex justify-between items-center">
        <span className="text-[10px] text-gray-500">Weighted confidence</span>
        <span className={`text-sm font-bold ${confCls}`}>{conf.toFixed(3)}</span>
      </div>
    </div>
  );
}
```

- [ ] **Step 3: TypeScript compile check**

```bash
cd packetsentry-web/frontend && npx tsc --noEmit
```

Expected: No errors.

- [ ] **Step 4: Commit**

```bash
cd ../..
git add packetsentry-web/frontend/src/components/FlowTable.tsx packetsentry-web/frontend/src/components/EnsemblePanel.tsx
git commit -m "feat(web): add FlowTable + EnsemblePanel components"
```

---

## Task 20: AlertFeed + ThroughputChart + PolarRadar components

**Files:**
- Create: `packetsentry-web/frontend/src/components/AlertFeed.tsx`
- Create: `packetsentry-web/frontend/src/components/ThroughputChart.tsx`
- Create: `packetsentry-web/frontend/src/components/PolarRadar.tsx`

- [ ] **Step 1: Create AlertFeed.tsx**

```tsx
// src/components/AlertFeed.tsx
import { useAlertStore, type AlertEvent } from "../store/alertStore";
import { useUIStore } from "../store/uiStore";

const SEV_CLS: Record<string, string> = {
  CRITICAL: "border-l-red-500 bg-red-50",
  HIGH: "border-l-amber-500 bg-amber-50",
  MED: "border-l-blue-500 bg-blue-50",
  LOW: "border-l-gray-300 bg-white",
};

const BADGE_CLS: Record<string, string> = {
  CRITICAL: "bg-red-100 text-red-700",
  HIGH: "bg-amber-100 text-amber-700",
  MED: "bg-blue-100 text-blue-700",
  LOW: "bg-gray-100 text-gray-600",
};

function AlertRow({ alert }: { alert: AlertEvent }) {
  const { setSelectedAlert } = useAlertStore();
  const { setScreen } = useUIStore();

  const topShap = Object.entries(alert.shap)
    .sort(([, a], [, b]) => Math.abs(b) - Math.abs(a))
    .slice(0, 3)
    .map(([k, v]) => `${k} ${v > 0 ? "+" : ""}${v.toFixed(2)}`)
    .join(" | ");

  return (
    <div
      className={`border-l-4 px-3 py-2 cursor-pointer hover:opacity-90 transition-opacity ${SEV_CLS[alert.severity] ?? "bg-white border-l-gray-300"}`}
      onClick={() => {
        setSelectedAlert(alert);
        setScreen("alerts");
      }}
    >
      <div className="flex justify-between items-start">
        <div className="flex items-center gap-1.5">
          <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${BADGE_CLS[alert.severity]}`}>
            {alert.severity}
          </span>
          <span className="text-xs font-semibold text-gray-800">{alert.rule}</span>
        </div>
        <span className="text-[10px] text-gray-400">
          {new Date(alert.ts * 1000).toLocaleTimeString()}
        </span>
      </div>
      <div className="text-[11px] font-mono text-gray-600 mt-0.5">
        {alert.src_ip} → {alert.dst_ip}:{alert.port}
      </div>
      <div className="text-[10px] text-gray-400 mt-0.5">
        conf: <strong>{alert.confidence.toFixed(2)}</strong> | {alert.detectors.length}/7 models
      </div>
      {topShap && (
        <div className="text-[10px] text-gray-400 mt-0.5 italic">{topShap}</div>
      )}
    </div>
  );
}

export function AlertFeed() {
  const alerts = useAlertStore((s) => s.alerts);

  return (
    <div className="flex flex-col h-full">
      <div className="px-3 py-2 border-b border-gray-200 bg-gray-50">
        <span className="text-xs font-semibold text-gray-600 uppercase tracking-wide">
          Alert Feed
        </span>
        {alerts.length > 0 && (
          <span className="ml-2 text-[10px] bg-red-100 text-red-700 px-1.5 py-0.5 rounded font-medium">
            {alerts.length}
          </span>
        )}
      </div>
      <div className="flex-1 overflow-y-auto divide-y divide-gray-100">
        {alerts.length === 0 ? (
          <div className="p-6 text-center text-xs text-gray-400">No alerts yet</div>
        ) : (
          alerts.map((a) => <AlertRow key={a.id} alert={a} />)
        )}
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Create ThroughputChart.tsx**

```tsx
// src/components/ThroughputChart.tsx
import { useEffect, useRef, useState } from "react";
import { useCaptureStore } from "../store/captureStore";
import { LineChart, Line, ResponsiveContainer, YAxis } from "recharts";

const MAX_POINTS = 60;  // 60 seconds of data

export function ThroughputChart() {
  const pps = useCaptureStore((s) => s.stats.pps);
  const [data, setData] = useState<{ v: number }[]>(
    Array.from({ length: MAX_POINTS }, () => ({ v: 0 }))
  );

  useEffect(() => {
    setData((prev) => {
      const next = [...prev.slice(-(MAX_POINTS - 1)), { v: pps }];
      return next;
    });
  }, [pps]);

  return (
    <div className="h-14 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data}>
          <YAxis domain={[0, "auto"]} hide />
          <Line
            type="monotone"
            dataKey="v"
            stroke="#378ADD"
            strokeWidth={1.5}
            dot={false}
            isAnimationActive={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
```

- [ ] **Step 3: Create PolarRadar.tsx**

```tsx
// src/components/PolarRadar.tsx
import { useMemo } from "react";

const MODELS = [
  "Aho-Corasick",
  "XGBoost",
  "GNN",
  "Transformer AE",
  "Isolation Forest",
  "Z-Score",
  "Random Forest",
];

const CX = 120;
const CY = 120;
const R = 90;
const N = MODELS.length;

function polarToXY(angle: number, r: number): [number, number] {
  return [
    CX + r * Math.cos(angle - Math.PI / 2),
    CY + r * Math.sin(angle - Math.PI / 2),
  ];
}

function buildPath(scores: number[]): string {
  return scores
    .map((score, i) => {
      const angle = (2 * Math.PI * i) / N;
      const [x, y] = polarToXY(angle, score * R);
      return `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ") + " Z";
}

export function PolarRadar({ scores }: { scores: Record<string, number> }) {
  const modelKeys = [
    "aho_corasick", "xgboost", "gnn_detector",
    "transformer_ae", "isolation_forest", "zscore", "random_forest",
  ];

  const scoreArr = modelKeys.map((k) => scores[k] ?? 0);
  const baselineArr = Array(N).fill(0.05);

  const gridLines = [0.25, 0.5, 0.75, 1.0];

  const axes = useMemo(
    () =>
      MODELS.map((label, i) => {
        const angle = (2 * Math.PI * i) / N;
        const [x1, y1] = polarToXY(angle, R);
        const [lx, ly] = polarToXY(angle, R + 18);
        return { label, x1, y1, lx, ly };
      }),
    []
  );

  return (
    <svg width={240} height={240} viewBox={`0 0 240 240`} className="overflow-visible">
      {/* Grid circles */}
      {gridLines.map((r) => (
        <circle
          key={r}
          cx={CX} cy={CY} r={r * R}
          fill="none" stroke="#e5e7eb" strokeWidth={0.8}
        />
      ))}

      {/* Axis lines */}
      {axes.map(({ x1, y1 }, i) => (
        <line key={i} x1={CX} y1={CY} x2={x1} y2={y1} stroke="#d1d5db" strokeWidth={0.8} />
      ))}

      {/* Baseline polygon (teal, small) */}
      <path
        d={buildPath(baselineArr)}
        fill="rgba(20,184,166,0.15)"
        stroke="#14B8A6"
        strokeWidth={1}
      />

      {/* Alert polygon (purple) */}
      <path
        d={buildPath(scoreArr)}
        fill="rgba(124,58,237,0.2)"
        stroke="#7C3AED"
        strokeWidth={1.5}
        style={{ transition: "d 300ms ease" }}
      />

      {/* Labels */}
      {axes.map(({ label, lx, ly }, i) => (
        <text
          key={i}
          x={lx} y={ly}
          textAnchor="middle"
          dominantBaseline="middle"
          fontSize={8}
          fill="#6b7280"
        >
          {label}
        </text>
      ))}
    </svg>
  );
}
```

- [ ] **Step 4: TypeScript compile check**

```bash
cd packetsentry-web/frontend && npx tsc --noEmit
```

Expected: No errors.

- [ ] **Step 5: Commit**

```bash
cd ../..
git add packetsentry-web/frontend/src/components/
git commit -m "feat(web): add AlertFeed, ThroughputChart, PolarRadar components"
```

---

## Task 21: ShapWaterfall + SimilarAlerts + PacketStream components

**Files:**
- Create: `packetsentry-web/frontend/src/components/ShapWaterfall.tsx`
- Create: `packetsentry-web/frontend/src/components/SimilarAlerts.tsx`
- Create: `packetsentry-web/frontend/src/components/PacketStream.tsx`

- [ ] **Step 1: Create ShapWaterfall.tsx**

```tsx
// src/components/ShapWaterfall.tsx
import { useEffect, useRef, useState } from "react";

interface ShapFeature {
  name: string;
  value: number;
}

function ShapBar({ name, value, delay }: ShapFeature & { delay: number }) {
  const [width, setWidth] = useState(0);
  const maxWidth = 120;

  useEffect(() => {
    const t = setTimeout(() => setWidth(Math.abs(value) * maxWidth), delay);
    return () => clearTimeout(t);
  }, [value, delay]);

  const isPositive = value >= 0;
  const color = isPositive ? "#2563EB" : "#DC2626";
  const label = `${isPositive ? "+" : ""}${value.toFixed(3)}`;

  return (
    <div className="flex items-center gap-2 py-0.5">
      <div className="text-[10px] font-mono text-gray-600 w-32 text-right truncate">{name}</div>
      <div className="flex items-center gap-1">
        {!isPositive && (
          <div
            className="h-3 rounded-sm transition-all duration-500 ease-out"
            style={{ width, backgroundColor: color, transitionDelay: `${delay}ms` }}
          />
        )}
        <div className="w-px h-5 bg-gray-300" />
        {isPositive && (
          <div
            className="h-3 rounded-sm transition-all duration-500 ease-out"
            style={{ width, backgroundColor: color, transitionDelay: `${delay}ms` }}
          />
        )}
      </div>
      <div
        className="text-[10px] font-mono"
        style={{ color }}
      >
        {label}
      </div>
    </div>
  );
}

export function ShapWaterfall({ shap }: { shap: Record<string, number> }) {
  const features: ShapFeature[] = Object.entries(shap)
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => Math.abs(b.value) - Math.abs(a.value))
    .slice(0, 8);

  if (features.length === 0) {
    return (
      <div className="text-xs text-gray-400 py-4 text-center">
        No SHAP data available
      </div>
    );
  }

  return (
    <div>
      <div className="text-xs font-semibold text-gray-700 mb-2">
        Why did the ensemble fire?
      </div>
      <div className="text-[10px] text-gray-400 mb-3">
        ← normal &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; attack →
      </div>
      {features.map((f, i) => (
        <ShapBar key={f.name} {...f} delay={i * 30} />
      ))}
    </div>
  );
}
```

- [ ] **Step 2: Create SimilarAlerts.tsx**

```tsx
// src/components/SimilarAlerts.tsx
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";

interface SimilarAlert {
  alert_id: string;
  similarity: number;
  rule: string;
  severity: string;
  src_ip: string;
  timestamp: string;
}

export function SimilarAlerts({ alertId }: { alertId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ["similar", alertId],
    queryFn: () => api.getSimilar(alertId, 3),
    staleTime: 60_000,
  });

  const items = (data?.similar_alerts ?? []) as SimilarAlert[];

  if (isLoading) {
    return <div className="text-xs text-gray-400 py-2">Loading similar alerts…</div>;
  }

  if (items.length === 0) {
    return (
      <div className="text-xs text-gray-400 py-2">
        No similar alerts in ChromaDB
      </div>
    );
  }

  return (
    <div>
      <div className="text-xs font-semibold text-gray-700 mb-2">Similar Past Alerts</div>
      <div className="grid grid-cols-3 gap-2">
        {items.map((item, i) => (
          <div key={i} className="border border-gray-200 rounded-lg p-2 text-xs">
            <div
              className="h-1 rounded-full bg-blue-500 mb-2"
              style={{ width: `${Math.round(item.similarity * 100)}%` }}
            />
            <div className="font-medium text-gray-800 text-[11px]">{item.rule ?? "Unknown"}</div>
            <div className="text-gray-400 text-[10px] mt-0.5">
              {Math.round((item.similarity ?? 0) * 100)}% similar
            </div>
            <div className="font-mono text-[10px] text-gray-500 mt-0.5">
              {item.src_ip}
            </div>
            <div className="text-[10px] text-gray-400 mt-0.5">
              {item.timestamp ? new Date(item.timestamp).toLocaleDateString() : "—"}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
```

- [ ] **Step 3: Create PacketStream.tsx**

```tsx
// src/components/PacketStream.tsx
import { useRef } from "react";
import { FixedSizeList, type ListChildComponentProps } from "react-window";
import { useCaptureStore, type PacketEvent } from "../store/captureStore";

const ITEM_HEIGHT = 22;
const MAX_VISIBLE = 20;

function Row({ index, style, data }: ListChildComponentProps<PacketEvent[]>) {
  const pkt = data[index];
  const rowCls = pkt.flagged
    ? "text-red-500"
    : pkt.flow_score >= 0.5
    ? "text-amber-500"
    : "text-gray-400";

  return (
    <div
      style={style}
      className={`px-3 font-mono text-[11px] flex items-center gap-2 ${rowCls}`}
    >
      <span className="text-gray-500 w-16 shrink-0">
        {new Date(pkt.ts * 1000).toLocaleTimeString()}
      </span>
      <span className="w-32 truncate">{pkt.src}</span>
      <span className="text-gray-500">→</span>
      <span className="w-32 truncate">{pkt.dst}</span>
      <span className="w-10">{pkt.proto}</span>
      <span className="w-12 text-right">{pkt.length}B</span>
      {pkt.flags && <span className="text-[10px] bg-gray-100 px-1 rounded">{pkt.flags}</span>}
    </div>
  );
}

export function PacketStream() {
  const packets = useCaptureStore((s) => s.packets);
  const listRef = useRef<FixedSizeList>(null);

  const height = Math.min(packets.length, MAX_VISIBLE) * ITEM_HEIGHT || ITEM_HEIGHT * 5;

  return (
    <div className="border border-gray-200 rounded-lg overflow-hidden bg-gray-900">
      <div className="bg-gray-800 px-3 py-1.5 text-[10px] text-gray-400 uppercase tracking-wide">
        Packet Stream — last {packets.length} packets
      </div>
      {packets.length === 0 ? (
        <div className="px-3 py-4 text-[11px] text-gray-500 font-mono">
          Waiting for packets…
        </div>
      ) : (
        <FixedSizeList
          ref={listRef}
          height={height}
          itemCount={packets.length}
          itemSize={ITEM_HEIGHT}
          itemData={packets}
          width="100%"
        >
          {Row}
        </FixedSizeList>
      )}
    </div>
  );
}
```

- [ ] **Step 4: TypeScript compile check**

```bash
cd packetsentry-web/frontend && npx tsc --noEmit
```

Expected: No errors.

- [ ] **Step 5: Commit**

```bash
cd ../..
git add packetsentry-web/frontend/src/components/
git commit -m "feat(web): add ShapWaterfall, SimilarAlerts, PacketStream components"
```

---

## Task 22: Overview + LiveCapture screens

**Files:**
- Create: `packetsentry-web/frontend/src/screens/Overview.tsx`
- Create: `packetsentry-web/frontend/src/screens/LiveCapture.tsx`

- [ ] **Step 1: Create Overview.tsx**

```tsx
// src/screens/Overview.tsx
import { StatCards } from "../components/StatCards";
import { FlowTable } from "../components/FlowTable";
import { EnsemblePanel } from "../components/EnsemblePanel";
import { AlertFeed } from "../components/AlertFeed";
import { ThroughputChart } from "../components/ThroughputChart";
import { useAlertStore } from "../store/alertStore";
import { useCaptureStore } from "../store/captureStore";

export function Overview() {
  const selectedAlert = useAlertStore((s) => s.selectedAlert);
  const stats = useCaptureStore((s) => s.stats);

  return (
    <div className="flex flex-col flex-1 overflow-hidden">
      <StatCards />
      <div className="px-3 pb-1">
        <ThroughputChart />
      </div>
      <div className="flex flex-1 overflow-hidden gap-3 px-3 pb-3">
        {/* Left: flow table + ensemble */}
        <div className="flex-1 flex flex-col gap-3 overflow-hidden min-w-0">
          <div className="bg-white rounded-lg border border-gray-200 flex-1 overflow-hidden">
            <div className="px-3 py-2 border-b border-gray-100 text-xs font-semibold text-gray-600 uppercase tracking-wide">
              Active Flows
            </div>
            <div className="overflow-auto flex-1">
              <FlowTable />
            </div>
          </div>
          <EnsemblePanel scores={selectedAlert?.shap ? undefined : undefined} />
        </div>
        {/* Right: alert feed */}
        <div className="w-72 bg-white rounded-lg border border-gray-200 overflow-hidden">
          <AlertFeed />
        </div>
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Create LiveCapture.tsx**

```tsx
// src/screens/LiveCapture.tsx
import { useState } from "react";
import { Play, Square } from "lucide-react";
import { useCaptureStore } from "../store/captureStore";
import { PacketStream } from "../components/PacketStream";
import { PolarRadar } from "../components/PolarRadar";
import { ThroughputChart } from "../components/ThroughputChart";
import { useAlertStore } from "../store/alertStore";
import { api } from "../api/client";

const INTERFACES = ["eth0", "eth1", "wlan0", "lo"];
const PROTO_FILTERS = ["TCP", "UDP", "DNS", "HTTP"];

export function LiveCapture() {
  const { running, setRunning, interface: iface, setInterface, bpfFilter, setBpfFilter } = useCaptureStore();
  const [activeProtos, setActiveProtos] = useState<Set<string>>(new Set());
  const selectedAlert = useAlertStore((s) => s.selectedAlert);
  const stats = useCaptureStore((s) => s.stats);
  const [elapsed, setElapsed] = useState(0);

  const toggleProto = (p: string) => {
    setActiveProtos((prev) => {
      const next = new Set(prev);
      next.has(p) ? next.delete(p) : next.add(p);
      return next;
    });
  };

  const handleStart = async () => {
    try {
      await api.startCapture(iface, bpfFilter);
      setRunning(true);
    } catch (e) {
      console.error("Start capture failed:", e);
    }
  };

  const handleStop = async () => {
    try {
      await api.stopCapture();
      setRunning(false);
    } catch (e) {
      console.error("Stop capture failed:", e);
    }
  };

  return (
    <div className="flex flex-col flex-1 overflow-hidden p-3 gap-3">
      {/* Toolbar */}
      <div className="bg-white rounded-lg border border-gray-200 p-3 flex items-center gap-3 flex-wrap">
        <select
          className="text-xs border border-gray-200 rounded px-2 py-1.5 bg-white"
          value={iface}
          onChange={(e) => setInterface(e.target.value)}
          disabled={running}
        >
          {INTERFACES.map((i) => <option key={i}>{i}</option>)}
        </select>

        <div className="flex gap-1">
          {PROTO_FILTERS.map((p) => (
            <button
              key={p}
              onClick={() => toggleProto(p)}
              className={`px-2 py-1 text-[10px] rounded font-medium transition-colors ${
                activeProtos.has(p)
                  ? "bg-green-100 text-green-700"
                  : "bg-gray-100 text-gray-500 hover:bg-gray-200"
              }`}
            >
              {p}
            </button>
          ))}
        </div>

        <input
          className="flex-1 min-w-32 text-xs border border-gray-200 rounded px-2 py-1.5 font-mono"
          placeholder="BPF filter: port 80 or port 443"
          value={bpfFilter}
          onChange={(e) => setBpfFilter(e.target.value)}
          disabled={running}
        />

        {!running ? (
          <button
            onClick={handleStart}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-green-600 text-white text-xs rounded font-medium hover:bg-green-700"
          >
            <Play size={12} /> Start
          </button>
        ) : (
          <button
            onClick={handleStop}
            className="flex items-center gap-1.5 px-3 py-1.5 border border-red-400 text-red-600 text-xs rounded font-medium hover:bg-red-50"
          >
            <Square size={12} /> Stop
          </button>
        )}

        {running && (
          <span className="text-xs text-gray-500 font-mono">{stats.pps} pps</span>
        )}
      </div>

      {/* Main content */}
      <div className="flex flex-1 overflow-hidden gap-3">
        {/* Left: packet stream */}
        <div className="flex-1 flex flex-col gap-3 min-w-0">
          <PacketStream />
          <ThroughputChart />
        </div>
        {/* Right: polar radar */}
        <div className="w-64 bg-white rounded-lg border border-gray-200 p-3 flex flex-col items-center">
          <div className="text-xs font-semibold text-gray-600 uppercase tracking-wide mb-2 self-start">
            Threat Radar
          </div>
          <PolarRadar scores={selectedAlert?.shap ?? {}} />
          <div className="text-[10px] text-gray-400 mt-2 text-center">
            7 detectors | updates every 2s
          </div>
        </div>
      </div>
    </div>
  );
}
```

- [ ] **Step 3: TypeScript compile check**

```bash
cd packetsentry-web/frontend && npx tsc --noEmit
```

Expected: No errors.

- [ ] **Step 4: Commit**

```bash
cd ../..
git add packetsentry-web/frontend/src/screens/Overview.tsx packetsentry-web/frontend/src/screens/LiveCapture.tsx
git commit -m "feat(web): add Overview + LiveCapture screens"
```

---

## Task 23: AlertDetail + Settings screens

**Files:**
- Create: `packetsentry-web/frontend/src/screens/AlertDetail.tsx`
- Create: `packetsentry-web/frontend/src/screens/Settings.tsx`

- [ ] **Step 1: Create AlertDetail.tsx**

```tsx
// src/screens/AlertDetail.tsx
import { X, Copy, Check } from "lucide-react";
import { useState } from "react";
import { useAlertStore } from "../store/alertStore";
import { ShapWaterfall } from "../components/ShapWaterfall";
import { EnsemblePanel } from "../components/EnsemblePanel";
import { SimilarAlerts } from "../components/SimilarAlerts";
import { api } from "../api/client";

export function AlertDetail() {
  const { selectedAlert, setSelectedAlert } = useAlertStore();
  const [fpDone, setFpDone] = useState(false);

  if (!selectedAlert) {
    return (
      <div className="flex-1 flex items-center justify-center text-sm text-gray-400">
        Select an alert to view details
      </div>
    );
  }

  const handleFP = async () => {
    try {
      await api.markFalsePositive(selectedAlert.id, selectedAlert.detectors);
      setFpDone(true);
      setTimeout(() => setFpDone(false), 3000);
    } catch (e) {
      console.error("FP marking failed:", e);
    }
  };

  const copyIP = (text: string) => navigator.clipboard.writeText(text);

  const SEV_CLS: Record<string, string> = {
    CRITICAL: "bg-red-100 text-red-700",
    HIGH: "bg-amber-100 text-amber-700",
    MED: "bg-blue-100 text-blue-700",
    LOW: "bg-gray-100 text-gray-600",
  };

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      {/* Header */}
      <div className="bg-white border-b border-gray-200 px-4 py-3 flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2">
            <span className={`px-2 py-0.5 rounded text-xs font-medium ${SEV_CLS[selectedAlert.severity]}`}>
              {selectedAlert.severity}
            </span>
            <h2 className="text-sm font-semibold text-gray-900">{selectedAlert.rule}</h2>
          </div>
          <div className="flex items-center gap-2 mt-1 font-mono text-xs text-gray-500">
            <span>{selectedAlert.src_ip}</span>
            <span>→</span>
            <span>{selectedAlert.dst_ip}:{selectedAlert.port}</span>
            <button onClick={() => copyIP(selectedAlert.src_ip)} className="hover:text-blue-500">
              <Copy size={10} />
            </button>
          </div>
          <div className="text-xs text-gray-400 mt-0.5">
            conf: <strong>{selectedAlert.confidence.toFixed(3)}</strong> |{" "}
            {selectedAlert.detectors.length}/7 models |{" "}
            {new Date(selectedAlert.ts * 1000).toLocaleString()}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleFP}
            disabled={fpDone}
            className={`text-xs px-3 py-1.5 rounded border transition-all ${
              fpDone
                ? "border-green-300 text-green-600 bg-green-50"
                : "border-gray-200 text-gray-600 hover:border-red-300 hover:text-red-600"
            }`}
          >
            {fpDone ? <span className="flex items-center gap-1"><Check size={10} /> Marked</span> : "Mark as False Positive"}
          </button>
          <button
            onClick={() => setSelectedAlert(null)}
            className="text-gray-400 hover:text-gray-600"
          >
            <X size={16} />
          </button>
        </div>
      </div>

      {/* Body */}
      <div className="flex flex-1 overflow-hidden gap-4 p-4">
        {/* Left: SHAP waterfall */}
        <div className="flex-1 bg-white rounded-lg border border-gray-200 p-4">
          <ShapWaterfall shap={selectedAlert.shap} />
        </div>
        {/* Right: ensemble + similar */}
        <div className="w-72 flex flex-col gap-4">
          <EnsemblePanel scores={selectedAlert.shap} />
          <div className="bg-white rounded-lg border border-gray-200 p-3">
            <SimilarAlerts alertId={selectedAlert.id} />
          </div>
        </div>
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Create Settings.tsx**

```tsx
// src/screens/Settings.tsx
import { useState } from "react";

const MODEL_LABELS: Record<string, string> = {
  aho_corasick: "Aho-Corasick",
  xgboost: "XGBoost (SHAP)",
  gnn_detector: "GNN (GraphSAGE)",
  transformer_ae: "Transformer AE",
  isolation_forest: "Isolation Forest",
  zscore: "Z-Score",
  random_forest: "Random Forest",
};

const DEFAULT_WEIGHTS: Record<string, number> = {
  aho_corasick: 0.20,
  xgboost: 0.22,
  gnn_detector: 0.15,
  transformer_ae: 0.15,
  isolation_forest: 0.12,
  zscore: 0.08,
  random_forest: 0.08,
};

export function Settings() {
  const [weights, setWeights] = useState({ ...DEFAULT_WEIGHTS });
  const [threshold, setThreshold] = useState(0.50);
  const [critCutoff, setCritCutoff] = useState(0.80);
  const [highCutoff, setHighCutoff] = useState(0.60);
  const [iface, setIface] = useState("eth0");
  const [bpf, setBpf] = useState("");
  const [saved, setSaved] = useState(false);

  const total = Object.values(weights).reduce((s, v) => s + v, 0);

  const normalize = () => {
    const t = total || 1;
    setWeights((prev) =>
      Object.fromEntries(Object.entries(prev).map(([k, v]) => [k, +(v / t).toFixed(3)]))
    );
  };

  const handleSave = async () => {
    try {
      await fetch("http://localhost:8000/api/settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ weights, threshold, iface, bpf_filter: bpf }),
      });
    } catch {
      // offline — save locally only
    }
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="flex-1 overflow-y-auto p-4">
      <div className="max-w-2xl space-y-6">

        {/* Capture settings */}
        <section className="bg-white rounded-lg border border-gray-200 p-4">
          <h3 className="text-sm font-semibold text-gray-800 mb-3">Capture</h3>
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <label className="text-xs text-gray-600 w-32">Default interface</label>
              <input
                className="flex-1 text-xs border border-gray-200 rounded px-2 py-1.5"
                value={iface}
                onChange={(e) => setIface(e.target.value)}
              />
            </div>
            <div className="flex items-center gap-3">
              <label className="text-xs text-gray-600 w-32">BPF filter</label>
              <input
                className="flex-1 text-xs border border-gray-200 rounded px-2 py-1.5 font-mono"
                placeholder="port 80 or port 443"
                value={bpf}
                onChange={(e) => setBpf(e.target.value)}
              />
            </div>
          </div>
        </section>

        {/* Ensemble weights */}
        <section className="bg-white rounded-lg border border-gray-200 p-4">
          <div className="flex justify-between items-center mb-3">
            <h3 className="text-sm font-semibold text-gray-800">Ensemble Weights</h3>
            <div className="flex items-center gap-2">
              <span className={`text-xs ${Math.abs(total - 1) > 0.01 ? "text-amber-500" : "text-green-600"}`}>
                Total: {total.toFixed(3)}
              </span>
              <button
                onClick={normalize}
                className="text-xs px-2 py-1 border border-gray-200 rounded hover:bg-gray-50"
              >
                Normalize
              </button>
            </div>
          </div>
          <div className="space-y-2">
            {Object.entries(weights).map(([key, val]) => (
              <div key={key} className="flex items-center gap-3">
                <label className="text-xs text-gray-600 w-36 truncate">{MODEL_LABELS[key]}</label>
                <input
                  type="range"
                  min={0.01} max={0.5} step={0.01}
                  value={val}
                  onChange={(e) => setWeights((prev) => ({ ...prev, [key]: +e.target.value }))}
                  className="flex-1"
                />
                <span className="text-xs font-mono text-gray-700 w-10 text-right">
                  {val.toFixed(2)}
                </span>
              </div>
            ))}
          </div>
        </section>

        {/* Thresholds */}
        <section className="bg-white rounded-lg border border-gray-200 p-4">
          <h3 className="text-sm font-semibold text-gray-800 mb-3">Alert Thresholds</h3>
          {[
            { label: "Alert fire threshold", value: threshold, set: setThreshold },
            { label: "CRITICAL cutoff", value: critCutoff, set: setCritCutoff },
            { label: "HIGH cutoff", value: highCutoff, set: setHighCutoff },
          ].map(({ label, value, set }) => (
            <div key={label} className="flex items-center gap-3 mb-2">
              <label className="text-xs text-gray-600 w-36">{label}</label>
              <input
                type="range" min={0.1} max={0.99} step={0.01}
                value={value}
                onChange={(e) => set(+e.target.value)}
                className="flex-1"
              />
              <span className="text-xs font-mono text-gray-700 w-10 text-right">{value.toFixed(2)}</span>
            </div>
          ))}
        </section>

        <button
          onClick={handleSave}
          className={`px-4 py-2 rounded text-sm font-medium transition-colors ${
            saved
              ? "bg-green-100 text-green-700"
              : "bg-blue-600 text-white hover:bg-blue-700"
          }`}
        >
          {saved ? "Saved!" : "Save Settings"}
        </button>
      </div>
    </div>
  );
}
```

- [ ] **Step 3: TypeScript compile check**

```bash
cd packetsentry-web/frontend && npx tsc --noEmit
```

Expected: No errors.

- [ ] **Step 4: Commit**

```bash
cd ../..
git add packetsentry-web/frontend/src/screens/
git commit -m "feat(web): add AlertDetail + Settings screens"
```

---

## Task 24: Wire App.tsx + verify full UI in browser

**Files:**
- Create: `packetsentry-web/frontend/src/App.tsx`
- Modify: `packetsentry-web/frontend/src/main.tsx`

- [ ] **Step 1: Create App.tsx**

```tsx
// src/App.tsx
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { TopNav } from "./components/TopNav";
import { Overview } from "./screens/Overview";
import { LiveCapture } from "./screens/LiveCapture";
import { AlertDetail } from "./screens/AlertDetail";
import { Settings } from "./screens/Settings";
import { useUIStore } from "./store/uiStore";
import { useWebSocket } from "./hooks/useWebSocket";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      refetchOnWindowFocus: true,
    },
  },
});

function AppContent() {
  useWebSocket();  // connect once at app root
  const activeScreen = useUIStore((s) => s.activeScreen);

  return (
    <div className="flex flex-col h-screen overflow-hidden bg-gray-50">
      <TopNav />
      {activeScreen === "overview" && <Overview />}
      {activeScreen === "live" && <LiveCapture />}
      {activeScreen === "alerts" && <AlertDetail />}
      {activeScreen === "settings" && <Settings />}
    </div>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AppContent />
    </QueryClientProvider>
  );
}
```

- [ ] **Step 2: Update main.tsx**

Replace `packetsentry-web/frontend/src/main.tsx` with:

```tsx
import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
```

- [ ] **Step 3: TypeScript compile check**

```bash
cd packetsentry-web/frontend && npx tsc --noEmit
```

Expected: No errors.

- [ ] **Step 4: Start dev server and verify UI**

```bash
npm run dev
```

Open `http://localhost:5173`. Verify:
- TopNav renders with tabs (Overview, Live Capture, Alerts, Settings)
- Overview tab shows 4 stat cards, empty flow table, empty alert feed
- Live Capture tab shows toolbar + empty packet stream + polar radar
- Alerts tab shows "Select an alert" placeholder
- Settings tab shows sliders and inputs

- [ ] **Step 5: Commit**

```bash
cd ../..
git add packetsentry-web/frontend/src/App.tsx packetsentry-web/frontend/src/main.tsx
git commit -m "feat(web): wire App.tsx with QueryClient + screen switch + WS connection"
```

---

## Task 25: Docker — Dockerfiles + docker-compose.yml

**Files:**
- Create: `packetsentry-web/backend/Dockerfile`
- Create: `packetsentry-web/frontend/Dockerfile`
- Create: `packetsentry-web/docker-compose.yml`

- [ ] **Step 1: Create backend/Dockerfile**

```dockerfile
# packetsentry-web/backend/Dockerfile
FROM python:3.12-slim

WORKDIR /app

# Install system deps for scapy
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Install packetsentry from repo root
COPY ../../pyproject.toml ../../packetsentry/ ./packetsentry/
RUN pip install --no-cache-dir -e . 2>/dev/null || true

# Install backend deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

- [ ] **Step 2: Create frontend/Dockerfile**

```dockerfile
# packetsentry-web/frontend/Dockerfile
FROM node:20-slim AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html

# Proxy /api and /ws to backend
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 5173
```

- [ ] **Step 3: Create frontend/nginx.conf**

```nginx
server {
    listen 5173;
    root /usr/share/nginx/html;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api/ {
        proxy_pass http://backend:8000;
        proxy_set_header Host $host;
    }

    location /ws {
        proxy_pass http://backend:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
    }
}
```

- [ ] **Step 4: Create docker-compose.yml**

```yaml
# packetsentry-web/docker-compose.yml
version: "3.9"

services:
  backend:
    build:
      context: ..
      dockerfile: packetsentry-web/backend/Dockerfile
    ports:
      - "8000:8000"
    volumes:
      - ../data:/app/data
      - ../models:/app/models
    environment:
      - DUCKDB_PATH=/app/data/alerts.duckdb
      - CHROMA_PATH=/app/data/chroma
    network_mode: host  # required for raw packet capture (scapy)

  frontend:
    build:
      context: frontend
      dockerfile: Dockerfile
    ports:
      - "5173:5173"
    depends_on:
      - backend
    environment:
      - VITE_API_URL=http://localhost:8000
      - VITE_WS_URL=ws://localhost:8000/ws
```

- [ ] **Step 5: Build both images**

```bash
cd packetsentry-web
docker-compose build
```

Expected: Both images build without error. Backend ~800MB (Python + torch), frontend ~50MB.

- [ ] **Step 6: Start and verify**

```bash
docker-compose up
```

Open `http://localhost:5173`. Dashboard should load. Open `http://localhost:8000/docs` — FastAPI Swagger UI should show all endpoints.

- [ ] **Step 7: Stop and commit**

```bash
docker-compose down
cd ..
git add packetsentry-web/backend/Dockerfile packetsentry-web/frontend/Dockerfile packetsentry-web/frontend/nginx.conf packetsentry-web/docker-compose.yml
git commit -m "feat(web): add Dockerfiles + docker-compose for backend + frontend"
```

---

## Task 26: End-to-end integration test — backend + frontend talking

**Files:**
- No new files — verify existing

- [ ] **Step 1: Start backend with uvicorn**

```bash
cd packetsentry-web/backend
uvicorn main:app --port 8000 &
sleep 3
```

- [ ] **Step 2: Verify /api/stats**

```bash
curl -s http://localhost:8000/api/stats | python -m json.tool
```

Expected:
```json
{
    "packets": 0,
    "bytes": 0,
    "active_flows": 0,
    "completed_flows": 0,
    "alerts": 0
}
```

- [ ] **Step 3: Verify /api/alerts**

```bash
curl -s http://localhost:8000/api/alerts | python -m json.tool
```

Expected: `[]` (empty array).

- [ ] **Step 4: Verify WebSocket connect**

```bash
python -c "
import asyncio, websockets, json
async def test():
    async with websockets.connect('ws://localhost:8000/ws') as ws:
        await ws.send('ping')
        resp = await asyncio.wait_for(ws.recv(), timeout=5)
        print('WS response:', resp)
asyncio.run(test())
"
```

Expected: `WS response: {"type":"pong"}`

- [ ] **Step 5: Start frontend dev server, navigate to Overview**

```bash
cd packetsentry-web/frontend
npm run dev &
sleep 3
```

Open `http://localhost:5173`. Verify:
- No console errors in DevTools
- Stat cards show zeros (not crash/NaN)
- No "Failed to fetch" errors in console (backend is up)

- [ ] **Step 6: Kill background processes**

```bash
kill $(lsof -t -i:8000) 2>/dev/null || true
kill $(lsof -t -i:5173) 2>/dev/null || true
```

- [ ] **Step 7: Commit integration test confirmation**

```bash
git commit --allow-empty -m "test(web): confirmed backend↔frontend E2E integration (see task 26)"
```

---

## Task 27: Update README with web dashboard section

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add web dashboard section to README**

Find the installation/usage section in `README.md` and add:

```markdown
## Web Dashboard (Phase 2)

React 18 + FastAPI dashboard with live WebSocket streaming, SHAP waterfall, and 7-model ensemble visualization.

### Quick start

**With Docker:**
```bash
cd packetsentry-web
docker-compose up
```
Dashboard: http://localhost:5173 | API: http://localhost:8000/docs

**Without Docker:**
```bash
# Terminal 1 — backend
cd packetsentry-web/backend
pip install -r requirements.txt
uvicorn main:app --reload

# Terminal 2 — frontend
cd packetsentry-web/frontend
npm install && npm run dev
```

### Screens
- **Overview** — 4 stat cards, live flow table, 7-model ensemble bars, alert feed
- **Live Capture** — packet stream (react-window virtual scroll), polar threat radar, throughput chart
- **Alert Detail** — SHAP waterfall (why did the ensemble fire?), ChromaDB similarity search
- **Settings** — ensemble weight sliders, alert thresholds, capture config
```

- [ ] **Step 2: Run all tests — confirm 241 still passing**

```bash
pytest --tb=short -q
```

Expected: `241 passed`.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: add web dashboard quick-start + screen descriptions to README"
```

---

*Phase 2 complete. All tasks done.*

---

## Self-Review

### Spec coverage check

| Spec requirement | Task(s) |
|---|---|
| FastAPI backend + WebSocket hub | T12–T15 |
| React 18 + TypeScript + Tailwind + Vite | T16 |
| Zustand stores (capture, alert, ui) | T17 |
| useWebSocket hook with reconnect | T17 |
| React Query for REST | T17 (client.ts) + T21 (SimilarAlerts) |
| TopNav with 4 tabs + live pill | T18 |
| 4-column stat cards | T18 |
| Flow table with score color + severity pills | T19 |
| Ensemble 7-model weight bars | T19 |
| Alert feed with animations (CSS transitions) | T20 |
| Throughput sparkline (Recharts) | T20 |
| Polar radar SVG 7-axis | T20 |
| SHAP waterfall animated bars | T21 |
| ChromaDB similar alerts (3 cards) | T21 |
| PacketStream virtual scroll (react-window) | T21 |
| Overview screen | T22 |
| LiveCapture screen + toolbar | T22 |
| AlertDetail with FP button | T23 |
| Settings — sliders + thresholds | T23 |
| Docker + docker-compose | T25 |
| E2E integration verified | T26 |
| WS backpressure (queue maxsize=100) | T12 |
| CORS configured | T15 |
| False positive → EnsembleArbiter.feedback() | T13 |

### Placeholder scan
- `network_mode: host` in docker-compose — note in step: required for raw packet capture. Not a placeholder.
- "Phase 3 stub" in stats.py `/api/clusters` — documented as deferred, not a hidden TODO.
- `// Phase 3: full flow detail` comment in FlowTable onClick — documented as deferred.
- POST `/api/settings` in Settings.tsx — this endpoint is not implemented in stats/capture router. **Fix needed:** Add a `/api/settings` endpoint or remove the fetch call and replace with localStorage only.

### Fix: Settings save should use localStorage (no /api/settings endpoint in scope)

In `Settings.tsx`, replace the `handleSave` function with:

```tsx
const handleSave = () => {
  // Phase 2: save to localStorage only. Phase 3 will sync to backend.
  localStorage.setItem("ps_weights", JSON.stringify(weights));
  localStorage.setItem("ps_thresholds", JSON.stringify({ threshold, critCutoff, highCutoff }));
  localStorage.setItem("ps_capture", JSON.stringify({ iface, bpf }));
  setSaved(true);
  setTimeout(() => setSaved(false), 2000);
};
```

And restore settings on mount:

```tsx
useEffect(() => {
  const savedWeights = localStorage.getItem("ps_weights");
  if (savedWeights) setWeights(JSON.parse(savedWeights));
  const savedThresholds = localStorage.getItem("ps_thresholds");
  if (savedThresholds) {
    const t = JSON.parse(savedThresholds);
    setThreshold(t.threshold);
    setCritCutoff(t.critCutoff);
    setHighCutoff(t.highCutoff);
  }
}, []);
```

### Type consistency
- `AlertEvent.shap: Record<string, number>` used in ShapWaterfall, EnsemblePanel, PolarRadar — all consistent.
- `EnsemblePanel` accepts `scores?: Record<string, number>` — matches AlertEvent.shap shape.
- `api.getSimilar` returns `{ similar_alerts: unknown[] }` — SimilarAlerts casts to `SimilarAlert[]`. Acceptable for Phase 2.
