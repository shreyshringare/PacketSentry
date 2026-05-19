"""WebSocket connection manager + DetectionPipeline bridge.

Each connected client gets its own asyncio.Queue (maxsize=100).
Slow clients are dropped when their queue is full (non-blocking put_nowait).
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
        await ws.accept()
        self._clients[ws] = asyncio.Queue(maxsize=_QUEUE_MAXSIZE)
        logger.info("WS client connected. Total: %d", len(self._clients))

    def disconnect(self, ws: WebSocket) -> None:
        self._clients.pop(ws, None)
        logger.info("WS client disconnected. Total: %d", len(self._clients))

    async def broadcast(self, message: dict[str, Any]) -> None:
        """Broadcast a message to all connected clients. Drops slow clients."""
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

    # ── Message builders ───────────────────────────────────────────────────

    def make_packet_event(
        self,
        src: str, dst: str, proto: str,
        length: int, flags: str,
        flow_score: float, flagged: bool,
    ) -> dict:
        return {
            "type": "packet_event",
            "ts": time.time(),
            "src": src, "dst": dst, "proto": proto,
            "length": length, "flags": flags,
            "flow_score": round(flow_score, 3),
            "flagged": flagged,
        }

    def make_alert_event(
        self,
        alert_id: str, rule: str, severity: str,
        confidence: float, src_ip: str, dst_ip: str,
        port: int, detectors: list[str], shap: dict[str, float],
    ) -> dict:
        return {
            "type": "alert_event",
            "id": alert_id, "rule": rule, "severity": severity,
            "confidence": round(confidence, 3),
            "src_ip": src_ip, "dst_ip": dst_ip, "port": port,
            "detectors": detectors,
            "shap": {k: round(v, 3) for k, v in shap.items()},
            "ts": int(time.time()),
        }

    def make_stats_update(
        self, pps: int, flows: int, ensemble_conf: float, active_alerts: int,
    ) -> dict:
        return {
            "type": "stats_update",
            "pps": pps, "flows": flows,
            "ensemble_conf": round(ensemble_conf, 3),
            "active_alerts": active_alerts,
        }

    def make_flow_update(self, flows: list[dict]) -> dict:
        return {"type": "flow_update", "flows": flows}
