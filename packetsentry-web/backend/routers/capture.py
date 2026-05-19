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
    """Background task: sniff packets, feed to pipeline, broadcast events."""
    try:
        from scapy.all import AsyncSniffer
        from packetsentry.dissector.ethernet import dissect_packet

        def _packet_handler(raw_pkt):
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
