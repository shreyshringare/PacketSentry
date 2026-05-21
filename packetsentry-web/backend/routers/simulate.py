"""Simulation endpoint — generate synthetic attack flows through the ensemble.

POST /api/simulate        — burst: generate N synthetic alerts immediately
POST /api/simulate/start  — stream: background task emitting alerts on interval
POST /api/simulate/stop   — stop background stream
GET  /api/simulate/status — check if stream is running

All alerts are run through EnsembleArbiter.decide(), persisted to DuckDB,
and broadcast via WebSocket — indistinguishable from live capture alerts.
No auth required (demo-friendly).
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import time
import uuid
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/simulate", tags=["simulate"])

# ── Injected singletons ────────────────────────────────────────────────────

_store = None
_arbiter = None
_ws_manager = None
_stream_task: Optional[asyncio.Task] = None


def set_dependencies(store, arbiter, ws_manager) -> None:
    global _store, _arbiter, _ws_manager
    _store = store
    _arbiter = arbiter
    _ws_manager = ws_manager


# ── Attack profiles ────────────────────────────────────────────────────────
# Each profile defines realistic detector score ranges for that attack type.
# Scores are sampled from (min, max) ranges — adds natural variance.

_ATTACK_PROFILES: dict[str, dict] = {
    "port_scan": {
        "label": "Port Scan",
        "scores": {
            "aho_corasick":     (0.05, 0.20),
            "xgboost":          (0.70, 0.92),
            "random_forest":    (0.65, 0.88),
            "isolation_forest": (0.75, 0.95),
            "transformer_ae":   (0.30, 0.55),
            "gnn_detector":     (0.80, 0.96),  # topology: star pattern
            "zscore":           (0.60, 0.85),
        },
        "src_ips": ["192.168.1.{}", "10.0.0.{}"],
        "dst_ips": ["10.10.10.1", "172.16.0.1", "192.168.0.1"],
        "ports": [22, 23, 80, 443, 3306, 5432, 8080, 8443],
        "shap_features": {
            "dst_host_count": (0.12, 0.22),
            "diff_srv_rate": (0.08, 0.18),
            "count": (0.10, 0.20),
            "flag_syn": (0.06, 0.14),
            "packets_per_second": (0.05, 0.12),
            "duration": (-0.04, -0.01),
            "src_bytes": (-0.03, -0.01),
        },
    },
    "dos": {
        "label": "DoS Flood",
        "scores": {
            "aho_corasick":     (0.10, 0.30),
            "xgboost":          (0.75, 0.95),
            "random_forest":    (0.70, 0.90),
            "isolation_forest": (0.80, 0.98),
            "transformer_ae":   (0.70, 0.92),  # temporal: sustained burst
            "gnn_detector":     (0.60, 0.82),
            "zscore":           (0.85, 0.99),
        },
        "src_ips": ["203.0.113.{}", "198.51.100.{}"],
        "dst_ips": ["10.10.10.5", "172.16.0.10"],
        "ports": [80, 443, 53],
        "shap_features": {
            "bytes_per_second": (0.18, 0.30),
            "packets_per_second": (0.15, 0.25),
            "count": (0.12, 0.20),
            "srv_count": (0.10, 0.18),
            "duration": (0.06, 0.14),
            "flag_syn": (0.04, 0.10),
            "dst_bytes": (-0.02, -0.01),
        },
    },
    "sql_injection": {
        "label": "SQL Injection",
        "scores": {
            "aho_corasick":     (0.75, 0.98),  # signature: exact match
            "xgboost":          (0.65, 0.85),
            "random_forest":    (0.60, 0.80),
            "isolation_forest": (0.40, 0.65),
            "transformer_ae":   (0.30, 0.55),
            "gnn_detector":     (0.20, 0.45),
            "zscore":           (0.35, 0.60),
        },
        "src_ips": ["192.168.2.{}", "10.1.1.{}"],
        "dst_ips": ["10.10.10.20", "172.16.0.50"],
        "ports": [80, 443, 3306, 5432],
        "shap_features": {
            "src_bytes": (0.14, 0.24),
            "avg_packet_size": (0.10, 0.20),
            "flag_psh": (0.08, 0.16),
            "dst_port": (0.06, 0.14),
            "duration": (0.04, 0.10),
            "count": (-0.03, -0.01),
            "packets_per_second": (-0.02, -0.01),
        },
    },
    "brute_force": {
        "label": "Brute Force",
        "scores": {
            "aho_corasick":     (0.20, 0.45),
            "xgboost":          (0.68, 0.88),
            "random_forest":    (0.65, 0.85),
            "isolation_forest": (0.55, 0.78),
            "transformer_ae":   (0.60, 0.82),  # temporal: repeated pattern
            "gnn_detector":     (0.45, 0.68),
            "zscore":           (0.50, 0.75),
        },
        "src_ips": ["185.220.101.{}", "45.142.212.{}"],
        "dst_ips": ["10.10.10.1", "192.168.0.10"],
        "ports": [22, 3389, 5900, 21],
        "shap_features": {
            "count": (0.15, 0.25),
            "srv_count": (0.12, 0.22),
            "flag_rst": (0.08, 0.16),
            "serror_rate": (0.07, 0.15),
            "rerror_rate": (0.06, 0.13),
            "packets_per_second": (0.04, 0.10),
            "dst_bytes": (-0.03, -0.01),
        },
    },
    "data_exfil": {
        "label": "Data Exfiltration",
        "scores": {
            "aho_corasick":     (0.05, 0.20),
            "xgboost":          (0.60, 0.82),
            "random_forest":    (0.55, 0.78),
            "isolation_forest": (0.65, 0.88),
            "transformer_ae":   (0.55, 0.80),
            "gnn_detector":     (0.50, 0.72),
            "zscore":           (0.60, 0.85),
        },
        "src_ips": ["10.10.10.{}", "192.168.1.{}"],
        "dst_ips": ["91.108.4.{}", "149.154.160.{}"],
        "ports": [443, 8443, 4444, 1337],
        "shap_features": {
            "src_bytes": (0.20, 0.35),
            "bytes_per_second": (0.12, 0.22),
            "duration": (0.10, 0.20),
            "dst_bytes": (0.06, 0.14),
            "avg_packet_size": (0.05, 0.12),
            "flag_psh": (0.04, 0.10),
            "flag_ack": (-0.02, -0.01),
        },
    },
}

_ALL_ATTACK_TYPES = list(_ATTACK_PROFILES.keys())


# ── Helpers ────────────────────────────────────────────────────────────────

def _rnd(lo: float, hi: float) -> float:
    return random.uniform(lo, hi)


def _pick_ip(templates: list[str]) -> str:
    t = random.choice(templates)
    if "{}" in t:
        return t.format(random.randint(1, 254))
    return t


_SEVERITY_THRESHOLDS = [(0.90, "CRITICAL"), (0.75, "HIGH"), (0.60, "MED"), (0.0, "LOW")]


def _severity(conf: float) -> str:
    for threshold, label in _SEVERITY_THRESHOLDS:
        if conf >= threshold:
            return label
    return "LOW"


def _rule_from_scores(scores: dict[str, float], attack_label: str) -> str:
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
    return f"{attack_label} — {rules.get(top[0], 'Unknown')}"


def _generate_alert(attack_type: Optional[str] = None) -> dict:
    """Generate one synthetic alert, run through arbiter, return alert dict."""
    if attack_type and attack_type in _ATTACK_PROFILES:
        profile = _ATTACK_PROFILES[attack_type]
    else:
        profile = random.choice(list(_ATTACK_PROFILES.values()))

    # Sample detector scores from profile ranges
    scores = {
        detector: round(_rnd(*rng), 4)
        for detector, rng in profile["scores"].items()
    }

    # Run through ensemble arbiter
    result = _arbiter.decide(scores)
    if not result.is_alert:
        # Nudge xgboost/isolation_forest to ensure it fires (demo purposes)
        scores["xgboost"] = max(scores["xgboost"], 0.55)
        scores["isolation_forest"] = max(scores["isolation_forest"], 0.55)
        result = _arbiter.decide(scores)

    conf = result.confidence
    severity = _severity(conf)

    # Synthetic SHAP values from profile
    shap = {
        feat: round(_rnd(*rng), 4)
        for feat, rng in profile["shap_features"].items()
    }

    src_ip = _pick_ip(profile["src_ips"])
    dst_ip = random.choice(profile["dst_ips"])
    dst_port = random.choice(profile["ports"])
    alert_id = str(uuid.uuid4())
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    label = profile["label"]

    fired = [k for k, v in scores.items() if v > 0.5]

    return {
        "alert_id": alert_id,
        "timestamp": ts,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "confidence": round(conf, 4),
        "severity": severity,
        "rule": _rule_from_scores(scores, label),
        "shap_explanation": json.dumps(shap),
        "scores": scores,
        "fired": fired,
        "shap": shap,
    }


async def _emit_alert(alert: dict) -> None:
    """Persist to DuckDB + broadcast via WebSocket."""
    if _store:
        _store.insert_alert({
            "alert_id": alert["alert_id"],
            "timestamp": alert["timestamp"],
            "src_ip": alert["src_ip"],
            "dst_ip": alert["dst_ip"],
            "dst_port": alert["dst_port"],
            "confidence": alert["confidence"],
            "severity": alert["severity"],
            "shap_explanation": alert["shap_explanation"],
        })

    if _ws_manager:
        alert_event = _ws_manager.make_alert_event(
            alert_id=alert["alert_id"],
            rule=alert["rule"],
            severity=alert["severity"],
            confidence=alert["confidence"],
            src_ip=alert["src_ip"],
            dst_ip=alert["dst_ip"],
            port=alert["dst_port"],
            detectors=alert["fired"],
            shap=alert["shap"],
        )
        await _ws_manager.broadcast(alert_event)

        # Also push a stats update
        stats_event = _ws_manager.make_stats_update(
            pps=random.randint(80, 350),
            flows=random.randint(10, 60),
            ensemble_conf=alert["confidence"],
            active_alerts=random.randint(1, 8),
        )
        await _ws_manager.broadcast(stats_event)


# ── Stream task ────────────────────────────────────────────────────────────

async def _stream_loop(interval: float, attack_type: Optional[str]) -> None:
    """Background task: emit one synthetic alert every `interval` seconds."""
    logger.info("Simulate stream started: interval=%.1fs attack=%s", interval, attack_type or "random")
    try:
        while True:
            alert = _generate_alert(attack_type)
            await _emit_alert(alert)
            logger.debug("Simulated alert: id=%s severity=%s conf=%.3f",
                         alert["alert_id"], alert["severity"], alert["confidence"])
            await asyncio.sleep(interval)
    except asyncio.CancelledError:
        logger.info("Simulate stream stopped")
        raise


# ── Request/response models ────────────────────────────────────────────────

class BurstRequest(BaseModel):
    count: int = Field(default=5, ge=1, le=50, description="Number of alerts to generate (max 50)")
    attack_type: Optional[str] = Field(default=None, description="Attack type or null for random")


class StreamRequest(BaseModel):
    interval: float = Field(default=5.0, ge=1.0, le=60.0, description="Seconds between alerts (1–60)")
    attack_type: Optional[str] = Field(default=None, description="Attack type or null for random")


# ── Endpoints ──────────────────────────────────────────────────────────────

@router.get("/attack-types")
def list_attack_types() -> dict:
    """List available attack profiles for simulation."""
    return {
        "attack_types": [
            {"id": k, "label": v["label"]}
            for k, v in _ATTACK_PROFILES.items()
        ]
    }


@router.post("")
async def simulate_burst(body: BurstRequest) -> dict:
    """Generate N synthetic attack alerts immediately.

    Alerts are persisted to DuckDB and broadcast via WebSocket.
    No auth required — safe for public demo.
    """
    if _arbiter is None:
        raise HTTPException(503, "Arbiter not initialized")

    if body.attack_type and body.attack_type not in _ATTACK_PROFILES:
        raise HTTPException(400, f"Unknown attack_type. Valid: {_ALL_ATTACK_TYPES}")

    generated = []
    for _ in range(body.count):
        alert = _generate_alert(body.attack_type)
        await _emit_alert(alert)
        generated.append({
            "alert_id": alert["alert_id"],
            "severity": alert["severity"],
            "confidence": alert["confidence"],
            "src_ip": alert["src_ip"],
            "rule": alert["rule"],
        })
        # Small stagger so timestamps differ
        await asyncio.sleep(0.05)

    logger.info("Simulated %d alerts (type=%s)", body.count, body.attack_type or "random")
    return {"ok": True, "generated": len(generated), "alerts": generated}


@router.post("/start")
async def stream_start(body: StreamRequest) -> dict:
    """Start continuous alert simulation stream."""
    global _stream_task

    if _arbiter is None:
        raise HTTPException(503, "Arbiter not initialized")

    if body.attack_type and body.attack_type not in _ATTACK_PROFILES:
        raise HTTPException(400, f"Unknown attack_type. Valid: {_ALL_ATTACK_TYPES}")

    if _stream_task and not _stream_task.done():
        return {"ok": True, "already_running": True, "interval": body.interval}

    _stream_task = asyncio.create_task(
        _stream_loop(body.interval, body.attack_type)
    )
    return {"ok": True, "started": True, "interval": body.interval, "attack_type": body.attack_type or "random"}


@router.post("/stop")
async def stream_stop() -> dict:
    """Stop the continuous simulation stream."""
    global _stream_task
    if _stream_task and not _stream_task.done():
        _stream_task.cancel()
        _stream_task = None
        return {"ok": True, "stopped": True}
    return {"ok": True, "was_running": False}


@router.get("/status")
def stream_status() -> dict:
    """Check if the simulation stream is active."""
    running = bool(_stream_task and not _stream_task.done())
    return {"running": running}
