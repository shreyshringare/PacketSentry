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

from fastapi import APIRouter, Depends, HTTPException, Query

from dependencies import get_current_user

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
async def get_stats(user: dict = Depends(get_current_user)) -> dict:
    """Return current pipeline statistics."""
    if _pipeline is None:
        return {"packets": 0, "flows": 0, "alerts": 0, "active_flows": 0, "bytes": 0}
    return _pipeline.stats()


@router.get("/api/flows/active")
async def get_active_flows(limit: int = Query(50, ge=1, le=200), user: dict = Depends(get_current_user)) -> list[dict]:
    """Return top flows sorted by anomaly score descending."""
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
            "proto": "TCP",
            "score": float(a.get("confidence", 0)),
            "severity": a.get("severity", "LOW"),
            "detectors": detectors,
            "bytes": 0,
        })
    return sorted(flows, key=lambda x: x["score"], reverse=True)


@router.get("/api/similar/{alert_id}")
async def get_similar(
    alert_id: str,
    top: int = Query(5, ge=1, le=20),
    user: dict = Depends(get_current_user),
) -> dict:
    """Return ChromaDB top-N similar alerts by embedding cosine similarity."""
    if _vector_store is None:
        return {"similar_alerts": []}

    try:
        results = _vector_store._collection.get(ids=[alert_id], include=["embeddings"])
        if not results.get("embeddings"):
            return {"similar_alerts": []}
        
        import numpy as np
        matches = _vector_store.find_similar(np.array(results["embeddings"][0]), top_k=top+1)
        similar = [m for m in matches if m["alert_id"] != alert_id][:top]
        
        formatted = []
        for m in similar:
             formatted.append({
                  "alert_id": m["alert_id"],
                  "similarity": max(0.0, 1.0 - m["distance"]),
                  "rule": m["metadata"].get("rule", "Unknown"),
                  "severity": m["metadata"].get("severity", "LOW"),
                  "src_ip": m["metadata"].get("src_ip", "0.0.0.0"),
                  "timestamp": m["metadata"].get("timestamp", "")
             })
        return {"similar_alerts": formatted}
    except Exception as exc:
        logger.warning("ChromaDB similarity query failed: %s", exc)
        return {"similar_alerts": []}


@router.get("/api/clusters")
async def get_clusters(user: dict = Depends(get_current_user)) -> dict:
    """Stub for Phase 3 Memory/UMAP screen."""
    return {"clusters": [], "note": "Phase 3 — not yet implemented"}
