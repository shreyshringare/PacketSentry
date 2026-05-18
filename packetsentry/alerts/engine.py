"""Alert Engine for routing and deduplicating ML decisions.

Sits between the EnsembleArbiter and the Storage layer.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime
from typing import Optional

from packetsentry.alerts.store import DuckDBAlertStore
from packetsentry.detection.ensemble import DecisionResult
from packetsentry.features.extractor import FlowFeatures
from packetsentry.storage.embedding import EmbeddingExtractor
from packetsentry.storage.vector_store import ChromaStore

logger = logging.getLogger(__name__)


class AlertEngine:
    """Processes ML decisions, applies deduplication, and routes to storage."""

    def __init__(
        self,
        db_store: DuckDBAlertStore,
        chroma_store: ChromaStore,
        embedding_extractor: EmbeddingExtractor,
        dedup_seconds: float = 60.0
    ) -> None:
        """Initialize the AlertEngine.

        Args:
            db_store: DuckDB store for structured alerts.
            chroma_store: ChromaDB store for vector memory.
            embedding_extractor: Extractor for 64-dim embeddings.
            dedup_seconds: Cooldown period per source IP to prevent spamming.
        """
        self.db_store = db_store
        self.chroma_store = chroma_store
        self.embedding_extractor = embedding_extractor
        self._dedup_seconds = dedup_seconds

        # Maps source IP -> timestamp of last alert
        self._last_alert_time: dict[str, datetime] = {}

    def process(
        self,
        result: DecisionResult,
        features: FlowFeatures,
        src_ip: str,
        dst_ip: str,
        dst_port: int
    ) -> None:
        """Process a decision result.

        If it's an alert and not deduplicated, stores it in DuckDB and ChromaDB.

        Args:
            result: Decision from the EnsembleArbiter.
            features: The flow features that triggered this.
            src_ip: Source IP.
            dst_ip: Destination IP.
            dst_port: Destination port.
        """
        if not result.is_alert:
            return

        now = datetime.now()

        # Deduplication check
        if src_ip in self._last_alert_time:
            time_since_last = (now - self._last_alert_time[src_ip]).total_seconds()
            if time_since_last < self._dedup_seconds:
                return  # Drop alert to avoid spam

        self._last_alert_time[src_ip] = now

        alert_id = str(uuid.uuid4())
        severity = self._get_severity(result.confidence)

        # Build structured alert
        shap_json = "{}"
        if result.explanation:
            shap_json = json.dumps({
                "top_features": result.explanation.top_features,
                "summary": result.explanation.summary
            })

        alert_data = {
            "alert_id": alert_id,
            "timestamp": now,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "confidence": result.confidence,
            "severity": severity,
            "shap_explanation": shap_json,
        }

        # Save to DuckDB
        self.db_store.insert_alert(alert_data)
        logger.warning(f"🚨 ALERT [{severity}] {src_ip} -> {dst_ip}:{dst_port} (Conf: {result.confidence:.2f})")

        # Save to ChromaDB
        embedding = self.embedding_extractor.extract(features)
        if embedding is not None:
            self.chroma_store.store_alert(
                alert_id=alert_id,
                embedding=embedding,
                metadata={"src_ip": src_ip, "severity": severity, "timestamp": now.isoformat()}
            )

    def _get_severity(self, confidence: float) -> str:
        """Map a confidence score to a string severity."""
        if confidence >= 0.90:
            return "CRITICAL"
        elif confidence >= 0.75:
            return "HIGH"
        elif confidence >= 0.60:
            return "MED"
        else:
            return "LOW"
