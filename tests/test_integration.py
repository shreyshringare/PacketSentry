"""End-to-end integration tests: ParsedPacket → DetectionPipeline → DecisionResult.

These tests exercise the full detection path without mocking any internal
component. They prove that the pipeline wiring is correct — packet ingested,
flow completed, features extracted, ensemble decided, alert returned.

Two paths are tested:
  - Gate 1 (Aho-Corasick): payload containing a signature → instant CRITICAL alert
  - Gate 2 (ML ensemble): clean flow completed via flush() → DecisionResult returned
"""

from __future__ import annotations

import time
from typing import Iterator

import pytest

from packetsentry.capture.pipeline import DetectionPipeline
from packetsentry.features.flow_tracker import ParsedPacket


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pkt(
    src: str = "10.0.0.1",
    dst: str = "10.0.0.2",
    sport: int = 50000,
    dport: int = 80,
    proto: int = 6,
    length: int = 512,
    flags: int = 0x02,
    payload: bytes = b"",
    ts_offset: float = 0.0,
) -> ParsedPacket:
    """Build a minimal ParsedPacket for testing."""
    return ParsedPacket(
        timestamp=time.time() + ts_offset,
        src_ip=src,
        dst_ip=dst,
        src_port=sport,
        dst_port=dport,
        protocol=proto,
        length=length,
        flags=flags,
        payload=payload,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ingest_and_flush(
    pipeline: DetectionPipeline,
    payload: bytes,
    src: str = "10.0.0.1",
    dst: str = "10.0.0.2",
) -> list:
    """Send one packet then flush so the flow completes and Gate 1/2 runs."""
    pipeline.ingest(_pkt(src=src, dst=dst, payload=payload, ts_offset=0.0))
    return pipeline.flush()


# ---------------------------------------------------------------------------
# Gate 1: Aho-Corasick signature path
# ---------------------------------------------------------------------------

class TestGate1SignaturePath:
    """Packets with known-bad payloads trigger an alert on flow completion."""

    def test_sql_injection_payload_triggers_alert(self) -> None:
        """SQL injection bytes in payload → is_alert=True, confidence=1.0."""
        pipeline = DetectionPipeline(signatures=[b"' OR '1'='1"], flow_timeout=120.0)
        results = _ingest_and_flush(
            pipeline,
            payload=b"POST /login HTTP/1.1\r\n\r\nuser=admin' OR '1'='1&pass=x",
        )
        assert results, "flush() should return at least one DecisionResult"
        r = results[0]
        assert r.is_alert is True
        assert r.confidence == 1.0
        assert r.scores.get("aho_corasick") == 1.0

    def test_xss_payload_triggers_alert(self) -> None:
        """XSS bytes in payload → alert fired."""
        pipeline = DetectionPipeline(signatures=[b"<script>"], flow_timeout=120.0)
        results = _ingest_and_flush(pipeline, payload=b"GET /?q=<script>alert(1)</script>")
        assert results and results[0].is_alert is True

    def test_path_traversal_triggers_alert(self) -> None:
        """Path traversal pattern → alert fired."""
        pipeline = DetectionPipeline(signatures=[b"../../../"], flow_timeout=120.0)
        results = _ingest_and_flush(pipeline, payload=b"GET /../../../etc/passwd HTTP/1.1")
        assert results and results[0].is_alert is True

    def test_clean_payload_does_not_trigger_gate1(self) -> None:
        """Benign payload → no Aho-Corasick match; result may still come from Gate 2."""
        pipeline = DetectionPipeline(signatures=[b"' OR '1'='1"], flow_timeout=120.0)
        results = _ingest_and_flush(pipeline, payload=b"GET /index.html HTTP/1.1\r\n\r\n")
        # Gate 1 must NOT have fired (no aho_corasick=1.0 hit)
        for r in results:
            assert r.scores.get("aho_corasick", 0.0) != 1.0

    def test_alert_callback_fires_on_gate1_match(self) -> None:
        """alert_callback is invoked when Gate 1 fires."""
        fired: list[tuple] = []

        def _cb(result, features, src, dst, port):
            fired.append((result.confidence, src, dst, port))

        pipeline = DetectionPipeline(
            signatures=[b"/etc/passwd"],
            alert_callback=_cb,
            flow_timeout=120.0,
        )
        _ingest_and_flush(pipeline, payload=b"GET /../../../etc/passwd")
        assert len(fired) == 1
        assert fired[0][0] == 1.0  # confidence


# ---------------------------------------------------------------------------
# Gate 2: ML ensemble path via flush()
# ---------------------------------------------------------------------------

class TestGate2EnsemblePath:
    """Full ML pipeline path: ingest packets, flush flows, get DecisionResult."""

    def test_flush_returns_decision_result(self) -> None:
        """Ingesting packets then flushing produces at least one DecisionResult."""
        pipeline = DetectionPipeline(signatures=[], flow_timeout=120.0)
        # Feed several packets from the same flow
        for i in range(5):
            pipeline.ingest(_pkt(ts_offset=float(i), length=100 + i * 10))
        results = pipeline.flush()
        assert isinstance(results, list)
        assert len(results) >= 1

    def test_decision_result_has_required_fields(self) -> None:
        """Every DecisionResult exposes is_alert, confidence, and scores."""
        pipeline = DetectionPipeline(signatures=[], flow_timeout=120.0)
        pipeline.ingest(_pkt(ts_offset=0.0))
        results = pipeline.flush()
        assert results, "Expected at least one result from flush()"
        r = results[0]
        assert isinstance(r.is_alert, bool)
        assert 0.0 <= r.confidence <= 1.0
        assert isinstance(r.scores, dict)
        assert len(r.scores) > 0

    def test_scores_dict_contains_all_detectors(self) -> None:
        """Ensemble scores include all 7 detectors."""
        expected = {
            "aho_corasick", "xgboost", "random_forest",
            "isolation_forest", "transformer_ae", "gnn_detector", "zscore",
        }
        pipeline = DetectionPipeline(signatures=[], flow_timeout=120.0)
        pipeline.ingest(_pkt())
        results = pipeline.flush()
        assert results
        assert expected.issubset(set(results[0].scores.keys()))

    def test_stats_increment_on_ingest(self) -> None:
        """Pipeline stats reflect packet and flow counts after processing."""
        pipeline = DetectionPipeline(signatures=[], flow_timeout=120.0)
        for i in range(3):
            pipeline.ingest(_pkt(ts_offset=float(i)))
        pipeline.flush()
        s = pipeline.stats()
        assert s["packets"] == 3
        assert s["completed_flows"] >= 1

    def test_multi_flow_separation(self) -> None:
        """Packets from two different src IPs produce independent flows."""
        pipeline = DetectionPipeline(signatures=[], flow_timeout=120.0)
        pipeline.ingest(_pkt(src="10.0.0.1", ts_offset=0.0))
        pipeline.ingest(_pkt(src="10.0.0.2", ts_offset=0.0))
        results = pipeline.flush()
        # Should have at least 2 results (one per flow)
        assert len(results) >= 2
