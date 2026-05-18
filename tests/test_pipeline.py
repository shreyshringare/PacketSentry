"""Tests for DetectionPipeline — the end-to-end orchestrator.

Verifies that raw ParsedPackets flow through:
  FlowTracker → FeatureExtractor → Detectors → EnsembleArbiter → AlertEngine
"""

from __future__ import annotations

import time

import pytest

from packetsentry.features.flow_tracker import ParsedPacket


def _pkt(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "192.168.1.1",
    src_port: int = 12345,
    dst_port: int = 80,
    protocol: int = 6,
    length: int = 500,
    flags: int = 0x02,
    payload: bytes = b"",
    ts_offset: float = 0.0,
) -> ParsedPacket:
    return ParsedPacket(
        timestamp=time.time() + ts_offset,
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        protocol=protocol, length=length,
        flags=flags, payload=payload,
    )


class TestDetectionPipeline:
    def test_pipeline_creates_without_crash(self) -> None:
        from packetsentry.capture.pipeline import DetectionPipeline
        pipeline = DetectionPipeline()
        assert pipeline is not None

    def test_ingest_single_packet_returns_none(self) -> None:
        """Single packet doesn't complete a flow — no decision yet."""
        from packetsentry.capture.pipeline import DetectionPipeline
        pipeline = DetectionPipeline()
        result = pipeline.ingest(_pkt())
        assert result is None

    def test_ingest_flow_completion_returns_result(self) -> None:
        """Feed packets past the flow timeout → flow completes → decision."""
        from packetsentry.capture.pipeline import DetectionPipeline
        pipeline = DetectionPipeline(flow_timeout=0.5)

        # First packet starts the flow
        pipeline.ingest(_pkt(ts_offset=0.0))
        # Second packet after timeout triggers completion
        result = pipeline.ingest(_pkt(ts_offset=1.0))

        # The flow should have completed and produced a decision
        assert result is not None
        assert hasattr(result, "is_alert")
        assert hasattr(result, "confidence")

    def test_stats_returns_counters(self) -> None:
        from packetsentry.capture.pipeline import DetectionPipeline
        pipeline = DetectionPipeline()
        pipeline.ingest(_pkt())

        stats = pipeline.stats()
        assert "packets" in stats
        assert stats["packets"] == 1
        assert "active_flows" in stats
        assert "alerts" in stats

    def test_flush_processes_remaining_flows(self) -> None:
        from packetsentry.capture.pipeline import DetectionPipeline
        pipeline = DetectionPipeline()
        pipeline.ingest(_pkt())
        pipeline.ingest(_pkt(dst_port=443))

        results = pipeline.flush()
        # flush() should return decisions for all active flows
        assert isinstance(results, list)

    def test_signature_match_fires_alert(self) -> None:
        """Packet with known Aho-Corasick pattern should boost score."""
        from packetsentry.capture.pipeline import DetectionPipeline
        pipeline = DetectionPipeline(flow_timeout=0.5)

        # Inject a packet with SQL injection payload
        pipeline.ingest(_pkt(
            payload=b"GET /index.php?id=1' OR '1'='1 HTTP/1.1",
            ts_offset=0.0,
        ))
        result = pipeline.ingest(_pkt(ts_offset=1.0))

        assert result is not None
        # aho_corasick score should be non-zero
        assert result.scores.get("aho_corasick", 0.0) > 0.0

    def test_pipeline_tracks_alert_count(self) -> None:
        from packetsentry.capture.pipeline import DetectionPipeline
        pipeline = DetectionPipeline(flow_timeout=0.5)
        pipeline.ingest(_pkt(ts_offset=0.0))
        pipeline.ingest(_pkt(ts_offset=1.0))
        stats = pipeline.stats()
        # alerts count should be a non-negative int
        assert stats["alerts"] >= 0
