"""Tests for AlertEngine."""

from datetime import datetime, timedelta
import json
from unittest.mock import MagicMock

import pytest

from packetsentry.alerts.engine import AlertEngine
from packetsentry.detection.ensemble import DecisionResult
from packetsentry.features.extractor import FlowFeatures


def _feat() -> FlowFeatures:
    return FlowFeatures(
        duration=2.0, protocol_type=0,
        src_bytes=500, dst_bytes=300,
        flag_syn=1, flag_ack=3, flag_fin=1, flag_rst=0, flag_psh=1,
        packet_count=5, avg_packet_size=160.0,
        bytes_per_second=400.0, packets_per_second=2.5,
        count=0, srv_count=0, dst_host_count=0, dst_host_srv_count=0,
        serror_rate=0.0, rerror_rate=0.0,
        same_srv_rate=1.0, diff_srv_rate=0.0,
        src_port=12345, dst_port=80,
    )


class TestAlertEngine:
    @pytest.fixture
    def engine(self):
        db_mock = MagicMock()
        chroma_mock = MagicMock()
        extractor_mock = MagicMock()
        return AlertEngine(
            db_store=db_mock,
            chroma_store=chroma_mock,
            embedding_extractor=extractor_mock,
            dedup_seconds=1.0
        )

    def test_process_ignores_non_alerts(self, engine) -> None:
        result = DecisionResult(is_alert=False, confidence=0.2, scores={}, explanation=None)
        
        engine.process(result, _feat(), "1.1.1.1", "2.2.2.2", 80)
        
        engine.db_store.insert_alert.assert_not_called()
        engine.chroma_store.store_alert.assert_not_called()

    def test_process_stores_alerts(self, engine) -> None:
        result = DecisionResult(is_alert=True, confidence=0.8, scores={}, explanation=None)
        
        engine.process(result, _feat(), "1.1.1.1", "2.2.2.2", 80)
        
        # Check DuckDB insertion
        engine.db_store.insert_alert.assert_called_once()
        args = engine.db_store.insert_alert.call_args[0][0]
        assert args["src_ip"] == "1.1.1.1"
        assert args["severity"] == "HIGH"
        
        # Check ChromaDB insertion (extractor returns mocked embedding)
        engine.chroma_store.store_alert.assert_called_once()

    def test_severity_mapping(self, engine) -> None:
        assert engine._get_severity(0.95) == "CRITICAL"
        assert engine._get_severity(0.80) == "HIGH"
        assert engine._get_severity(0.65) == "MED"
        assert engine._get_severity(0.55) == "LOW"

    def test_deduplication(self, engine) -> None:
        result = DecisionResult(is_alert=True, confidence=0.8, scores={}, explanation=None)
        
        # First call should process
        engine.process(result, _feat(), "1.1.1.1", "2.2.2.2", 80)
        assert engine.db_store.insert_alert.call_count == 1
        
        # Second call within 1 second should be ignored
        engine.process(result, _feat(), "1.1.1.1", "2.2.2.2", 80)
        assert engine.db_store.insert_alert.call_count == 1
        
        # Call from a different IP should be processed
        engine.process(result, _feat(), "3.3.3.3", "2.2.2.2", 80)
        assert engine.db_store.insert_alert.call_count == 2
