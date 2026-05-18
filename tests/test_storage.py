"""Tests for EmbeddingExtractor and ChromaDB VectorStore."""

from __future__ import annotations

import numpy as np
import pytest

from packetsentry.features.extractor import FlowFeatures
from packetsentry.detection.transformer_ae import TransformerAEDetector


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


class TestEmbeddingExtractor:
    def test_extract_returns_none_if_untrained(self) -> None:
        from packetsentry.storage.embedding import EmbeddingExtractor
        transformer = TransformerAEDetector(warmup=10)
        extractor = EmbeddingExtractor(transformer)
        
        # Add some flows but not enough to train
        for _ in range(5):
            transformer.score(_feat())
            
        emb = extractor.extract(_feat())
        assert emb is None

    def test_extract_returns_normalized_vector(self) -> None:
        from packetsentry.storage.embedding import EmbeddingExtractor
        transformer = TransformerAEDetector(warmup=10, seq_len=5, epochs=2)
        extractor = EmbeddingExtractor(transformer)
        
        # Train and fill window
        for _ in range(15):
            transformer.score(_feat())
            
        emb = extractor.extract(_feat())
        assert emb is not None
        assert emb.shape == (64,)
        
        # Check L2 norm is approx 1.0
        norm = np.linalg.norm(emb)
        assert norm == pytest.approx(1.0)


class TestChromaStore:
    @pytest.fixture
    def store(self):
        from packetsentry.storage.vector_store import ChromaStore
        import uuid
        # Use ephemeral in-memory client for tests and unique collection
        return ChromaStore(persist_directory=None, collection_name=f"test_{uuid.uuid4().hex}")

    def test_store_and_find_similar(self, store) -> None:
        emb1 = np.random.randn(64).astype(np.float32)
        emb1 /= np.linalg.norm(emb1)
        
        emb2 = np.random.randn(64).astype(np.float32)
        emb2 /= np.linalg.norm(emb2)

        store.store_alert("alert-1", emb1, {"src_ip": "1.1.1.1", "severity": "HIGH"})
        store.store_alert("alert-2", emb2, {"src_ip": "2.2.2.2", "severity": "LOW"})

        # Search with emb1
        results = store.find_similar(emb1, top_k=2)
        
        assert len(results) == 2
        # First result should be alert-1 since distance is 0
        assert results[0]["alert_id"] == "alert-1"
        assert results[0]["metadata"]["src_ip"] == "1.1.1.1"
        assert results[0]["distance"] < 1e-5  # Almost 0 distance
        
        # Second result is alert-2
        assert results[1]["alert_id"] == "alert-2"
        assert results[1]["distance"] > 0.0

    def test_empty_store_search(self, store) -> None:
        emb = np.random.randn(64).astype(np.float32)
        emb /= np.linalg.norm(emb)
        
        results = store.find_similar(emb)
        assert len(results) == 0
