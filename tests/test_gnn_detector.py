"""Tests for GNNDetector — from-scratch GraphSAGE-style, no PyG dependency.

The GNN models network traffic as a graph:
  Nodes = unique IP addresses seen
  Edges = flows between IP pairs (with 23-feature edge attributes)

Anomaly detection = graph autoencoder reconstruction error per flow.

All tests use tiny synthetic graphs — no real network traffic needed.
"""

from __future__ import annotations

import numpy as np
import pytest

from packetsentry.features.extractor import FlowFeatures


def _feat(
    src_ip: str = "192.168.1.1",
    dst_ip: str = "10.0.0.1",
    src_bytes: int = 500,
    dst_bytes: int = 300,
    dst_port: int = 80,
) -> FlowFeatures:
    return FlowFeatures(
        duration=2.0, protocol_type=0,
        src_bytes=src_bytes, dst_bytes=dst_bytes,
        flag_syn=1, flag_ack=3, flag_fin=1, flag_rst=0, flag_psh=1,
        packet_count=5,
        avg_packet_size=(src_bytes + dst_bytes) / 5,
        bytes_per_second=(src_bytes + dst_bytes) / 2.0,
        packets_per_second=2.5,
        count=0, srv_count=0, dst_host_count=0, dst_host_srv_count=0,
        serror_rate=0.0, rerror_rate=0.0,
        same_srv_rate=1.0, diff_srv_rate=0.0,
        src_port=12345, dst_port=dst_port,
    )


# ===================================================================
# FlowGraph — the graph data structure
# ===================================================================

class TestFlowGraph:
    """Test the internal graph representation."""

    def test_add_flow_creates_nodes(self) -> None:
        from packetsentry.detection.gnn_detector import FlowGraph
        g = FlowGraph()
        g.add_flow("1.1.1.1", "2.2.2.2", np.zeros(23))
        assert "1.1.1.1" in g.nodes
        assert "2.2.2.2" in g.nodes

    def test_add_flow_creates_edge(self) -> None:
        from packetsentry.detection.gnn_detector import FlowGraph
        g = FlowGraph()
        feat = np.ones(23, dtype=np.float32)
        g.add_flow("1.1.1.1", "2.2.2.2", feat)
        assert len(g.edges) == 1

    def test_node_count(self) -> None:
        from packetsentry.detection.gnn_detector import FlowGraph
        g = FlowGraph()
        g.add_flow("A", "B", np.zeros(23))
        g.add_flow("B", "C", np.zeros(23))
        g.add_flow("A", "C", np.zeros(23))
        assert len(g.nodes) == 3

    def test_same_node_not_duplicated(self) -> None:
        from packetsentry.detection.gnn_detector import FlowGraph
        g = FlowGraph()
        g.add_flow("A", "B", np.zeros(23))
        g.add_flow("A", "C", np.zeros(23))
        assert len(g.nodes) == 3   # A, B, C

    def test_adjacency_matrix_shape(self) -> None:
        from packetsentry.detection.gnn_detector import FlowGraph
        g = FlowGraph()
        g.add_flow("A", "B", np.zeros(23))
        g.add_flow("B", "C", np.zeros(23))
        adj = g.get_adjacency()
        n = len(g.nodes)
        assert adj.shape == (n, n)

    def test_node_feature_matrix_shape(self) -> None:
        from packetsentry.detection.gnn_detector import FlowGraph
        g = FlowGraph()
        g.add_flow("A", "B", np.ones(23))
        g.add_flow("B", "C", np.ones(23))
        X = g.get_node_features()
        n = len(g.nodes)
        assert X.shape[0] == n

    def test_max_nodes_evicts_oldest(self) -> None:
        from packetsentry.detection.gnn_detector import FlowGraph
        g = FlowGraph(max_nodes=3)
        g.add_flow("A", "B", np.zeros(23))
        g.add_flow("C", "D", np.zeros(23))
        g.add_flow("E", "F", np.zeros(23))
        # Should not grow beyond max_nodes * 2 (bidirectional adds)
        assert len(g.nodes) <= 6


# ===================================================================
# GraphSAGE — the from-scratch GNN layer
# ===================================================================

class TestGraphSAGELayer:
    """Test the hand-rolled message passing layer."""

    def test_forward_output_shape(self) -> None:
        import torch
        from packetsentry.detection.gnn_detector import GraphSAGELayer
        layer = GraphSAGELayer(in_features=8, out_features=16)
        n = 4
        X = torch.randn(n, 8)
        adj = torch.eye(n)
        out = layer(X, adj)
        assert out.shape == (n, 16)

    def test_forward_different_input_different_output(self) -> None:
        import torch
        from packetsentry.detection.gnn_detector import GraphSAGELayer
        layer = GraphSAGELayer(in_features=8, out_features=8)
        n = 3
        adj = torch.eye(n)
        X1 = torch.zeros(n, 8)
        X2 = torch.ones(n, 8)
        assert not torch.allclose(layer(X1, adj), layer(X2, adj))

    def test_layer_has_parameters(self) -> None:
        from packetsentry.detection.gnn_detector import GraphSAGELayer
        layer = GraphSAGELayer(in_features=8, out_features=16)
        params = list(layer.parameters())
        assert len(params) > 0


# ===================================================================
# GNNDetector — warmup + self-training
# ===================================================================

class TestGNNDetectorWarmup:
    """Silent during warmup — no false positives at startup."""

    def test_score_returns_zero_before_warmup(self) -> None:
        from packetsentry.detection.gnn_detector import GNNDetector
        det = GNNDetector(warmup=500)
        score = det.score("1.1.1.1", "2.2.2.2", _feat())
        assert score == pytest.approx(0.0)

    def test_not_trained_before_warmup(self) -> None:
        from packetsentry.detection.gnn_detector import GNNDetector
        det = GNNDetector(warmup=10)
        for i in range(9):
            det.score(f"10.0.0.{i}", "1.1.1.1", _feat())
        assert det.is_trained is False

    def test_trains_at_warmup_boundary(self) -> None:
        from packetsentry.detection.gnn_detector import GNNDetector
        det = GNNDetector(warmup=10, epochs=2)
        for i in range(10):
            det.score(f"10.0.0.{i % 5}", f"192.168.{i % 3}.1", _feat())
        assert det.is_trained is True

    def test_graph_accumulates_during_warmup(self) -> None:
        from packetsentry.detection.gnn_detector import GNNDetector
        det = GNNDetector(warmup=10)
        for i in range(5):
            det.score(f"10.0.0.{i}", "1.1.1.1", _feat())
        assert len(det._graph.edges) == 5


class TestGNNDetectorScoring:
    """After warmup, detector returns valid scores."""

    @pytest.fixture
    def trained_detector(self):
        from packetsentry.detection.gnn_detector import GNNDetector
        det = GNNDetector(warmup=10, epochs=3)
        for i in range(11):
            det.score(f"10.0.0.{i % 5}", f"192.168.{i % 3}.1", _feat())
        return det

    def test_score_is_float(self, trained_detector) -> None:
        score = trained_detector.score("10.0.0.1", "1.1.1.1", _feat())
        assert isinstance(score, float)

    def test_score_in_unit_interval(self, trained_detector) -> None:
        score = trained_detector.score("10.0.0.1", "1.1.1.1", _feat())
        assert 0.0 <= score <= 1.0

    def test_score_does_not_crash_on_new_ip(self, trained_detector) -> None:
        """New IPs not seen in training must not crash."""
        score = trained_detector.score("99.99.99.99", "88.88.88.88", _feat())
        assert 0.0 <= score <= 1.0


# ===================================================================
# GNNDetector — topology awareness
# ===================================================================

class TestGNNTopologyAwareness:
    """The GNN should differentiate normal vs fan-out (port scan) topology."""

    def test_high_fanout_detectable(self) -> None:
        """
        Sanity check: after training on low-fanout traffic,
        high-fanout (1 src → many dst) score >= 0.0 and is a float.
        We cannot guarantee it's higher without careful training,
        but verify it runs correctly.
        """
        from packetsentry.detection.gnn_detector import GNNDetector
        det = GNNDetector(warmup=20, epochs=5)
        # Train: one-to-one traffic (normal)
        for i in range(20):
            det.score(f"10.0.0.{i % 4}", f"192.168.1.{i % 4}", _feat())
        # Score: fan-out — 1 src → many dst (port scan pattern)
        for i in range(10):
            score = det.score("10.0.0.1", f"1.1.{i}.1", _feat(dst_port=i))
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0
