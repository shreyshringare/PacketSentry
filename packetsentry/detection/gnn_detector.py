"""GNN-based network traffic anomaly detector — from scratch, no PyG.

Implements a GraphSAGE-style message passing network entirely in raw
PyTorch tensors. No PyTorch Geometric dependency.

Architecture inspired by:
  - E-GraphSAGE (Lo et al., 2022) — edge-centric NIDS
  - DIGNN-A (Liu & Guo, 2025) — dynamic graph + multi-head attention

Graph construction:
  Nodes  = unique IP addresses observed in the traffic window
  Edges  = individual network flows (each flow is an edge)
  Node features = mean of all flow feature vectors incident to that node
                  (i.e., the "average behaviour" of that IP address)

Anomaly detection:
  Train a Graph Autoencoder (unsupervised) on normal baseline traffic.
  Anomaly score per flow = reconstruction error of the endpoint node features
  involved in that flow.

Why GNNs catch attacks Transformers miss:
  - Port scan: 1 source IP has degree >> normal → high node anomaly score
  - DDoS: many sources all pointing to 1 destination → star topology
  - C2 beaconing: regular periodic edges → unusual temporal edge density
  - All of these are TOPOLOGY features, invisible to per-flow classifiers.
"""

from __future__ import annotations

import logging
from collections import deque, defaultdict
from typing import Optional

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

from packetsentry.features.extractor import FlowFeatures

logger = logging.getLogger(__name__)

_N_FEATURES = 23


# ===================================================================
# FlowGraph — dynamic graph data structure
# ===================================================================

class FlowGraph:
    """Dynamic graph: nodes=IPs, edges=flows.

    Maintains a sliding window of flows. Node features are the
    mean aggregation of all incident edge (flow) features.

    Args:
        max_nodes: Cap on unique nodes (oldest evicted when exceeded).
        max_edges: Cap on edges in the window.
    """

    def __init__(self, max_nodes: int = 256, max_edges: int = 1024) -> None:
        self._max_nodes = max_nodes
        self._max_edges = max_edges
        self.nodes: dict[str, int] = {}          # ip → node_index
        self.edges: list[tuple[int, int, np.ndarray]] = []   # (src_idx, dst_idx, feat)
        self._node_feats: defaultdict[int, list[np.ndarray]] = defaultdict(list)
        self._next_id = 0

    def add_flow(
        self, src_ip: str, dst_ip: str, features: np.ndarray
    ) -> tuple[int, int]:
        """Add a flow as an edge. Creates nodes if needed.

        Args:
            src_ip: Source IP address string.
            dst_ip: Destination IP address string.
            features: Flow feature vector of shape ``(23,)``.

        Returns:
            (src_node_idx, dst_node_idx)
        """
        src_idx = self._get_or_create_node(src_ip)
        dst_idx = self._get_or_create_node(dst_ip)

        feat = features.astype(np.float32)
        self.edges.append((src_idx, dst_idx, feat))
        self._node_feats[src_idx].append(feat)
        self._node_feats[dst_idx].append(feat)

        # Evict oldest edges if over limit
        if len(self.edges) > self._max_edges:
            self.edges = self.edges[-self._max_edges:]

        return src_idx, dst_idx

    def get_node_features(self) -> np.ndarray:
        """Return node feature matrix X of shape ``(n_nodes, 23)``.

        Each node's feature = mean of all incident flow vectors.
        Nodes with no flows get zero vectors.
        """
        n = len(self.nodes)
        X = np.zeros((n, _N_FEATURES), dtype=np.float32)
        for idx, feats in self._node_feats.items():
            if idx < n:
                X[idx] = np.mean(feats, axis=0)
        return X

    def get_adjacency(self) -> np.ndarray:
        """Return normalised symmetric adjacency matrix of shape ``(n, n)``.

        Uses symmetric normalisation: D^{-1/2} A D^{-1/2}
        so message passing is stable regardless of node degree.
        """
        n = len(self.nodes)
        if n == 0:
            return np.zeros((0, 0), dtype=np.float32)

        A = np.zeros((n, n), dtype=np.float32)
        for src, dst, _ in self.edges:
            if src < n and dst < n:
                A[src, dst] = 1.0
                A[dst, src] = 1.0  # undirected
        np.fill_diagonal(A, 1.0)   # self-loops

        degree = A.sum(axis=1)
        d_inv_sqrt = np.where(degree > 0, 1.0 / np.sqrt(degree), 0.0)
        D_inv_sqrt = np.diag(d_inv_sqrt)
        return (D_inv_sqrt @ A @ D_inv_sqrt).astype(np.float32)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_or_create_node(self, ip: str) -> int:
        if ip not in self.nodes:
            if len(self.nodes) >= self._max_nodes:
                # Evict oldest node (first inserted)
                oldest = next(iter(self.nodes))
                old_idx = self.nodes.pop(oldest)
                self._node_feats.pop(old_idx, None)
            self.nodes[ip] = self._next_id
            self._next_id += 1
        return self.nodes[ip]


# ===================================================================
# GraphSAGE layer — from scratch
# ===================================================================

class GraphSAGELayer(nn.Module):
    """Single GraphSAGE message-passing layer.

    For each node v:
      1. Aggregate neighbours: h_N = mean({h_u | u ∈ N(v)})
         (implemented as: A_norm @ X where A_norm is the normalised adj)
      2. Concatenate self + neighbour: [h_v || h_N]
      3. Linear transform + ReLU: h_v' = ReLU(W @ [h_v || h_N])

    This is equivalent to the inductive GraphSAGE formulation but
    implemented purely with matrix multiplications — no sparse ops needed.

    Args:
        in_features: Input node feature dimension.
        out_features: Output node feature dimension.
    """

    def __init__(self, in_features: int, out_features: int) -> None:
        super().__init__()
        # Concatenation of self + aggregated neighbour → out_features
        self.linear = nn.Linear(in_features * 2, out_features)

    def forward(
        self, x: torch.Tensor, adj: torch.Tensor
    ) -> torch.Tensor:
        """Message passing forward pass.

        Args:
            x: Node feature matrix ``(n_nodes, in_features)``.
            adj: Normalised adjacency matrix ``(n_nodes, n_nodes)``.

        Returns:
            Updated node embeddings ``(n_nodes, out_features)``.
        """
        # Aggregate: normalised sum of neighbour features
        aggregated = adj @ x                        # (n, in_features)
        # Concatenate self + aggregated
        combined = torch.cat([x, aggregated], dim=-1)   # (n, 2*in_features)
        return F.relu(self.linear(combined))        # (n, out_features)


# ===================================================================
# Graph Autoencoder — from scratch
# ===================================================================

class GraphAutoencoder(nn.Module):
    """Two-layer GraphSAGE encoder + linear decoder.

    Encoder:
      Layer 1: 23 → hidden (64)  with ReLU
      Layer 2: 64 → latent (32)  with ReLU
    Decoder:
      Linear:  32 → 23

    Trained unsupervised: reconstruct node features from the graph.
    Anomaly = high reconstruction error for that node's features.

    Args:
        in_features: Node feature dimension (23).
        hidden: Intermediate GraphSAGE dimension.
        latent: Bottleneck (embedding) dimension.
    """

    def __init__(
        self,
        in_features: int = _N_FEATURES,
        hidden: int = 64,
        latent: int = 32,
    ) -> None:
        super().__init__()
        self.sage1 = GraphSAGELayer(in_features, hidden)
        self.sage2 = GraphSAGELayer(hidden, latent)
        self.decoder = nn.Linear(latent, in_features)
        self._latent = latent

    def encode(
        self, x: torch.Tensor, adj: torch.Tensor
    ) -> torch.Tensor:
        """Return latent node embeddings ``(n, latent)``."""
        h1 = self.sage1(x, adj)    # (n, hidden)
        return self.sage2(h1, adj) # (n, latent)

    def forward(
        self, x: torch.Tensor, adj: torch.Tensor
    ) -> torch.Tensor:
        """Encode then decode. Returns reconstruction ``(n, in_features)``."""
        z = self.encode(x, adj)
        return self.decoder(z)


# ===================================================================
# GNNDetector — the public interface
# ===================================================================

class GNNDetector:
    """Graph-based anomaly detector using from-scratch GraphSAGE.

    Models network traffic as a dynamic graph to detect topology-level
    attacks invisible to per-flow classifiers:
      - Port scans: single source IP, high out-degree
      - DDoS sources: many IPs → single destination (star pattern)
      - C2 beaconing: periodic edges between fixed IP pairs

    Self-trains on the first ``warmup`` flows (no labels required).
    Score = reconstruction error of the endpoint nodes for this flow.

    Args:
        warmup: Flows to accumulate before training.
        epochs: Training epochs at warmup boundary.
        hidden: GraphSAGE hidden dimension.
        latent: Encoder bottleneck dimension.
        max_nodes: Max unique IPs in the graph (oldest evicted).
        retrain_every: Retrain the model every N flows after the initial
            warmup. Reduces O(n²) overhead by amortising training cost
            across a batch of flows instead of retraining on each one.
            Set to 0 to disable periodic retraining.
    """

    def __init__(
        self,
        warmup: int = 500,
        epochs: int = 20,
        hidden: int = 64,
        latent: int = 32,
        max_nodes: int = 256,
        retrain_every: int = 50,
    ) -> None:
        self._model = GraphAutoencoder(hidden=hidden, latent=latent)
        self._warmup = warmup
        self._epochs = epochs
        self._retrain_every = retrain_every
        self._graph = FlowGraph(max_nodes=max_nodes)
        self._flow_count = 0
        self._is_trained = False
        self._threshold = 1.0

    @property
    def is_trained(self) -> bool:
        """True once the model has been fitted."""
        return self._is_trained

    def score(
        self, src_ip: str, dst_ip: str, features: FlowFeatures
    ) -> float:
        """Return graph anomaly score for this flow in [0.0, 1.0].

        Returns 0.0 silently during warmup.

        Args:
            src_ip: Source IP address (string).
            dst_ip: Destination IP address (string).
            features: Extracted flow features.

        Returns:
            Graph reconstruction anomaly score in [0.0, 1.0].
        """
        vec = features.to_vector().astype(np.float32)
        src_idx, dst_idx = self._graph.add_flow(src_ip, dst_ip, vec)
        self._flow_count += 1

        if not self._is_trained:
            if self._flow_count >= self._warmup:
                self._train()
            return 0.0

        # Periodic batch retrain: amortises O(n²) graph training cost across
        # retrain_every flows instead of retraining on every single flow.
        if (
            self._retrain_every > 0
            and self._flow_count % self._retrain_every == 0
        ):
            self._train()

        return self._score_flow(src_idx, dst_idx)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_tensors(self) -> tuple[torch.Tensor, torch.Tensor]:
        """Build (X, A) tensors from the current graph state."""
        X = torch.from_numpy(self._graph.get_node_features())
        A = torch.from_numpy(self._graph.get_adjacency())
        return X, A

    def _score_flow(self, src_idx: int, dst_idx: int) -> float:
        """Compute anomaly score as reconstruction error of endpoint nodes."""
        n = len(self._graph.nodes)
        if n < 2:
            return 0.0
        try:
            X, A = self._build_tensors()
            with torch.no_grad():
                recon = self._model(X, A)
            # Error = mean reconstruction error of the two endpoint nodes
            src_err = float(F.mse_loss(recon[src_idx % n], X[src_idx % n]).item())
            dst_err = float(F.mse_loss(recon[dst_idx % n], X[dst_idx % n]).item())
            raw_score = (src_err + dst_err) / 2.0
            return float(np.clip(raw_score / self._threshold, 0.0, 1.0))
        except Exception as exc:
            logger.error("GNNDetector.score() failed: %s", exc)
            return 0.0

    def _train(self) -> None:
        """Train the Graph Autoencoder on the accumulated graph."""
        n = len(self._graph.nodes)
        if n < 2:
            self._is_trained = True
            return

        X, A = self._build_tensors()
        optimizer = torch.optim.Adam(self._model.parameters(), lr=1e-3)
        criterion = nn.MSELoss()

        self._model.train()
        for _ in range(self._epochs):
            recon = self._model(X, A)
            loss = criterion(recon, X)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

        self._model.eval()
        self._is_trained = True

        # Calibrate threshold to 95th percentile of training node errors
        with torch.no_grad():
            recon = self._model(X, A)
        errors = F.mse_loss(recon, X, reduction="none").mean(dim=1)
        self._threshold = max(float(torch.quantile(errors, 0.95).item()), 1e-6)

        logger.info(
            "GNNDetector trained on %d nodes, %d flows. Threshold=%.4f",
            n, self._flow_count, self._threshold,
        )
