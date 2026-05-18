"""Transformer Autoencoder — temporal anomaly detector.

Self-supervised: trains on normal flow sequences, then flags sequences
whose reconstruction error is high (i.e., they don't look like anything
the model learned).

Architecture:
  - Linear input projection: 23 → d_model (64)
  - TransformerEncoder: multi-head self-attention, 2 layers
  - Linear decoder: d_model (64) → 23 (reconstruction)

Key advantage over LSTM for NIDS:
  - Parallel processing (no sequential bottleneck)
  - Multi-head attention captures relationships between ANY two flows in
    the sequence simultaneously — a slow port scan spread over 5 minutes
    creates attention patterns the LSTM's fixed hidden state misses.

Warmup: silent for first 2000 flows. Trains once at boundary (20 epochs).
After warmup: scores every new flow using the sliding window.
"""

from __future__ import annotations

import logging
from collections import deque

import numpy as np
import torch
import torch.nn as nn

from packetsentry.features.extractor import FlowFeatures

logger = logging.getLogger(__name__)

_N_FEATURES = 23


class TransformerAutoencoder(nn.Module):
    """Multi-head self-attention encoder + linear decoder.

    Args:
        input_size: Feature vector dimension (23 for NSL-KDD aligned).
        d_model: Transformer internal dimension (embedding size).
        nhead: Number of attention heads. Must divide d_model evenly.
        num_layers: Number of TransformerEncoder layers.
    """

    def __init__(
        self,
        input_size: int = _N_FEATURES,
        d_model: int = 64,
        nhead: int = 1,
        num_layers: int = 2,
    ) -> None:
        super().__init__()
        self.input_proj = nn.Linear(input_size, d_model)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=nhead,
            dim_feedforward=d_model * 2,
            batch_first=True,
            dropout=0.0,
        )
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        self.decoder = nn.Linear(d_model, input_size)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Encode then decode — returns reconstructed sequence.

        Args:
            x: Input tensor of shape ``(batch, seq_len, input_size)``.

        Returns:
            Reconstructed tensor of shape ``(batch, seq_len, input_size)``.
        """
        encoded = self.encoder(self.input_proj(x))   # (B, T, d_model)
        return self.decoder(encoded)                  # (B, T, input_size)

    def encode(self, x: torch.Tensor) -> torch.Tensor:
        """Extract latent representation — used for ChromaDB embeddings.

        Args:
            x: Input tensor of shape ``(batch, seq_len, input_size)``.

        Returns:
            Mean-pooled hidden state of shape ``(batch, d_model)``.
        """
        encoded = self.encoder(self.input_proj(x))   # (B, T, d_model)
        return encoded.mean(dim=1)                   # (B, d_model)


class TransformerAEDetector:
    """Temporal anomaly detector wrapping TransformerAutoencoder.

    Self-trains on the first ``warmup`` flows (normal baseline).
    After training, anomaly score = normalised reconstruction error.

    Args:
        seq_len: Sequence window length in flows.
        warmup: Number of flows to collect before training.
        d_model: Transformer embedding dimension.
        epochs: Training epochs at warmup boundary.
        threshold: Reconstruction MSE corresponding to score=1.0.
    """

    def __init__(
        self,
        seq_len: int = 10,
        warmup: int = 2000,
        d_model: int = 64,
        epochs: int = 20,
        threshold: float = 1.0,
    ) -> None:
        self._model = TransformerAutoencoder(d_model=d_model, nhead=1)
        self._seq_len = seq_len
        self._warmup = warmup
        self._epochs = epochs
        self._threshold = threshold
        self._window: deque[np.ndarray] = deque(maxlen=seq_len)
        self._buffer: list[np.ndarray] = []
        self._is_trained = False

    @property
    def is_trained(self) -> bool:
        """True once the model has been fitted."""
        return self._is_trained

    def score(self, features: FlowFeatures) -> float:
        """Return temporal anomaly score in [0.0, 1.0].

        Returns 0.0 silently during warmup and until the sliding window
        is fully populated.

        Args:
            features: Extracted flow features.

        Returns:
            Clipped reconstruction error normalised to [0.0, 1.0].
        """
        vec = features.to_vector().astype(np.float32)
        self._window.append(vec)

        if not self._is_trained:
            self._buffer.append(vec)
            if len(self._buffer) >= self._warmup:
                self._train()
            return 0.0

        if len(self._window) < self._seq_len:
            return 0.0

        return self._score_window()

    def get_embedding(self, features: FlowFeatures) -> np.ndarray | None:
        """Return 64-dim encoder hidden state for ChromaDB storage.

        Returns None if the model has not been trained yet.

        Args:
            features: Extracted flow features.

        Returns:
            Numpy array of shape ``(d_model,)`` or None.
        """
        if not self._is_trained or len(self._window) < self._seq_len:
            return None
        seq = self._build_seq_tensor()
        with torch.no_grad():
            embedding = self._model.encode(seq)
        return embedding.squeeze(0).numpy()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_seq_tensor(self) -> torch.Tensor:
        """Build a (1, seq_len, 23) tensor from the sliding window."""
        seq = np.array(list(self._window)[-self._seq_len:], dtype=np.float32)
        return torch.from_numpy(seq).unsqueeze(0)   # (1, T, 23)

    def _score_window(self) -> float:
        """Compute reconstruction MSE for the current window."""
        try:
            seq = self._build_seq_tensor()
            with torch.no_grad():
                recon = self._model(seq)
            mse = torch.mean((seq - recon) ** 2).item()
            return float(np.clip(mse / self._threshold, 0.0, 1.0))
        except Exception as exc:
            logger.error("TransformerAEDetector.score() failed: %s", exc)
            return 0.0

    def _train(self) -> None:
        """Train the autoencoder on the collected baseline flows."""
        data = np.array(self._buffer, dtype=np.float32)
        n = len(data)
        optimizer = torch.optim.Adam(self._model.parameters(), lr=1e-3)
        criterion = nn.MSELoss()

        self._model.train()
        for epoch in range(self._epochs):
            total_loss = 0.0
            count = 0
            for i in range(0, n - self._seq_len, self._seq_len):
                seq = torch.from_numpy(
                    data[i : i + self._seq_len]
                ).unsqueeze(0)   # (1, T, 23)
                recon = self._model(seq)
                loss = criterion(recon, seq)
                optimizer.zero_grad()
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
                count += 1

        self._model.eval()
        self._is_trained = True
        self._buffer.clear()

        # Calibrate threshold to 90th percentile of training errors
        self._calibrate_threshold(data)
        logger.info(
            "TransformerAEDetector trained on %d flows. "
            "Threshold=%.4f", n, self._threshold,
        )

    def _calibrate_threshold(self, data: np.ndarray) -> None:
        """Set threshold to 90th percentile of reconstruction errors."""
        errors = []
        with torch.no_grad():
            for i in range(0, len(data) - self._seq_len, self._seq_len):
                seq = torch.from_numpy(
                    data[i : i + self._seq_len].astype(np.float32)
                ).unsqueeze(0)
                recon = self._model(seq)
                mse = torch.mean((seq - recon) ** 2).item()
                errors.append(mse)
        if errors:
            p90 = float(np.percentile(errors, 90))
            self._threshold = max(p90, 1e-6)
