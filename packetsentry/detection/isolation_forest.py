"""Isolation Forest detector — unsupervised, self-trains on network baseline.

Requires NO labeled data. Learns what "normal" looks like from the first
``warmup`` flows it sees, then flags deviations as anomalies.

Design:
  - Silent during warmup: returns 0.0 to avoid false positives at startup.
  - Trains once at warmup boundary, then scores online.
  - Score formula: ``clip(1.0 - (decision_function + 0.5), 0.0, 1.0)``
    This maps IF's negative decision_function (more anomalous = more negative)
    to a 0.0–1.0 probability scale.
"""

from __future__ import annotations

import logging

import numpy as np
from sklearn.ensemble import IsolationForest

from packetsentry.features.extractor import FlowFeatures

logger = logging.getLogger(__name__)


class IsolationForestDetector:
    """Unsupervised anomaly detector using Isolation Forest.

    Self-trains on the first ``warmup`` flows observed, building a
    statistical model of your network's baseline traffic. No labeled
    data needed.

    Args:
        contamination: Expected fraction of anomalies in training data.
        warmup: Number of flows to collect before training.
        random_state: Reproducibility seed.
    """

    def __init__(
        self,
        contamination: float = 0.05,
        warmup: int = 500,
        random_state: int = 42,
    ) -> None:
        self._model = IsolationForest(
            contamination=contamination,
            random_state=random_state,
            n_estimators=100,
        )
        self._warmup = warmup
        self._buffer: list[np.ndarray] = []
        self._is_trained = False

    @property
    def is_trained(self) -> bool:
        """True once the model has been fitted."""
        return self._is_trained

    def score(self, features: FlowFeatures) -> float:
        """Return anomaly score in [0.0, 1.0].

        Returns 0.0 silently during warmup to avoid false positives at
        startup when the model has no baseline yet.

        Args:
            features: Extracted flow features.

        Returns:
            0.0 during warmup; clipped anomaly score afterwards.
        """
        vec = features.to_vector()

        if not self._is_trained:
            self._buffer.append(vec)
            if len(self._buffer) >= self._warmup:
                self._train()
            return 0.0

        try:
            raw = self._model.decision_function([vec])[0]
            return float(np.clip(1.0 - (raw + 0.5), 0.0, 1.0))
        except Exception as exc:
            logger.error("IsolationForestDetector.score() failed: %s", exc)
            return 0.0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _train(self) -> None:
        """Fit the model on the collected baseline flows."""
        data = np.array(self._buffer, dtype=np.float32)
        self._model.fit(data)
        self._is_trained = True
        self._buffer.clear()
        logger.info(
            "IsolationForestDetector trained on %d baseline flows.", len(data)
        )
