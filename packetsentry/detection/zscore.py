"""Z-Score statistical baseline detector.

Maintains a running mean and variance (Welford's online algorithm) for
all 23 features. Anomaly score is the fraction of features whose
z-score exceeds the configured threshold.

Advantages:
  - Zero ML dependencies — pure statistics.
  - Adapts continuously (online updates).
  - Immediate insight: "feature X is 5 sigma above normal."
  - Requires no warmup — starts scoring after ``min_samples``.
"""

from __future__ import annotations

import logging

import numpy as np

from packetsentry.features.extractor import FlowFeatures

logger = logging.getLogger(__name__)

_N_FEATURES = 23


class ZScoreDetector:
    """Statistical anomaly detector using per-feature z-scores.

    Uses Welford's online algorithm for numerically stable running
    mean and variance computation without storing all past samples.

    Score = fraction of features with |z| > threshold, clipped to [0, 1].

    Args:
        threshold: Z-score threshold above which a feature is anomalous.
                   Default 3.0 (three sigma rule).
        min_samples: Minimum observations before scoring begins. Returns
                     0.0 below this to avoid false positives on startup.
    """

    def __init__(
        self,
        threshold: float = 3.0,
        min_samples: int = 30,
    ) -> None:
        self._threshold = threshold
        self._min_samples = min_samples
        self._n: int = 0
        self._mean = np.zeros(_N_FEATURES, dtype=np.float64)
        self._m2 = np.zeros(_N_FEATURES, dtype=np.float64)  # sum of squares

    def score(self, features: FlowFeatures) -> float:
        """Return anomaly score in [0.0, 1.0].

        Updates the running statistics with the new observation, then
        scores it. Returns 0.0 if fewer than ``min_samples`` seen.

        Args:
            features: Extracted flow features.

        Returns:
            Fraction of features exceeding z-score threshold, in [0.0, 1.0].
        """
        vec = features.to_vector().astype(np.float64)
        self._n += 1
        delta = vec - self._mean
        self._mean += delta / self._n
        delta2 = vec - self._mean
        self._m2 += delta * delta2

        if self._n < self._min_samples:
            return 0.0

        variance = self._m2 / (self._n - 1)
        std = np.sqrt(np.maximum(variance, 1e-10))
        z_scores = np.abs((vec - self._mean) / std)
        anomalous_fraction = float(np.mean(z_scores > self._threshold))
        return float(np.clip(anomalous_fraction, 0.0, 1.0))
