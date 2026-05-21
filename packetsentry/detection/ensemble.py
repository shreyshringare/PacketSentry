"""Ensemble arbiter — confidence-weighted voting across 7 detectors.

Combines scores from all detectors into a single decision with:
  - Confidence-weighted vote (weighted sum)
  - SHAP explanation attached to every alert
  - Self-calibrating false positive feedback loop

The 7 detectors and their initial weights:

    Detector            Weight   Type
    ─────────────────── ──────   ─────────────────────────────────────
    aho_corasick        0.20     Signature — exact pattern matching
    xgboost             0.22     Supervised — trained on NSL-KDD
    gnn_detector        0.15     Topology — GraphSAGE from scratch
    transformer_ae      0.15     Temporal — Transformer Autoencoder
    isolation_forest    0.12     Unsupervised — self-trains on baseline
    random_forest       0.08     Supervised — baseline comparison
    zscore              0.08     Statistical — Welford online z-score

Decision threshold: 0.50. Weights are renormalised after every feedback
call so they always sum to 1.0.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import numpy as np

if TYPE_CHECKING:
    from packetsentry.detection.explainer import ExplanationResult

logger = logging.getLogger(__name__)

_MIN_WEIGHT = 0.01  # no detector ever reaches zero
_THRESHOLD = 0.50


@dataclass
class DecisionResult:
    """Result of the ensemble vote for a single flow.

    Attributes:
        is_alert: True if the weighted confidence exceeds the threshold.
        confidence: Weighted sum of all detector scores (0.0–1.0).
        scores: Per-detector raw scores.
        explanation: SHAP explanation from XGBoost, or None.
    """

    is_alert: bool
    confidence: float
    scores: dict[str, float]
    explanation: "ExplanationResult | None" = field(default=None)


class EnsembleArbiter:
    """7-model confidence-weighted voting with self-calibrating FP feedback.

    All detectors must implement ``score(features) -> float``.
    The arbiter is detector-agnostic — it only sees the scores dict.

    Args:
        threshold: Decision boundary. Flows above this are alerts.
    """

    def __init__(self, threshold: float = _THRESHOLD) -> None:
        self._threshold = threshold
        self.weights: dict[str, float] = {
            "aho_corasick":     0.20,
            "xgboost":          0.22,
            "random_forest":    0.08,
            "isolation_forest": 0.12,
            "transformer_ae":   0.15,
            "gnn_detector":     0.15,
            "zscore":           0.08,
        }
        # Ring buffer tracking recent FP/TP per detector (last 100)
        self._fp_tracker: dict[str, list[bool]] = {
            k: [] for k in self.weights
        }

    def decide(
        self,
        scores: dict[str, float],
        explanation: "ExplanationResult | None" = None,
    ) -> DecisionResult:
        """Compute weighted confidence and make alert decision.

        Args:
            scores: Per-detector scores in [0.0, 1.0]. Unknown detector
                    keys are silently ignored.
            explanation: Optional SHAP explanation from XGBoost.

        Returns:
            :class:`DecisionResult` with decision, confidence, and explanation.
        """
        weighted = sum(
            self.weights.get(name, 0.0) * score
            for name, score in scores.items()
        )
        confidence = float(np.clip(weighted, 0.0, 1.0))

        result = DecisionResult(
            is_alert=confidence > self._threshold,
            confidence=confidence,
            scores=scores,
            explanation=explanation,
        )
        logger.debug(
            "Ensemble decision: alert=%s confidence=%.3f scores=%s",
            result.is_alert, result.confidence,
            {k: f"{v:.2f}" for k, v in scores.items()},
        )
        return result

    def feedback(self, detector: str, was_false_positive: bool) -> None:
        """Adjust detector weight based on a confirmed outcome.

        Confirmed false positives reduce the detector's influence.
        True positives do not increase weight (only FPs penalise).

        Args:
            detector: Detector name (must be a key in ``self.weights``).
            was_false_positive: True if the alert was a confirmed FP.
        """
        if detector not in self._fp_tracker:
            logger.warning(
                "feedback() called for unknown detector '%s' — ignored.",
                detector,
            )
            return

        buf = self._fp_tracker[detector]
        buf.append(was_false_positive)
        # Keep only the last 100 outcomes
        if len(buf) > 100:
            self._fp_tracker[detector] = buf[-100:]

        recent = self._fp_tracker[detector]
        fp_rate = sum(recent) / len(recent)
        self.weights[detector] = max(_MIN_WEIGHT, 1.0 - fp_rate)
        self._normalize()

        logger.info(
            "Detector '%s' FP rate=%.2f new_weight=%.3f",
            detector, fp_rate, self.weights[detector],
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _normalize(self) -> None:
        """Renormalise weights so they sum to 1.0."""
        total = sum(self.weights.values())
        if total > 0:
            self.weights = {k: v / total for k, v in self.weights.items()}
