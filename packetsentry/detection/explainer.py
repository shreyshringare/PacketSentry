"""SHAP-based alert explainer for XGBoost detections.

Provides feature-level attribution for every alert, answering:
"WHY did XGBoost flag this flow?"

Uses ``shap.TreeExplainer`` which is exact and fast for tree models
(no sampling, no approximation).  The 23 NSL-KDD feature names are
baked in so the output is always human-readable.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import numpy as np

logger = logging.getLogger(__name__)

# Ordered to match FlowFeatures.to_vector() exactly
FEATURE_NAMES: list[str] = [
    "duration", "protocol_type", "src_bytes", "dst_bytes",
    "flag_syn", "flag_ack", "flag_fin", "flag_rst", "flag_psh",
    "packet_count", "avg_packet_size", "bytes_per_second",
    "packets_per_second", "count", "srv_count", "dst_host_count",
    "dst_host_srv_count", "serror_rate", "rerror_rate",
    "same_srv_rate", "diff_srv_rate", "src_port", "dst_port",
]


@dataclass
class ExplanationResult:
    """SHAP-based explanation for a single alert.

    Attributes:
        top_features: Top-5 contributing features as (name, shap_value) pairs,
                      sorted by absolute SHAP value descending.
        explanation: Human-readable string, e.g.
                     "dst_bytes (+0.42), flag_syn (+0.31), src_port (-0.18), ..."
        shap_values: Full SHAP value vector, shape ``(23,)`` dtype float32.
    """

    top_features: list[tuple[str, float]]
    explanation: str
    shap_values: np.ndarray


class AlertExplainer:
    """Wraps SHAP TreeExplainer for XGBoost model attribution.

    Computes exact Shapley values — no sampling approximation.
    Safe to instantiate once and reuse across many ``explain()`` calls.

    Args:
        model: A fitted ``xgboost.Booster`` instance.
        top_k: Number of top features to include in the summary. Default 5.
    """

    def __init__(self, model, top_k: int = 5) -> None:
        import shap
        self._explainer = shap.TreeExplainer(model)
        self._top_k = top_k

    def explain(self, vec: np.ndarray) -> ExplanationResult:
        """Compute SHAP explanation for a single feature vector.

        Args:
            vec: Feature vector of shape ``(23,)`` — from
                 ``FlowFeatures.to_vector()``.

        Returns:
            :class:`ExplanationResult` with top features and human-readable
            explanation string.
        """
        # TreeExplainer expects 2-D input
        shap_values = self._explainer.shap_values(
            vec.reshape(1, -1).astype(np.float32)
        )
        # Binary classification: shap_values may be list[array] for sklearn
        # For XGBoost Booster with binary:logistic it is a single 2-D array
        if isinstance(shap_values, list):
            sv = np.array(shap_values[1][0], dtype=np.float32)
        else:
            sv = np.array(shap_values[0], dtype=np.float32)

        # Top-k by absolute value
        top_indices = np.argsort(np.abs(sv))[-self._top_k:][::-1]
        top_features = [
            (FEATURE_NAMES[i], float(sv[i])) for i in top_indices
        ]
        explanation = ", ".join(
            f"{name} ({val:+.3f})" for name, val in top_features
        )

        logger.debug("SHAP explanation: %s", explanation)
        return ExplanationResult(
            top_features=top_features,
            explanation=explanation,
            shap_values=sv,
        )
