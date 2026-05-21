"""Shared severity mapping for PacketSentry alerts.

Single source of truth for confidence → severity label.
Used by AlertEngine (runtime) and evaluate_all.py (offline eval)
to ensure consistent labelling.
"""

from __future__ import annotations

# Thresholds: confidence ∈ [0.0, 1.0] → severity string
_THRESHOLDS: list[tuple[float, str]] = [
    (0.90, "CRITICAL"),
    (0.75, "HIGH"),
    (0.60, "MED"),
    (0.0,  "LOW"),
]


def confidence_to_severity(confidence: float) -> str:
    """Map a confidence score (0.0–1.0) to a severity label.

    Args:
        confidence: Float in [0.0, 1.0].

    Returns:
        One of "CRITICAL", "HIGH", "MED", "LOW".
    """
    for threshold, label in _THRESHOLDS:
        if confidence >= threshold:
            return label
    return "LOW"
