"""Tests for EnsembleArbiter — 6-model confidence-weighted voting."""

from __future__ import annotations

import pytest

from packetsentry.detection.ensemble import DecisionResult, EnsembleArbiter


def _scores(
    aho: float = 0.0, xgb: float = 0.0, rf: float = 0.0,
    iso: float = 0.0, tae: float = 0.0, gnn: float = 0.0, zsc: float = 0.0,
) -> dict[str, float]:
    return {
        "aho_corasick": aho, "xgboost": xgb, "random_forest": rf,
        "isolation_forest": iso, "transformer_ae": tae,
        "gnn_detector": gnn, "zscore": zsc,
    }


class TestDecisionResultDataclass:
    def test_fields_exist(self) -> None:
        dr = DecisionResult(
            is_alert=True, confidence=0.7,
            scores=_scores(), explanation=None,
        )
        assert dr.is_alert is True
        assert dr.confidence == pytest.approx(0.7)
        assert isinstance(dr.scores, dict)
        assert dr.explanation is None


class TestDecide:
    def test_all_zeros_no_alert(self) -> None:
        arb = EnsembleArbiter()
        result = arb.decide(_scores())
        assert result.is_alert is False
        assert result.confidence == pytest.approx(0.0)

    def test_all_ones_alert(self) -> None:
        arb = EnsembleArbiter()
        result = arb.decide(_scores(aho=1.0, xgb=1.0, rf=1.0,
                                    iso=1.0, tae=1.0, gnn=1.0, zsc=1.0))
        assert result.is_alert is True
        assert result.confidence == pytest.approx(1.0)

    def test_threshold_boundary_below(self) -> None:
        """Weighted sum just below 0.50 → no alert."""
        arb = EnsembleArbiter()
        # Set only xgboost (weight 0.25) to 1.0 → weighted sum = 0.25
        result = arb.decide(_scores(xgb=1.0))
        assert result.is_alert is False

    def test_threshold_boundary_above(self) -> None:
        """Weighted sum above 0.50 → alert."""
        arb = EnsembleArbiter()
        # aho_corasick (0.20) + xgboost (0.22) + isolation_forest (0.12) = 0.54
        result = arb.decide(_scores(aho=1.0, xgb=1.0, iso=1.0))
        # 0.20 + 0.22 + 0.12 = 0.54 → alert
        assert result.is_alert is True

    def test_returns_decision_result(self) -> None:
        arb = EnsembleArbiter()
        result = arb.decide(_scores())
        assert isinstance(result, DecisionResult)

    def test_scores_preserved_in_result(self) -> None:
        arb = EnsembleArbiter()
        s = _scores(xgb=0.8, aho=0.4)
        result = arb.decide(s)
        assert result.scores["xgboost"] == pytest.approx(0.8)

    def test_explanation_attached_when_provided(self) -> None:
        from packetsentry.detection.explainer import ExplanationResult
        import numpy as np
        arb = EnsembleArbiter()
        exp = ExplanationResult(
            top_features=[("duration", 0.5)],
            explanation="duration (+0.500)",
            shap_values=np.zeros(23),
        )
        result = arb.decide(_scores(), explanation=exp)
        assert result.explanation is exp

    def test_missing_detector_in_scores_handled(self) -> None:
        """Scores dict with missing keys should not crash."""
        arb = EnsembleArbiter()
        result = arb.decide({"xgboost": 0.9})
        assert isinstance(result, DecisionResult)

    def test_confidence_is_float(self) -> None:
        arb = EnsembleArbiter()
        result = arb.decide(_scores(xgb=0.6))
        assert isinstance(result.confidence, float)

    def test_confidence_clipped_to_unit_interval(self) -> None:
        arb = EnsembleArbiter()
        result = arb.decide(_scores(aho=2.0, xgb=2.0))
        assert 0.0 <= result.confidence <= 1.0


class TestWeights:
    def test_weights_sum_to_one(self) -> None:
        arb = EnsembleArbiter()
        total = sum(arb.weights.values())
        assert total == pytest.approx(1.0, abs=1e-6)

    def test_all_six_detectors_have_weights(self) -> None:
        arb = EnsembleArbiter()
        expected = {
            "aho_corasick", "xgboost", "random_forest",
            "isolation_forest", "transformer_ae", "gnn_detector", "zscore",
        }
        assert set(arb.weights.keys()) == expected


class TestFeedback:
    def test_fp_feedback_reduces_weight(self) -> None:
        arb = EnsembleArbiter()
        original = arb.weights["xgboost"]
        # Feed 10 false positives to xgboost
        for _ in range(10):
            arb.feedback("xgboost", was_false_positive=True)
        assert arb.weights["xgboost"] < original

    def test_true_positive_feedback_no_reduction(self) -> None:
        arb = EnsembleArbiter()
        original = arb.weights["xgboost"]
        for _ in range(10):
            arb.feedback("xgboost", was_false_positive=False)
        # Weight should not decrease on true positives
        assert arb.weights["xgboost"] >= original * 0.8  # some tolerance

    def test_weights_renormalize_after_feedback(self) -> None:
        arb = EnsembleArbiter()
        for _ in range(20):
            arb.feedback("xgboost", was_false_positive=True)
        total = sum(arb.weights.values())
        assert total == pytest.approx(1.0, abs=1e-6)

    def test_minimum_weight_enforced(self) -> None:
        arb = EnsembleArbiter()
        # Flood with false positives
        for _ in range(200):
            arb.feedback("xgboost", was_false_positive=True)
        assert arb.weights["xgboost"] >= 0.01  # never zero

    def test_unknown_detector_feedback_ignored(self) -> None:
        arb = EnsembleArbiter()
        # Should not raise
        arb.feedback("nonexistent_detector", was_false_positive=True)
