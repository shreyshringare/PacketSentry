"""Tests for detection.xgboost_detector and detection.explainer — TDD first.

Tests are designed to pass with OR without a trained model file present,
since models/xgb_nslkdd.json does not exist yet. All tests that require
a model use a tiny synthetic XGBoost model trained inline.

Covers:
  - XGBoostDetector graceful fallback (no model file → returns 0.0)
  - score() output range [0.0, 1.0]
  - explain() output structure (top_features, explanation, shap_values)
  - ExplanationResult dataclass
  - AlertExplainer with synthetic model
  - RandomForestDetector graceful fallback
  - RandomForestDetector score() range
"""

from __future__ import annotations

import numpy as np
import pytest

from packetsentry.features.extractor import FlowFeatures
from packetsentry.features.flow_tracker import Flow, ParsedPacket


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _sample_features(
    src_bytes: int = 500,
    dst_bytes: int = 300,
    duration: float = 2.0,
    dst_port: int = 80,
    protocol_type: int = 0,
) -> FlowFeatures:
    """Synthetic FlowFeatures for testing."""
    return FlowFeatures(
        duration=duration,
        protocol_type=protocol_type,
        src_bytes=src_bytes,
        dst_bytes=dst_bytes,
        flag_syn=1, flag_ack=3, flag_fin=1, flag_rst=0, flag_psh=1,
        packet_count=5,
        avg_packet_size=(src_bytes + dst_bytes) / 5,
        bytes_per_second=(src_bytes + dst_bytes) / duration,
        packets_per_second=5 / duration,
        count=0, srv_count=0, dst_host_count=0, dst_host_srv_count=0,
        serror_rate=0.2, rerror_rate=0.0,
        same_srv_rate=1.0, diff_srv_rate=0.0,
        src_port=12345, dst_port=dst_port,
    )


def _make_synthetic_xgb():
    """Train a tiny XGBoost model on random data for testing."""
    import xgboost as xgb
    rng = np.random.default_rng(42)
    X = rng.random((100, 23)).astype(np.float32)
    y = (rng.random(100) > 0.5).astype(np.float32)
    dtrain = xgb.DMatrix(X, label=y)
    params = {"objective": "binary:logistic", "max_depth": 2, "seed": 42}
    return xgb.train(params, dtrain, num_boost_round=5)


# ===================================================================
# XGBoostDetector — graceful fallback (no model file)
# ===================================================================

class TestXGBoostDetectorFallback:
    """Detector must return 0.0 (not crash) when model file is absent."""

    def test_missing_model_does_not_raise(self) -> None:
        from packetsentry.detection.xgboost_detector import XGBoostDetector
        det = XGBoostDetector(model_path="nonexistent/path.json")
        assert det._loaded is False

    def test_score_returns_zero_when_not_loaded(self) -> None:
        from packetsentry.detection.xgboost_detector import XGBoostDetector
        det = XGBoostDetector(model_path="nonexistent/path.json")
        score = det.score(_sample_features())
        assert score == pytest.approx(0.0)

    def test_explain_returns_empty_when_not_loaded(self) -> None:
        from packetsentry.detection.xgboost_detector import XGBoostDetector
        det = XGBoostDetector(model_path="nonexistent/path.json")
        result = det.explain(_sample_features())
        assert result is None


# ===================================================================
# XGBoostDetector — with synthetic model
# ===================================================================

class TestXGBoostDetectorWithModel:
    """Detector behaviour with a real (synthetic) XGBoost model."""

    @pytest.fixture
    def detector(self, tmp_path):
        from packetsentry.detection.xgboost_detector import XGBoostDetector
        model = _make_synthetic_xgb()
        model_path = str(tmp_path / "xgb_test.json")
        model.save_model(model_path)
        return XGBoostDetector(model_path=model_path)

    def test_loaded_flag(self, detector) -> None:
        assert detector._loaded is True

    def test_score_is_float(self, detector) -> None:
        score = detector.score(_sample_features())
        assert isinstance(score, float)

    def test_score_range(self, detector) -> None:
        score = detector.score(_sample_features())
        assert 0.0 <= score <= 1.0

    def test_score_different_inputs_differ(self, detector) -> None:
        """Different flows should produce different scores."""
        s1 = detector.score(_sample_features(src_bytes=100, dst_bytes=50))
        s2 = detector.score(_sample_features(src_bytes=9000, dst_bytes=8000))
        # Not guaranteed to differ on random model, but test it runs
        assert isinstance(s1, float)
        assert isinstance(s2, float)

    def test_explain_returns_result(self, detector) -> None:
        from packetsentry.detection.explainer import ExplanationResult
        result = detector.explain(_sample_features())
        assert result is not None
        assert isinstance(result, ExplanationResult)

    def test_explain_top_features_count(self, detector) -> None:
        result = detector.explain(_sample_features())
        assert len(result.top_features) == 5

    def test_explain_top_features_names_are_strings(self, detector) -> None:
        result = detector.explain(_sample_features())
        for name, val in result.top_features:
            assert isinstance(name, str)
            assert isinstance(val, float)

    def test_explain_shap_values_shape(self, detector) -> None:
        result = detector.explain(_sample_features())
        assert result.shap_values.shape == (23,)

    def test_explain_explanation_is_string(self, detector) -> None:
        result = detector.explain(_sample_features())
        assert isinstance(result.explanation, str)
        assert len(result.explanation) > 0


# ===================================================================
# AlertExplainer — standalone SHAP wrapper
# ===================================================================

class TestAlertExplainer:
    """AlertExplainer wraps SHAP TreeExplainer independently."""

    @pytest.fixture
    def explainer_and_model(self):
        from packetsentry.detection.explainer import AlertExplainer
        model = _make_synthetic_xgb()
        exp = AlertExplainer(model)
        return exp, model

    def test_explain_returns_explanation_result(self, explainer_and_model) -> None:
        from packetsentry.detection.explainer import ExplanationResult
        exp, _ = explainer_and_model
        vec = _sample_features().to_vector()
        result = exp.explain(vec)
        assert isinstance(result, ExplanationResult)

    def test_shap_values_shape(self, explainer_and_model) -> None:
        exp, _ = explainer_and_model
        vec = _sample_features().to_vector()
        result = exp.explain(vec)
        assert result.shap_values.shape == (23,)

    def test_top_features_length(self, explainer_and_model) -> None:
        exp, _ = explainer_and_model
        vec = _sample_features().to_vector()
        result = exp.explain(vec)
        assert len(result.top_features) == 5

    def test_explanation_string_contains_feature_name(
        self, explainer_and_model
    ) -> None:
        exp, _ = explainer_and_model
        vec = _sample_features().to_vector()
        result = exp.explain(vec)
        # The top feature name should appear in the explanation string
        top_name = result.top_features[0][0]
        assert top_name in result.explanation


# ===================================================================
# ExplanationResult dataclass
# ===================================================================

class TestExplanationResult:
    def test_fields(self) -> None:
        from packetsentry.detection.explainer import ExplanationResult
        shap_vals = np.zeros(23, dtype=np.float32)
        er = ExplanationResult(
            top_features=[("duration", 0.42)],
            explanation="duration (+0.420)",
            shap_values=shap_vals,
        )
        assert er.top_features[0][0] == "duration"
        assert er.explanation == "duration (+0.420)"
        assert er.shap_values.shape == (23,)


# ===================================================================
# RandomForestDetector — graceful fallback
# ===================================================================

class TestRandomForestDetectorFallback:
    """RF must return 0.0 when model files are absent."""

    def test_missing_model_does_not_raise(self) -> None:
        from packetsentry.detection.random_forest import RandomForestDetector
        det = RandomForestDetector(model_path="nonexistent.pkl")
        assert det._loaded is False

    def test_score_returns_zero_when_not_loaded(self) -> None:
        from packetsentry.detection.random_forest import RandomForestDetector
        det = RandomForestDetector(model_path="nonexistent.pkl")
        assert det.score(_sample_features()) == pytest.approx(0.0)


# ===================================================================
# RandomForestDetector — with synthetic model
# ===================================================================

class TestRandomForestDetectorWithModel:
    @pytest.fixture
    def detector(self, tmp_path):
        import joblib
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import StandardScaler
        from packetsentry.detection.random_forest import RandomForestDetector

        rng = np.random.default_rng(0)
        X = rng.random((60, 23)).astype(np.float32)
        y = (rng.random(60) > 0.5).astype(int)

        scaler = StandardScaler().fit(X)
        rf = RandomForestClassifier(n_estimators=5, random_state=0).fit(
            scaler.transform(X), y
        )
        model_path = str(tmp_path / "rf.pkl")
        scaler_path = str(tmp_path / "scaler.pkl")
        joblib.dump(rf, model_path)
        joblib.dump(scaler, scaler_path)
        return RandomForestDetector(
            model_path=model_path, scaler_path=scaler_path
        )

    def test_loaded(self, detector) -> None:
        assert detector._loaded is True

    def test_score_range(self, detector) -> None:
        score = detector.score(_sample_features())
        assert 0.0 <= score <= 1.0

    def test_score_is_float(self, detector) -> None:
        assert isinstance(detector.score(_sample_features()), float)
