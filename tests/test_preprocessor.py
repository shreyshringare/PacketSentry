"""Tests for features.preprocessor — scaling and encoding for ML pipeline."""

from __future__ import annotations

import numpy as np
import pytest

from packetsentry.features.extractor import FlowFeatures
from packetsentry.features.preprocessor import FeaturePreprocessor


def _sample_features(n: int = 10) -> list[FlowFeatures]:
    """Generate n synthetic FlowFeatures for testing."""
    rng = np.random.default_rng(42)
    result: list[FlowFeatures] = []
    for _ in range(n):
        result.append(FlowFeatures(
            duration=rng.uniform(0.001, 60.0),
            protocol_type=int(rng.integers(0, 3)),
            src_bytes=int(rng.integers(0, 10000)),
            dst_bytes=int(rng.integers(0, 10000)),
            flag_syn=int(rng.integers(0, 10)),
            flag_ack=int(rng.integers(0, 50)),
            flag_fin=int(rng.integers(0, 5)),
            flag_rst=int(rng.integers(0, 3)),
            flag_psh=int(rng.integers(0, 20)),
            packet_count=int(rng.integers(1, 100)),
            avg_packet_size=rng.uniform(40.0, 1500.0),
            bytes_per_second=rng.uniform(0.0, 50000.0),
            packets_per_second=rng.uniform(0.1, 500.0),
            count=int(rng.integers(0, 20)),
            srv_count=int(rng.integers(0, 20)),
            dst_host_count=int(rng.integers(0, 100)),
            dst_host_srv_count=int(rng.integers(0, 50)),
            serror_rate=rng.uniform(0.0, 1.0),
            rerror_rate=rng.uniform(0.0, 1.0),
            same_srv_rate=rng.uniform(0.0, 1.0),
            diff_srv_rate=rng.uniform(0.0, 1.0),
            src_port=int(rng.integers(1024, 65535)),
            dst_port=int(rng.integers(1, 1024)),
        ))
    return result


class TestFitTransform:
    """Fitting and transforming feature vectors."""

    def test_fit_returns_self(self) -> None:
        pp = FeaturePreprocessor()
        features = _sample_features(20)
        result = pp.fit(features)
        assert result is pp

    def test_transform_shape(self) -> None:
        pp = FeaturePreprocessor()
        features = _sample_features(20)
        pp.fit(features)
        vec = pp.transform(features[0])
        assert vec.shape == (23,)

    def test_transform_dtype(self) -> None:
        pp = FeaturePreprocessor()
        features = _sample_features(20)
        pp.fit(features)
        vec = pp.transform(features[0])
        assert vec.dtype == np.float32

    def test_batch_transform_shape(self) -> None:
        pp = FeaturePreprocessor()
        features = _sample_features(20)
        pp.fit(features)
        batch = pp.transform_batch(features[:5])
        assert batch.shape == (5, 23)

    def test_fit_transform_combined(self) -> None:
        pp = FeaturePreprocessor()
        features = _sample_features(20)
        batch = pp.fit_transform(features)
        assert batch.shape == (20, 23)

    def test_scaled_values_near_zero_mean(self) -> None:
        pp = FeaturePreprocessor()
        features = _sample_features(50)
        batch = pp.fit_transform(features)
        means = batch.mean(axis=0)
        # After StandardScaler, means should be close to 0
        assert np.allclose(means, 0.0, atol=0.15)


class TestEdgeCases:
    """Edge cases: NaN, inf, unfitted transform."""

    def test_transform_before_fit_raises(self) -> None:
        pp = FeaturePreprocessor()
        features = _sample_features(1)
        with pytest.raises(RuntimeError, match="fit"):
            pp.transform(features[0])

    def test_nan_replaced(self) -> None:
        pp = FeaturePreprocessor()
        features = _sample_features(20)
        pp.fit(features)
        # Manually create a feature with NaN
        bad = _sample_features(1)[0]
        bad.duration = float("nan")
        vec = pp.transform(bad)
        assert not np.any(np.isnan(vec))

    def test_inf_replaced(self) -> None:
        pp = FeaturePreprocessor()
        features = _sample_features(20)
        pp.fit(features)
        bad = _sample_features(1)[0]
        bad.bytes_per_second = float("inf")
        vec = pp.transform(bad)
        assert not np.any(np.isinf(vec))


class TestPersistence:
    """Save and load preprocessor state."""

    def test_save_load_roundtrip(self, tmp_path) -> None:
        pp = FeaturePreprocessor()
        features = _sample_features(30)
        pp.fit(features)
        original = pp.transform(features[0])

        path = str(tmp_path / "preprocessor.pkl")
        pp.save(path)

        loaded = FeaturePreprocessor.load(path)
        restored = loaded.transform(features[0])
        np.testing.assert_array_almost_equal(original, restored)

    def test_is_fitted_after_load(self, tmp_path) -> None:
        pp = FeaturePreprocessor()
        pp.fit(_sample_features(20))

        path = str(tmp_path / "preprocessor.pkl")
        pp.save(path)

        loaded = FeaturePreprocessor.load(path)
        assert loaded.is_fitted
