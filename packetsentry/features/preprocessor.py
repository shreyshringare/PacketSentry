"""Feature preprocessor: scaling + encoding for the ML pipeline.

Wraps scikit-learn's StandardScaler with additional handling for:

  - NaN / inf replacement (replaced with 0.0 before scaling)
  - Consistent float32 output dtype
  - Save / load for model persistence via joblib
  - Both single-feature and batch transform APIs

The preprocessing pipeline must be identical to the one used in the
training notebook so that the Random Forest model receives features
in the same distribution it was trained on.

Usage::

    pp = FeaturePreprocessor()
    pp.fit(training_features)         # list[FlowFeatures]
    vec = pp.transform(flow_features) # single FlowFeatures → ndarray(23,)
    pp.save("models/preprocessor.pkl")

    # Later...
    pp = FeaturePreprocessor.load("models/preprocessor.pkl")
"""

from __future__ import annotations

import logging
from pathlib import Path

import joblib
import numpy as np
from sklearn.preprocessing import StandardScaler

from packetsentry.features.extractor import FlowFeatures

logger = logging.getLogger(__name__)


class FeaturePreprocessor:
    """Scales and encodes feature vectors for ML models.

    Wraps ``sklearn.preprocessing.StandardScaler`` with NaN/inf
    sanitisation and persistence helpers.

    Attributes:
        is_fitted: Whether ``fit()`` has been called.
    """

    def __init__(self) -> None:
        self._scaler = StandardScaler()
        self._is_fitted = False

    @property
    def is_fitted(self) -> bool:
        """Whether the preprocessor has been fitted to data."""
        return self._is_fitted

    def fit(
        self, features: list[FlowFeatures] | np.ndarray,
    ) -> "FeaturePreprocessor":
        """Fit the scaler on a collection of feature vectors.

        Args:
            features: List of FlowFeatures or a 2-D numpy array of
                      shape ``(n_samples, 23)``.

        Returns:
            self (for method chaining).
        """
        matrix = self._to_matrix(features)
        matrix = self._sanitise(matrix)
        self._scaler.fit(matrix)
        self._is_fitted = True
        logger.info(
            "FeaturePreprocessor fitted on %d samples", matrix.shape[0],
        )
        return self

    def transform(
        self, features: FlowFeatures | np.ndarray,
    ) -> np.ndarray:
        """Transform a single feature vector.

        Args:
            features: A single FlowFeatures or a 1-D numpy array of
                      shape ``(23,)``.

        Returns:
            Scaled array of shape ``(23,)`` with dtype ``float32``.

        Raises:
            RuntimeError: If called before ``fit()``.
        """
        if not self._is_fitted:
            raise RuntimeError(
                "FeaturePreprocessor must be fit() before transform().",
            )
        vec = self._to_vector(features)
        vec = self._sanitise(vec.reshape(1, -1))
        scaled = self._scaler.transform(vec)
        return scaled[0].astype(np.float32)

    def transform_batch(
        self, features: list[FlowFeatures] | np.ndarray,
    ) -> np.ndarray:
        """Transform a batch of feature vectors.

        Args:
            features: List of FlowFeatures or a 2-D numpy array.

        Returns:
            Scaled array of shape ``(n, 23)`` with dtype ``float32``.

        Raises:
            RuntimeError: If called before ``fit()``.
        """
        if not self._is_fitted:
            raise RuntimeError(
                "FeaturePreprocessor must be fit() before transform_batch().",
            )
        matrix = self._to_matrix(features)
        matrix = self._sanitise(matrix)
        return self._scaler.transform(matrix).astype(np.float32)

    def fit_transform(
        self, features: list[FlowFeatures] | np.ndarray,
    ) -> np.ndarray:
        """Fit and transform in one step.

        Args:
            features: List of FlowFeatures or a 2-D numpy array.

        Returns:
            Scaled array of shape ``(n, 23)`` with dtype ``float32``.
        """
        matrix = self._to_matrix(features)
        matrix = self._sanitise(matrix)
        self._is_fitted = True
        return self._scaler.fit_transform(matrix).astype(np.float32)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: str) -> None:
        """Save fitted preprocessor state to disk.

        Args:
            path: File path (typically ``models/preprocessor.pkl``).
        """
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {"scaler": self._scaler, "is_fitted": self._is_fitted},
            path,
        )
        logger.info("FeaturePreprocessor saved to %s", path)

    @classmethod
    def load(cls, path: str) -> "FeaturePreprocessor":
        """Load a previously saved preprocessor.

        Args:
            path: Path to the saved ``.pkl`` file.

        Returns:
            A fitted FeaturePreprocessor instance.
        """
        data = joblib.load(path)
        pp = cls()
        pp._scaler = data["scaler"]
        pp._is_fitted = data["is_fitted"]
        logger.info("FeaturePreprocessor loaded from %s", path)
        return pp

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _to_vector(features: FlowFeatures | np.ndarray) -> np.ndarray:
        """Convert a single FlowFeatures to a 1-D numpy array."""
        if isinstance(features, FlowFeatures):
            return features.to_vector()
        return np.asarray(features, dtype=np.float32)

    @staticmethod
    def _to_matrix(
        features: list[FlowFeatures] | np.ndarray,
    ) -> np.ndarray:
        """Convert a collection of FlowFeatures to a 2-D numpy array."""
        if isinstance(features, np.ndarray):
            return features.astype(np.float32)
        return np.array(
            [f.to_vector() for f in features], dtype=np.float32,
        )

    @staticmethod
    def _sanitise(arr: np.ndarray) -> np.ndarray:
        """Replace NaN and inf values with 0.0."""
        return np.nan_to_num(arr, nan=0.0, posinf=0.0, neginf=0.0)
