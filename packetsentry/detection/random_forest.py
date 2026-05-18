"""Random Forest detector — baseline comparison model.

Loads a pre-trained scikit-learn Random Forest from ``models/rf_nslkdd.pkl``
(exported from the existing notebook).  Kept as a **baseline** alongside
XGBoost to demonstrate improvement via benchmarking.

Graceful degradation: returns 0.0 if model files are absent.
"""

from __future__ import annotations

import logging
from pathlib import Path

import numpy as np

from packetsentry.features.extractor import FlowFeatures

logger = logging.getLogger(__name__)


class RandomForestDetector:
    """Baseline Random Forest detector.

    Loads ``models/rf_nslkdd.pkl`` + ``models/scaler.pkl`` exported from
    the original NSL-KDD notebook.  Used alongside XGBoost to benchmark
    the improvement from the upgraded ML pipeline.

    Args:
        model_path: Path to the serialised ``RandomForestClassifier``.
        scaler_path: Path to the serialised ``StandardScaler``.
    """

    def __init__(
        self,
        model_path: str = "models/rf_nslkdd.pkl",
        scaler_path: str = "models/scaler.pkl",
    ) -> None:
        self._loaded = False
        self._model = None
        self._scaler = None

        if not Path(model_path).exists():
            logger.warning(
                "RF model not found at '%s' — scoring disabled.", model_path
            )
            return

        try:
            import joblib
            self._model = joblib.load(model_path)
            if Path(scaler_path).exists():
                self._scaler = joblib.load(scaler_path)
            else:
                logger.warning(
                    "Scaler not found at '%s' — using raw features.", scaler_path
                )
            self._loaded = True
            logger.info("RandomForestDetector loaded from '%s'", model_path)
        except Exception as exc:
            logger.error(
                "Failed to load RF model from '%s': %s", model_path, exc
            )

    def score(self, features: FlowFeatures) -> float:
        """Return attack probability in [0.0, 1.0].

        Returns 0.0 if model is not loaded.

        Args:
            features: Extracted flow features.

        Returns:
            Float in [0.0, 1.0] — probability of attack class.
        """
        if not self._loaded or self._model is None:
            return 0.0

        try:
            vec = features.to_vector().reshape(1, -1)
            if self._scaler is not None:
                vec = self._scaler.transform(vec)
            proba = self._model.predict_proba(vec)[0]
            # attack class is index 1 for binary classification
            attack_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])
            return float(np.clip(attack_prob, 0.0, 1.0))
        except Exception as exc:
            logger.error("RandomForestDetector.score() failed: %s", exc)
            return 0.0
