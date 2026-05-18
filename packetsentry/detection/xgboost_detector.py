"""XGBoost detector — primary supervised classifier.

Loads a pre-trained XGBoost model (``models/xgb_nslkdd.json``) and
scores each flow as a probability of being an attack (0.0–1.0).

Provides SHAP-based explanations via :class:`AlertExplainer` so every
alert includes feature attribution — no black-box decisions.

Graceful degradation: returns 0.0 (not a crash) if the model file is
absent, so the rest of the ensemble still runs during development or
before the training script has been executed.
"""

from __future__ import annotations

import logging
from pathlib import Path

import numpy as np

from packetsentry.detection.explainer import AlertExplainer, ExplanationResult
from packetsentry.features.extractor import FlowFeatures

logger = logging.getLogger(__name__)


class XGBoostDetector:
    """Primary supervised detector using XGBoost.

    Industry-standard for tabular network data.  Achieves ~99% accuracy
    on NSL-KDD with Optuna-tuned hyperparameters and SMOTE oversampling.

    Args:
        model_path: Path to ``xgb_nslkdd.json`` (XGBoost native format).
        top_k: Number of top SHAP features to include in explanations.
    """

    def __init__(
        self,
        model_path: str = "models/xgb_nslkdd.json",
        top_k: int = 5,
    ) -> None:
        self._loaded = False
        self._model = None
        self._explainer: AlertExplainer | None = None
        self._top_k = top_k

        if not Path(model_path).exists():
            logger.warning(
                "XGBoost model not found at '%s' — scoring disabled. "
                "Run scripts/train_xgboost.py to create the model.",
                model_path,
            )
            return

        try:
            import xgboost as xgb
            model = xgb.Booster()
            model.load_model(model_path)
            self._model = model
            self._explainer = AlertExplainer(model, top_k=top_k)
            self._loaded = True
            logger.info("XGBoostDetector loaded from '%s'", model_path)
        except Exception as exc:
            logger.error(
                "Failed to load XGBoost model from '%s': %s", model_path, exc
            )

    def score(self, features: FlowFeatures) -> float:
        """Return attack probability in [0.0, 1.0].

        Returns 0.0 if the model is not loaded.

        Args:
            features: Extracted flow features.

        Returns:
            Float in [0.0, 1.0] — probability of being an attack.
        """
        if not self._loaded or self._model is None:
            return 0.0

        try:
            import xgboost as xgb
            vec = features.to_vector().reshape(1, -1).astype(np.float32)
            dmat = xgb.DMatrix(vec)
            proba = float(self._model.predict(dmat)[0])
            return float(np.clip(proba, 0.0, 1.0))
        except Exception as exc:
            logger.error("XGBoostDetector.score() failed: %s", exc)
            return 0.0

    def explain(self, features: FlowFeatures) -> ExplanationResult | None:
        """Return SHAP explanation for this flow.

        Returns None if the model is not loaded.

        Args:
            features: Extracted flow features.

        Returns:
            :class:`ExplanationResult` or None.
        """
        if not self._loaded or self._explainer is None:
            return None

        try:
            vec = features.to_vector()
            return self._explainer.explain(vec)
        except Exception as exc:
            logger.error("XGBoostDetector.explain() failed: %s", exc)
            return None
