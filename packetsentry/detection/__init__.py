"""Detection pipeline: signature matching + ML ensemble.

Public API:
    - ``AhoCorasick``: O(n) multi-pattern signature matcher (from scratch).
    - ``XGBoostDetector``: Primary supervised classifier with SHAP explainability.
    - ``AlertExplainer``: SHAP TreeExplainer wrapper — feature attribution per alert.
    - ``ExplanationResult``: Dataclass carrying top-5 features + explanation string.
    - ``RandomForestDetector``: Baseline comparison model.
    - ``IsolationForestDetector``: Unsupervised, self-trains on 500 baseline flows.
    - ``ZScoreDetector``: Statistical Welford online z-score detector.
    - ``TransformerAEDetector``: Temporal anomaly detector — self-trains on 2000 flows.
    - ``GNNDetector``: Graph-based topology anomaly detector — from-scratch GraphSAGE.
    - ``EnsembleArbiter``: 7-model confidence-weighted voting + FP feedback loop.
    - ``DecisionResult``: Dataclass carrying alert decision + SHAP explanation.
"""

from packetsentry.detection.aho_corasick import AhoCorasick
from packetsentry.detection.ensemble import DecisionResult, EnsembleArbiter
from packetsentry.detection.explainer import AlertExplainer, ExplanationResult
from packetsentry.detection.gnn_detector import GNNDetector
from packetsentry.detection.isolation_forest import IsolationForestDetector
from packetsentry.detection.random_forest import RandomForestDetector
from packetsentry.detection.transformer_ae import TransformerAEDetector
from packetsentry.detection.xgboost_detector import XGBoostDetector
from packetsentry.detection.zscore import ZScoreDetector

__all__ = [
    "AhoCorasick",
    "XGBoostDetector",
    "AlertExplainer",
    "ExplanationResult",
    "RandomForestDetector",
    "IsolationForestDetector",
    "ZScoreDetector",
    "TransformerAEDetector",
    "GNNDetector",
    "EnsembleArbiter",
    "DecisionResult",
]
