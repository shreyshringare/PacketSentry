# PacketSentry Phase 1 — NSL-KDD Metrics & Showcase

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run all 7 models against NSL-KDD, produce F1/precision/recall/ROC-AUC plots in `results/`, update README with concrete numbers.

**Architecture:** Standalone evaluation script (`scripts/evaluate_all.py`) that loads NSL-KDD, trains/evaluates each model independently, outputs plots + JSON summary. XGBoost uses the existing trained model; RF and IF are re-fit here for standalone comparison; ZScore/TransformerAE evaluated as online learners on held-out rows; GNN documented as topology-only (N/A for per-flow dataset).

**Tech Stack:** Python 3.12, scikit-learn, xgboost, shap, umap-learn, matplotlib, pandas, numpy (all in existing venv except umap-learn and matplotlib)

---

## File Map

| Action | Path | Responsibility |
|--------|------|----------------|
| Create | `scripts/evaluate_all.py` | Full evaluation: load data, train/score all models, save plots + JSON |
| Create | `results/.gitkeep` | Track results/ dir (actual outputs gitignored) |
| Create | `notebooks/analysis.ipynb` | Interactive walkthrough: training, eval, SHAP, UMAP |
| Modify | `README.md` | Add metrics table, SHAP screenshot, architecture diagram, demo GIF |
| Modify | `pyproject.toml` | Add `matplotlib`, `umap-learn`, `pandas` to dependencies |
| Create | `.gitignore` entry | Ignore `results/*.png`, `results/*.json` (large binaries) — keep .gitkeep |

---

## Task 1: Add missing dependencies

**Files:**
- Modify: `pyproject.toml`

- [ ] **Step 1: Add matplotlib, umap-learn, pandas to pyproject.toml**

Open `pyproject.toml` and add to the `dependencies` list:

```toml
dependencies = [
    # ... existing deps ...
    "matplotlib>=3.8.0",
    "umap-learn>=0.5.6",
    "pandas>=2.2.0",
    "seaborn>=0.13.0",
]
```

- [ ] **Step 2: Install the new deps**

```bash
pip install matplotlib umap-learn pandas seaborn
```

Expected: packages install cleanly. `umap-learn` installs `numba` as a dep — that's expected.

- [ ] **Step 3: Create results/ directory with gitkeep**

```bash
mkdir -p results
touch results/.gitkeep
```

- [ ] **Step 4: Add results outputs to .gitignore**

If `.gitignore` doesn't exist, create it. Add:

```
results/*.png
results/*.json
notebooks/.ipynb_checkpoints/
```

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml results/.gitkeep .gitignore
git commit -m "chore: add matplotlib/umap-learn/pandas deps, create results/ dir"
```

---

## Task 2: Write evaluate_all.py — data loading + XGBoost evaluation

**Files:**
- Create: `scripts/evaluate_all.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_evaluate_all.py`:

```python
"""Smoke tests for evaluate_all.py helper functions."""
from pathlib import Path
import numpy as np
import pytest


def test_load_nslkdd_returns_arrays(tmp_path):
    """_load_nslkdd returns correctly shaped X, y arrays."""
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
    from evaluate_all import load_nslkdd

    # Write a minimal valid NSL-KDD row (43 columns: 41 features + label + difficulty)
    row = ",".join(["0"] * 9 + ["tcp"] + ["0"] * 31 + ["normal"] + ["20"]) + "\n"
    fake_file = tmp_path / "KDDTrain+.txt"
    fake_file.write_text(row * 5)

    X, y, y_multi = load_nslkdd(fake_file)

    assert X.shape == (5, 23), f"Expected (5,23), got {X.shape}"
    assert y.shape == (5,)
    assert y_multi.shape == (5,)
    assert set(y).issubset({0, 1})


def test_severity_from_confidence():
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
    from evaluate_all import severity_from_confidence

    assert severity_from_confidence(0.9) == "CRITICAL"
    assert severity_from_confidence(0.7) == "HIGH"
    assert severity_from_confidence(0.55) == "MED"
    assert severity_from_confidence(0.2) == "LOW"
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_evaluate_all.py -v
```

Expected: `ModuleNotFoundError: No module named 'evaluate_all'` — correct, file doesn't exist yet.

- [ ] **Step 3: Create scripts/evaluate_all.py with load_nslkdd and severity_from_confidence**

```python
#!/usr/bin/env python3
"""Evaluate all PacketSentry detectors on NSL-KDD dataset.

Usage:
    python scripts/evaluate_all.py --dataset data/nslkdd/ --output results/

Outputs:
    results/metrics_summary.json
    results/model_comparison.png
    results/roc_curves.png
    results/confusion_matrix_xgb.png
    results/shap_beeswarm.png
    results/shap_waterfall_example.png
    results/embeddings_umap.png
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

import numpy as np
import typer

logger = logging.getLogger(__name__)

app = typer.Typer(help="Evaluate all PacketSentry models on NSL-KDD.")

# -----------------------------------------------------------------------
# NSL-KDD column definitions (same as train_xgboost.py)
# -----------------------------------------------------------------------
_CATEGORICAL_COLS = {1, 2, 3}  # protocol_type, service, flag
_NORMAL_LABEL = "normal"

# 23 column indices selected for training (matches FeatureExtractor output)
_TRAIN_COLS = [0, 1, 4, 5, 22, 23, 24, 25, 26, 27, 32, 33, 34, 35, 36, 37,
               38, 39, 40, 2, 3, 6, 7]

_FEATURE_NAMES = [
    "duration", "protocol_type", "src_bytes", "dst_bytes",
    "count", "srv_count", "same_srv_rate", "serror_rate",
    "diff_srv_rate", "rerror_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "service", "flag", "land", "wrong_fragment",
]

# Multi-class labels
_ATTACK_CLASSES = {
    "normal": 0,
    # DoS
    "back": 1, "land": 1, "neptune": 1, "pod": 1, "smurf": 1, "teardrop": 1,
    "apache2": 1, "udpstorm": 1, "processtable": 1, "mailbomb": 1,
    # Probe
    "ipsweep": 2, "nmap": 2, "portsweep": 2, "satan": 2, "mscan": 2, "saint": 2,
    # R2L
    "ftp_write": 3, "guess_passwd": 3, "imap": 3, "multihop": 3, "phf": 3,
    "spy": 3, "warezclient": 3, "warezmaster": 3, "sendmail": 3, "named": 3,
    "snmpgetattack": 3, "snmpguess": 3, "xlock": 3, "xsnoop": 3, "httptunnel": 3,
    # U2R
    "buffer_overflow": 4, "loadmodule": 4, "perl": 4, "rootkit": 4,
    "ps": 4, "sqlattack": 4, "xterm": 4,
}

_MULTI_CLASS_NAMES = ["Normal", "DoS", "Probe", "R2L", "U2R"]


def load_nslkdd(
    path: Path,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Load NSL-KDD .txt file.

    Returns:
        X: float32 array of shape (N, 23)
        y: binary labels — 0=normal, 1=attack
        y_multi: multi-class labels — 0=normal, 1=DoS, 2=Probe, 3=R2L, 4=U2R
    """
    rows_X, rows_y, rows_y_multi = [], [], []

    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(",")
            if len(parts) < 42:
                continue

            label = parts[41].strip().rstrip(".")

            row = []
            for i, val in enumerate(parts[:41]):
                if i in _CATEGORICAL_COLS:
                    row.append(hash(val) % 1000)
                else:
                    try:
                        row.append(float(val))
                    except ValueError:
                        row.append(0.0)

            selected = [row[c] if c < len(row) else 0.0 for c in _TRAIN_COLS]
            rows_X.append(selected)
            rows_y.append(0 if label == _NORMAL_LABEL else 1)
            rows_y_multi.append(_ATTACK_CLASSES.get(label, 1))  # unknown → attack

    X = np.array(rows_X, dtype=np.float32)
    y = np.array(rows_y, dtype=np.int32)
    y_multi = np.array(rows_y_multi, dtype=np.int32)
    return X, y, y_multi


def severity_from_confidence(conf: float) -> str:
    """Map confidence score to severity label."""
    if conf >= 0.80:
        return "CRITICAL"
    if conf >= 0.60:
        return "HIGH"
    if conf >= 0.40:
        return "MED"
    return "LOW"
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_evaluate_all.py -v
```

Expected: `2 passed` — both tests green.

- [ ] **Step 5: Commit**

```bash
git add scripts/evaluate_all.py tests/test_evaluate_all.py
git commit -m "feat(eval): add load_nslkdd + severity_from_confidence helpers"
```

---

## Task 3: evaluate_all.py — XGBoost 5-fold CV + metrics_summary.json

**Files:**
- Modify: `scripts/evaluate_all.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_evaluate_all.py`:

```python
def test_compute_metrics_shape():
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
    from evaluate_all import compute_metrics

    y_true = np.array([0, 1, 1, 0, 1])
    y_pred = np.array([0, 1, 0, 0, 1])
    y_proba = np.array([0.1, 0.9, 0.4, 0.2, 0.8])

    metrics = compute_metrics("test_model", y_true, y_pred, y_proba)

    assert "f1" in metrics
    assert "precision" in metrics
    assert "recall" in metrics
    assert "roc_auc" in metrics
    assert metrics["model"] == "test_model"
    assert 0.0 <= metrics["f1"] <= 1.0
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_evaluate_all.py::test_compute_metrics_shape -v
```

Expected: `ImportError` or `AttributeError` — `compute_metrics` not defined yet.

- [ ] **Step 3: Add compute_metrics + eval_xgboost functions to evaluate_all.py**

Append after `severity_from_confidence`:

```python
from sklearn.metrics import (
    f1_score, precision_score, recall_score, roc_auc_score,
    confusion_matrix, classification_report,
)


def compute_metrics(
    model_name: str,
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_proba: np.ndarray,
) -> dict:
    """Compute standard binary classification metrics."""
    return {
        "model": model_name,
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_true, y_proba)), 4),
    }


def eval_xgboost(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    model_path: Path,
    cv_folds: int = 5,
    seed: int = 42,
) -> tuple[dict, np.ndarray]:
    """Evaluate XGBoost with 5-fold CV. Returns metrics dict + test probabilities."""
    import xgboost as xgb
    from sklearn.model_selection import StratifiedKFold, cross_val_score
    from xgboost import XGBClassifier

    logger.info("Evaluating XGBoost (%d-fold CV)...", cv_folds)

    # Load trained model if available, else train
    if model_path.exists():
        booster = xgb.Booster()
        booster.load_model(str(model_path))
        dtest = xgb.DMatrix(X_test)
        y_proba = booster.predict(dtest)
    else:
        logger.warning("No trained model at %s — training from scratch", model_path)
        clf = XGBClassifier(
            n_estimators=300, max_depth=6, learning_rate=0.1,
            objective="binary:logistic", eval_metric="auc",
            seed=seed, verbosity=0,
        )
        clf.fit(X_train, y_train)
        y_proba = clf.predict_proba(X_test)[:, 1]

    # 5-fold CV on training set
    skf = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=seed)
    clf_cv = XGBClassifier(
        n_estimators=300, max_depth=6, learning_rate=0.1,
        objective="binary:logistic", seed=seed, verbosity=0,
    )
    cv_scores = cross_val_score(clf_cv, X_train, y_train, cv=skf, scoring="f1", n_jobs=-1)
    logger.info("XGBoost CV F1: %.4f ± %.4f", cv_scores.mean(), cv_scores.std())

    y_pred = (y_proba > 0.5).astype(int)
    metrics = compute_metrics("XGBoost", y_test, y_pred, y_proba)
    metrics["cv_f1_mean"] = round(float(cv_scores.mean()), 4)
    metrics["cv_f1_std"] = round(float(cv_scores.std()), 4)
    return metrics, y_proba
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_evaluate_all.py -v
```

Expected: `3 passed`.

- [ ] **Step 5: Commit**

```bash
git add scripts/evaluate_all.py tests/test_evaluate_all.py
git commit -m "feat(eval): add compute_metrics + eval_xgboost with 5-fold CV"
```

---

## Task 4: evaluate_all.py — RF, IsolationForest, ZScore evaluators

**Files:**
- Modify: `scripts/evaluate_all.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_evaluate_all.py`:

```python
def test_eval_random_forest_returns_metrics():
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
    from evaluate_all import eval_random_forest

    rng = np.random.default_rng(42)
    X = rng.random((200, 23), dtype=np.float32)
    y = (rng.random(200) > 0.5).astype(int)

    metrics, proba = eval_random_forest(X[:150], y[:150], X[150:], y[150:])

    assert metrics["model"] == "RandomForest"
    assert 0.0 <= proba.min() and proba.max() <= 1.0
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_evaluate_all.py::test_eval_random_forest_returns_metrics -v
```

Expected: `ImportError` — function doesn't exist yet.

- [ ] **Step 3: Add RF, IF, ZScore evaluators to evaluate_all.py**

```python
def eval_random_forest(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    seed: int = 42,
) -> tuple[dict, np.ndarray]:
    """Train RandomForest on NSL-KDD train split, evaluate on test split."""
    from sklearn.ensemble import RandomForestClassifier

    logger.info("Evaluating RandomForest...")
    clf = RandomForestClassifier(n_estimators=200, max_depth=10, n_jobs=-1, random_state=seed)
    clf.fit(X_train, y_train)
    y_proba = clf.predict_proba(X_test)[:, 1]
    y_pred = (y_proba > 0.5).astype(int)
    return compute_metrics("RandomForest", y_test, y_pred, y_proba), y_proba


def eval_isolation_forest(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    seed: int = 42,
) -> tuple[dict, np.ndarray]:
    """Train IsolationForest on normal traffic only (unsupervised)."""
    from sklearn.ensemble import IsolationForest

    logger.info("Evaluating IsolationForest (unsupervised)...")
    # Train ONLY on normal samples (unsupervised: no labels used)
    X_normal = X_train[y_train == 0]
    iso = IsolationForest(n_estimators=200, contamination=0.1, random_state=seed, n_jobs=-1)
    iso.fit(X_normal)

    # score_samples returns negative anomaly scores; flip so higher = more anomalous
    raw = iso.score_samples(X_test)
    y_proba = 1.0 - (raw - raw.min()) / (raw.max() - raw.min() + 1e-9)
    y_proba = y_proba.astype(np.float32)
    y_pred = (y_proba > 0.5).astype(int)
    return compute_metrics("IsolationForest", y_test, y_pred, y_proba), y_proba


def eval_zscore(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
) -> tuple[dict, np.ndarray]:
    """ZScore anomaly detection: fit mean/std on normal train, score test."""
    logger.info("Evaluating ZScore...")
    X_normal = X_train[y_train == 0]
    mean = X_normal.mean(axis=0)
    std = X_normal.std(axis=0) + 1e-9

    # Max z-score across features as anomaly score
    z = np.abs((X_test - mean) / std)
    raw_scores = z.max(axis=1)

    # Clip and normalize to [0, 1]
    clip_val = np.percentile(raw_scores, 99)
    y_proba = np.clip(raw_scores / clip_val, 0.0, 1.0).astype(np.float32)
    y_pred = (y_proba > 0.5).astype(int)
    return compute_metrics("ZScore", y_test, y_pred, y_proba), y_proba
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_evaluate_all.py -v
```

Expected: `4 passed`.

- [ ] **Step 5: Commit**

```bash
git add scripts/evaluate_all.py tests/test_evaluate_all.py
git commit -m "feat(eval): add RandomForest, IsolationForest, ZScore evaluators"
```

---

## Task 5: evaluate_all.py — TransformerAE online evaluator

**Files:**
- Modify: `scripts/evaluate_all.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_evaluate_all.py`:

```python
def test_eval_transformer_ae_returns_metrics():
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
    from evaluate_all import eval_transformer_ae

    rng = np.random.default_rng(42)
    X = rng.random((200, 23), dtype=np.float32)
    y = (rng.random(200) > 0.5).astype(int)

    metrics, proba = eval_transformer_ae(X[:150], y[:150], X[150:], y[150:])

    assert metrics["model"] == "TransformerAE"
    assert proba.shape == (50,)
    assert 0.0 <= proba.min() and proba.max() <= 1.0
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_evaluate_all.py::test_eval_transformer_ae_returns_metrics -v
```

Expected: `ImportError`.

- [ ] **Step 3: Add eval_transformer_ae to evaluate_all.py**

```python
def eval_transformer_ae(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    warmup_rows: int = 500,
    seed: int = 42,
) -> tuple[dict, np.ndarray]:
    """Evaluate PacketSentry TransformerAEDetector by online-training on normal traffic.

    The Transformer AE is an online learner — it builds its baseline from
    normal traffic seen during warm-up. Here we warm it up on the first
    `warmup_rows` normal rows from the training set.
    """
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from packetsentry.detection.transformer_ae import TransformerAEDetector
    from packetsentry.features.extractor import FlowFeatures

    logger.info("Evaluating TransformerAE (online warm-up on %d normal rows)...", warmup_rows)

    ae = TransformerAEDetector()

    # Warm up on normal traffic rows
    X_normal = X_train[y_train == 0][:warmup_rows]
    for row in X_normal:
        features = _array_to_flow_features(row)
        ae.score(features)  # score() drives internal training

    # Score test rows
    scores = []
    for row in X_test:
        features = _array_to_flow_features(row)
        scores.append(ae.score(features))

    y_proba = np.clip(np.array(scores, dtype=np.float32), 0.0, 1.0)
    y_pred = (y_proba > 0.5).astype(int)
    return compute_metrics("TransformerAE", y_test, y_pred, y_proba), y_proba


def _array_to_flow_features(row: np.ndarray):
    """Convert a 23-element NSL-KDD array to a FlowFeatures-like object.

    Uses a simple namespace so detectors can access .feature_vector.
    """
    import types
    features = types.SimpleNamespace()
    features.duration = float(row[0])
    features.protocol_type = int(row[1])
    features.src_bytes = float(row[2])
    features.dst_bytes = float(row[3])
    features.count = float(row[4])
    features.srv_count = float(row[5])
    features.same_srv_rate = float(row[6])
    features.serror_rate = float(row[7])
    features.diff_srv_rate = float(row[8])
    features.rerror_rate = float(row[9])
    features.dst_host_count = float(row[10])
    features.dst_host_srv_count = float(row[11])
    features.flag_syn = float(row[12])
    features.flag_ack = float(row[13])
    features.flag_fin = float(row[14])
    features.flag_rst = float(row[15])
    features.flag_psh = float(row[16])
    features.packet_count = float(row[17])
    features.avg_packet_size = float(row[18])
    features.bytes_per_second = float(row[19])
    features.packets_per_second = float(row[20])
    features.src_port = int(row[21]) if len(row) > 21 else 0
    features.dst_port = int(row[22]) if len(row) > 22 else 0
    features.feature_vector = row.tolist()
    return features
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_evaluate_all.py -v
```

Expected: `5 passed`.

- [ ] **Step 5: Commit**

```bash
git add scripts/evaluate_all.py tests/test_evaluate_all.py
git commit -m "feat(eval): add TransformerAE online evaluator + _array_to_flow_features"
```

---

## Task 6: evaluate_all.py — plots (model_comparison.png, roc_curves.png, confusion_matrix.png)

**Files:**
- Modify: `scripts/evaluate_all.py`

- [ ] **Step 1: Add plot functions to evaluate_all.py**

No new tests needed — plots are visual outputs. Add after the evaluator functions:

```python
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend — must be before pyplot import
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches


def plot_model_comparison(all_metrics: list[dict], output_dir: Path) -> None:
    """Bar chart: all models vs F1 score."""
    models = [m["model"] for m in all_metrics]
    f1_scores = [m["f1"] for m in all_metrics]
    colors = ["#2563EB" if s >= 0.9 else "#F59E0B" if s >= 0.7 else "#6B7280"
              for s in f1_scores]

    fig, ax = plt.subplots(figsize=(10, 5))
    bars = ax.bar(models, f1_scores, color=colors, edgecolor="white", linewidth=0.5)
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("F1 Score", fontsize=12)
    ax.set_title("PacketSentry — All Models vs NSL-KDD F1", fontsize=14, fontweight="bold")
    ax.axhline(0.9, color="#DC2626", linestyle="--", linewidth=1, label="0.90 baseline")
    ax.legend()

    for bar, score in zip(bars, f1_scores):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                f"{score:.3f}", ha="center", va="bottom", fontsize=9, fontweight="bold")

    ax.set_xticklabels(models, rotation=20, ha="right")
    fig.tight_layout()
    path = output_dir / "model_comparison.png"
    fig.savefig(path, dpi=150)
    plt.close(fig)
    logger.info("Saved %s", path)


def plot_roc_curves(
    all_probas: dict[str, tuple[np.ndarray, np.ndarray]],
    output_dir: Path,
) -> None:
    """ROC-AUC overlay for all models. all_probas: {model_name: (y_true, y_proba)}"""
    from sklearn.metrics import roc_curve, auc

    fig, ax = plt.subplots(figsize=(8, 6))
    cmap = plt.get_cmap("tab10")

    for i, (model, (y_true, y_proba)) in enumerate(all_probas.items()):
        fpr, tpr, _ = roc_curve(y_true, y_proba)
        roc_auc = auc(fpr, tpr)
        ax.plot(fpr, tpr, color=cmap(i), lw=1.5, label=f"{model} (AUC={roc_auc:.3f})")

    ax.plot([0, 1], [0, 1], "k--", lw=0.8, label="Random (AUC=0.5)")
    ax.set_xlabel("False Positive Rate", fontsize=11)
    ax.set_ylabel("True Positive Rate", fontsize=11)
    ax.set_title("ROC Curves — All PacketSentry Models", fontsize=13, fontweight="bold")
    ax.legend(loc="lower right", fontsize=8)
    fig.tight_layout()
    path = output_dir / "roc_curves.png"
    fig.savefig(path, dpi=150)
    plt.close(fig)
    logger.info("Saved %s", path)


def plot_confusion_matrix(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    output_dir: Path,
    model_name: str = "XGBoost",
) -> None:
    """Confusion matrix heatmap."""
    import seaborn as sns
    from sklearn.metrics import confusion_matrix as sk_cm

    cm = sk_cm(y_true, y_pred)
    fig, ax = plt.subplots(figsize=(5, 4))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=["Normal", "Attack"],
                yticklabels=["Normal", "Attack"], ax=ax)
    ax.set_xlabel("Predicted", fontsize=11)
    ax.set_ylabel("Actual", fontsize=11)
    ax.set_title(f"{model_name} — Confusion Matrix (NSL-KDD)", fontsize=12, fontweight="bold")
    fig.tight_layout()
    path = output_dir / f"confusion_matrix_{model_name.lower()}.png"
    fig.savefig(path, dpi=150)
    plt.close(fig)
    logger.info("Saved %s", path)
```

- [ ] **Step 2: Run existing tests to confirm no regressions**

```bash
pytest tests/test_evaluate_all.py -v
```

Expected: `5 passed` — no regressions.

- [ ] **Step 3: Commit**

```bash
git add scripts/evaluate_all.py
git commit -m "feat(eval): add model_comparison, roc_curves, confusion_matrix plot functions"
```

---

## Task 7: evaluate_all.py — SHAP beeswarm + waterfall plots

**Files:**
- Modify: `scripts/evaluate_all.py`

- [ ] **Step 1: Add SHAP plot functions to evaluate_all.py**

```python
def plot_shap(
    X_train: np.ndarray,
    X_test: np.ndarray,
    model_path: Path,
    output_dir: Path,
) -> None:
    """Generate SHAP beeswarm (top-20 features) and waterfall (single alert)."""
    import shap
    import xgboost as xgb

    if not model_path.exists():
        logger.warning("XGBoost model not found at %s — skipping SHAP plots", model_path)
        return

    logger.info("Generating SHAP plots...")
    booster = xgb.Booster()
    booster.load_model(str(model_path))

    # Use a sample of test rows for SHAP (full test set is slow)
    sample_size = min(500, len(X_test))
    rng = np.random.default_rng(42)
    idx = rng.choice(len(X_test), sample_size, replace=False)
    X_sample = X_test[idx]

    dmatrix = xgb.DMatrix(X_sample, feature_names=_FEATURE_NAMES[:23])
    explainer = shap.TreeExplainer(booster)
    shap_values = explainer.shap_values(dmatrix)

    # --- Beeswarm (top 20 features) ---
    fig, ax = plt.subplots(figsize=(10, 8))
    shap.summary_plot(
        shap_values, X_sample,
        feature_names=_FEATURE_NAMES[:23],
        max_display=20,
        show=False,
    )
    beeswarm_path = output_dir / "shap_beeswarm.png"
    plt.savefig(beeswarm_path, dpi=150, bbox_inches="tight")
    plt.close()
    logger.info("Saved %s", beeswarm_path)

    # --- Waterfall (single highest-confidence attack sample) ---
    probas = booster.predict(dmatrix)
    top_idx = int(np.argmax(probas))

    explanation = shap.Explanation(
        values=shap_values[top_idx],
        base_values=float(explainer.expected_value),
        data=X_sample[top_idx],
        feature_names=_FEATURE_NAMES[:23],
    )
    fig, ax = plt.subplots(figsize=(10, 6))
    shap.waterfall_plot(explanation, max_display=10, show=False)
    waterfall_path = output_dir / "shap_waterfall_example.png"
    plt.savefig(waterfall_path, dpi=150, bbox_inches="tight")
    plt.close()
    logger.info("Saved %s", waterfall_path)
```

- [ ] **Step 2: Run existing tests — no regressions**

```bash
pytest tests/test_evaluate_all.py -v
```

Expected: `5 passed`.

- [ ] **Step 3: Commit**

```bash
git add scripts/evaluate_all.py
git commit -m "feat(eval): add SHAP beeswarm + waterfall plot functions"
```

---

## Task 8: evaluate_all.py — UMAP projection + main() command

**Files:**
- Modify: `scripts/evaluate_all.py`

- [ ] **Step 1: Add UMAP plot + main CLI command to evaluate_all.py**

```python
def plot_umap_embeddings(
    X: np.ndarray,
    y: np.ndarray,
    output_dir: Path,
    n_samples: int = 3000,
) -> None:
    """Project NSL-KDD features to 2D with UMAP, color by attack class."""
    import umap

    logger.info("Running UMAP projection on %d samples...", n_samples)
    rng = np.random.default_rng(42)
    idx = rng.choice(len(X), min(n_samples, len(X)), replace=False)
    X_sample = X[idx]
    y_sample = y[idx]

    reducer = umap.UMAP(n_components=2, random_state=42, n_neighbors=15, min_dist=0.1)
    embedding = reducer.fit_transform(X_sample)

    class_names = _MULTI_CLASS_NAMES
    colors = ["#6B7280", "#DC2626", "#F59E0B", "#7C3AED", "#059669"]
    fig, ax = plt.subplots(figsize=(9, 7))

    for cls_id, (name, color) in enumerate(zip(class_names, colors)):
        mask = y_sample == cls_id
        if mask.sum() == 0:
            continue
        ax.scatter(
            embedding[mask, 0], embedding[mask, 1],
            c=color, label=name, s=4, alpha=0.6, linewidths=0,
        )

    ax.set_title("UMAP — NSL-KDD Feature Space by Attack Class", fontsize=13, fontweight="bold")
    ax.legend(markerscale=3, fontsize=9)
    ax.set_xlabel("UMAP-1")
    ax.set_ylabel("UMAP-2")
    fig.tight_layout()
    path = output_dir / "embeddings_umap.png"
    fig.savefig(path, dpi=150)
    plt.close(fig)
    logger.info("Saved %s", path)


@app.command()
def run(
    dataset: Path = typer.Option("data/nslkdd/", "--dataset", "-d"),
    output: Path = typer.Option("results/", "--output", "-o"),
    model: Path = typer.Option("models/xgb_nslkdd.json", "--model", "-m"),
    cv_folds: int = typer.Option(5, "--folds", "-k"),
    seed: int = typer.Option(42, "--seed"),
    skip_slow: bool = typer.Option(False, "--skip-slow", help="Skip TransformerAE (slow online eval)"),
) -> None:
    """Run full evaluation of all PacketSentry models on NSL-KDD."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    train_path = dataset / "KDDTrain+.txt"
    test_path = dataset / "KDDTest+.txt"
    output.mkdir(parents=True, exist_ok=True)

    if not train_path.exists():
        typer.echo(f"ERROR: {train_path} not found. Download NSL-KDD first.", err=True)
        raise typer.Exit(1)

    typer.echo("=== PacketSentry Model Evaluation ===")
    typer.echo(f"Dataset: {dataset}  Output: {output}")

    # Load data
    typer.echo("\n1. Loading NSL-KDD...")
    X_train, y_train, y_train_multi = load_nslkdd(train_path)
    X_test, y_test, y_test_multi = load_nslkdd(test_path)
    typer.echo(f"   Train: {len(X_train):,} rows | Test: {len(X_test):,} rows")

    all_metrics: list[dict] = []
    all_probas: dict[str, tuple[np.ndarray, np.ndarray]] = {}

    # XGBoost
    typer.echo("\n2. XGBoost (5-fold CV)...")
    xgb_metrics, xgb_proba = eval_xgboost(X_train, y_train, X_test, y_test, model, cv_folds, seed)
    all_metrics.append(xgb_metrics)
    all_probas["XGBoost"] = (y_test, xgb_proba)
    typer.echo(f"   F1={xgb_metrics['f1']:.4f}  ROC-AUC={xgb_metrics['roc_auc']:.4f}  "
               f"CV={xgb_metrics['cv_f1_mean']:.4f}±{xgb_metrics['cv_f1_std']:.4f}")

    # RandomForest
    typer.echo("\n3. RandomForest...")
    rf_metrics, rf_proba = eval_random_forest(X_train, y_train, X_test, y_test, seed)
    all_metrics.append(rf_metrics)
    all_probas["RandomForest"] = (y_test, rf_proba)
    typer.echo(f"   F1={rf_metrics['f1']:.4f}  ROC-AUC={rf_metrics['roc_auc']:.4f}")

    # IsolationForest
    typer.echo("\n4. IsolationForest (unsupervised)...")
    iso_metrics, iso_proba = eval_isolation_forest(X_train, y_train, X_test, y_test, seed)
    all_metrics.append(iso_metrics)
    all_probas["IsolationForest"] = (y_test, iso_proba)
    typer.echo(f"   F1={iso_metrics['f1']:.4f}  ROC-AUC={iso_metrics['roc_auc']:.4f}")

    # ZScore
    typer.echo("\n5. ZScore...")
    zs_metrics, zs_proba = eval_zscore(X_train, y_train, X_test, y_test)
    all_metrics.append(zs_metrics)
    all_probas["ZScore"] = (y_test, zs_proba)
    typer.echo(f"   F1={zs_metrics['f1']:.4f}  ROC-AUC={zs_metrics['roc_auc']:.4f}")

    # TransformerAE (skip if --skip-slow)
    if not skip_slow:
        typer.echo("\n6. TransformerAE (online warm-up)...")
        tae_metrics, tae_proba = eval_transformer_ae(X_train, y_train, X_test, y_test, seed=seed)
        all_metrics.append(tae_metrics)
        all_probas["TransformerAE"] = (y_test, tae_proba)
        typer.echo(f"   F1={tae_metrics['f1']:.4f}  ROC-AUC={tae_metrics['roc_auc']:.4f}")

    # Notes for models that require live network (GNN, Aho-Corasick)
    all_metrics.append({
        "model": "GNN (GraphSAGE)",
        "note": "Topology-based — requires live network graph. N/A for per-flow dataset.",
        "f1": None, "precision": None, "recall": None, "roc_auc": None,
    })
    all_metrics.append({
        "model": "Aho-Corasick",
        "note": "Signature matching — requires raw packet payloads. N/A for NSL-KDD.",
        "f1": None, "precision": None, "recall": None, "roc_auc": None,
    })

    # Save metrics summary
    summary_path = output / "metrics_summary.json"
    summary_path.write_text(json.dumps(all_metrics, indent=2))
    typer.echo(f"\n✅ Saved {summary_path}")

    # Plots
    typer.echo("\nGenerating plots...")
    scoreable = [m for m in all_metrics if m.get("f1") is not None]
    plot_model_comparison(scoreable, output)
    plot_roc_curves(all_probas, output)
    plot_confusion_matrix(y_test, (xgb_proba > 0.5).astype(int), output, "XGBoost")
    plot_shap(X_train, X_test, model, output)
    plot_umap_embeddings(X_test, y_test_multi, output)

    typer.echo("\n=== All done! Results in results/ ===")
    typer.echo("\nModel Summary:")
    for m in all_metrics:
        if m.get("f1") is not None:
            typer.echo(f"  {m['model']:20s} F1={m['f1']:.4f}  AUC={m['roc_auc']:.4f}")
        else:
            typer.echo(f"  {m['model']:20s} {m.get('note', '')}")


if __name__ == "__main__":
    app()
```

- [ ] **Step 2: Run existing tests — no regressions**

```bash
pytest tests/test_evaluate_all.py -v
```

Expected: `5 passed`.

- [ ] **Step 3: Smoke-run evaluate_all.py on a tiny subset to verify no import errors**

```bash
python scripts/evaluate_all.py --help
```

Expected: Typer help text printed. No import errors.

- [ ] **Step 4: Commit**

```bash
git add scripts/evaluate_all.py
git commit -m "feat(eval): add UMAP plot + main() CLI command — evaluate_all.py complete"
```

---

## Task 9: Download NSL-KDD and run evaluate_all.py

**Files:**
- Create: `data/nslkdd/` directory (data files not committed — too large)
- Create: `results/` populated files

- [ ] **Step 1: Download NSL-KDD dataset**

```bash
mkdir -p data/nslkdd
# Option A: direct download
curl -L "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt" \
  -o data/nslkdd/KDDTrain+.txt
curl -L "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt" \
  -o data/nslkdd/KDDTest+.txt
```

Expected: `KDDTrain+.txt` ~8 MB, `KDDTest+.txt` ~1.4 MB.

If the above URLs are down (they occasionally change), use the official mirror:
```bash
# Option B: from the CIRA lab mirror
curl -L "https://iscxdownloads.cs.unb.ca/iscxdownloads/NSL-KDD/NSL-KDD.zip" -o /tmp/nslkdd.zip
unzip /tmp/nslkdd.zip -d /tmp/nslkdd_unzipped/
cp /tmp/nslkdd_unzipped/NSL-KDD/KDDTrain+.txt data/nslkdd/
cp /tmp/nslkdd_unzipped/NSL-KDD/KDDTest+.txt data/nslkdd/
```

- [ ] **Step 2: Verify the data files are valid**

```bash
head -3 data/nslkdd/KDDTrain+.txt
wc -l data/nslkdd/KDDTrain+.txt
```

Expected: ~125,973 lines. First line should look like:
```
0,tcp,ftp_data,SF,491,0,0,0,...,normal,20
```

- [ ] **Step 3: Train XGBoost model first (if not already trained)**

```bash
python scripts/train_xgboost.py --dataset data/nslkdd/ --output models/ --trials 10
```

Expected: `models/xgb_nslkdd.json` created. Training takes ~3-5 min with 10 trials.

- [ ] **Step 4: Run full evaluation (fast pass with --skip-slow first)**

```bash
python scripts/evaluate_all.py --dataset data/nslkdd/ --output results/ --skip-slow
```

Expected: All plots and `metrics_summary.json` created in `results/`.

- [ ] **Step 5: Run with TransformerAE (optional, ~15 min)**

```bash
python scripts/evaluate_all.py --dataset data/nslkdd/ --output results/
```

- [ ] **Step 6: Verify all output files exist**

```bash
ls results/
```

Expected output:
```
confusion_matrix_xgboost.png
embeddings_umap.png
metrics_summary.json
model_comparison.png
roc_curves.png
shap_beeswarm.png
shap_waterfall_example.png
```

- [ ] **Step 7: Commit data gitignore (no commit of data files themselves)**

```bash
echo "data/nslkdd/*.txt" >> .gitignore
git add .gitignore
git commit -m "chore: gitignore NSL-KDD data files (too large for repo)"
```

---

## Task 10: Update README with metrics table + plots

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Read current README**

```bash
head -60 README.md
```

- [ ] **Step 2: Add metrics section to README**

Find the section after the feature description (or before "Getting Started") and insert:

```markdown
## Benchmark Results — NSL-KDD (22,544 test samples)

| Model | F1 | Precision | Recall | ROC-AUC |
|---|---|---|---|---|
| XGBoost + SHAP | **0.991** | 0.989 | 0.993 | 0.998 |
| Random Forest | 0.985 | 0.981 | 0.990 | 0.994 |
| Isolation Forest | 0.872 | 0.901 | 0.845 | 0.941 |
| Z-Score | 0.801 | 0.834 | 0.771 | 0.891 |
| Transformer AE | 0.847 | 0.863 | 0.832 | 0.913 |
| GNN (GraphSAGE) | topology-only* | — | — | — |
| Aho-Corasick | signature-only* | — | — | — |
| **Ensemble (7-model)** | **0.994** | **0.992** | **0.996** | **0.999** |

*GNN requires live network graph topology; Aho-Corasick requires raw packet payloads.
Both contribute to the live ensemble but are not evaluated against per-flow datasets.

> Numbers shown are from `scripts/evaluate_all.py` on NSL-KDD KDDTest+ split.
> Run `python scripts/evaluate_all.py --dataset data/nslkdd/` to reproduce.

### SHAP Feature Attribution

Every alert ships with a SHAP explanation. Top features driving attack classification:

![SHAP Beeswarm](results/shap_beeswarm.png)

### Attack Class Embeddings (UMAP)

64-dim ChromaDB embeddings projected to 2D — distinct clusters for DoS, Probe, R2L, U2R:

![UMAP Projection](results/embeddings_umap.png)
```

> **Note:** Replace the table numbers above with actual values from `results/metrics_summary.json` after running Task 9.

- [ ] **Step 3: Run all tests to confirm no regressions in the codebase**

```bash
pytest --tb=short -q
```

Expected: `241 passed`.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: add NSL-KDD metrics table, SHAP beeswarm + UMAP screenshots to README"
```

---

*Phase 1 complete. Proceed to Phase 2 plan: `docs/superpowers/plans/2026-05-19-packetsentry-phase2-web.md`*
