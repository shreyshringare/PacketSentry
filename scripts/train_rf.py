"""Train Random Forest baseline on NSL-KDD dataset.

Usage:
    python scripts/train_rf.py

Outputs:
    models/rf_nslkdd.pkl    Trained RandomForestClassifier
    models/scaler.pkl       StandardScaler fitted on training data
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.preprocessing import StandardScaler

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------
# NSL-KDD column definitions (same as train_xgboost.py)
# -----------------------------------------------------------------------
_CATEGORICAL_COLS = [1, 2, 3]
_NORMAL_LABEL = "normal"
_TRAIN_COLS = [0, 1, 4, 5, 22, 23, 24, 25, 26, 27, 32, 33, 34, 35, 36, 37,
               38, 39, 40, 2, 3, 6, 7]  # 23 columns


def _load_nslkdd(path: Path) -> tuple[np.ndarray, np.ndarray]:
    """Load NSL-KDD .txt file → (X, y) with binary labels."""
    rows_X, rows_y = [], []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(",")
            if len(parts) < 42:
                continue

            features = parts[:41]
            label = parts[41].strip().rstrip(".")

            row = []
            for i, val in enumerate(features):
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

    X = np.array(rows_X, dtype=np.float32)
    y = np.array(rows_y, dtype=np.int32)
    return X, y


def main() -> None:
    dataset = Path("data/nslkdd")
    output = Path("models")
    output.mkdir(exist_ok=True)

    train_path = dataset / "KDDTrain+.txt"
    test_path = dataset / "KDDTest+.txt"

    if not train_path.exists():
        logger.error("Training file not found: %s", train_path)
        raise SystemExit(1)

    logger.info("Loading NSL-KDD training data...")
    X_train, y_train = _load_nslkdd(train_path)
    logger.info(
        "Loaded %d rows. Normal: %d  Attack: %d",
        len(X_train), (y_train == 0).sum(), (y_train == 1).sum(),
    )

    logger.info("Fitting StandardScaler...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)

    logger.info("Training RandomForest (200 trees, n_jobs=-1)...")
    t0 = time.time()
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_split=5,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )
    rf.fit(X_train_scaled, y_train)
    elapsed = time.time() - t0
    logger.info("Training done in %.1fs", elapsed)

    # Evaluate on test set
    if test_path.exists():
        X_test, y_test = _load_nslkdd(test_path)
        X_test_scaled = scaler.transform(X_test)
        y_pred = rf.predict(X_test_scaled)
        y_prob = rf.predict_proba(X_test_scaled)[:, 1]
        auc = roc_auc_score(y_test, y_prob)
        logger.info("Test AUC: %.4f", auc)
        print(classification_report(y_test, y_pred, target_names=["normal", "attack"]))

    rf_path = output / "rf_nslkdd.pkl"
    scaler_path = output / "scaler.pkl"
    joblib.dump(rf, rf_path)
    joblib.dump(scaler, scaler_path)
    logger.info("Saved model → %s", rf_path)
    logger.info("Saved scaler → %s", scaler_path)


if __name__ == "__main__":
    main()
