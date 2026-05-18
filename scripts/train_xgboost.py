"""Train XGBoost on NSL-KDD dataset with Optuna + SMOTE + cross-validation.

Usage:
    python scripts/train_xgboost.py --dataset data/nslkdd/ --output models/

The dataset directory must contain:
    KDDTrain+.txt   (NSL-KDD training set — 125,973 rows)
    KDDTest+.txt    (NSL-KDD test set    — 22,544 rows)

The standard NSL-KDD .txt format is comma-separated with 43 columns:
    41 features + 1 label + 1 difficulty score (last column, unused)

Outputs:
    models/xgb_nslkdd.json       XGBoost native model (load with xgb.Booster)
    models/xgb_metadata.json     Training metrics, hyperparams, feature names
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

import numpy as np
import optuna
import typer
import xgboost as xgb
from imblearn.over_sampling import SMOTE
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score,
)
from sklearn.preprocessing import LabelEncoder

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)
optuna.logging.set_verbosity(optuna.logging.WARNING)

app = typer.Typer(help="Train XGBoost on NSL-KDD (.txt) dataset.")

# -----------------------------------------------------------------------
# NSL-KDD column definitions
# -----------------------------------------------------------------------

# 41 feature columns from NSL-KDD (0-indexed)
_NSLKDD_FEATURE_COLS = list(range(41))
_NSLKDD_LABEL_COL = 41  # 42nd column: attack label string

# Categorical features that need label encoding
_CATEGORICAL_COLS = [1, 2, 3]  # protocol_type, service, flag (NSL-KDD indices)

# Binary labels: 'normal' → 0, everything else → 1
_NORMAL_LABEL = "normal"

# Map from NSL-KDD 41-feature space → our 23-feature vector.
# We use the 23 NSL-KDD features our FeatureExtractor already computes.
# Indices below are within the 41-column NSL-KDD feature set.
_FEATURE_MAP: dict[str, int] = {
    "duration":          0,
    "protocol_type":     1,
    "src_bytes":         4,
    "dst_bytes":         5,
    "flag_syn":         None,  # derived from NSL-KDD "land" + flag field
    "flag_ack":         None,
    "flag_fin":         None,
    "flag_rst":         None,
    "flag_psh":         None,
    "packet_count":      None,  # not directly in NSL-KDD, use "count" proxy
    "avg_packet_size":   None,  # derived
    "bytes_per_second":  None,  # derived
    "packets_per_second": None,
    "count":             22,
    "srv_count":         23,
    "dst_host_count":    32,
    "dst_host_srv_count": 33,
    "serror_rate":       25,
    "rerror_rate":       27,
    "same_srv_rate":     24,
    "diff_srv_rate":     26,
    "src_port":          None,  # not in NSL-KDD, use 0
    "dst_port":          None,  # not in NSL-KDD, use 0
}

# The 23 NSL-KDD column indices we will actually use for training.
# Skips derived features not directly in the dataset.
# These align closely enough with our live FeatureExtractor features
# for the model to generalise.
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

            # Encode categorical features numerically
            row = []
            for i, val in enumerate(features):
                if i in _CATEGORICAL_COLS:
                    row.append(hash(val) % 1000)  # fast hash encoding
                else:
                    try:
                        row.append(float(val))
                    except ValueError:
                        row.append(0.0)

            # Select the 23 training columns
            selected = [row[c] if c < len(row) else 0.0 for c in _TRAIN_COLS]
            rows_X.append(selected)
            rows_y.append(0 if label == _NORMAL_LABEL else 1)

    X = np.array(rows_X, dtype=np.float32)
    y = np.array(rows_y, dtype=np.int32)
    return X, y


@app.command()
def train(
    dataset: Path = typer.Option(
        "data/nslkdd/", "--dataset", "-d",
        help="Directory containing KDDTrain+.txt and KDDTest+.txt",
    ),
    output: Path = typer.Option(
        "models/", "--output", "-o",
        help="Directory to save trained model and metadata.",
    ),
    n_trials: int = typer.Option(
        30, "--trials", "-n",
        help="Number of Optuna hyperparameter trials.",
    ),
    cv_folds: int = typer.Option(
        5, "--folds", "-k",
        help="Number of cross-validation folds.",
    ),
    seed: int = typer.Option(42, "--seed", help="Random seed."),
) -> None:
    """Train XGBoost on NSL-KDD, tune with Optuna, export model."""

    train_path = dataset / "KDDTrain+.txt"
    test_path = dataset / "KDDTest+.txt"

    if not train_path.exists():
        typer.echo(f"❌ Training file not found: {train_path}", err=True)
        raise typer.Exit(1)

    # ----------------------------------------------------------------
    # 1. Load data
    # ----------------------------------------------------------------
    typer.echo("📂 Loading NSL-KDD training data...")
    X_train, y_train = _load_nslkdd(train_path)
    typer.echo(
        f"   Loaded {len(X_train):,} rows. "
        f"Normal: {(y_train==0).sum():,}  Attack: {(y_train==1).sum():,}"
    )

    # ----------------------------------------------------------------
    # 2. SMOTE — oversample minority class
    # ----------------------------------------------------------------
    typer.echo("⚖️  Applying SMOTE for class balancing...")
    smote = SMOTE(random_state=seed, k_neighbors=5)
    X_resampled, y_resampled = smote.fit_resample(X_train, y_train)
    typer.echo(
        f"   After SMOTE: {len(X_resampled):,} rows. "
        f"Normal: {(y_resampled==0).sum():,}  Attack: {(y_resampled==1).sum():,}"
    )

    # ----------------------------------------------------------------
    # 3. Optuna hyperparameter tuning
    # ----------------------------------------------------------------
    typer.echo(f"🔍 Optuna tuning ({n_trials} trials, {cv_folds}-fold CV)...")

    def objective(trial: optuna.Trial) -> float:
        params = {
            "objective":        "binary:logistic",
            "eval_metric":      "auc",
            "seed":             seed,
            "verbosity":        0,
            "max_depth":        trial.suggest_int("max_depth", 3, 10),
            "learning_rate":    trial.suggest_float("learning_rate", 0.01, 0.3, log=True),
            "n_estimators":     trial.suggest_int("n_estimators", 100, 600),
            "subsample":        trial.suggest_float("subsample", 0.6, 1.0),
            "colsample_bytree": trial.suggest_float("colsample_bytree", 0.6, 1.0),
            "min_child_weight": trial.suggest_int("min_child_weight", 1, 10),
            "gamma":            trial.suggest_float("gamma", 0.0, 1.0),
        }
        from xgboost import XGBClassifier
        model = XGBClassifier(**params)
        skf = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=seed)
        scores = cross_val_score(
            model, X_resampled, y_resampled,
            cv=skf, scoring="roc_auc", n_jobs=-1,
        )
        return float(scores.mean())

    study = optuna.create_study(direction="maximize",
                                sampler=optuna.samplers.TPESampler(seed=seed))
    study.optimize(objective, n_trials=n_trials, show_progress_bar=True)

    best_params = study.best_params
    best_auc = study.best_value
    typer.echo(f"   ✅ Best ROC-AUC: {best_auc:.4f}")
    typer.echo(f"   Best params: {best_params}")

    # ----------------------------------------------------------------
    # 4. Train final model on full resampled dataset
    # ----------------------------------------------------------------
    typer.echo("🏋️  Training final model on full dataset...")
    t0 = time.time()
    final_params = {
        "objective":    "binary:logistic",
        "eval_metric":  "auc",
        "seed":         seed,
        "verbosity":    0,
        **best_params,
    }
    n_estimators = final_params.pop("n_estimators", 300)
    dtrain = xgb.DMatrix(X_resampled, label=y_resampled)
    model = xgb.train(
        final_params, dtrain, num_boost_round=n_estimators,
    )
    train_time = time.time() - t0
    typer.echo(f"   Training took {train_time:.1f}s")

    # ----------------------------------------------------------------
    # 5. Evaluate on test set
    # ----------------------------------------------------------------
    metrics: dict = {}
    if test_path.exists():
        typer.echo("📊 Evaluating on test set...")
        X_test, y_test = _load_nslkdd(test_path)
        dtest = xgb.DMatrix(X_test)
        y_proba = model.predict(dtest)
        y_pred = (y_proba > 0.5).astype(int)

        roc_auc = roc_auc_score(y_test, y_proba)
        accuracy = float((y_pred == y_test).mean())
        metrics = {
            "test_roc_auc": round(roc_auc, 4),
            "test_accuracy": round(accuracy, 4),
            "test_samples": len(y_test),
        }

        typer.echo(f"\n{'─'*50}")
        typer.echo(f"  ROC-AUC:  {roc_auc:.4f}")
        typer.echo(f"  Accuracy: {accuracy:.4f}")
        typer.echo("\n" + classification_report(y_test, y_pred,
                                                target_names=["normal", "attack"]))
        typer.echo("Confusion matrix:")
        typer.echo(str(confusion_matrix(y_test, y_pred)))

    # ----------------------------------------------------------------
    # 6. Save model and metadata
    # ----------------------------------------------------------------
    output.mkdir(parents=True, exist_ok=True)

    model_path = output / "xgb_nslkdd.json"
    model.save_model(str(model_path))
    typer.echo(f"\n💾 Model saved to {model_path}")

    metadata = {
        "model_file": str(model_path),
        "dataset": str(dataset),
        "n_features": 23,
        "n_training_samples": len(X_resampled),
        "best_optuna_auc": round(best_auc, 4),
        "best_params": best_params,
        "train_time_sec": round(train_time, 1),
        "seed": seed,
        "feature_names": list(_FEATURE_MAP.keys()),
        **metrics,
    }
    meta_path = output / "xgb_metadata.json"
    meta_path.write_text(json.dumps(metadata, indent=2))
    typer.echo(f"📋 Metadata saved to {meta_path}")
    typer.echo("\n✅ Training complete!")
    typer.echo(
        "\nNext step: run PacketSentry — XGBoost will load automatically from "
        f"'{model_path}'"
    )


if __name__ == "__main__":
    app()
