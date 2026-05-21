"""Train all 7 PacketSentry ML models on the CICIDS-2017 dataset.

============================================================
Dataset Download
============================================================
CICIDS-2017 is publicly available from the Canadian Institute for
Cybersecurity:

    https://www.unb.ca/cic/datasets/ids-2017.html

Direct CSV download (GeneratedLabelledFlows.zip, ~8 GB):
    http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/CIC-IDS-2017/CSVs/

============================================================
Expected Directory Structure
============================================================
After extracting the zip, pass the directory containing the CSV
files to --data. The script accepts any subset of the files:

    data/cicids2017/
        Monday-WorkingHours.pcap_ISCX.csv
        Tuesday-WorkingHours.pcap_ISCX.csv
        Wednesday-workingHours.pcap_ISCX.csv
        Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
        Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
        Friday-WorkingHours-Morning.pcap_ISCX.csv
        Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
        Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv

============================================================
Estimated Runtime (modern 8-core machine, full dataset ~2.8M rows)
============================================================
  Data loading + cleaning  :  ~2 min
  SMOTE oversampling       :  ~5 min
  Optuna / XGBoost (50 tr) :  ~25 min
  Random Forest (CV)       :  ~10 min
  IsolationForest fit      :  ~1 min
  ZScore fitting           :  <1 min
  Preprocessor + saves     :  <1 min
  ---------------------------------
  Total                    :  ~45 min

============================================================
Outputs (mirroring paths that DetectionPipeline expects)
============================================================
    models/xgb_nslkdd.json        XGBoost model (native xgb format)
    models/xgb_metadata.json      Training metrics + hyperparams
    models/rf_nslkdd.pkl          RandomForestClassifier (joblib)
    models/scaler.pkl             StandardScaler used by RF
    models/isolation_forest.pkl   IsolationForestDetector state
    models/zscore.pkl             ZScoreDetector state
    models/preprocessor.pkl       FeaturePreprocessor (StandardScaler)

Usage::

    python scripts/train_cicids2017.py --data data/cicids2017/ --output models/
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import optuna
import pandas as pd
import typer
import xgboost as xgb
from imblearn.over_sampling import SMOTE
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    f1_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)
optuna.logging.set_verbosity(optuna.logging.WARNING)

app = typer.Typer(help="Train PacketSentry ML models on CICIDS-2017 dataset.")

# ---------------------------------------------------------------------------
# CICIDS-2017 feature mapping
#
# The CICIDS-2017 CSVs expose 78 flow-level features. PacketSentry's internal
# feature vector (FlowFeatures.to_vector()) has 23 fields designed to mirror
# a subset of those features. We select the CICIDS columns whose semantics
# most closely match each PacketSentry feature and rename them for clarity.
#
# Mapping: CICIDS-2017 column  →  PacketSentry FlowFeatures field
# ----------------------------------------------------------------
# Flow Duration               → duration
# Protocol                    → protocol_type  (0=TCP,1=UDP,2=ICMP,3=other)
# Total Length of Fwd Packets → src_bytes
# Total Length of Bwd Packets → dst_bytes
# Fwd Flag SYN (proxy: SYN flag count — not directly in CICIDS; we derive it
#                             from SYN flag rate × total packets)
# ACK Flag Count              → flag_ack
# FIN Flag Count              → flag_fin
# RST Flag Count              → flag_rst
# PSH Flag Count              → flag_psh
# Total Fwd Packets + Bwd     → packet_count
# Average Packet Size         → avg_packet_size
# Flow Bytes/s                → bytes_per_second
# Flow Packets/s              → packets_per_second
# Fwd Header Length (proxy for connection behaviour — approximation)
#   CICIDS does not have exact NSL-KDD "count/srv_count" features.
#   We use the closest available numeric columns as proxies.
# Bwd Header Length           → dst_host_count (proxy)
# Fwd IAT Mean                → srv_count (proxy — inter-arrival time)
# Bwd IAT Mean                → dst_host_srv_count (proxy)
# SYN Flag Count / Total Pkts → serror_rate
# RST Flag Count / Total Pkts → rerror_rate
# Same Service Rate (derived) → same_srv_rate (set to 0.0 — not in CICIDS)
# Diff Service Rate (derived) → diff_srv_rate (set to 0.0 — not in CICIDS)
# Source Port                 → src_port
# Destination Port            → dst_port
# ---------------------------------------------------------------------------

# CICIDS-2017 column names vary slightly across files (whitespace, case).
# We normalise by stripping and lower-casing. These are the normalised names
# we expect after that step (values are stripped+lowercased CICIDS col names).
_CICIDS_TO_PS: dict[str, str] = {
    "flow duration":                "duration",
    "protocol":                     "protocol_type",
    "total length of fwd packets":  "src_bytes",
    "total length of bwd packets":  "dst_bytes",
    "ack flag count":               "flag_ack",
    "fin flag count":               "flag_fin",
    "rst flag count":               "flag_rst",
    "psh flag count":               "flag_psh",
    "total fwd packets":            "fwd_packets",   # intermediate
    "total backward packets":       "bwd_packets",   # intermediate
    "average packet size":          "avg_packet_size",
    "flow bytes/s":                 "bytes_per_second",
    "flow packets/s":               "packets_per_second",
    "fwd header length":            "count",          # proxy
    "bwd header length":            "srv_count",      # proxy
    "fwd iat mean":                 "dst_host_count", # proxy
    "bwd iat mean":                 "dst_host_srv_count",  # proxy
    "syn flag count":               "syn_flag_count",  # intermediate
    "source port":                  "src_port",
    "destination port":             "dst_port",
    "label":                        "label",
}

# Final 23 feature column names — must match FlowFeatures.to_vector() order
_FEATURE_NAMES: list[str] = [
    "duration", "protocol_type", "src_bytes", "dst_bytes",
    "flag_syn", "flag_ack", "flag_fin", "flag_rst", "flag_psh",
    "packet_count", "avg_packet_size", "bytes_per_second", "packets_per_second",
    "count", "srv_count", "dst_host_count", "dst_host_srv_count",
    "serror_rate", "rerror_rate", "same_srv_rate", "diff_srv_rate",
    "src_port", "dst_port",
]

# Labels that map to "attack" (binary 1). Everything else → 0 (BENIGN).
_ATTACK_LABELS: set[str] = {
    "dos hulk", "dos goldeneye", "dos slowloris", "dos slowhttptest",
    "web attack – brute force", "web attack – xss",
    "web attack – sql injection", "infiltration", "bot",
    "portscan", "ddos", "heartbleed", "ftp-patator", "ssh-patator",
}


# ---------------------------------------------------------------------------
# Data loading and cleaning
# ---------------------------------------------------------------------------

def load_and_clean(data_dir: Path) -> pd.DataFrame:
    """Load all CICIDS-2017 CSV files from *data_dir* and return a clean DataFrame.

    Steps:
      1. Glob all ``*.csv`` files in the directory.
      2. Concatenate into a single DataFrame.
      3. Strip leading/trailing whitespace from column names.
      4. Replace Infinity values with NaN, then fill NaN with 0.
      5. Drop exact duplicate rows.

    Args:
        data_dir: Directory containing CICIDS-2017 CSV files.

    Returns:
        Cleaned DataFrame with original CICIDS column names.
    """
    csv_files = sorted(data_dir.glob("*.csv"))
    if not csv_files:
        typer.echo(f"No CSV files found in {data_dir}", err=True)
        raise typer.Exit(1)

    typer.echo(f"   Found {len(csv_files)} CSV file(s): "
               + ", ".join(f.name for f in csv_files))

    parts: list[pd.DataFrame] = []
    for f in csv_files:
        typer.echo(f"   Loading {f.name}...")
        df = pd.read_csv(f, low_memory=False)
        parts.append(df)

    combined = pd.concat(parts, ignore_index=True)
    typer.echo(f"   Combined shape: {combined.shape}")

    # Normalise column names (strip whitespace; keep original case for label)
    combined.columns = combined.columns.str.strip()

    # Replace inf/-inf with NaN, then fill NaN → 0
    combined.replace([np.inf, -np.inf], np.nan, inplace=True)
    combined.fillna(0, inplace=True)

    # Drop duplicate rows to remove any accidental data duplication
    before = len(combined)
    combined.drop_duplicates(inplace=True)
    after = len(combined)
    typer.echo(f"   Dropped {before - after:,} duplicate rows.")

    return combined


def extract_features_and_labels(
    df: pd.DataFrame,
) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """Map CICIDS-2017 columns to PacketSentry's 23-feature vector.

    Applies the _CICIDS_TO_PS mapping, derives composite features
    (packet_count, flag_syn, error rates), and returns a numpy matrix
    aligned with FlowFeatures.to_vector() order.

    Args:
        df: Cleaned CICIDS-2017 DataFrame (column names stripped).

    Returns:
        Tuple of (X, y, feature_names) where:
          - X: float32 array of shape (n_samples, 23)
          - y: int array of shape (n_samples,) — 0=benign, 1=attack
          - feature_names: list of 23 feature names
    """
    # Normalise column names for lookup (lower + strip)
    df_norm = df.copy()
    df_norm.columns = [c.strip().lower() for c in df_norm.columns]

    # Find the label column (normalised)
    label_col_norm = "label"
    if label_col_norm not in df_norm.columns:
        raise ValueError(
            f"Label column 'label' not found. Available columns: "
            f"{list(df_norm.columns[:10])}"
        )

    # Build binary label vector: 0=BENIGN, 1=attack
    raw_labels = df_norm[label_col_norm].astype(str).str.strip().str.lower()
    y = (raw_labels != "benign").astype(np.int32).values

    # -----------------------------------------------------------------------
    # Feature extraction: map each PacketSentry feature to a CICIDS column
    # -----------------------------------------------------------------------
    available = set(df_norm.columns)

    def col(name: str, default: float = 0.0) -> np.ndarray:
        """Return column values if present, else a constant array."""
        if name in available:
            return pd.to_numeric(df_norm[name], errors="coerce").fillna(0).values.astype(np.float32)
        logger.warning("CICIDS column '%s' not found — using %.1f", name, default)
        return np.full(len(df_norm), default, dtype=np.float32)

    # Packet counts — needed for derived features
    fwd_pkts = col("total fwd packets")
    bwd_pkts = col("total backward packets")
    packet_count = fwd_pkts + bwd_pkts
    packet_count = np.maximum(packet_count, 1.0)  # avoid /0

    # SYN flag count — used to derive flag_syn and serror_rate
    syn_count = col("syn flag count")

    # Error rates: fraction of SYN and RST flags over total packets
    rst_count = col("rst flag count")
    serror_rate = np.clip(syn_count / packet_count, 0.0, 1.0)
    rerror_rate = np.clip(rst_count / packet_count, 0.0, 1.0)

    # Assemble the 23-column matrix in FlowFeatures.to_vector() order
    X = np.column_stack([
        col("flow duration"),               # duration
        col("protocol"),                    # protocol_type
        col("total length of fwd packets"), # src_bytes
        col("total length of bwd packets"), # dst_bytes
        syn_count,                          # flag_syn
        col("ack flag count"),              # flag_ack
        col("fin flag count"),              # flag_fin
        col("rst flag count"),              # flag_rst
        col("psh flag count"),              # flag_psh
        packet_count,                       # packet_count
        col("average packet size"),         # avg_packet_size
        col("flow bytes/s"),                # bytes_per_second
        col("flow packets/s"),              # packets_per_second
        col("fwd header length"),           # count (proxy)
        col("bwd header length"),           # srv_count (proxy)
        col("fwd iat mean"),                # dst_host_count (proxy)
        col("bwd iat mean"),                # dst_host_srv_count (proxy)
        serror_rate,                        # serror_rate
        rerror_rate,                        # rerror_rate
        np.zeros(len(df_norm), dtype=np.float32),  # same_srv_rate (not in CICIDS)
        np.zeros(len(df_norm), dtype=np.float32),  # diff_srv_rate (not in CICIDS)
        col("source port"),                 # src_port
        col("destination port"),            # dst_port
    ]).astype(np.float32)

    # Final sanitisation — clear any remaining NaN/inf introduced by coerce
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    return X, y, _FEATURE_NAMES


# ---------------------------------------------------------------------------
# XGBoost training (Optuna + SMOTE, mirrors train_xgboost.py)
# ---------------------------------------------------------------------------

def train_xgboost(
    X_resampled: np.ndarray,
    y_resampled: np.ndarray,
    output_dir: Path,
    feature_names: list[str],
    n_trials: int = 50,
    cv_folds: int = 5,
    seed: int = 42,
) -> dict:
    """Train XGBoost with Optuna hyperparameter search and save to disk.

    Uses the same Optuna + StratifiedKFold setup as train_xgboost.py so
    that the saved model is compatible with XGBoostDetector (which loads
    ``models/xgb_nslkdd.json``).

    Args:
        X_resampled: SMOTE-balanced feature matrix.
        y_resampled: SMOTE-balanced labels.
        output_dir: Directory to write model files.
        feature_names: List of 23 feature names for metadata.
        n_trials: Number of Optuna trials.
        cv_folds: Number of cross-validation folds.
        seed: Random seed for reproducibility.

    Returns:
        Dict of training metrics (roc_auc, f1, best params, etc.).
    """
    typer.echo(f"   Running {n_trials} Optuna trials with {cv_folds}-fold CV...")

    def objective(trial: optuna.Trial) -> float:
        """Optuna objective: cross-validated ROC-AUC on resampled data."""
        from xgboost import XGBClassifier
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
        model = XGBClassifier(**params)
        skf = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=seed)
        scores = cross_val_score(
            model, X_resampled, y_resampled,
            cv=skf, scoring="roc_auc", n_jobs=-1,
        )
        return float(scores.mean())

    study = optuna.create_study(
        direction="maximize",
        sampler=optuna.samplers.TPESampler(seed=seed),
    )
    study.optimize(objective, n_trials=n_trials, show_progress_bar=True)

    best_params = study.best_params
    best_auc = study.best_value
    typer.echo(f"   Best ROC-AUC (Optuna): {best_auc:.4f}")

    # Train final model on the full resampled dataset
    t0 = time.time()
    final_params = {
        "objective":   "binary:logistic",
        "eval_metric": "auc",
        "seed":        seed,
        "verbosity":   0,
        **best_params,
    }
    n_estimators = final_params.pop("n_estimators", 300)
    dtrain = xgb.DMatrix(X_resampled, label=y_resampled,
                         feature_names=feature_names)
    final_model = xgb.train(final_params, dtrain, num_boost_round=n_estimators)
    train_time = time.time() - t0

    # CV F1 on resampled data (approximate — same split as Optuna)
    from xgboost import XGBClassifier
    skf = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=seed)
    cv_f1 = cross_val_score(
        XGBClassifier(**{**best_params, "seed": seed, "verbosity": 0}),
        X_resampled, y_resampled,
        cv=skf, scoring="f1", n_jobs=-1,
    ).mean()
    typer.echo(f"   CV F1: {cv_f1:.4f}  |  Train time: {train_time:.1f}s")

    # Save model — XGBoostDetector loads "models/xgb_nslkdd.json"
    model_path = output_dir / "xgb_nslkdd.json"
    final_model.save_model(str(model_path))
    typer.echo(f"   Saved: {model_path}")

    metadata = {
        "model_file":         str(model_path),
        "dataset":            "CICIDS-2017",
        "n_features":         len(feature_names),
        "feature_names":      feature_names,
        "n_training_samples": int(len(X_resampled)),
        "best_optuna_auc":    round(best_auc, 4),
        "cv_f1":              round(cv_f1, 4),
        "best_params":        best_params,
        "train_time_sec":     round(train_time, 1),
        "seed":               seed,
    }
    meta_path = output_dir / "xgb_metadata.json"
    meta_path.write_text(json.dumps(metadata, indent=2))
    typer.echo(f"   Metadata saved: {meta_path}")

    return metadata


# ---------------------------------------------------------------------------
# Random Forest training
# ---------------------------------------------------------------------------

def train_random_forest(
    X_resampled: np.ndarray,
    y_resampled: np.ndarray,
    output_dir: Path,
    cv_folds: int = 5,
    seed: int = 42,
) -> float:
    """Train a RandomForestClassifier and save model + scaler to disk.

    RandomForestDetector loads ``models/rf_nslkdd.pkl`` and
    ``models/scaler.pkl``. We train a StandardScaler on the resampled
    data and persist both so the detector gets consistent feature scaling.

    Args:
        X_resampled: SMOTE-balanced feature matrix.
        y_resampled: SMOTE-balanced labels.
        output_dir: Directory to write model files.
        cv_folds: Cross-validation folds for F1 reporting.
        seed: Random seed.

    Returns:
        Mean cross-validated F1 score.
    """
    # Fit the scaler on the training data (same scaler RandomForestDetector will use)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_resampled)

    # Cross-validated F1 for reporting
    skf = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=seed)
    rf_cv = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_split=2,
        class_weight="balanced",
        random_state=seed,
        n_jobs=-1,
    )
    cv_f1 = cross_val_score(
        rf_cv, X_scaled, y_resampled, cv=skf, scoring="f1", n_jobs=-1,
    ).mean()
    typer.echo(f"   CV F1: {cv_f1:.4f}")

    # Train final model on full resampled dataset
    t0 = time.time()
    rf_final = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_split=2,
        class_weight="balanced",
        random_state=seed,
        n_jobs=-1,
    )
    rf_final.fit(X_scaled, y_resampled)
    typer.echo(f"   Train time: {time.time() - t0:.1f}s")

    # Save — RandomForestDetector loads models/rf_nslkdd.pkl + models/scaler.pkl
    rf_path = output_dir / "rf_nslkdd.pkl"
    scaler_path = output_dir / "scaler.pkl"
    joblib.dump(rf_final, rf_path)
    joblib.dump(scaler, scaler_path)
    typer.echo(f"   Saved: {rf_path}  |  {scaler_path}")

    return float(cv_f1)


# ---------------------------------------------------------------------------
# IsolationForest training
# ---------------------------------------------------------------------------

def train_isolation_forest(
    X_benign: np.ndarray,
    output_dir: Path,
    contamination: float = 0.01,
    seed: int = 42,
) -> None:
    """Fit IsolationForest on benign-only traffic and save detector state.

    IsolationForestDetector is unsupervised — it models "normal" traffic
    and flags deviations. We train exclusively on BENIGN rows so the
    learned baseline is uncontaminated by attack traffic.

    The raw sklearn model is saved so DetectionPipeline can load it via
    joblib and inject it into IsolationForestDetector._model directly.

    Args:
        X_benign: Feature matrix containing BENIGN rows only.
        output_dir: Directory to write the saved state.
        contamination: Expected anomaly fraction (low — benign-only data).
        seed: Random seed.
    """
    t0 = time.time()
    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=seed,
        n_jobs=-1,
    )
    model.fit(X_benign)
    typer.echo(f"   Fit on {len(X_benign):,} benign rows in {time.time()-t0:.1f}s")

    # Persist the full IsolationForestDetector-compatible state dict so that
    # DetectionPipeline can restore it with:
    #   state = joblib.load("models/isolation_forest.pkl")
    #   detector._model = state["model"]
    #   detector._is_trained = state["is_trained"]
    state = {
        "model":      model,
        "is_trained": True,
        "n_training": int(len(X_benign)),
        "contamination": contamination,
    }
    out_path = output_dir / "isolation_forest.pkl"
    joblib.dump(state, out_path)
    typer.echo(f"   Saved: {out_path}")


# ---------------------------------------------------------------------------
# ZScore fitting
# ---------------------------------------------------------------------------

def fit_zscore(
    X_benign: np.ndarray,
    output_dir: Path,
) -> None:
    """Fit ZScoreDetector statistics on benign-only traffic.

    ZScoreDetector uses Welford's online algorithm. We replay each benign
    row through the running-statistics update (same update path as
    ZScoreDetector.score()) to pre-warm the mean/variance baseline.

    The resulting state dict is saved so DetectionPipeline can restore it:
        state = joblib.load("models/zscore.pkl")
        detector._n    = state["n"]
        detector._mean = state["mean"]
        detector._m2   = state["m2"]

    Args:
        X_benign: Feature matrix containing BENIGN rows only.
        output_dir: Directory to write the saved state.
    """
    n_features = X_benign.shape[1]
    n: int = 0
    mean = np.zeros(n_features, dtype=np.float64)
    m2 = np.zeros(n_features, dtype=np.float64)

    # Welford's online update — identical to ZScoreDetector.score()
    for row in X_benign:
        vec = row.astype(np.float64)
        n += 1
        delta = vec - mean
        mean += delta / n
        delta2 = vec - mean
        m2 += delta * delta2

    typer.echo(f"   Updated Welford stats over {n:,} benign rows.")

    state = {
        "n":    n,
        "mean": mean,
        "m2":   m2,
        "n_features": n_features,
    }
    out_path = output_dir / "zscore.pkl"
    joblib.dump(state, out_path)
    typer.echo(f"   Saved: {out_path}")


# ---------------------------------------------------------------------------
# FeaturePreprocessor persistence
# ---------------------------------------------------------------------------

def fit_and_save_preprocessor(
    X: np.ndarray,
    output_dir: Path,
) -> None:
    """Fit a StandardScaler-backed FeaturePreprocessor on the training data.

    Saves the state to ``models/preprocessor.pkl`` using the same format
    as FeaturePreprocessor.save() so DetectionPipeline.load() works:
        {"scaler": StandardScaler, "is_fitted": True}

    Args:
        X: Full (unbalanced) feature matrix — fit on original distribution.
        output_dir: Directory to write the saved state.
    """
    scaler = StandardScaler()
    scaler.fit(X)

    out_path = output_dir / "preprocessor.pkl"
    joblib.dump({"scaler": scaler, "is_fitted": True}, out_path)
    typer.echo(f"   Saved: {out_path}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

@app.command()
def train(
    data: Path = typer.Option(
        ...,
        "--data",
        help="Directory containing CICIDS-2017 CSV files.",
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
    ),
    output: Path = typer.Option(
        Path("models"),
        "--output",
        help="Output directory for trained model files (default: models/).",
    ),
    n_trials: int = typer.Option(50, "--trials", help="Optuna trials for XGBoost."),
    cv_folds: int = typer.Option(5, "--cv-folds", help="Cross-validation folds."),
    seed: int = typer.Option(42, "--seed", help="Random seed."),
    sample: Optional[int] = typer.Option(
        None,
        "--sample",
        help="Subsample N rows for quick testing (default: use all rows).",
    ),
) -> None:
    """Retrain all PacketSentry ML models on the CICIDS-2017 dataset.

    Loads, cleans, and maps CICIDS-2017 CSV features to PacketSentry's
    23-feature internal representation, then trains XGBoost (Optuna),
    RandomForest, IsolationForest, and ZScore detectors.
    """
    overall_start = time.time()
    output.mkdir(parents=True, exist_ok=True)

    # -----------------------------------------------------------------------
    # STEP 1 — Load and clean all CSVs
    # -----------------------------------------------------------------------
    typer.echo("\n[1/7] Loading CICIDS-2017 CSVs...")
    df = load_and_clean(data)

    if sample is not None:
        typer.echo(f"   Subsampling to {sample:,} rows for testing...")
        df = df.sample(n=min(sample, len(df)), random_state=seed).reset_index(drop=True)

    typer.echo(f"   Final dataset: {len(df):,} rows x {df.shape[1]} columns")

    # -----------------------------------------------------------------------
    # STEP 2 — Extract features and labels
    # -----------------------------------------------------------------------
    typer.echo("\n[2/7] Extracting 23-feature vectors from CICIDS columns...")
    X, y, feature_names = extract_features_and_labels(df)

    n_total = len(y)
    n_benign = int((y == 0).sum())
    n_attack = int((y == 1).sum())
    pct_attack = 100.0 * n_attack / max(n_total, 1)

    typer.echo(f"   Total rows  : {n_total:,}")
    typer.echo(f"   Benign      : {n_benign:,} ({100-pct_attack:.1f}%)")
    typer.echo(f"   Attack      : {n_attack:,} ({pct_attack:.1f}%)")

    # Benign-only slice for unsupervised models
    X_benign = X[y == 0]

    # -----------------------------------------------------------------------
    # STEP 3 — Fit FeaturePreprocessor (StandardScaler) on full dataset
    # -----------------------------------------------------------------------
    typer.echo("\n[3/7] Fitting FeaturePreprocessor (StandardScaler)...")
    fit_and_save_preprocessor(X, output)

    # -----------------------------------------------------------------------
    # STEP 4 — SMOTE to balance classes for supervised models
    # -----------------------------------------------------------------------
    typer.echo("\n[4/7] Applying SMOTE for class balancing...")
    smote = SMOTE(random_state=seed, k_neighbors=5)
    X_resampled, y_resampled = smote.fit_resample(X, y)
    typer.echo(
        f"   After SMOTE: {len(X_resampled):,} rows. "
        f"Benign: {(y_resampled==0).sum():,}  Attack: {(y_resampled==1).sum():,}"
    )

    # -----------------------------------------------------------------------
    # STEP 5 — XGBoost (Optuna + CV)
    # -----------------------------------------------------------------------
    typer.echo(f"\n[5/7] Training XGBoost ({n_trials} Optuna trials)...")
    xgb_metrics = train_xgboost(
        X_resampled, y_resampled, output, feature_names,
        n_trials=n_trials, cv_folds=cv_folds, seed=seed,
    )

    # -----------------------------------------------------------------------
    # STEP 6 — RandomForest
    # -----------------------------------------------------------------------
    typer.echo("\n[6/7] Training RandomForest...")
    rf_cv_f1 = train_random_forest(
        X_resampled, y_resampled, output, cv_folds=cv_folds, seed=seed,
    )

    # -----------------------------------------------------------------------
    # STEP 7 — IsolationForest + ZScore (benign-only)
    # -----------------------------------------------------------------------
    typer.echo(f"\n[7/7] Fitting IsolationForest on {len(X_benign):,} benign rows...")
    train_isolation_forest(X_benign, output, seed=seed)

    typer.echo(f"      Fitting ZScore Welford stats on {len(X_benign):,} benign rows...")
    fit_zscore(X_benign, output)

    # -----------------------------------------------------------------------
    # Training summary
    # -----------------------------------------------------------------------
    elapsed = time.time() - overall_start
    typer.echo("\n" + "=" * 60)
    typer.echo("TRAINING SUMMARY")
    typer.echo("=" * 60)
    typer.echo(f"  Dataset         : CICIDS-2017  ({data})")
    typer.echo(f"  Total rows      : {n_total:,}")
    typer.echo(f"  Class balance   : {n_benign:,} benign / {n_attack:,} attack ({pct_attack:.1f}% attack)")
    typer.echo(f"  After SMOTE     : {len(X_resampled):,} rows (balanced)")
    typer.echo(f"  XGBoost ROC-AUC : {xgb_metrics['best_optuna_auc']:.4f}")
    typer.echo(f"  XGBoost CV F1   : {xgb_metrics['cv_f1']:.4f}")
    typer.echo(f"  RandomForest F1 : {rf_cv_f1:.4f}")
    typer.echo(f"  IsolationForest : trained on {len(X_benign):,} benign flows")
    typer.echo(f"  ZScore          : Welford stats over {len(X_benign):,} benign flows")
    typer.echo(f"  Total time      : {elapsed/60:.1f} min")
    typer.echo("=" * 60)
    typer.echo("\nOutput files:")
    for name in [
        "xgb_nslkdd.json", "xgb_metadata.json",
        "rf_nslkdd.pkl", "scaler.pkl",
        "isolation_forest.pkl", "zscore.pkl",
        "preprocessor.pkl",
    ]:
        p = output / name
        status = "OK" if p.exists() else "MISSING"
        typer.echo(f"  [{status}] {p}")

    typer.echo(
        "\nNext step: run PacketSentry — all detectors load their models "
        "automatically from the output directory."
    )


if __name__ == "__main__":
    app()
