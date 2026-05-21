#!/usr/bin/env python3
"""Evaluate all PacketSentry detectors on NSL-KDD dataset.

Usage:
    python scripts/evaluate_all.py run --dataset data/nslkdd/ --output results/

Outputs:
    results/metrics_summary.json
    results/model_comparison.png
    results/roc_curves.png
    results/confusion_matrix_xgboost.png
    results/shap_beeswarm.png
    results/shap_waterfall_example.png
    results/embeddings_umap.png
"""

from __future__ import annotations

import json
import logging
import sys
import types
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import typer
from sklearn.metrics import (
    auc,
    confusion_matrix as sk_cm,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

logger = logging.getLogger(__name__)
app = typer.Typer(help="Evaluate all PacketSentry models on NSL-KDD.")

# ── NSL-KDD column definitions ──────────────────────────────────────────────
_CATEGORICAL_COLS = {1, 2, 3}
_NORMAL_LABEL = "normal"
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
_ATTACK_CLASSES = {
    "normal": 0,
    "back": 1, "land": 1, "neptune": 1, "pod": 1, "smurf": 1, "teardrop": 1,
    "apache2": 1, "udpstorm": 1, "processtable": 1, "mailbomb": 1,
    "ipsweep": 2, "nmap": 2, "portsweep": 2, "satan": 2, "mscan": 2, "saint": 2,
    "ftp_write": 3, "guess_passwd": 3, "imap": 3, "multihop": 3, "phf": 3,
    "spy": 3, "warezclient": 3, "warezmaster": 3, "sendmail": 3, "named": 3,
    "snmpgetattack": 3, "snmpguess": 3, "xlock": 3, "xsnoop": 3, "httptunnel": 3,
    "buffer_overflow": 4, "loadmodule": 4, "perl": 4, "rootkit": 4,
    "ps": 4, "sqlattack": 4, "xterm": 4,
}
_MULTI_CLASS_NAMES = ["Normal", "DoS", "Probe", "R2L", "U2R"]
_N_FEATURES = 23


# ── T2: Data loading ─────────────────────────────────────────────────────────

def load_nslkdd(path: Path) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Load NSL-KDD .txt file → (X, y_binary, y_multi)."""
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
            rows_y_multi.append(_ATTACK_CLASSES.get(label, 1))
    X = np.array(rows_X, dtype=np.float32)
    y = np.array(rows_y, dtype=np.int32)
    y_multi = np.array(rows_y_multi, dtype=np.int32)
    return X, y, y_multi


def severity_from_confidence(conf: float) -> str:
    """Map confidence score → severity label."""
    if conf >= 0.80:
        return "CRITICAL"
    if conf >= 0.60:
        return "HIGH"
    if conf >= 0.40:
        return "MED"
    return "LOW"


# ── T3: Metrics + XGBoost ────────────────────────────────────────────────────

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
    """Evaluate XGBoost with 5-fold CV."""
    import xgboost as xgb
    from sklearn.model_selection import StratifiedKFold, cross_val_score
    from xgboost import XGBClassifier

    logger.info("Evaluating XGBoost (%d-fold CV)...", cv_folds)
    if model_path.exists():
        booster = xgb.Booster()
        booster.load_model(str(model_path))
        y_proba = booster.predict(xgb.DMatrix(X_test))
    else:
        logger.warning("No trained model at %s — training from scratch", model_path)
        clf = XGBClassifier(
            n_estimators=300, max_depth=6, learning_rate=0.1,
            objective="binary:logistic", seed=seed, verbosity=0,
        )
        clf.fit(X_train, y_train)
        y_proba = clf.predict_proba(X_test)[:, 1]

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


# ── T4: RF / IF / ZScore ─────────────────────────────────────────────────────

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
    X_normal = X_train[y_train == 0]
    iso = IsolationForest(n_estimators=200, contamination=0.1, random_state=seed, n_jobs=-1)
    iso.fit(X_normal)
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
    z = np.abs((X_test - mean) / std)
    raw_scores = z.max(axis=1)
    clip_val = np.percentile(raw_scores, 99)
    y_proba = np.clip(raw_scores / clip_val, 0.0, 1.0).astype(np.float32)
    y_pred = (y_proba > 0.5).astype(int)
    return compute_metrics("ZScore", y_test, y_pred, y_proba), y_proba


# ── T4b: GNN topology benchmark ─────────────────────────────────────────────

def eval_gnn(
    n_normal: int = 500,
    n_portscan: int = 50,
    n_ddos: int = 50,
    seed: int = 42,
) -> tuple[dict, np.ndarray, np.ndarray]:
    """Benchmark GNN topology detection on synthetic graph scenarios.

    NSL-KDD has no IP addresses, so this builds synthetic topology:
    - Normal: 500 flows distributed across many (src, dst) pairs
    - Port scan: 1 attacker → 50 different dst IPs (high out-degree)
    - DDoS: 50 sources → 1 victim (star topology)

    GNN autoencoder trained on normal graph, scored on attack flows.
    Returns binary classification metrics over the synthetic dataset.
    """
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from packetsentry.detection.gnn_detector import GNNDetector

    logger.info("Benchmarking GNN on synthetic topology (port-scan + DDoS)...")
    rng = np.random.default_rng(seed)
    gnn = GNNDetector()

    def _make_ff(feat_vec: np.ndarray) -> object:
        ff = types.SimpleNamespace()
        ff.to_vector = lambda: feat_vec.astype(np.float32)
        for i, name in enumerate(_FEATURE_NAMES):
            setattr(ff, name, float(feat_vec[i]) if i < len(feat_vec) else 0.0)
        return ff

    # Normal: 500 flows across diverse (src, dst) pairs
    normal_flows = []
    for _ in range(n_normal):
        src = f"10.0.{rng.integers(0, 100)}.{rng.integers(1, 255)}"
        dst = f"10.1.{rng.integers(0, 100)}.{rng.integers(1, 255)}"
        feat = rng.uniform(0, 1, size=_N_FEATURES).astype(np.float32)
        normal_flows.append((src, dst, feat))

    # Port scan: 1 attacker → 50 different hosts (high out-degree)
    attacker = "192.168.1.100"
    scan_flows = [
        (attacker, f"10.0.0.{i + 1}", rng.uniform(0, 0.1, size=_N_FEATURES).astype(np.float32))
        for i in range(n_portscan)
    ]

    # DDoS: 50 sources → 1 victim (star topology)
    victim = "10.0.0.1"
    ddos_flows = [
        (f"172.16.{i}.1", victim, rng.uniform(0, 0.1, size=_N_FEATURES).astype(np.float32))
        for i in range(n_ddos)
    ]

    # Train GNN on normal flows — add to graph and warm up
    for src, dst, feat in normal_flows:
        try:
            gnn._graph.add_flow(src, dst, feat)
        except Exception:
            pass
    normal_scores = []
    for _, _, feat in normal_flows:
        try:
            normal_scores.append(float(gnn.score(_make_ff(feat))))
        except Exception as exc:
            logger.debug("GNN score failed for normal flow: %s", exc)
            normal_scores.append(0.1)

    # Score attack flows
    attack_scores = []
    for src, dst, feat in scan_flows + ddos_flows:
        try:
            gnn._graph.add_flow(src, dst, feat)
            attack_scores.append(float(gnn.score(_make_ff(feat))))
        except Exception as exc:
            logger.debug("GNN score failed for attack flow: %s", exc)
            attack_scores.append(0.1)

    all_scores = np.array(normal_scores + attack_scores, dtype=np.float32)
    y_true = np.array([0] * len(normal_scores) + [1] * len(attack_scores), dtype=np.int32)
    y_proba = np.clip(all_scores, 0.0, 1.0)
    y_pred = (y_proba > 0.5).astype(int)

    metrics = compute_metrics("GNN (GraphSAGE)", y_true, y_pred, y_proba)
    metrics["note"] = "Synthetic topology: port-scan (1→50) + DDoS (50→1) vs 500 normal flows"
    logger.info("GNN topology benchmark: F1=%.4f AUC=%.4f", metrics["f1"], metrics["roc_auc"])
    return metrics, y_proba, y_true


# ── T5: TransformerAE + helper ───────────────────────────────────────────────

def _array_to_flow_features(row: np.ndarray):
    """Convert a 23-element NSL-KDD array to a FlowFeatures-compatible object."""
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from packetsentry.features.extractor import FlowFeatures

    ff = types.SimpleNamespace()
    ff.to_vector = lambda: row
    # Attach named attrs for any detector that reads them directly
    names = _FEATURE_NAMES
    for i, name in enumerate(names):
        setattr(ff, name, float(row[i]) if i < len(row) else 0.0)
    return ff


def eval_transformer_ae(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    warmup_rows: int = 500,
    seed: int = 42,
) -> tuple[dict, np.ndarray]:
    """Evaluate TransformerAEDetector by online-training on normal traffic."""
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from packetsentry.detection.transformer_ae import TransformerAEDetector

    logger.info("Evaluating TransformerAE (online warm-up on %d normal rows)...", warmup_rows)
    ae = TransformerAEDetector(warmup=warmup_rows)

    X_normal = X_train[y_train == 0][:warmup_rows]
    for row in X_normal:
        ae.score(_array_to_flow_features(row))

    scores = [ae.score(_array_to_flow_features(row)) for row in X_test]
    y_proba = np.clip(np.array(scores, dtype=np.float32), 0.0, 1.0)
    y_pred = (y_proba > 0.5).astype(int)
    return compute_metrics("TransformerAE", y_test, y_pred, y_proba), y_proba


# ── T6: Plots ────────────────────────────────────────────────────────────────

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
    """ROC-AUC overlay for all models."""
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


# ── T7: SHAP ─────────────────────────────────────────────────────────────────

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

    rng = np.random.default_rng(42)
    sample_size = min(500, len(X_test))
    idx = rng.choice(len(X_test), sample_size, replace=False)
    X_sample = X_test[idx]

    dmatrix = xgb.DMatrix(X_sample, feature_names=_FEATURE_NAMES)
    explainer = shap.TreeExplainer(booster)
    shap_values = explainer.shap_values(dmatrix)

    # Beeswarm
    shap.summary_plot(shap_values, X_sample, feature_names=_FEATURE_NAMES,
                      max_display=20, show=False)
    beeswarm_path = output_dir / "shap_beeswarm.png"
    plt.savefig(beeswarm_path, dpi=150, bbox_inches="tight")
    plt.close()
    logger.info("Saved %s", beeswarm_path)

    # Waterfall — highest-confidence attack sample
    probas = booster.predict(dmatrix)
    top_idx = int(np.argmax(probas))
    explanation = shap.Explanation(
        values=shap_values[top_idx],
        base_values=float(explainer.expected_value),
        data=X_sample[top_idx],
        feature_names=_FEATURE_NAMES,
    )
    shap.waterfall_plot(explanation, max_display=10, show=False)
    waterfall_path = output_dir / "shap_waterfall_example.png"
    plt.savefig(waterfall_path, dpi=150, bbox_inches="tight")
    plt.close()
    logger.info("Saved %s", waterfall_path)


# ── T8: UMAP + main CLI ──────────────────────────────────────────────────────

def plot_umap_embeddings(
    X: np.ndarray,
    y: np.ndarray,
    output_dir: Path,
    n_samples: int = 3000,
) -> None:
    """Project NSL-KDD features to 2D with UMAP, colour by attack class."""
    import umap

    logger.info("Running UMAP projection on %d samples...", n_samples)
    rng = np.random.default_rng(42)
    idx = rng.choice(len(X), min(n_samples, len(X)), replace=False)
    X_sample, y_sample = X[idx], y[idx]

    reducer = umap.UMAP(n_components=2, random_state=42, n_neighbors=15, min_dist=0.1)
    embedding = reducer.fit_transform(X_sample)

    colors = ["#6B7280", "#DC2626", "#F59E0B", "#7C3AED", "#059669"]
    fig, ax = plt.subplots(figsize=(9, 7))
    for cls_id, (name, color) in enumerate(zip(_MULTI_CLASS_NAMES, colors)):
        mask = y_sample == cls_id
        if mask.sum() == 0:
            continue
        ax.scatter(embedding[mask, 0], embedding[mask, 1],
                   c=color, label=name, s=4, alpha=0.6, linewidths=0)
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
    dataset: Path = typer.Option(Path("data/nslkdd/"), "--dataset", "-d"),
    output: Path = typer.Option(Path("results/"), "--output", "-o"),
    model: Path = typer.Option(Path("models/xgb_nslkdd.json"), "--model", "-m"),
    cv_folds: int = typer.Option(5, "--folds", "-k"),
    seed: int = typer.Option(42, "--seed"),
    skip_slow: bool = typer.Option(False, "--skip-slow", help="Skip TransformerAE (slow)"),
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

    typer.echo("\n1. Loading NSL-KDD...")
    X_train, y_train, y_train_multi = load_nslkdd(train_path)
    X_test, y_test, y_test_multi = load_nslkdd(test_path)
    typer.echo(f"   Train: {len(X_train):,} rows | Test: {len(X_test):,} rows")

    all_metrics: list[dict] = []
    all_probas: dict[str, tuple[np.ndarray, np.ndarray]] = {}

    typer.echo("\n2. XGBoost (5-fold CV)...")
    xgb_metrics, xgb_proba = eval_xgboost(X_train, y_train, X_test, y_test, model, cv_folds, seed)
    all_metrics.append(xgb_metrics)
    all_probas["XGBoost"] = (y_test, xgb_proba)
    typer.echo(f"   F1={xgb_metrics['f1']:.4f}  AUC={xgb_metrics['roc_auc']:.4f}  "
               f"CV={xgb_metrics['cv_f1_mean']:.4f}±{xgb_metrics['cv_f1_std']:.4f}")

    typer.echo("\n3. RandomForest...")
    rf_metrics, rf_proba = eval_random_forest(X_train, y_train, X_test, y_test, seed)
    all_metrics.append(rf_metrics)
    all_probas["RandomForest"] = (y_test, rf_proba)
    typer.echo(f"   F1={rf_metrics['f1']:.4f}  AUC={rf_metrics['roc_auc']:.4f}")

    typer.echo("\n4. IsolationForest (unsupervised)...")
    iso_metrics, iso_proba = eval_isolation_forest(X_train, y_train, X_test, y_test, seed)
    all_metrics.append(iso_metrics)
    all_probas["IsolationForest"] = (y_test, iso_proba)
    typer.echo(f"   F1={iso_metrics['f1']:.4f}  AUC={iso_metrics['roc_auc']:.4f}")

    typer.echo("\n5. ZScore...")
    zs_metrics, zs_proba = eval_zscore(X_train, y_train, X_test, y_test)
    all_metrics.append(zs_metrics)
    all_probas["ZScore"] = (y_test, zs_proba)
    typer.echo(f"   F1={zs_metrics['f1']:.4f}  AUC={zs_metrics['roc_auc']:.4f}")

    if not skip_slow:
        typer.echo("\n6. TransformerAE (online warm-up, ~5 min)...")
        tae_metrics, tae_proba = eval_transformer_ae(X_train, y_train, X_test, y_test, seed=seed)
        all_metrics.append(tae_metrics)
        all_probas["TransformerAE"] = (y_test, tae_proba)
        typer.echo(f"   F1={tae_metrics['f1']:.4f}  AUC={tae_metrics['roc_auc']:.4f}")

    if not skip_slow:
        typer.echo("\n7. GNN GraphSAGE (synthetic topology benchmark)...")
        gnn_metrics, gnn_proba, gnn_ytrue = eval_gnn(seed=seed)
        all_metrics.append(gnn_metrics)
        all_probas["GNN (GraphSAGE)"] = (gnn_ytrue, gnn_proba)
        typer.echo(f"   F1={gnn_metrics['f1']:.4f}  AUC={gnn_metrics['roc_auc']:.4f}  [{gnn_metrics.get('note', '')}]")
    else:
        all_metrics.append(
            {"model": "GNN (GraphSAGE)", "f1": None, "precision": None, "recall": None,
             "roc_auc": None, "note": "Skipped (--skip-slow). Run without flag to benchmark."}
        )

    all_metrics.append(
        {"model": "Aho-Corasick", "f1": None, "precision": None, "recall": None,
         "roc_auc": None, "note": "Signature matching — requires raw packet payloads. N/A for NSL-KDD."}
    )

    summary_path = output / "metrics_summary.json"
    summary_path.write_text(json.dumps(all_metrics, indent=2))
    typer.echo(f"\n[OK] Saved {summary_path}")

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
