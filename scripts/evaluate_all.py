#!/usr/bin/env python3
"""Evaluate all PacketSentry detectors on NSL-KDD dataset.

Usage:
    python scripts/evaluate_all.py --dataset data/nslkdd/ --output results/

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
               38, 39, 40, 2, 3, 6, 7]  # 23 columns

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
            rows_y_multi.append(_ATTACK_CLASSES.get(label, 1))

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


if __name__ == "__main__":
    app()
