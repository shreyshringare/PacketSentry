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


def test_eval_random_forest_returns_metrics():
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
    from evaluate_all import eval_random_forest

    rng = np.random.default_rng(42)
    X = rng.random((200, 23)).astype(np.float32)
    y = (rng.random(200) > 0.5).astype(int)

    metrics, proba = eval_random_forest(X[:150], y[:150], X[150:], y[150:])

    assert metrics["model"] == "RandomForest"
    assert 0.0 <= proba.min() and proba.max() <= 1.0


def test_eval_transformer_ae_returns_metrics():
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
    from evaluate_all import eval_transformer_ae

    rng = np.random.default_rng(42)
    X = rng.random((300, 23)).astype(np.float32)
    y = (rng.random(300) > 0.5).astype(int)

    metrics, proba = eval_transformer_ae(X[:250], y[:250], X[250:], y[250:], warmup_rows=100)

    assert metrics["model"] == "TransformerAE"
    assert proba.shape == (50,)
    assert 0.0 <= proba.min() and proba.max() <= 1.0
