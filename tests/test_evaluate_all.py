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
