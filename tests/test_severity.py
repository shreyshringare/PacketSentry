"""Tests for shared severity mapping."""
from packetsentry.alerts.severity import confidence_to_severity


def test_critical_threshold() -> None:
    assert confidence_to_severity(0.95) == "CRITICAL"
    assert confidence_to_severity(0.90) == "CRITICAL"


def test_high_threshold() -> None:
    assert confidence_to_severity(0.89) == "HIGH"
    assert confidence_to_severity(0.75) == "HIGH"


def test_med_threshold() -> None:
    assert confidence_to_severity(0.74) == "MED"
    assert confidence_to_severity(0.60) == "MED"


def test_low_threshold() -> None:
    assert confidence_to_severity(0.59) == "LOW"
    assert confidence_to_severity(0.0) == "LOW"


def test_boundary_values() -> None:
    assert confidence_to_severity(1.0) == "CRITICAL"
    assert confidence_to_severity(0.0) == "LOW"
