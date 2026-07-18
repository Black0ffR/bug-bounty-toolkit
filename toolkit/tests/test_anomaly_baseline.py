"""Tests for toolkit.testers.anomaly_baseline (Phase A: A6)."""
from __future__ import annotations

import statistics

from toolkit.testers.anomaly_baseline import (
    AnomalyDetector,
    ResponseSpec,
    to_finding,
)


def _spec(status: int = 200, size: int = 100, elapsed: float = 100.0) -> ResponseSpec:
    return ResponseSpec(status=status, size_bytes=size, elapsed_ms=elapsed, headers={})


def test_calibrate_uses_sample_stdev_not_population():
    """Baseline is a *sample*; use statistics.stdev (sample sd), not pstdev.
    For n>1, stdev is strictly larger than pstdev, so z-scores are correct."""
    det = AnomalyDetector(min_samples=2)
    timings = [100.0, 102.0, 98.0, 101.0, 99.0]
    for t in timings:
        det.observe(_spec(elapsed=t))
    det.calibrate()
    assert det._calibrated
    assert det._timing_stdev == statistics.stdev(timings)
    assert det._timing_stdev > statistics.pstdev(timings)


def test_check_anomaly_with_sample_stdev():
    """A value within the (sample) band is not anomalous; a far timing outlier
    that also changes status class is (>=2 signals required)."""
    det = AnomalyDetector(threshold_stdev=3.0, min_samples=2)
    for t in [100.0, 102.0, 98.0, 101.0, 99.0, 100.0, 101.0]:
        det.observe(_spec(elapsed=t))
    det.calibrate()
    # Within band, only status 200 (in baseline) — single signal → not anomalous
    assert det.check(_spec(elapsed=110.0)).is_anomalous is False
    # Far timing outlier + status-class change → 2 signals → anomalous (HIGH)
    anom = det.check(_spec(elapsed=500.0, status=500))
    assert anom is not None
    assert anom.is_anomalous is True
    assert anom.severity == "HIGH"
    assert any("timing" in r for r in anom.reasons)


def test_to_finding_shape():
    det = AnomalyDetector(min_samples=2)
    for t in [100.0, 102.0, 98.0, 101.0, 99.0]:
        det.observe(_spec(elapsed=t))
    det.calibrate()
    anom = det.check(_spec(elapsed=500.0, status=500))
    assert anom is not None and anom.is_anomalous
    f = to_finding(anom)
    assert f["source_tool"] == "anomaly_baseline.py"
    assert f["vuln_class_key"] == "RESPONSE_ANOMALY"
    assert f["severity"] == "HIGH"


def test_body_change_flagged_even_when_length_unchanged():
    """B11: a same-length content swap must be flagged as an anomaly even
    though the size z-score stays at zero."""
    det = AnomalyDetector(min_samples=2)
    for t in [100.0, 102.0, 98.0, 101.0, 99.0]:
        det.observe(_spec(elapsed=t, size=100, status=200))
    det.observe(ResponseSpec(status=200, size_bytes=100, elapsed_ms=100.0,
                             headers={}, body="token=aaaaaaaa"))
    det.calibrate()
    # Same 100 bytes, same status, near-baseline timing — but content differs.
    anom = det.check(ResponseSpec(status=200, size_bytes=100, elapsed_ms=100.0,
                                  headers={}, body="token=bbbbbbbb"))
    assert anom is not None
    assert anom.body_changed is True
    assert anom.is_anomalous is True
    assert anom.severity == "MEDIUM"


def test_body_unchanged_not_flagged():
    det = AnomalyDetector(min_samples=2)
    for t in [100.0, 102.0, 98.0, 101.0, 99.0]:
        det.observe(_spec(elapsed=t, size=100, status=200))
    det.observe(ResponseSpec(status=200, size_bytes=100, elapsed_ms=100.0,
                             headers={}, body="value=42"))
    det.calibrate()
    anom = det.check(ResponseSpec(status=200, size_bytes=100, elapsed_ms=100.0,
                                  headers={}, body="value=42"))
    assert anom.body_changed is False
    assert anom.is_anomalous is False


def test_body_structural_normalization_ignores_numbers():
    """'user 1' and 'user 999' are structurally identical → not flagged."""
    det = AnomalyDetector(min_samples=2)
    for t in [100.0, 102.0, 98.0, 101.0, 99.0]:
        det.observe(_spec(elapsed=t, size=100, status=200))
    det.observe(ResponseSpec(status=200, size_bytes=100, elapsed_ms=100.0,
                             headers={}, body="user 1"))
    det.calibrate()
    anom = det.check(ResponseSpec(status=200, size_bytes=100, elapsed_ms=100.0,
                                  headers={}, body="user 999"))
    assert anom.body_changed is False
