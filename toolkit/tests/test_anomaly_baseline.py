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
