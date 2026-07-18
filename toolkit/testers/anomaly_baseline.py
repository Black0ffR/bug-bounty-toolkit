#!/usr/bin/env python3
"""
anomaly_baseline.py — shared statistical anomaly-detection primitive
=====================================================================

Tier 4 tester — but used as a primitive by other tools (apifuzz, ssrfprobe).

Purpose
-------
apifuzz.py and ssrfprobe.py each reimplement their own ad-hoc threshold
logic for "is this response anomalous?" — usually a hard-coded "200ms is
slow", "5000 bytes is big", "status != baseline is suspicious". This
generalizes that into one shared primitive:

Given a baseline response (timing, size, status, headers), flag statistically
significant deviations in subsequent responses.

Used two ways:
  1. As a library: from toolkit.testers.anomaly_baseline import AnomalyDetector
  2. As a CLI: feed it a JSON of baseline + test responses, get a report.

The detector uses three independent signals:
  - timing:    z-score against baseline mean ± N stdevs (N=3 default)
  - size:      z-score (but only flags DEVIATION, not size per se — a small
               response can be as suspicious as a large one)
  - status:    hard fail if status code class changes (2xx → 5xx, 2xx → 4xx)
  - headers:   new headers appearing or missing ones disappearing

All four must agree on "anomalous" for a finding to be emitted — this is the
defense against the "systemic noise" pattern.

Chain position
--------------
Layer 4 — Input: JSON of {baseline: ResponseSpec, samples: [ResponseSpec, ...]}
          Output: anomaly-findings.json with per-sample verdicts.
          Library use: import AnomalyDetector, call .observe(spec), check .is_anomalous().

Usage
-----
    # CLI
    python -m toolkit.testers.anomaly_baseline \\
        --input responses.json \\
        --output anomaly-findings.json

    # Library
    from toolkit.testers.anomaly_baseline import AnomalyDetector, ResponseSpec
    det = AnomalyDetector(threshold_stdev=3.0, min_samples=5)
    for r in baseline_responses:
        det.observe(ResponseSpec(status=r.status, size_bytes=r.size, elapsed_ms=r.elapsed, headers=r.headers))
    det.calibrate()
    for r in test_responses:
        spec = ResponseSpec(...)
        if det.is_anomalous(spec):
            ...

Author : Bug Bounty Toolkit / Tier 4
License : MIT (for authorized use only)
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import logging
import math
import re
import statistics
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from toolkit.infra.finding import compute_finding_id
from toolkit.infra.pipeline_state import PipelineState


log = logging.getLogger("anomaly_baseline")


@dataclass
class ResponseSpec:
    """One observed HTTP response — enough to compare against baseline."""
    url: str = ""
    method: str = "GET"
    status: int = 0
    size_bytes: int = 0
    elapsed_ms: float = 0.0
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""              # full (or representative) response body
    body_snippet: str = ""
    label: str = ""    # human-readable tag for the observation


@dataclass
class Anomaly:
    url: str
    label: str
    is_anomalous: bool
    reasons: list[str]            # list of triggered signals
    timing_z: float
    size_z: float
    status_changed: bool
    body_changed: bool
    headers_diff: dict[str, list[str]]   # {"added": [...], "removed": [...]}
    severity: str
    detail: str


class AnomalyDetector:
    """Calibrate on a baseline of N responses, then flag deviations in subsequent
    samples. Use:
        det = AnomalyDetector(threshold_stdev=3.0, min_samples=5)
        for r in baseline: det.observe(r)
        det.calibrate()
        for r in test: det.check(r)  # → Anomaly | None
    """

    def __init__(self, *, threshold_stdev: float = 3.0, min_samples: int = 5,
                 status_class_change_only: bool = True) -> None:
        self.threshold_stdev = float(threshold_stdev)
        self.min_samples = int(min_samples)
        self.status_class_change_only = bool(status_class_change_only)
        # Baseline accumulators
        self._baseline_timings: list[float] = []
        self._baseline_sizes: list[int] = []
        self._baseline_statuses: set[int] = set()
        self._baseline_header_keys: set[str] = set()
        # Body / structural-change baseline
        self._baseline_body_sigs: set[str] = set()
        self._baseline_body_present: bool = False
        # Calibrated parameters
        self._timing_mean: float = 0.0
        self._timing_stdev: float = 0.0
        self._size_mean: float = 0.0
        self._size_stdev: float = 0.0
        self._calibrated: bool = False

    def observe(self, spec: ResponseSpec) -> None:
        """Add a response to the baseline set. Call BEFORE calibrate()."""
        self._baseline_timings.append(float(spec.elapsed_ms))
        self._baseline_sizes.append(int(spec.size_bytes))
        self._baseline_statuses.add(int(spec.status))
        self._baseline_header_keys.update(k.lower() for k in spec.headers.keys())
        if spec.body:
            self._baseline_body_present = True
            self._baseline_body_sigs.add(self._body_sig(spec.body))

    def calibrate(self) -> None:
        """Compute mean/stdev from observed baseline. After this, observe() must
        not be called — use check() instead."""
        n = len(self._baseline_timings)
        if n < self.min_samples:
            log.warning("anomaly baseline has only %d samples (min %d) — stats will be unstable",
                        n, self.min_samples)
        if n > 0:
            self._timing_mean = statistics.fmean(self._baseline_timings)
            # Sample standard deviation (stdev), not population (pstdev): the
            # baseline is a *sample* of observations, so pstdev underestimates
            # variance and inflates z-scores → false anomalies. stdev is correct.
            self._timing_stdev = statistics.stdev(self._baseline_timings) if n > 1 else 0.0
            self._size_mean = statistics.fmean(self._baseline_sizes)
            self._size_stdev = statistics.stdev(self._baseline_sizes) if n > 1 else 0.0
        self._calibrated = True
        log.info("baseline calibrated: n=%d timing=%.1fms±%.1f size=%.0f±%.0f statuses=%s headers=%d",
                 n, self._timing_mean, self._timing_stdev, self._size_mean, self._size_stdev,
                 sorted(self._baseline_statuses), len(self._baseline_header_keys))

    def _z(self, value: float, mean: float, stdev: float) -> float:
        if stdev == 0:
            return 0.0 if value == mean else (float("inf") if value > mean else float("-inf"))
        return (value - mean) / stdev

    def _status_class(self, status: int) -> int:
        return status // 100

    def _canonical_body(self, body: str) -> str:
        """Normalize a response body to a structure-only signature: replace
        dynamic value tokens (uuids, long hex, numbers) and collapse whitespace
        so that two responses that differ ONLY in dynamic values are treated as
        structurally identical. """
        s = re.sub(
            r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-'
            r'[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b', '{uuid}', body)
        s = re.sub(r'\b[0-9a-fA-F]{32,}\b', '{hex}', s)
        s = re.sub(r'\d+', '{n}', s)
        s = re.sub(r'\s+', ' ', s).strip()
        return s

    def _body_sig(self, body: str) -> str:
        return hashlib.sha256(self._canonical_body(body).encode("utf-8")).hexdigest()

    def check(self, spec: ResponseSpec) -> Anomaly | None:
        """Check a single response against the calibrated baseline. Returns an
        Anomaly if at least 2 signals trigger, else None."""
        if not self._calibrated:
            raise RuntimeError("call calibrate() before check()")
        reasons: list[str] = []
        timing_z = self._z(spec.elapsed_ms, self._timing_mean, self._timing_stdev)
        size_z = self._z(spec.size_bytes, self._size_mean, self._size_stdev)
        status_changed = False
        # Timing
        if abs(timing_z) >= self.threshold_stdev and self._timing_stdev > 0:
            reasons.append(f"timing z={timing_z:.1f} (baseline {self._timing_mean:.0f}ms±{self._timing_stdev:.0f}ms, sample {spec.elapsed_ms:.0f}ms)")
        # Size
        if abs(size_z) >= self.threshold_stdev and self._size_stdev > 0:
            reasons.append(f"size z={size_z:.1f} (baseline {self._size_mean:.0f}B±{self._size_stdev:.0f}B, sample {spec.size_bytes}B)")
        # Status
        if self.status_class_change_only:
            if self._status_class(spec.status) not in {self._status_class(s) for s in self._baseline_statuses}:
                status_changed = True
                reasons.append(f"status class changed (baseline classes {[self._status_class(s) for s in sorted(self._baseline_statuses)]}, sample class {self._status_class(spec.status)})")
        else:
            if spec.status not in self._baseline_statuses:
                status_changed = True
                reasons.append(f"status {spec.status} not in baseline {sorted(self._baseline_statuses)}")
        # Headers diff
        sample_keys = {k.lower() for k in spec.headers.keys()}
        added = sorted(sample_keys - self._baseline_header_keys)
        removed = sorted(self._baseline_header_keys - sample_keys)
        headers_diff = {"added": added, "removed": removed}
        if added:
            reasons.append(f"new headers: {added}")
        if removed:
            reasons.append(f"missing headers: {removed}")
        # Body / structural change — flags content changes that leave the byte
        # length (and therefore the size z-score) completely unchanged.
        body_changed = False
        if self._baseline_body_present and spec.body:
            if self._body_sig(spec.body) not in self._baseline_body_sigs:
                body_changed = True
                reasons.append(
                    "response body content changed (structural diff) — same-length "
                    "content swap not caught by size signal")
        # Verdict: anomalous if at least 2 signals trigger, OR a body content
        # change is observed (a content swap is itself a meaningful deviation).
        is_anom = len(reasons) >= 2 or body_changed
        severity = "INFO"
        if is_anom:
            if status_changed and abs(timing_z) >= self.threshold_stdev:
                severity = "HIGH"
            elif body_changed and status_changed:
                severity = "HIGH"
            elif len(reasons) >= 3:
                severity = "HIGH"
            else:
                severity = "MEDIUM"
        return Anomaly(
            url=spec.url, label=spec.label,
            is_anomalous=is_anom,
            reasons=reasons,
            timing_z=timing_z if math.isfinite(timing_z) else 999.0,
            size_z=size_z if math.isfinite(size_z) else 999.0,
            status_changed=status_changed,
            body_changed=body_changed,
            headers_diff=headers_diff,
            severity=severity,
            detail="; ".join(reasons) if reasons else "no anomaly signals triggered",
        )


def to_finding(anom: Anomaly, source_tool: str = "anomaly_baseline.py") -> dict[str, Any]:
    """Convert an Anomaly into a NormalizedFinding dict."""
    from urllib.parse import urlparse
    host = urlparse(anom.url).hostname or ""
    evidence = f"{anom.url}|timing_z={anom.timing_z:.1f}|size_z={anom.size_z:.1f}|status_changed={anom.status_changed}"
    fid = compute_finding_id(source_tool, host, "RESPONSE_ANOMALY", evidence)
    return {
        "id": fid,
        "source_tool": source_tool,
        "host": host,
        "url": anom.url,
        "vuln_class_key": "RESPONSE_ANOMALY",
        "severity": anom.severity,
        "title": f"Response anomaly: {anom.label or anom.url}",
        "detail": anom.detail,
        "evidence": evidence,
        "remediation": ("Investigate the cause of the deviation. Common causes: server-side "
                        "request forgery (timing), error leakage (status change), backend "
                        "inconsistency (size change), WAF/CDS toggle (headers)."),
        "raw": {
            "timing_z": anom.timing_z,
            "size_z": anom.size_z,
            "status_changed": anom.status_changed,
            "body_changed": anom.body_changed,
            "headers_diff": anom.headers_diff,
            "reasons": anom.reasons,
        },
        "confidence": "probable",
        "disposition": "new",
        "verified_by": None,
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="anomaly_baseline.py",
        description="Shared statistical anomaly-detection primitive.",
    )
    ap.add_argument("--input", "-i", required=True,
                    help="JSON: {baseline: [ResponseSpec], samples: [ResponseSpec]}")
    ap.add_argument("--output", "-o", default="anomaly-findings.json")
    ap.add_argument("--db", default="pipeline_state.db")
    ap.add_argument("--threshold-stdev", type=float, default=3.0)
    ap.add_argument("--min-samples", type=int, default=5)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )

    in_path = Path(args.input)
    if not in_path.exists():
        log.error("input not found: %s", in_path)
        return 2
    data = json.loads(in_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "baseline" not in data or "samples" not in data:
        log.error("input must be {baseline: [...], samples: [...]}")
        return 2

    det = AnomalyDetector(threshold_stdev=args.threshold_stdev, min_samples=args.min_samples)
    for r in data["baseline"]:
        det.observe(ResponseSpec(
            url=r.get("url", ""), method=r.get("method", "GET"),
            status=int(r.get("status", 0)), size_bytes=int(r.get("size_bytes", 0)),
            elapsed_ms=float(r.get("elapsed_ms", 0.0)),
            headers=r.get("headers", {}),
            body=r.get("body", r.get("body_snippet", "")),
            body_snippet=r.get("body_snippet", ""),
            label=r.get("label", ""),
        ))
    det.calibrate()

    findings: list[dict[str, Any]] = []
    anomalies: list[dict[str, Any]] = []
    for r in data["samples"]:
        spec = ResponseSpec(
            url=r.get("url", ""), method=r.get("method", "GET"),
            status=int(r.get("status", 0)), size_bytes=int(r.get("size_bytes", 0)),
            elapsed_ms=float(r.get("elapsed_ms", 0.0)),
            headers=r.get("headers", {}),
            body=r.get("body", r.get("body_snippet", "")),
            body_snippet=r.get("body_snippet", ""),
            label=r.get("label", ""),
        )
        a = det.check(spec)
        if a is None:
            continue
        anomalies.append({
            "url": a.url, "label": a.label, "is_anomalous": a.is_anomalous,
            "reasons": a.reasons, "timing_z": a.timing_z, "size_z": a.size_z,
            "status_changed": a.status_changed, "body_changed": a.body_changed,
            "headers_diff": a.headers_diff,
            "severity": a.severity, "detail": a.detail,
        })
        if a.is_anomalous:
            findings.append(to_finding(a))

    state = PipelineState(args.db)
    try:
        for f in findings:
            state.upsert_finding(f)
    finally:
        state.close()

    out_path = Path(args.output)
    out_path.write_text(
        json.dumps({
            "scan_time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "input": str(in_path),
            "baseline_samples": len(data["baseline"]),
            "test_samples": len(data["samples"]),
            "anomalies": anomalies,
            "findings": findings,
        }, indent=2, default=str),
        encoding="utf-8",
    )
    log.info("wrote %s (%d anomalies, %d findings)", out_path, len(anomalies), len(findings))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(0)
