# anomaly_baseline

Shared statistical anomaly-detection primitive. `apifuzz.py` and `ssrfprobe.py` each reimplement their own ad-hoc threshold logic for "is this response anomalous?" — usually a hard-coded "200ms is slow", "5000 bytes is big", "status != baseline is suspicious". This generalizes that into one shared primitive: given a baseline response set (timing, size, status, headers), flag statistically significant deviations in subsequent responses. Three independent signals: timing z-score (default ±3σ), size z-score (deviation in either direction — small can be as suspicious as large), status class change (2xx→5xx, 2xx→4xx), header diff (new/missing headers). At least 2 signals must agree for a finding — defense against the systemic-noise pattern.

## Layer / Tier
Tier 4 tester — but used as a primitive by other tools (apifuzz, ssrfprobe). Layer 4 in the pipeline.

## Depends on
- `toolkit.infra.finding` — `compute_finding_id`.
- `toolkit.infra.pipeline_state` — `PipelineState` for `upsert_finding()`.
- Python stdlib: `statistics`, `math`, `json`, `argparse`, `datetime`.

## Feeds into
- `anomaly-findings.json` — per-sample verdicts with `is_anomalous`, `reasons[]`, `timing_z`, `size_z`, `status_changed`, `headers_diff`, `severity`.
- `pipeline_state.db.findings_history` — only anomalous samples are upserted (as `RESPONSE_ANOMALY` findings).
- Library use: `apifuzz.py` and `ssrfprobe.py` import `AnomalyDetector` directly to replace their ad-hoc thresholds.

## Usage

```bash
# CLI: feed baseline + test responses, get a report
python -m toolkit.testers.anomaly_baseline \
    --input responses.json \
    --output anomaly-findings.json \
    --threshold-stdev 3.0 --min-samples 5
```

`responses.json` shape:
```json
{
  "baseline": [{"url": "...", "status": 200, "size_bytes": 1234, "elapsed_ms": 45, "headers": {...}}, ...],
  "samples":  [{"url": "...", "status": 500, "size_bytes": 89, "elapsed_ms": 1200, "headers": {...}, "label": "ssrf-probe"}, ...]
}
```

## Library use
```python
from toolkit.testers.anomaly_baseline import AnomalyDetector, ResponseSpec, to_finding

det = AnomalyDetector(threshold_stdev=3.0, min_samples=5)
for r in baseline_responses:
    det.observe(ResponseSpec(
        url=r.url, status=r.status, size_bytes=r.size,
        elapsed_ms=r.elapsed, headers=r.headers,
    ))
det.calibrate()

for r in test_responses:
    spec = ResponseSpec(url=r.url, status=r.status, size_bytes=r.size,
                        elapsed_ms=r.elapsed, headers=r.headers, label="ssrf-probe")
    a = det.check(spec)        # → Anomaly | None (always returns Anomaly; check .is_anomalous)
    if a.is_anomalous:
        finding = to_finding(a, source_tool="ssrfprobe.py")
```

## Input / Output
- **Input:** JSON `{baseline: [ResponseSpec], samples: [ResponseSpec]}`. Each `ResponseSpec` has `url`, `method`, `status`, `size_bytes`, `elapsed_ms`, `headers` (dict), `body_snippet`, `label`.
- **Output:** `anomaly-findings.json` with `scan_time`, `input`, `baseline_samples`, `test_samples`, `anomalies[]` (per-sample verdict, including non-anomalous ones), `findings[]` (only anomalous, as NormalizedFinding dicts with `vuln_class_key=RESPONSE_ANOMALY`).
- **Side effects:** Writes to `pipeline_state.db`. No network calls — this tool consumes already-collected response metadata.

## Key classes / functions
| Name | Purpose |
|---|---|
| `ResponseSpec` | `dataclass(url, method, status, size_bytes, elapsed_ms, headers, body_snippet, label)`. One observed HTTP response — enough to compare against baseline. |
| `Anomaly` | `dataclass(url, label, is_anomalous, reasons[], timing_z, size_z, status_changed, headers_diff, severity, detail)`. |
| `AnomalyDetector` | Calibrate on N baseline responses, then `check(spec)` each test response. `observe(spec)` adds to baseline; `calibrate()` computes mean/stdev; `check(spec)` returns an `Anomaly` (always — inspect `.is_anomalous`). |
| `to_finding(anom, source_tool)` | Convert an anomalous `Anomaly` to a NormalizedFinding dict. `confidence=probable`, `vuln_class_key=RESPONSE_ANOMALY`. |

## Configuration
- `--input` (required): JSON `{baseline, samples}`.
- `--output` (default `anomaly-findings.json`).
- `--db` (default `pipeline_state.db`).
- `--threshold-stdev` (default 3.0): z-score cutoff for timing + size signals.
- `--min-samples` (default 5): warn (not fail) if baseline has fewer samples — stats become unstable below this.

## Safety notes
- Read-only against input JSON. No network calls — operates on already-collected response metadata.
- `AnomalyDetector.check()` returns an `Anomaly` object always (even when not anomalous) — callers must inspect `.is_anomalous` before treating it as a finding. The CLI's `to_finding()` is only called when `is_anomalous=True`.
- The 2-of-N-signals agreement rule is deliberate — a single signal (e.g., timing spike on a slow sample) is not enough to flag. This is the defense against systemic noise.
- `calibrate()` uses `statistics.pstdev` (population stdev). For sample stdev, replace with `statistics.stdev` if baseline is a sample rather than the full population.

## See also
- ARCHITECTURE.md §5.1 (anomaly detection) and §Systemic-noise (multi-signal agreement defense)
- Related tools: `apifuzz.py` (consumer), `ssrfprobe.py` (consumer), `triage_memory.py` (downstream consumer)
