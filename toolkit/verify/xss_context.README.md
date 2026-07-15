# xss_context

Context-aware XSS candidate verifier. Existing tools (jsreaper, paramfuzz) already detect reflection and DOM sinks, but they don't pick payloads based on where the reflection lands. Blind-firing every payload at every endpoint produces the "systemic noise" pattern the Bugcrowd research warns about. This tool: (1) consumes endpoints + params from jsreaper.py / paramfuzz.py; (2) sends a single harmless PROBE value (`xssprobe<random8>`) per injection point; (3) inspects where the token lands in the response (`html_body`, `html_attribute`, `script_block`, `url`, `js_string`, `html_comment`, `css_value`); (4) fires ONE context-appropriate payload per confirmed-reflection endpoint; (5) confirms XSS by re-requesting and checking that the payload appears verbatim AND breakout characters (`< > " '`) survive unescaped.

## Layer / Tier
Tier 2 verify. Layer 3 in the pipeline (live probe stage).

## Depends on
- `toolkit.infra.finding` — `compute_finding_id`.
- `toolkit.infra.pipeline_state` — `PipelineState` for `upsert_finding()`.
- `toolkit.infra.scope_guard` — `ScopeGuard` for scope + rate-limit enforcement on every probe.
- `httpx` (required — no urllib fallback for async probing).

## Feeds into
- `xss-findings.json` — confirmed reflected/DOM XSS findings (severity HIGH for breakout succeeded, MEDIUM for encoding bypass needed, LOW for reflection-only).
- `pipeline_state.db.findings_history` — every confirmed XSS finding is upserted.
- Downstream: `triage_memory.py` (triage queue), `nuclei-harvest.py` (aggregation).

## Usage

```bash
python -m toolkit.verify.xss_context \
    --input params.json \
    --scope scope.yaml \
    --output xss-findings.json

# Extract injection points only, no live probes
python -m toolkit.verify.xss_context --input params.json --dry-run
```

## Library use
```python
import asyncio
from toolkit.verify.xss_context import extract_injection_points, verify_all, to_normalized_findings
from toolkit.infra import scope_guard

endpoints = extract_injection_points(raw_paramfuzz_findings)
guard = scope_guard.ScopeGuard("scope.yaml")
xss_results = asyncio.run(verify_all(endpoints, guard, concurrency=5))
normalized = to_normalized_findings(xss_results)
```

## Input / Output
- **Input:** `paramfuzz.py` JSON (`findings[]` with `url`, `method`, `param_name`, `inject_via`) or `jsreaper.py` JSON (`all_endpoints[]` with `endpoint`/`method`/`params`). Both shapes are tolerated.
- **Output:** `xss-findings.json` with `scan_time`, `total_injection_points`, `total_findings`, `confirmed_breakout`, and `findings[]` (NormalizedFinding dicts with `vuln_class_key=XSS_REFLECTED`, severity HIGH/MEDIUM/LOW).
- **Side effects:** Two live HTTP requests per reflected injection point (one probe, one payload per detected context). Rate-limited via `scope_guard` — one token per request. Writes to `pipeline_state.db`.

## Key classes / functions
| Name | Purpose |
|---|---|
| `ReflectionProbe` | `dataclass(endpoint, method, param_name, inject_via, probe_value, response_status, response_body, reflected, contexts[])`. |
| `XssFinding` | `dataclass(endpoint, method, param_name, inject_via, context, payload, probe_reflected, payload_reflected, breakout_succeeded, severity, title, detail, evidence)`. |
| `_PAYLOADS` | Dict of context → payload template with `{token}` placeholder. One payload per context — no blind firing. |
| `extract_injection_points(findings)` | Dedup `(url, method, param)` tuples from paramfuzz/jsreaper output. |
| `_detect_contexts(probe, body)` | Locate every occurrence of the probe in the response body; for each, inspect the preceding 200 chars to determine context (HTML body / attribute / script block / JS string / URL / comment / CSS). |
| `_check_breakout(payload, body)` | True if `< >` survive unescaped near the payload's landing point. |
| `verify_endpoint(client, endpoint, guard)` | Probe one endpoint, then fire one payload per detected context. Returns `list[XssFinding]`. |
| `to_normalized_findings(xss)` | Convert `XssFinding` list to NormalizedFinding dicts. `breakout_succeeded=True` → `confidence=confirmed`, `verified_by=xss_context.py`. |

## Configuration
- `--input` (required): paramfuzz.py or jsreaper.py JSON output.
- `--scope`: `scope.yaml` for live probes. Falls back to module default if omitted.
- `--output` (default `xss-findings.json`).
- `--db` (default `pipeline_state.db`).
- `--concurrency` (default 5): max concurrent endpoint probes.
- `--dry-run`: extract injection points only, no live probes.

## Safety notes
- Two HTTP requests per reflected injection point. The probe value is a harmless alphanumeric token (`xssprobe<random8>`). The payload is a single context-appropriate XSS payload with an embedded `alert("<token>")` — the token makes it provable which request fired the alert if the user later reproduces in a browser.
- This tool does NOT execute the payload — it only checks whether the breakout characters survive unescaped in the response body. Browser-based execution is the researcher's responsibility.
- `scope_guard` enforces scope on every probe URL. Out-of-scope endpoints are skipped silently.
- TLS verification is OFF on the async client to match the existing toolkit pattern.

## See also
- ARCHITECTURE.md §4.3 (XSS verification) and §Systemic-noise (defense via context-aware payloads)
- Related tools: `jsreaper.py` (upstream producer), `paramfuzz.py` (upstream producer), `triage_memory.py` (downstream consumer)
