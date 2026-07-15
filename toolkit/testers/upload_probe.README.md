# upload_probe

File-upload abuse testing. `ssrfprobe.py` treats upload URL fields purely as an SSRF injection surface (URL fields → metadata/internal payloads). But file uploads have their own vulnerability class: extension/MIME/magic-byte mismatch (server allows `.php` upload but only checks `Content-Type: image/jpeg`), polyglot files (valid image + embedded payload), path-traversal via filename, unrestricted upload → RCE, SVG upload → XSS/XXE, `.htaccess` upload → Apache config override. This tool probes upload endpoints discovered by `jsreaper.py` / `paramfuzz.py` with a controlled set of 8 test files (each containing a unique `UPLOADPROBE_<random>` marker) and reports which validations (if any) are enforced.

## Layer / Tier
Tier 4 tester. Layer 3 in the pipeline.

## Depends on
- `toolkit.infra.scope_guard` — `ScopeGuard` for scope + rate-limit enforcement on every upload attempt.
- `toolkit.infra.finding` — `compute_finding_id`.
- `toolkit.infra.pipeline_state` — `PipelineState` for `upsert_finding()`.
- `httpx` (required for multipart uploads — no fallback).

## Feeds into
- `upload-findings.json` — findings with `vuln_class_key` in `UPLOAD_EXTENSION_MISMATCH`, `UPLOAD_DOUBLE_EXTENSION`, `UPLOAD_POLYGLOT`, `UPLOAD_PATH_TRAVERSAL`, `UPLOAD_SVG_XSS`, `UPLOAD_SVG_XXE`, `UPLOAD_HTACCESS`.
- `pipeline_state.db.findings_history` — every finding is upserted.
- Downstream: `triage_memory.py` (triage queue).

## Usage

```bash
# From jsreaper.py / paramfuzz.py output (heuristic endpoint discovery)
python -m toolkit.testers.upload_probe \
    --input js-findings.json \
    --scope scope.yaml \
    --output upload-findings.json

# Direct endpoint
python -m toolkit.testers.upload_probe --url https://target.com/upload --method POST --param file
```

## Library use
```python
import asyncio
from toolkit.testers.upload_probe import find_upload_endpoints, scan_endpoint, to_normalized, _build_test_files
from toolkit.infra import scope_guard

endpoints = find_upload_endpoints(raw_findings)  # URL pattern + param name heuristics
guard = scope_guard.ScopeGuard("scope.yaml")
results = []
for ep in endpoints:
    results.extend(asyncio.run(scan_endpoint(ep["url"], ep["method"], ep["param_name"], guard)))
normalized = to_normalized(results)  # only emits findings where expected_blocked=True but wasn't
```

## Input / Output
- **Input:** Either `--input jsreaper.json` / `paramfuzz.json` (heuristic endpoint discovery via `_UPLOAD_URL_RE` and `_UPLOAD_PARAM_RE`), OR `--url` direct with `--method` (default POST) and `--param` (default `file`).
- **Output:** `upload-findings.json` with `scan_time`, `endpoints_scanned`, `total_uploads_attempted`, `total_findings`, and `findings[]` (NormalizedFinding dicts). Only tests where `expected_blocked=True` and `actually_blocked=False` produce findings.
- **Side effects:** 8 HTTP multipart uploads per endpoint (one per test file in `_build_test_files()`). Rate-limited via `scope_guard`. Writes to `pipeline_state.db`.

## Key classes / functions
| Name | Purpose |
|---|---|
| `TestFile` | `dataclass(name, content_type, body, expect_blocked, vuln_class, severity, detail)`. |
| `_build_test_files(token)` | Builds the 8 test files: benign PNG baseline, `.php` extension mismatch, `.jpg.php` double extension, GIF/PHP polyglot, `../{token}.txt` path traversal, SVG with `<script>`, SVG with XXE entity, `.htaccess` override. Every body contains the unique token for round-trip verification. |
| `UploadResult` | `dataclass(endpoint, test_file, vuln_class, expected_blocked, actually_blocked, severity, detail, response_status, response_snippet, token)`. |
| `find_upload_endpoints(findings)` | Heuristic: match URL against `_UPLOAD_URL_RE` (`/upload|file|attachment|media|image|avatar|...`) OR param name against `_UPLOAD_PARAM_RE`. |
| `upload_one(client, endpoint, method, param, tf)` | Send one multipart upload. "Blocked" = HTTP 4xx/5xx OR body contains `error|invalid|rejected|not allowed|forbidden`. |
| `scan_endpoint(endpoint, method, param, guard)` | Run all 8 test files against one endpoint. |
| `to_normalized(results)` | Convert to NormalizedFinding dicts. Only emits findings where `expected_blocked and not actually_blocked`. |

## Configuration
- `--input` OR `--url` (mutually exclusive, one required).
- `--method` (default POST), `--param` (default `file`) — used with `--url`.
- `--scope`: `scope.yaml` for scope + rate-limit.
- `--output` (default `upload-findings.json`).
- `--db` (default `pipeline_state.db`).
- No flag to customize the test-file set — patch `_build_test_files()` to add/remove cases.

## Safety notes
- Every test file body contains a benign `UPLOADPROBE_<random>` marker — no real exploit payloads. The PHP files contain `<?php echo 'UPLOADPROBE_xxx'; ?>` (echo only, no system/exec). The SVG XSS contains `alert("UPLOADPROBE_xxx")` (alert only, no cookie exfil). The SVG XXE points at `file:///etc/passwd` but the tool does NOT parse the response — it only checks whether the upload was accepted.
- This tool does NOT attempt to access the uploaded file afterward, does NOT trigger its execution, and does NOT perform path traversal beyond a benign `../probe.txt` filename probe (never overwriting real files).
- `scope_guard` enforces scope on every endpoint. Out-of-scope endpoints are skipped.
- TLS verification is OFF on the async client.

## See also
- ARCHITECTURE.md §5.5 (upload testing) and §Safety (benign markers, no execution)
- Related tools: `jsreaper.py` (upstream endpoint source), `paramfuzz.py` (upstream param source), `ssrfprobe.py` (complementary URL-field testing), `triage_memory.py` (downstream consumer)
