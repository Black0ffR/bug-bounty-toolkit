# IMPLEMENTATION_NOTES — toolkit vs ARCHITECTURE.md

This doc lists every deviation from the original `ARCHITECTURE.md` spec, with
rationale. Read this if you're reviewing the implementation or porting it.

## Summary

14 of the 14 proposed tools are implemented. All Layer 0 infrastructure is in
place. The existing scripts (`nuclei-harvest.py`, `apifuzz.py`, `jsreaper.py`)
are patched for deep integration with the new schema. The test suite has 139
passing tests covering unit + integration paths.

## Deviations

### 1. Stdlib + httpx + PyYAML (vs "Termux pure stdlib")

**Spec §4.1**: "scope_guard.py — Termux note: pure stdlib (re, ipaddress),
zero new dependencies."

**Implementation**: User chose "Stdlib + httpx + PyYAML" in clarification. All
new tools use httpx for HTTP (matching the existing scripts' pattern) and
PyYAML for YAML parsing. A fallback YAML parser is included in `scope_guard.py`
for environments where PyYAML isn't installed — handles the restricted subset
used by `scope.yaml` / `auth_profiles.yaml`.

**Rationale**: The existing scripts (`apifuzz.py`, `jsreaper.py`, `paramfuzz.py`,
`ssrfprobe.py`, `subtakeover10.py`) all use httpx. Matching that pattern keeps
the toolchain consistent and lets tools share the same connection pooling /
redirect / TLS-verify conventions. The fallback parser preserves the "runs on
fresh Termux without pip" property for the infra layer.

### 2. Toolkit subdir layout (vs spec §7 layout)

**Spec §7**: Proposed layout puts new tools in `infra/`, `verify/`, `discover/`,
`testers/`, `infra_ext/` at the repo root alongside `scripts/`.

**Implementation**: User chose "Toolkit subdir" — new tools live in
`toolkit/{infra,verify,discover,testers,infra_ext}/` keeping the existing
`scripts/` directory visually separate.

**Rationale**: Keeps the existing scripts directory untouched at the file
hierarchy level. All new code is under `toolkit/` and importable as
`toolkit.<subdir>.<tool>`.

### 3. NormalizedFinding — added 5 new fields, not 4

**Spec §3.1**: Adds 4 fields: `confidence`, `disposition`, `first_seen`,
`last_seen`, `verified_by`.

**Implementation**: Added all 5 fields to `nuclei-harvest.py`'s
`NormalizedFinding` dataclass + the JSON output in `save_json_report`. (The
spec's count of "four" appears to be a typo — the JSON example shows 5 new
fields: `confidence`, `disposition`, `first_seen`, `last_seen`, `verified_by`.)

The fields are added with defaults (`confidence="candidate"`,
`disposition="new"`, `verified_by=None`) so existing callers that don't set
them get pre-patch behavior. This means the patch is backwards-compatible:
existing nuclei-harvest output consumers don't break.

### 4. Finding ID — sha256 truncated to 16 hex chars

**Spec §3.1**: `"id": "sha256(source_tool+host+vuln_class_key+evidence)"`

**Implementation**: `compute_finding_id()` in `toolkit/infra/finding.py`
returns `sha256(...).hexdigest()[:16]` — 16 hex chars (64 bits). The existing
nuclei-harvest.py uses an 8-char prefix + 6-digit hash; the new tools use the
new format. Both formats are accepted by `pipeline_state.upsert_finding()`.

**Rationale**: 16 chars gives a ~1% collision probability at 6 billion
findings, which is more than enough. The shorter format is more readable in
terminal output. Collisions within a single target/scan are extremely
unlikely and would just cause two findings to share a row in
`findings_history` (the second `upsert_finding` updates the first).

### 5. apifuzz.py patch — added `replay_request` field

**Spec §5 (idor_crosssession)**: "Replays the exact captured request from
apifuzz.py under a second authenticated identity."

**Implementation**: Added a `replay_request: dict = field(default_factory=dict)`
field to `apifuzz.py`'s `APIFinding` dataclass, populated at both BOLA emission
sites (cross-user confirmed + single-session heuristic). The dict has the
shape `{method, url, headers, body}`. `idor_crosssession.py` prefers
`replay_request` when available and falls back to parsing `curl_command`
otherwise.

**Rationale**: The spec describes the replay operation but the original
`APIFinding` only stored a `curl_command` string (lossy — would require
shell-parsing to recover method/headers/body). Adding a structured field is
the minimal change that makes replay reliable. The field defaults to `{}` so
existing finding files (without `replay_request`) still load.

### 6. secret_verify.py — only reads jsreaper.py output, not js-extractor_3.py

**Spec §5 (secret_verify)**: "Input: credential_matches from any of the three
JS tools (js-extractor_3.py, jsreaper.py, recon_pipeline_v4.py)"

**Implementation**: `extract_secrets_from_findings()` handles jsreaper-style
`SecretFinding` dicts and recon_pipeline_v4-style `Secret` dataclass dicts.
For js-extractor_3.py's `credential_matches` (which stores per-pattern counts,
not raw values), the tool logs a warning and skips — without raw values, we
can't verify liveness.

**Rationale**: js-extractor_3.py's `credential_matches` field is `{pattern_name:
count}` — it tells you a secret exists but not what the secret IS. To verify
liveness, we need the actual key value. The fix is to feed `jsreaper.py`
output (which includes raw `value` + `raw_line`) into `secret_verify.py`, not
js-extractor_3.py output. The tool emits a clear warning when given
js-extractor_3.py input.

### 7. check_aws requires both access_key_id AND secret_access_key

**Spec §5 (secret_verify)**: "AWS: sts:GetCallerIdentity"

**Implementation**: `check_aws()` returns a "cannot verify" result if only
the access key ID is available (no secret). AWS SigV4 requires both halves —
the access key ID alone is useless for signing.

**Rationale**: A real-world bug bounty finding might leak only the access key
ID (e.g., `AWS_ACCESS_KEY_ID=AKIA...` in env vars without the secret). We
can't verify liveness without the secret, so we mark the finding as
"candidate" with a clear note explaining what to look for (the secret is
probably in the same JS file or nearby config).

### 8. idor_crosssession.py — uses httpx.AsyncClient directly, not AuthenticatedSession

**Spec §4.2**: "auth_profiles.py: hands any tool a ready-to-use httpx-style
session object for a named profile."

**Implementation**: `idor_crosssession.py`'s `verify_finding()` calls
`profiles.get_profile(name).auth_headers()` to get the auth headers, then
creates an `httpx.AsyncClient` directly. It does NOT use
`AuthenticatedSession` (which wraps `httpx.Client`, sync).

**Rationale**: `idor_crosssession.py` needs async (it makes 2+ concurrent
HTTP requests per finding and uses `asyncio.gather` for parallelism). The
`AuthenticatedSession` in `auth_profiles.py` wraps sync `httpx.Client`. Rather
than build a parallel async session wrapper, the verifier uses the profile's
`auth_headers()` method (which is sync, lightweight, and gives exactly what
we need) and creates its own async client. This is a one-off design choice —
future async tools should follow the same pattern.

### 9. orchestrator.py shells out to existing scripts via subprocess

**Spec §5 (orchestrator)**: "replaces WORKFLOW.md's manual 10-step process
with one entry point."

**Implementation**: Each stage function shells out to
`python3 scripts/<tool>.py` (for existing tools) or
`python3 -m toolkit.<subdir>.<tool>` (for new tools) via `subprocess.run`.
This is intentional, not a wrapper-based approach.

**Rationale**: The existing scripts are large (1.5-2.5k lines each) with their
own argparse, async main(), and rich console output. Wrapping them as library
calls would require refactoring each one's `main()` to be importable. The
subprocess approach is more robust to upstream changes (existing scripts can
be updated independently) and matches how a human would run them. The
downside is per-stage Python startup overhead (~50ms per stage) — negligible
vs. the actual scan time.

### 10. watch_daemon.py uses subprocess + JSON file diff (not direct DB triggers)

**Spec §5 (watch_daemon)**: "scheduled re-runs (cron-friendly); diffs current
asset_history against pipeline_state.db."

**Implementation**: Each cycle runs `orchestrator.py` as a subprocess, then
calls `_extract_assets_from_workdir()` to walk the produced JSON files and
extract subdomains/JS hashes/params/endpoints. These are diffed against
`pipeline_state.asset_history` via `state.diff_assets()`.

**Rationale**: Running orchestrator in-process would require importing it as
a module, but `orchestrator.py` lives at the repo root (not under `toolkit/`)
and has side-effecting module-level imports. Subprocess isolation is cleaner.
The JSON file walk is brittle (depends on each stage's output format) but
it's documented per-stage and tested.

### 11. oob_catcher.py — DNS server is minimal, not a full resolver

**Spec §5 (oob_catcher)**: "Self-hosted interactsh-compatible callback server
(DNS + HTTP)."

**Implementation**: The DNS server (`DNSHandler`) only handles A, AAAA, and
TXT queries — enough to log callbacks. It replies to A queries with
`127.0.0.1` (configurable). It does NOT do recursion, DNSSEC, or any of the
things a real resolver does. It's a callback catcher, not a resolver.

**Rationale**: A full DNS resolver is a separate project (see `dnsmasq`,
`coredns`). For OOB callback detection, we just need to log that a query
happened + extract the callback ID from the query name. The minimal
implementation is ~200 lines of stdlib `socketserver` and is easy to audit.

### 12. apk_static.py — uses ElementTree (not lxml)

**Spec §5 (apk_static)**: "Reuses the secret-regex + entropy engine from
secret_verify.py's normalization layer against decompiled Smali/strings.xml/
AndroidManifest.xml."

**Implementation**: AndroidManifest.xml is parsed with stdlib
`xml.etree.ElementTree`. Smali and strings.xml are scanned line-by-line with
regex.

**Rationale**: Stdlib only — matches the rest of the toolkit. The Android
namespace (`http://schemas.android.com/apk/res/android`) is handled
explicitly via `f"{{{_ANDROID_NS}}}"` attribute lookups. apktool's decoded
manifest is plain XML (not binary AXML), so ElementTree handles it fine.

### 13. xss_context.py — uses `verify_endpoint` not `verify_one_request`

**Spec §5 (xss_context)**: "context-aware payload selection (HTML body vs.
attribute vs. `<script>` vs. URL — not blind-fire)."

**Implementation**: Two-stage per endpoint: (1) send a probe value, (2)
detect which contexts it landed in, (3) fire ONE payload per detected context.
The `_detect_contexts()` function uses a stack-based heuristic (count
`<script>` opens vs. closes in the preceding 200 chars) to detect
script-block context, plus quote-tracking for JS-string context.

**Rationale**: The original spec implies "one payload per context" but
doesn't specify the detection logic. The stack-based approach handles nested
contexts (e.g., a probe inside a JS string inside a script block) better than
the simpler "look at the immediately preceding tag" approach. It's still
heuristic — a real browser-quality parser would be more accurate but would
require BeautifulSoup or lxml.

### 14. Test suite uses pytest fixtures + mock HTTP server

**Spec**: doesn't specify testing approach.

**Implementation**: 139 tests in `toolkit/tests/`. The `conftest.py` defines
a `mock_http_server` fixture (ThreadingHTTPServer with configurable routes)
used by integration tests for `idor_crosssession.py`, `xss_context.py`,
`oob_catcher.py`. Unit tests cover scope matching, UUID neighbor generation,
JWT validation, schema normalization, anomaly detection, etc.

**Rationale**: User chose "Full suite" (unit + integration with mock HTTP
server). pytest is the standard Python testing framework. The mock server
lets us test the live-HTTP code paths without external dependencies.

## Things deferred (per spec §8 Tier 4)

These are implemented but not yet integrated into the orchestrator's deep
mode by default — they're conditional stages the user opts into:

- `apk_static.py` — only runs when `--apk-dir` is provided
- `oob_catcher.py` — runs as a standalone server, not as a pipeline stage

## Things NOT implemented (out of scope for this pass)

- **MCP server / IDE integration** — not in the spec
- **Burp/Caido plugin** — not in the spec
- **Slack/Discord alerts** — `subtakeover10.py` has `--webhook` already;
  extending this to all tools would require a shared notifier module (future
  work)
- **Schema validation against `finding.schema.json`** — the schema is shipped
  for documentation; runtime validation isn't enforced (would require adding
  `jsonschema` as a dependency)

## Test results

```
$ python -m pytest toolkit/tests/ --tb=short
============================= 139 passed in 4.47s ==============================
```

Coverage:

- `test_scope_guard.py` (10 tests) — wildcard, CIDR, deny-wins, automation
  flag, rate limiting, blocked.log, request_slot context manager
- `test_auth_profiles.py` (10 tests) — load profiles, auth_headers for
  bearer/cookie/api_key, redaction, two-user requirement, refresh callback
- `test_pipeline_state.py` (11 tests) — upsert/dedup, disposition filtering,
  severity sort, run tracking, asset diff
- `test_finding.py` (12 tests) — compute_finding_id stability, defaults,
  passthrough, normalize for apifuzz/paramfuzz/ssrfprobe/subtakeover/jsreaper
- `test_triage_memory.py` (13 tests) — load_final_json, severity sort,
  submitted/rejected filtering, writeup generation (h1 + bc), batch CSV
- `test_idor_crosssession.py` (15 tests) — BOLA filtering, curl parsing,
  UUIDv1 neighbors, three-way verdict, end-to-end against mock server
- `test_secret_verify.py` (19 tests) — provider detection for all 6
  providers, placeholder detection, JWT validation (expired/no-exp/alg-none),
  extract from redacted value, build_verified_findings
- `test_tools_e2e.py` (49 tests) — xss_context detection/payload, spa_router
  for Next/Nuxt/React/Vue, anomaly baseline, graphql suggestions, upload
  endpoint discovery, apk_static manifest parsing, oob_catcher store

## File inventory

```
SubTakeover/
├── ARCHITECTURE.md                   # original spec (uploaded)
├── QUICKSTART.md                     # NEW — 5-command getting-started
├── WORKFLOW.md                       # NEW — replaces old WORKFLOW.md
├── IMPLEMENTATION_NOTES.md           # NEW — this file
├── orchestrator.py                   # NEW — top-level pipeline entry
├── watch_daemon.py                   # NEW — continuous monitoring
├── scope.yaml                        # NEW — minimal default (localhost)
├── auth_profiles.yaml                # NEW — minimal default (dummy cookies)
├── .gitignore                        # NEW
├── scripts/                          # existing scripts (3 patched)
│   ├── nuclei-harvest.py             # PATCHED — new schema fields
│   ├── apifuzz.py                    # PATCHED — replay_request field
│   ├── jsreaper.py                   # PATCHED — --scope/--cookie/--auth-profiles flags
│   ├── subtakeover10.py
│   ├── reconharvest.py
│   ├── headeraudit.py
│   ├── 4xxbypass.py
│   ├── paramfuzz.py
│   ├── cloudexpose.py
│   ├── ssrfprobe.py
│   ├── oauthprobe.py
│   ├── gitdump.py
│   ├── js-extractor_3.py
│   └── recon_pipeline_v4.py
└── toolkit/                          # NEW — all 14 new tools
    ├── __init__.py
    ├── infra/
    │   ├── __init__.py
    │   ├── scope_guard.py            # Layer 0
    │   ├── auth_profiles.py          # Layer 0
    │   ├── pipeline_state.py         # Layer 0
    │   ├── finding.py                # Layer 0 — NormalizedFinding + normalize_finding_dict
    │   └── schemas/
    │       └── finding.schema.json   # JSON Schema for the finding shape
    ├── verify/
    │   ├── __init__.py
    │   ├── triage_memory.py          # Tier 1
    │   ├── idor_crosssession.py      # Tier 1
    │   ├── secret_verify.py          # Tier 2
    │   └── xss_context.py            # Tier 2
    ├── discover/
    │   ├── __init__.py
    │   └── spa_router.py             # Tier 2
    ├── testers/
    │   ├── __init__.py
    │   ├── graphql_deep.py           # Tier 4
    │   ├── upload_probe.py           # Tier 4
    │   ├── apk_static.py             # Tier 4 (conditional)
    │   └── anomaly_baseline.py       # Tier 4
    ├── infra_ext/
    │   ├── __init__.py
    │   └── oob_catcher.py            # Tier 4 (infra_ext)
    ├── configs/
    │   ├── scope.example.yaml
    │   └── auth_profiles.example.yaml
    └── tests/
        ├── __init__.py
        ├── conftest.py               # mock HTTP server + fixtures
        ├── test_scope_guard.py       # 10 tests
        ├── test_auth_profiles.py     # 10 tests
        ├── test_pipeline_state.py    # 11 tests
        ├── test_finding.py           # 12 tests
        ├── test_triage_memory.py     # 13 tests
        ├── test_idor_crosssession.py # 15 tests
        ├── test_secret_verify.py     # 19 tests
        └── test_tools_e2e.py         # 49 tests
```
