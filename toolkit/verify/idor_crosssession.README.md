# idor_crosssession

Cross-session BOLA/IDOR verification. `apifuzz.py` flags BOLA candidates with `test_type="BOLA"` — but with only one session it can only say "this might be a problem." This tool takes apifuzz.py's BOLA candidates + `auth_profiles.yaml` (≥2 non-anon profiles), replays the captured request under user_b's session, and produces a three-way verdict: user_b gets 200 + user_a's data → IDOR CONFIRMED; user_b gets 200 + empty/generic data → false positive (shared/public); user_b gets 403/401 → correctly access-controlled. For confirmed IDORs, sweeps a small window of adjacent sequential IDs (or UUIDv1-neighboring IDs — the elite-workflow technique of incrementing the time_low timestamp) to estimate blast radius. Findings promoted from `candidate` → `confirmed` get `verified_by="idor_crosssession.py"` so downstream tools know not to re-flag them.

## Layer / Tier
Tier 1 verify. Layer 4 in the pipeline (live replay stage).

## Depends on
- `toolkit.infra.auth_profiles` — `AuthProfiles`, `redact_dict`, `redact_value`. Requires ≥2 authenticated profiles.
- `toolkit.infra.finding` — `NormalizedFinding`, `compute_finding_id`, `normalize_finding_dict`.
- `toolkit.infra.pipeline_state` — `PipelineState` for `upsert_finding()`.
- `toolkit.infra.scope_guard` — `ScopeGuard` for scope + rate-limit enforcement on every replay.
- `httpx` (required for async replay — no urllib fallback in this tool).

## Feeds into
- `idor-verified.json` — updated findings JSON with `confidence`, `verified_by`, and (for confirmed) `severity=CRITICAL` + `vuln_class_key=BOLA_CONFIRMED`.
- `pipeline_state.db.findings_history` — every verified finding is upserted.
- Downstream: `triage_memory.py` (filtered queue), `nuclei-harvest.py` (final aggregation).

## Usage

```bash
python -m toolkit.verify.idor_crosssession \
    --input api-findings.json \
    --auth-profiles auth_profiles.yaml \
    --scope scope.yaml \
    --output idor-verified.json

# Parse + filter only, no live requests
python -m toolkit.verify.idor_crosssession --input api-findings.json \
    --auth-profiles auth_profiles.yaml --dry-run
```

## Library use
```python
import asyncio
from toolkit.verify.idor_crosssession import filter_bola_candidates, verify_all, build_verified_findings
from toolkit.infra.auth_profiles import AuthProfiles
from toolkit.infra import scope_guard

findings = [...]  # apifuzz.py output
candidates = filter_bola_candidates(findings)
profiles = AuthProfiles("auth_profiles.yaml")
guard = scope_guard.ScopeGuard("scope.yaml")
results = asyncio.run(verify_all(candidates, profiles, guard, max_blast=5, concurrency=5))
verified = build_verified_findings(findings, results)
```

## Input / Output
- **Input:** apifuzz.py output JSON (list or `{"findings": [...]}`), filtered to `test_type="BOLA"` or `vuln_class_key in (BOLA_POSSIBLE, BOLA_CONFIRMED)` or title containing `BOLA`/`IDOR`. Each candidate's `curl_command` is parsed back into method/URL/headers/body via `parse_curl_command()`.
- **Output:** `idor-verified.json` with `scan_time`, `candidates`, `results` (per-finding verdict + blast radius + body similarity), and `findings` (the merged normalized findings). Logged summary: `confirmed=X false_positive=Y access_controlled=Z inconclusive=W`.
- **Side effects:** Live HTTP requests to the target host (rate-limited via `scope_guard`). Writes to `pipeline_state.db`. Two rate-limit tokens consumed per finding (user_a replay + user_b replay) + one per neighbor-ID swept.

## Key classes / functions
| Name | Purpose |
|---|---|
| `ReplayResult` | `dataclass(finding_id, user_a_status, user_a_body_hash, user_b_status, user_b_body_hash, body_similarity, verdict, blast_radius, evidence)`. |
| `filter_bola_candidates(findings)` | Filter apifuzz output to BOLA candidates only. |
| `parse_curl_command(curl)` | Best-effort shlex parse of apifuzz's `_build_curl()` output → `{method, url, headers, body}`. |
| `gen_neighbor_ids(current_id, count)` | Generate IDs to test blast radius. Integer: ±1,±2,±5. UUIDv1: increment time_low by ±1,±2,±5 ticks. UUIDv4: returns `[]` (no useful neighbors). |
| `verify_finding(finding, profiles, guard, max_blast)` | One finding → one `ReplayResult`. Strips auth headers from the parsed request, builds fresh ones from each profile. |
| `verify_all(findings, profiles, guard, ...)` | Bounded-concurrency wrapper around `verify_finding()`. |
| `build_verified_findings(findings, results)` | Merge verdicts back into NormalizedFindings: `confirmed` → `confidence=confirmed`, `severity=CRITICAL`, `vuln_class_key=BOLA_CONFIRMED`; `false_positive` → `disposition=rejected`; `access_controlled` → `confidence=probable`. |

## Configuration
- `--input` (required): apifuzz.py output JSON.
- `--auth-profiles` (required): `auth_profiles.yaml` path.
- `--scope` (recommended): `scope.yaml` for live replay. Falls back to the module default (permissive) if omitted.
- `--max-blast` (default 5): max neighbor IDs to test for blast radius.
- `--concurrency` (default 5): max concurrent verifications.
- `--dry-run`: parse + filter only, no live requests.

## Safety notes
- Read-only HTTP methods only (GET/POST/PUT/PATCH/DELETE replayed as captured — never invents destructive calls). The replay uses the EXACT method + body from apifuzz's `curl_command`; if apifuzz captured a `DELETE`, this tool will replay a `DELETE` under user_b's session.
- The blast-radius sweep uses GET only — it does NOT replay mutations against neighbor IDs.
- `scope_guard` enforces scope on every replay URL and every swept URL. Out-of-scope neighbors are skipped silently.
- TLS verification is OFF (`verify=False`) on the async client to match the existing toolkit pattern.

## See also
- ARCHITECTURE.md §4 (Tier 1 verification) and §6 (BOLA verification flow)
- Related tools: `auth_profiles.py` (sessions), `apifuzz.py` (upstream BOLA candidates), `triage_memory.py` (downstream consumer)
