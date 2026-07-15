# secret_verify

Verifies liveness of secrets harvested from JS / git dumps. JS tools (`js-extractor_3.py`, `jsreaper.py`, `recon_pipeline_v4.py`) all emit secret candidates — but a regex match is not a vuln. The key could be dead/rotated, a placeholder (`AKIAEXAMPLE`, `ghp_testtest...`), a public test key documented in API docs, or a live key with real account access. This tool does ONE thing per finding: a single read-only API call against the provider to confirm the key's identity. Findings with live keys get `confidence=confirmed` + `verified_by`. Findings with dead/placeholder keys get `disposition=rejected`.

Per-provider checks (all read-only, all non-mutating):
- AWS access key: `sts:GetCallerIdentity` (SigV4 signed GET, stdlib only — no boto3).
- GitHub PAT / fine-grained: `GET /user`.
- Slack bot/user token: `auth.test`.
- Stripe secret key: `GET /v1/balance`.
- Google API key: `GET maps.googleapis.com/maps/api/geocode/json` (free endpoint).
- GitLab PAT, Twilio API key: identity endpoint.
- Generic JWT: signature + expiry check only (can't verify against issuer without the secret); flags expired JWTs as dead, `alg=none` JWTs as suspicious.

## Layer / Tier
Tier 2 verify. Layer 4 in the pipeline (live provider call stage).

## Depends on
- `toolkit.infra.finding` — `NormalizedFinding`, `compute_finding_id`, `normalize_finding_dict`.
- `toolkit.infra.pipeline_state` — `PipelineState` for `upsert_finding()`.
- `toolkit.infra.scope_guard` — `ScopeGuard` for rate-limit tokens on each provider call.
- `httpx` (preferred) or `urllib.request` (fallback).
- Python stdlib: `hmac`, `hashlib`, `base64`, `datetime`, `asyncio`, `re`.

## Feeds into
- `secret-verified.json` — updated findings JSON with `confidence`, `verified_by`, and (for dead keys) `disposition=rejected`.
- `pipeline_state.db.findings_history` — every verified secret is upserted.
- Downstream: `apk_static.py` (re-uses `_PROVIDER_PATTERNS`, `_looks_like_placeholder`, `_detect_provider` from this module).

## Usage

```bash
python -m toolkit.verify.secret_verify \
    --input js-findings.json \
    --output secret-verified.json \
    --scope scope.yaml
```

## Library use
```python
from toolkit.verify.secret_verify import extract_secrets_from_findings, _detect_provider, _looks_like_placeholder, _redact
from toolkit.verify.secret_verify import check_aws, check_github_pat, check_slack  # etc.

secrets = extract_secrets_from_findings(raw_jsreaper_findings)
for s in secrets:
    provider = _detect_provider(s["raw_value"])
    if provider and not _looks_like_placeholder(s["raw_value"]):
        result = await check_provider_specific(s["raw_value"])
        # result.is_live → confidence=confirmed, verified_by=secret_verify.py
```

## Input / Output
- **Input:** Any of the three JS tools' output JSON. Normalizes their different shapes (`credential_matches`, `secrets[]` with `secret_type`/`value`/`raw_line`, or `Secret` dataclass with `type_`/`label`/`value`). jsreaper redacts `value` (replaces middle with `…`); this tool re-extracts the raw value from `raw_line` using `_PROVIDER_PATTERNS`.
- **Output:** `secret-verified.json` with `scan_time`, `results` (per-secret liveness check), and `findings` (merged normalized findings with `confidence`/`disposition` updated).
- **Side effects:** One read-only API call per live-looking secret to the provider's identity endpoint. Rate-limited via `scope_guard`. AWS check requires both access key AND secret — access-key-only findings are flagged with a detail explaining the secret must be located nearby. Writes to `pipeline_state.db`.

## Key classes / functions
| Name | Purpose |
|---|---|
| `SecretCheck` | `dataclass(raw_value, provider, is_live, identity, detail, redacted_value)`. |
| `_PROVIDER_PATTERNS` | Ordered dict of provider name → regex. Order matters: prefixed patterns (AKIA, ghp_, xoxb-, sk_live_) before generic catch-alls (40-char base64, 40-char hex). |
| `_PLACEHOLDERS` | Known example values (`AKIAEXAMPLE`, `wJalrXUtnFEMI/...EXAMPLEKEY`, etc.) — never reported as live. |
| `_detect_provider(value)` | Return provider name matching value, or `None`. |
| `_looks_like_placeholder(value)` | True if value is in `_PLACEHOLDERS` or contains `example`/`testtest`/`placeholder`/`your_key`/etc. |
| `extract_secrets_from_findings(findings)` | Normalize the three upstream shapes → unified list of `{raw_value, source_tool, host, js_url, context, original_finding}`. |
| `check_aws(access_key, secret_key)` | SigV4-signed `sts:GetCallerIdentity`. Returns the caller ARN on success. |
| `check_github_pat`, `check_slack`, `check_stripe`, `check_google_api_key`, `check_gitlab_pat`, `check_twilio`, `check_jwt` | Per-provider read-only liveness checks. |
| `_redact(value)` | Mask all but the first 4 and last 4 chars for logging. |

## Configuration
- `--input` (required): JS tool output JSON.
- `--output` (default `secret-verified.json`).
- `--scope`: `scope.yaml` for rate-limit enforcement on provider calls.
- `--db` (default `pipeline_state.db`).
- No env vars. AWS SigV4 implementation is stdlib-only — no AWS credentials needed beyond the ones being verified.

## Safety notes
- EVERY provider check is explicitly read-only. AWS uses `sts:GetCallerIdentity` (identity only, no resource access). GitHub uses `GET /user`. Slack uses `auth.test`. Stripe uses `GET /v1/balance`. None of these mutate state, list resources beyond the caller identity, or expose data beyond what the key owner already sees.
- This tool MUST NEVER be extended to use a live key beyond identity confirmation. Each provider check is documented inline so future maintainers can audit it.
- JWT verification is signature/expiry only — no calls to the issuer. Expired JWTs are flagged dead, `alg=none` JWTs are flagged suspicious.
- Placeholder detection runs before any provider call — `AKIAEXAMPLE` and similar documented examples never trigger a network request.

## See also
- ARCHITECTURE.md §4.2 (secret verification) and §Safety (read-only constraint)
- Related tools: `jsreaper.py` (upstream producer), `apk_static.py` (re-uses `_PROVIDER_PATTERNS`), `triage_memory.py` (downstream consumer)
