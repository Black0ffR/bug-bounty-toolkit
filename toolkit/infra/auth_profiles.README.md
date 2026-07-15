# auth_profiles

Loads `auth_profiles.yaml` and hands any tool a ready-to-use httpx-style session object for a named profile, instead of each tool parsing its own `--cookie` / `--session` string. Supports profile switching mid-script (`get_session("user_b")` → fresh client with that profile's cookies/headers/bearer preconfigured), auto-refresh hooks for short-lived tokens, and secret redaction in logs (any value >12 chars from `cookie`/`bearer`/`api_key`/`password` is masked). Falls back to a `urllib.request` wrapper exposing the same `.get/.post/.put/.patch/.delete/.request` surface when `httpx` is unavailable.

## Layer / Tier
Layer 0 infra. No upstream dependencies (besides reusing `scope_guard._fallback_yaml_parse`).

## Depends on
- `toolkit.infra.scope_guard._fallback_yaml_parse` — restricted-subset YAML parser fallback.
- Optional: `pyyaml` for full YAML parsing.
- Optional: `httpx` — preferred HTTP backend. Falls back to `urllib.request` if missing.

## Feeds into
- `apifuzz.py` (after patching), `idor_crosssession.py` (requires ≥2 authenticated profiles for BOLA verification), `oauthprobe.py`, `paramfuzz.py`, any tool needing authenticated requests.

## Usage

```bash
# Smoke test: load profiles, print one
python -m toolkit.infra.auth_profiles auth_profiles.yaml user_a
# profile user_a: user_id=8841 role=admin
# auth headers (redacted): {'Authorization': 'Bear…<redacted>'}
```

## Library use
```python
from toolkit.infra.auth_profiles import AuthProfiles

profiles = AuthProfiles("auth_profiles.yaml")
sess_a = profiles.get_session("user_a")
sess_b = profiles.get_session("user_b")
resp_a = sess_a.get("https://api.target.com/v1/users/8841")
resp_b = sess_b.get("https://api.target.com/v1/users/8841")
# If resp_b has user_a's data → IDOR confirmed.

# For IDOR comparisons requiring two distinct users:
prof_a, prof_b = profiles.require_two_users()
```

## Input / Output
- **Input:** `auth_profiles.yaml` with `profiles:` mapping of name → `{cookie, headers, bearer, api_key, user_id, role, email}`. See `toolkit/configs/auth_profiles.example.yaml`.
- **Output:** `AuthenticatedSession` instances from `get_session()`. CLI smoke-test prints redacted profile metadata.
- **Side effects:** None persistent. Logs at DEBUG with redacted request metadata (`REQ <method> <url> as=<profile> headers=<redacted>`). An `anon` profile is auto-created if not present.

## Key classes / functions
| Name | Purpose |
|---|---|
| `AuthProfiles` | Loads the YAML once. `get_session(name)` returns an `AuthenticatedSession`; `require_two_users()` returns `(user_a, user_b)` for IDOR tests. |
| `Profile` | Dataclass holding `cookie`, `headers`, `bearer`, `api_key`, `user_id`, `role`, `email`, optional `refresh_callback`. `auth_headers()` builds the merged Authorization/Cookie header set; `maybe_refresh()` re-invokes the callback if cached bearer is stale. |
| `AuthenticatedSession` | httpx-style wrapper; auto-injects profile auth headers on every request. Context-manager friendly (`with profiles.get_session("user_a") as s: ...`). |
| `redact_value(key, value)` / `redact_dict(d)` | Mask sensitive fields for logging. |
| `configure(path)` / `get_default()` / `get_session(name)` | Module-level singleton helpers. |

## Configuration
- `auth_profiles.yaml` (path passed to constructor or `configure()`).
- Per-profile optional `refresh_callback: Callable[[], str]` registered programmatically — invoked when cached bearer is older than `max_age` (default 1800s).
- Session defaults: `timeout=15.0`, `verify=False`, `follow_redirects=True`, `User-Agent: Mozilla/5.0 (compatible; ToolkitAuth/1.0)`.

## Safety notes
- Secrets are redacted in all log output via `redact_dict()`. The CLI smoke-test prints redacted auth headers only.
- TLS verification is OFF by default (`verify=False`) to match the existing toolkit pattern; flip per-call via `get_session(name, verify=True)`.
- The `urllib` fallback creates a fresh SSL context per request — no connection pooling.

## See also
- ARCHITECTURE.md §Layer 0 (auth profiles)
- `toolkit/configs/auth_profiles.example.yaml`
- Related tools: `scope_guard.py`, `idor_crosssession.py` (consumer)
