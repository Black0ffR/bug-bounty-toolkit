# scope_guard

Single import every tool calls before firing a request. Reads `scope.yaml` once at startup, exposes a stateless `check_scope(host)` call, and provides a process-wide token-bucket rate limiter so concurrently-running tools don't collectively blow past a program's stated rate limit. Hard-fails (raises `ScopeError`) on out-of-scope targets — never silently proceeds. Deny-wins (`out_of_scope` overrides `in_scope`), matching HackerOne/Bugcrowd policy semantics. Supports wildcard subdomain matching and IP/CIDR scope entries. Pure stdlib.

## Layer / Tier
Layer 0 infra. No upstream dependencies. Used by every Layer 1-5 tool.

## Depends on
- Python stdlib only (`re`, `ipaddress`, `threading`, `time`, `pathlib`, `json`, `os`, `sys`, `datetime`, `logging`).
- Optional: `pyyaml` for full YAML parsing. Falls back to an inline restricted-subset parser (`_fallback_yaml_parse`) when PyYAML is missing — sufficient for `scope.yaml`'s top-level mapping + list syntax.

## Feeds into
- Every Layer 1-5 tool: `apifuzz.py`, `idor_crosssession.py`, `oauthprobe.py`, `paramfuzz.py`, `xss_context.py`, `spa_router.py`, `graphql_deep.py`, `upload_probe.py`, `secret_verify.py`, etc.
- Writes `blocked.log` next to `scope.yaml` with timestamp/host/source_tool/reason tuples for every rejected request.

## Usage

```bash
python -m toolkit.infra.scope_guard --help   # (no argparse — see smoke-test below)
python -m toolkit.infra.scope_guard scope.yaml www.acme.com evil.com
# OK   www.acme.com
# FAIL evil.com  (evil.com is not in any in_scope entry)
```

## Library use
```python
from toolkit.infra.scope_guard import ScopeGuard, ScopeError

guard = ScopeGuard("scope.yaml")          # load once
guard.check_scope("www.acme.com")          # raises ScopeError if OOS
guard.acquire_token()                       # blocks until rate-limit slot free
try:
    ...  # do request
finally:
    guard.release_token()

# Recommended: context manager combines scope check + rate-limit slot
with guard.request_slot("www.acme.com", source_tool="apifuzz.py"):
    ...  # do request

# Or use the module-level singleton
from toolkit.infra import scope_guard
scope_guard.configure("scope.yaml")
scope_guard.check_scope("www.acme.com", source_tool="apifuzz.py")
```

## Input / Output
- **Input:** `scope.yaml` with `program`, `in_scope: []`, `out_of_scope: []`, `rate_limit: {max_rps, max_concurrent}`, `automation_allowed`. See `toolkit/configs/scope.example.yaml`.
- **Output:** None in normal operation. Side-effects only.
- **Side effects:** Appends to `blocked.log` next to the scope file. Logs at INFO when loaded, WARNING when a host is blocked, WARNING if `automation_allowed=false`.

## Key classes / functions
| Name | Purpose |
|---|---|
| `ScopeGuard` | Load once, call `check_scope(host)` / `check_url(url)` / `request_slot(host)` per request. Thread-safe after construction. |
| `ScopeError` | `RuntimeError` subclass raised on out-of-scope targets, invalid config, or `automation_allowed=false`. |
| `_RateLimit` | Token-bucket state with `max_rps` and `max_concurrent` enforcement. |
| `request_slot(host)` | Context manager: scope-checks then acquires/releases a rate-limit token. |
| `configure(path)` / `get_default()` / `check_scope(host)` | Module-level singleton helpers for tools that don't manage their own instance. |
| `_fallback_yaml_parse(text)` | Restricted-subset YAML parser used when PyYAML is unavailable; also re-exported for `auth_profiles.py`. |

## Configuration
- `scope.yaml` (path passed to constructor or `configure()`). Required fields: `in_scope` (list of hostnames / wildcards / CIDRs).
- Optional `rate_limit.max_rps` (default 5.0), `rate_limit.max_concurrent` (default 10), `automation_allowed` (default true).
- No env vars. Multi-process rate-limit enforcement is best-effort via `flock` on `/tmp/scope_guard.bucket` (Termux: `$TMPDIR`).

## Safety notes
- This is the scope enforcement gate — by design it FAILS CLOSED. `automation_allowed=false` makes every `check_scope()` raise, even for hosts that match `in_scope`.
- The rate limiter is per-process; cross-process enforcement uses file-lock + flock as a fallback. For multi-host scanning run one orchestrator process per program.
- `check_scope()` does NOT make network calls. `request_slot()` only gates local thread state.

## See also
- ARCHITECTURE.md §Layer 0 (scope + rate-limit)
- `toolkit/configs/scope.example.yaml`
- Related tools: `auth_profiles.py`, `pipeline_state.py` (other Layer 0 infra)
