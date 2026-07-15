# pipeline_state

Thin SQLite wrapper around `pipeline_state.db` providing cross-run persistence for the bug bounty pipeline. Three tables: `findings_history` (every normalized finding's id, first_seen/last_seen, disposition: `new | reviewed | submitted | rejected | duplicate_of`), `asset_history` (subdomains, JS hashes, params, CNAME chains, endpoints observed per scan — for diffing), `scan_runs` (one row per orchestrator invocation with stages completed/failed). Also a `triage_decisions` audit log of every disposition change. Generalizes the existing `subtakeover10.py` `DatabaseManager` pattern pipeline-wide; the same DB file is deliberately shared between `triage_memory.py` and `watch_daemon.py`.

## Layer / Tier
Layer 0 infra. No upstream dependencies (stdlib `sqlite3` only). Depended on by `triage_memory.py`, `watch_daemon.py`, `orchestrator.py`, every verify/tester tool that calls `upsert_finding()`.

## Depends on
- Python stdlib: `sqlite3`, `threading`, `datetime`, `json`, `logging`, `pathlib`, `dataclasses`.

## Feeds into
- `triage_memory.py` (reads/writes `findings_history`, `triage_decisions`).
- `watch_daemon.py` (reads/writes `asset_history` for diffing).
- `orchestrator.py` (writes `scan_runs`).
- Every Tier 1-4 tool that calls `upsert_finding()` after producing a normalized finding.

## Usage

```bash
# Smoke test: print counts by disposition + top 10 active findings
python -m toolkit.infra.pipeline_state pipeline_state.db
# counts by disposition: {'new': 17, 'submitted': 4, 'rejected': 2}
#   [HIGH    ] abc123def456...  BOLA confirmed cross-session
#   ...
```

## Library use
```python
from toolkit.infra.pipeline_state import PipelineState

state = PipelineState()  # defaults to ./pipeline_state.db
state.upsert_finding({
    "id": "abc123", "source_tool": "apifuzz.py", "host": "api.target.com",
    "vuln_class_key": "BOLA_POSSIBLE", "severity": "HIGH",
    "title": "...", "first_seen": "...", "last_seen": "...",
    "confidence": "candidate", "disposition": "new",
})
state.mark_disposition("abc123", "submitted", decided_by="alice", note="sent to H1")
state.get_active_findings()  # excludes submitted/rejected

state.record_assets("acme.com", subdomains=["www.acme.com", "api.acme.com"])
state.diff_assets("acme.com", subdomains=["www.acme.com", "new.acme.com"])
# → {"subdomain": AssetDiff(added=["new.acme.com"], removed=[], unchanged=["www.acme.com"])}
```

## Input / Output
- **Input:** `pipeline_state.db` (created on first run). Schema is idempotent — `CREATE TABLE IF NOT EXISTS` on construction.
- **Output:** CLI smoke-test prints disposition counts + top 10 active findings. Library returns `dict`/`list` from query methods.
- **Side effects:** Creates/updates `pipeline_state.db`. All writes are serialized through a single `threading.Lock`; the connection is opened with `check_same_thread=False` so the same instance can be shared across worker threads.

## Key classes / functions
| Name | Purpose |
|---|---|
| `PipelineState` | Main class. `upsert_finding(f)` returns True if new; `mark_disposition(id, disp)`; `get_active_findings()`; `get_findings_by_host(host)`; `count_findings()`. Asset history: `record_assets()`, `diff_assets()`, `get_asset_history()`. Scan runs: `start_run()`, `update_run()`, `get_last_run()`. |
| `AssetDiff` | `dataclass(added, removed, unchanged)` — output of `diff_assets()`. |
| `SCHEMA_SQL` | Full DDL — 4 tables + indexes. Edit to extend the schema. |
| `get_default()` / `configure(db_path)` | Module-level singleton (defaults to `./pipeline_state.db`). |

## Configuration
- `db_path` (constructor arg or `--db` flag on consumer CLIs). Default: `pipeline_state.db` next to the scripts dir.
- No env vars. SQLite timeout is 10s for cross-thread contention.

## Safety notes
- Read-write against a local SQLite file. No network calls.
- `upsert_finding()` uses parameterized queries throughout; no string interpolation of finding content.
- Connection is closed on `__exit__` / `close()` — use as a context manager in long-running tools.

## See also
- ARCHITECTURE.md §3.2 (pipeline state schema)
- Related tools: `finding.py` (NormalizedFinding shape), `triage_memory.py` (primary consumer)
