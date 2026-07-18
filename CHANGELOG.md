# Changelog

All notable changes to the Bug Bounty Toolkit are documented here. The format
is based on [Keep a Changelog](https://keepachangelog.com/); this project
adheres to no fixed version cadence (MIT, authorized-use only).

## [Unreleased]

### Added
- **Toolkit stages** (`toolkit/`): composable, importable modules replacing
  duplicated logic across the standalone scripts (ADR 0001).
- **Normalized finding schema** (`toolkit/infra/finding.py`) — single canonical
  shape for all results (ADR 0002).
- **Shared reporter** (`toolkit/infra/reporter.py`): render findings as
  HackerOne / Bugcrowd markdown, CSV, and SARIF 2.1.0 (C19).
- **JSON logging** (`toolkit/infra/logfmt.py`) + `--log-format json` on the core
  tools apifuzz / ssrfprobe / jsreaper / paramfuzz / reconharvest (C20).
- **Per-target config** (`toolkit/infra/config.py`) + `--config FILE` on
  apifuzz / jsreaper; YAML defaults applied only when the CLI flag is unset (C21).
- **`--user-agent` override** on apifuzz / ssrfprobe / jsreaper / paramfuzz /
  reconharvest (C18).
- **apifuzz `--session-a` shape detection**: JWT/Bearer/Basic/Cookie/Raw are
  auto-classified; cookie-shaped tokens are sent as a `Cookie:` header (C16).
- **ssrfprobe `--oob-dns-only`**: DNS-resolution-only OOB probes (no HTTP
  listener) for locked-down environments (C17).
- **cache_poisoning unkeyed query-param probing**: `--unkeyed-params` /
  `--param` to detect cache keys that ignore parameters, not just headers (C25).
- **`pipeline_state`** FTS5 full-text search, `sqlite3.backup` snapshot +
  RLock thread-safety, and synonym expansion for finding search (C1, C2, C29).
- **scope_guard** DNS-resolved CIDR exclusion and `map_scope()` host→scope
  mapping with a `map` CLI (C3, C15).
- **triage_memory** interactive triage (open/copy/full) and date-range filters
  (C4, C14).
- **secret_verify / idor_crosssession** PUT/PATCH curl parsing and a provider
  registry with entry points (C5, C6).
- **spa_router** `Route.params` auto-derivation and typed param parsers (C7).
- **apk_static** `--apk-file` androguard scan and **ipa_static** iOS `.ipa`
  analysis (C8, C9).
- **oob_catcher** TCP + DNS server with query logging and webhook forwarding
  (C10–C12).
- **orchestrator** `verify --dry-run` honors `--stages` subset; verify engine
  ports from `ports.py` (C13).

### Fixed
- `#1` Double-run / runaway scheduler fixed in `watch_daemon.py` (committed,
  pushed).
- `#2` `orchestrator verify` silent failure surfaced with clear error (committed,
  pushed).
- `#4` Chatty scheduler heartbeat reduced (committed, pushed).

### Docs
- `CONTRIBUTING.md`, PR template, and Architecture Decision Records under
  `docs/adr/` (C26, C27).
