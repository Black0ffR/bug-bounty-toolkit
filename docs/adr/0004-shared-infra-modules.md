# ADR 0004: Shared `toolkit/infra/*` cross-cutting modules

- Status: Accepted
- Date: 2026-07-18

## Context
Several cross-cutting concerns (logging format, per-target config, finding
normalization, reporting, OOB capture, scope) were reimplemented per tool.

## Decision
Centralize cross-cutting utilities in `toolkit/infra/`:
`logfmt.py` (JSON/text logging), `config.py` (YAML overlay), `finding.py`
(normalized schema), `reporter.py` (multi-format reports), `scope_guard.py`,
`oob_catcher.py`. Tools import these with a safe `try/except` fallback so they
still run standalone without the `toolkit` package on `PYTHONPATH`.

## Consequences
- One implementation per concern; consistent behavior across tools.
- Standalone scripts remain runnable outside the package (fallback paths).
- New tools get logging/config/reporting "for free" via the shared modules.
