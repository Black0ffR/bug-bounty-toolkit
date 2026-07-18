# Architecture Decision Records

This directory captures significant architectural decisions for the Bug Bounty
Toolkit. Format follows the lightweight ADR style (title, status, context,
decision, consequences).

- [ADR 0001](0001-toolkit-stages-composable-modules.md) — Split monolith tools into composable `toolkit/` stages
- [ADR 0002](0002-normalized-finding-schema.md) — Canonical normalized finding schema
- [ADR 0003](0003-network-off-by-default.md) — Exploit/offensive actions are opt-in only
- [ADR 0004](0004-shared-infra-modules.md) — Shared `toolkit/infra/*` for cross-cutting concerns
