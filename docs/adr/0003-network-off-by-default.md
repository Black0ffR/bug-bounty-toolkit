# ADR 0003: Offensive actions are opt-in only

- Status: Accepted
- Date: 2026-07-18

## Context
The toolkit performs active testing: parameter injection, SSRF probes, exploit
verification. Shipped by default, those payloads could be misused or cause
unintended harm against non-consenting targets.

## Decision
Destructive / clearly-offensive behavior is gated behind explicit flags
(`--exploit`, `--verify`, `--session-b`, OOB server opt-in, ...). Default runs
are detection/recon only. A scope guard (`toolkit/infra/scope_guard.py`) resolves
and enforces in-scope targets, and the orchestrator refuses out-of-scope hosts.
The MIT license restricts use to authorized testing.

## Consequences
- Safer default posture; users must consciously enable risky modes.
- Extra flag parsing/validation, but worth the safety margin.
- Scope enforcement lives in one place and is unit-tested with DNS resolution.
