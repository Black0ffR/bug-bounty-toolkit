# ADR 0001: Toolkit stages as composable modules

- Status: Accepted
- Date: 2026-07-18

## Context
The original toolkit shipped large standalone scripts (`apifuzz.py`,
`ssrfprobe.py`, ...) that duplicated discovery, auth, and reporting logic.
Reuse across tools was copy-paste, and the orchestrator could only shell out to
them. We needed a way to compose capabilities (e.g. run recon → feed secrets to
IDOR checks → produce a report) without subprocess boundaries.

## Decision
Extract shared capability into `toolkit/` Python modules ("stages") that expose
pure, importable functions and dataclasses. The standalone `scripts/` remain as
thin CLI wrappers. `orchestrator.py` can call stages directly across process
boundaries via a `pipeline_state` database.

## Consequences
- New logic lives once in `toolkit/` and is unit-testable without network.
- CLI tools keep their familiar flags while gaining `--session-a` plumbing,
  `--user-agent`, `--log-format`, and `--config` through shared infra.
- Slight duplication risk if a script and its stage drift; mitigated by having
  scripts import the stage where possible.
