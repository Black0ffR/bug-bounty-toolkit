# ADR 0002: Canonical normalized finding schema

- Status: Accepted
- Date: 2026-07-18

## Context
Different tools emitted findings in ad-hoc shapes (dicts, dataclasses, JSON).
Aggregating, deduplicating, and reporting on results was fragile and required
per-tool parsing in the orchestrator and reporter.

## Decision
Define one canonical `NormalizedFinding` shape in `toolkit/infra/finding.py`
with stable keys (`id`, `source_tool`, `host`, `url`, `vuln_class_key`,
`severity`, `title`, `confidence`, `evidence`, `cvss_vector`, ...). Every stage
normalizes its raw results into this shape; the reporter (`toolkit/infra/reporter.py`)
renders any list of these into HackerOne / Bugcrowd / CSV / SARIF.

## Consequences
- Reporters and the orchestrator depend only on the normalized shape, not on
  individual tools.
- Adding a new tool = implement a normalizer, no reporter changes required.
- Severity is a string enum (CRITICAL/HIGH/MEDIUM/LOW/INFO) with a derived CVSS
  default when no explicit vector is supplied.
