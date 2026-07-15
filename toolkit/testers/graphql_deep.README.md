# graphql_deep

Deep GraphQL abuse testing. `js-extractor_3.py`'s `--graphql-introspection` flag already confirms whether introspection is enabled — that's the bare minimum. This tool goes deeper: (1) schema recovery without introspection via the "field suggestion" technique (malformed queries trigger `Cannot query field 'userss' on type 'Query'. Did you mean 'users'?` responses which leak real field names; iterating on suggestions reconstructs most of the schema); (2) batching/aliasing abuse for rate-limit bypass (single HTTP POST with N aliased copies of `__typename`); (3) nested-query depth DoS candidates (probe depths 5/10/20/50, flag if depth-50 returns 200 in <5s); (4) mutation enumeration (if introspection gave the schema, list mutations and probe each with empty args for fail-open behavior).

## Layer / Tier
Tier 4 tester. Layer 3 in the pipeline.

## Depends on
- `toolkit.infra.scope_guard` — `ScopeGuard` for scope + rate-limit enforcement on every GraphQL request.
- `toolkit.infra.finding` — `compute_finding_id`.
- `toolkit.infra.pipeline_state` — `PipelineState` for `upsert_finding()`.
- `httpx` (required — no fallback).

## Feeds into
- `graphql-findings.json` — findings with `vuln_class_key` in `GQL_INTROSPECTION_ENABLED`, `GQL_SCHEMA_RECOVERED`, `GQL_BATCH_BYPASS`, `GQL_DEPTH_DOS`, `GQL_MUTATION_NOAUTH`.
- `pipeline_state.db.findings_history` — every finding is upserted.
- Downstream: `triage_memory.py` (triage queue).

## Usage

```bash
# Direct endpoint
python -m toolkit.testers.graphql_deep \
    --url https://api.target.com/graphql \
    --scope scope.yaml \
    --output graphql-findings.json

# From jsreaper.py output (uses all_graphql + host_results[].graphql_ops)
python -m toolkit.testers.graphql_deep --input js-findings.json --scope scope.yaml
```

## Library use
```python
import asyncio
from toolkit.testers.graphql_deep import scan_endpoint, to_normalized
from toolkit.infra import scope_guard

guard = scope_guard.ScopeGuard("scope.yaml")
findings = asyncio.run(scan_endpoint("https://api.target.com/graphql", guard))
normalized = to_normalized(findings)
# findings have test_type in: introspection_enabled | schema_recovered | batch_bypass | depth_dos | mutation_noauth
```

## Input / Output
- **Input:** Either `--url <endpoint>` direct, OR `--input jsreaper.json` (reads `all_graphql[]` and `host_results[].graphql_ops[]`).
- **Output:** `graphql-findings.json` with `scan_time`, `endpoints_scanned`, `total_findings`, and `findings[]` (NormalizedFinding dicts). Each finding's `vuln_class_key` is `GQL_<test_type>`; remediation is uniform ("disable introspection in production, enforce depth limit, count batched ops against rate limit, require auth on mutations").
- **Side effects:** Multiple HTTP POSTs per endpoint (introspection query, ~16 suggestion-recovery probes, one batch query, ~10 depth-increasing queries, one probe per mutation). Rate-limited via `scope_guard`. Writes to `pipeline_state.db`.

## Key classes / functions
| Name | Purpose |
|---|---|
| `GqlFinding` | `dataclass(endpoint, test_type, severity, title, detail, evidence, extra)`. `test_type` ∈ `introspection_enabled | schema_recovered | batch_bypass | depth_dos | mutation_noauth`. |
| `_INTROSPECTION_QUERY` | Standard full introspection query (same shape as `js-extractor_3.py`'s check). |
| `_SUGGESTION_RE` / `_UNKNOWN_FIELD_RE` | Extract `Did you mean` suggestions and `Cannot query field X on type Y` errors from GraphQL responses. |
| `check_introspection(client, endpoint)` | Returns `(enabled, schema_dict, raw_text)`. |
| `recover_schema_via_suggestions(client, endpoint, max_iterations)` | Iteratively probe made-up field names on Query/Mutation; harvest suggestions to reconstruct schema. Returns `({type: [fields]}, [raw_errors])`. |
| `test_batch_bypass(client, endpoint, batch_size)` | Send N aliased `__typename` in one POST; confirm all N execute. |
| `test_depth_dos(client, endpoint, max_depth, step)` | Escalate nested-query depth; returns `(max_successful_depth, elapsed, timed_out)`. Flags depth ≥ 20 in <5s as DoS candidate. |
| `enumerate_mutations(client, endpoint, schema)` | If introspection gave schema, list mutations and probe each with empty args. |
| `scan_endpoint(endpoint, guard)` | Run all five checks against one endpoint. |

## Configuration
- `--url` OR `--input` (mutually exclusive, one required).
- `--scope`: `scope.yaml` for scope + rate-limit.
- `--output` (default `graphql-findings.json`).
- `--db` (default `pipeline_state.db`).
- No depth/batch/iteration flags exposed on CLI — they're hardcoded at sensible defaults (depth max=50 step=5, batch_size=10, max_iterations=20). Patch the source to tune.

## Safety notes
- Read-only queries by default (`__typename`, `__schema`, field-suggestion probes). The mutation enumeration step DOES call mutations with empty args — if a mutation has side effects when called with no arguments, this tool will trigger them. This is intentional (the finding is "callable without auth") but researchers should review the schema before running this stage against production.
- The depth-DoS probe sends queries up to depth 50. If the server lacks a depth limit, this can consume server resources — bounded to one query per depth level, stops at first timeout/error.
- `scope_guard` enforces scope on every endpoint. Out-of-scope endpoints are skipped.
- TLS verification is OFF on the async client.

## See also
- ARCHITECTURE.md §5.4 (GraphQL testing)
- Related tools: `js-extractor_3.py` (upstream introspection check), `jsreaper.py` (upstream endpoint discovery), `triage_memory.py` (downstream consumer)
