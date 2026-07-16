#!/usr/bin/env python3
"""
graphql_deep.py — deep GraphQL abuse testing
=============================================

Tier 4 tester.

Purpose
-------
js-extractor_3.py's --graphql-introspection flag already confirms whether
introspection is enabled. That's the bare minimum. This tool goes deeper:

  1. **Schema recovery without introspection**: when introspection is disabled,
     extract schema hints from error messages using the "field suggestion"
     technique — malformed queries trigger responses like "Cannot query field
     'userss' on type 'Query'. Did you mean 'users'?" — which leaks the real
     field names. Iterating on suggestions can reconstruct most of the schema.

  2. **Batching / aliasing abuse for rate-limit bypass**: many GraphQL servers
     don't count batched or aliased queries against their rate limit. Send a
     single HTTP request with N aliased copies of an expensive query and see
     if all N execute.

  3. **Nested-query depth DoS candidates**: probe with increasingly deep
     nested queries (5, 10, 20, 50 levels). If the server returns a 200 within
     a reasonable time at depth 50, it likely lacks a depth limit — flag as a
     DoS candidate. Stops escalating at the first depth that times out or
     errors.

  4. **Mutation enumeration**: if introspection is enabled, list mutations
     and probe each with empty args to find ones that fail-open (return 200
     without auth).

Chain position
--------------
Layer 3 — Input: jsreaper.py output (graphql_ops field) OR --url direct.
          Output: graphql-findings.json.
          Persisted: pipeline_state.db.

Usage
-----
    python -m toolkit.testers.graphql_deep \\
        --url https://api.target.com/graphql \\
        --scope scope.yaml \\
        --output graphql-findings.json

Author : Bug Bounty Toolkit / Tier 4
License : MIT (for authorized use only)
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import json
import logging
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from toolkit.infra import scope_guard
from toolkit.infra.finding import compute_finding_id
from toolkit.infra.pipeline_state import PipelineState


log = logging.getLogger("graphql_deep")

# Standard introspection query (full) — used by step 1 to confirm/disprove
# introspection is enabled. Same shape as js-extractor_3.py's check.
_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields { name type { name kind ofType { name kind } } }
    }
  }
}
"""

# Suggestion-extraction regex: GraphQL servers (Apollo, Graphene, Hasura, etc.)
# emit errors like:
#   "Cannot query field 'User' on type 'Query'. Did you mean 'User'?"
#   "Cannot query field 'xyz' on type 'Query'."
# We pull the "Did you mean" suggestions out.
_SUGGESTION_RE = re.compile(
    r"Did you mean\s+(?:to use\s+|one of\s+)?(.+?)(?:\?|$)",
    re.IGNORECASE | re.DOTALL,
)
# Field-extraction regex: when a query references a non-existent field, the
# error mentions the parent type. We pull that to drive the next iteration.
_UNKNOWN_FIELD_RE = re.compile(
    r"Cannot query field ['\"]([^'\"]+)['\"] on type ['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)


@dataclass
class GqlFinding:
    endpoint: str
    test_type: str           # introspection_enabled | schema_recovered | batch_bypass | depth_dos | mutation_noauth
    severity: str
    title: str
    detail: str
    evidence: str
    extra: dict[str, Any]


async def _post_query(client, endpoint: str, query: str, *,
                      variables: dict[str, Any] | None = None,
                      headers: dict[str, str] | None = None) -> tuple[int, dict[str, Any], str]:
    """POST a GraphQL query. Returns (status, parsed_json_or_{}, raw_text)."""
    payload: dict[str, Any] = {"query": query}
    if variables:
        payload["variables"] = variables
    hdrs = {"Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (compatible; GraphqlDeep/1.0)",
            "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    try:
        r = await client.post(endpoint, json=payload, headers=hdrs, timeout=15.0)
        text = r.text or ""
        try:
            j = r.json() if text else {}
        except Exception:
            j = {}
        return (int(r.status_code or 0), j, text)
    except Exception as exc:
        log.debug("POST %s failed: %s", endpoint, exc)
        return (0, {}, "")


async def check_introspection(client, endpoint: str) -> tuple[bool, dict[str, Any] | None, str]:
    """Returns (introspection_enabled, schema_dict_or_None, raw_text)."""
    status, j, text = await _post_query(client, endpoint, _INTROSPECTION_QUERY)
    if status != 200 or not j:
        return (False, None, text)
    schema = j.get("data", {}).get("__schema") if isinstance(j.get("data"), dict) else None
    return (bool(schema), schema, text)


def _extract_suggestions(error_text: str) -> list[str]:
    """Pull 'Did you mean' suggestions from a GraphQL error message."""
    out: list[str] = []
    for m in _SUGGESTION_RE.finditer(error_text):
        # The captured group looks like "'User', 'Users', or 'UserMeta'"
        # OR '"User", "Users"' (double quotes — Apollo style)
        # Extract each quoted name (handles both single and double quotes)
        names = re.findall(r"""['\"]([^'\"]+)['\"]""", m.group(1))
        out.extend(names)
    return out


def _extract_unknown_field(error_text: str) -> tuple[str | None, str | None]:
    """Returns (field, type) from a 'Cannot query field X on type Y' error."""
    m = _UNKNOWN_FIELD_RE.search(error_text)
    if m:
        return (m.group(1), m.group(2))
    return (None, None)


async def recover_schema_via_suggestions(client, endpoint: str, *,
                                         max_iterations: int = 20) -> tuple[dict[str, list[str]], list[str]]:
    """Iteratively query made-up field names on Query and Mutation types;
    harvest the "Did you mean" suggestions to reconstruct the schema.

    Returns ({type_name: [field_names, ...]}, [raw_errors]).
    """
    schema: dict[str, list[str]] = {"Query": [], "Mutation": []}
    raw_errors: list[str] = []
    # Seed: probe common made-up names
    probes = ["nonexistentfield", "xyz", "asdf", "qwerty", "abc", "test", "foo", "bar"]
    for type_name in ("Query", "Mutation"):
        for probe in probes:
            query = f"{{ {probe} }}"
            if type_name == "Mutation":
                query = f"mutation {{ {probe} }}"
            status, j, text = await _post_query(client, endpoint, query)
            if status != 200 or not j:
                continue
            errors = j.get("errors") or []
            if not errors:
                continue
            err_str = json.dumps(errors)
            raw_errors.append(err_str)
            suggestions = _extract_suggestions(err_str)
            field, typ = _extract_unknown_field(err_str)
            for s in suggestions:
                if s not in schema.get(type_name, []):
                    schema.setdefault(type_name, []).append(s)
            # Verify each suggestion by querying it
            for s in list(suggestions):
                verify_query = f"{{ {s} }}"
                if type_name == "Mutation":
                    verify_query = f"mutation {{ {s} }}"
                _, vj, _ = await _post_query(client, endpoint, verify_query)
                verrors = vj.get("errors") or []
                if not verrors:
                    # Field exists AND returns without error — likely a leaf
                    if s not in schema[type_name]:
                        schema[type_name].append(s)
                    # Try to discover sub-fields by querying made-up children
                    for child_probe in probes[:3]:
                        sub_query = f"{{ {s} {{ {child_probe} }} }}"
                        if type_name == "Mutation":
                            sub_query = f"mutation {{ {s} {{ {child_probe} }} }}"
                        _, sj, sub_text = await _post_query(client, endpoint, sub_query)
                        serr = sj.get("errors") or []
                        if serr:
                            sub_suggestions = _extract_suggestions(json.dumps(serr))
                            child_type = None
                            _, child_type = _extract_unknown_field(json.dumps(serr))
                            if child_type and child_type not in schema:
                                schema[child_type] = sub_suggestions
            if len(raw_errors) >= max_iterations:
                break
    return schema, raw_errors


async def test_batch_bypass(client, endpoint: str, *,
                            batch_size: int = 10) -> tuple[bool, dict[str, Any]]:
    """Send a single HTTP POST with N aliased copies of a cheap query.
    If all N execute (status 200 with N data keys), batching is allowed —
    flag as a rate-limit-bypass candidate.
    Returns (bypass_confirmed, evidence_dict)."""
    # Build aliased query: { a1: __typename a2: __typename ... }
    aliases = [f"a{i}" for i in range(batch_size)]
    # __typename is always available and free
    query = "{ " + " ".join(f"{a}: __typename" for a in aliases) + " }"
    status, j, text = await _post_query(client, endpoint, query)
    if status != 200 or not j:
        return (False, {"status": status, "body": text[:300]})
    data = j.get("data") or {}
    if not isinstance(data, dict):
        return (False, {"status": status, "body": text[:300]})
    # Count how many aliases returned
    returned = sum(1 for a in aliases if a in data)
    return (returned == batch_size, {
        "status": status, "aliases_sent": batch_size,
        "aliases_returned": returned,
        "body_snippet": text[:500],
    })


def _unwrap_type(t: Any) -> str | None:
    """Walk NON_NULL/LIST wrappers to the named underlying type."""
    while isinstance(t, dict) and t.get("ofType"):
        t = t["ofType"]
    return t.get("name") if isinstance(t, dict) else None


def _object_field_map(schema: dict[str, Any] | None) -> dict[str, dict[str, str]]:
    """name -> {field_name: return_type_name} for OBJECT types (excludes __ introspection)."""
    out: dict[str, dict[str, str]] = {}
    if not isinstance(schema, dict):
        return out
    for t in schema.get("types", []) or []:
        if not isinstance(t, dict):
            continue
        if t.get("kind") != "OBJECT" or str(t.get("name", "")).startswith("__"):
            continue
        fields: dict[str, str] = {}
        for f in t.get("fields", []) or []:
            rt = _unwrap_type(f.get("type"))
            if rt:
                fields[str(f.get("name"))] = rt
        out[str(t["name"])] = fields
    return out


def _find_recursive_chain(schema: dict[str, Any] | None, max_len: int = 6) -> list[str]:
    """Find a field chain from Query that loops back on a type, so a valid
    recursive nested query can be built for the depth-DoS probe.

    Returns e.g. ``["user", "friends"]`` (Query.user → User.friends → User),
    or a 2-step object path as a fallback, or ``[]`` if no recursion is found.
    """
    fmap = _object_field_map(schema)
    query_name = (schema or {}).get("queryType") or {}
    query_name = query_name.get("name") if isinstance(query_name, dict) else "Query"
    if query_name not in fmap:
        return []

    def dfs(typ: str, chain: list[str], seen: set[str]) -> list[str] | None:
        for fld, rt in fmap.get(typ, {}).items():
            if rt in seen:
                return chain + [fld]  # closing the cycle
            if rt in fmap and len(chain) < max_len:
                res = dfs(rt, chain + [fld], seen | {rt})
                if res:
                    return res
        return None

    res = dfs(query_name, [], {query_name})
    if res:
        return res
    # Fallback: any 2-step object→object path from Query
    for fld, rt in fmap.get(query_name, {}).items():
        for fld2 in fmap.get(rt, {}):
            return [fld, fld2]
    return []


def _build_depth_query(chain: list[str], depth: int) -> str:
    """Build a syntactically valid nested query of `depth` levels following the
    recursive `chain` (cycled as needed). Returns ``"{}"`` if no chain given."""
    if not chain:
        return "{}"
    parts = [chain[i % len(chain)] for i in range(depth)]
    q = parts[0]
    for f in parts[1:]:
        q = f"{f} {{ {q} }}"
    return "{" + q + "}"


async def test_depth_dos(client, endpoint: str, *,
                         max_depth: int = 50,
                         step: int = 5,
                         schema: dict[str, Any] | None = None) -> tuple[int, float, bool]:
    """Send schema-aware nested queries at increasing depth. Returns
    (max_successful_depth, elapsed_at_max, timed_out_at_higher_depth).
    A depth-50 success in < 5s suggests no depth limit → DoS candidate.

    The nested query follows a real recursive field chain from the schema
    (e.g. ``Query.user → User.friends → User``) so the probe is a *valid*
    GraphQL document the server can actually execute — the previous probe
    nested ``__typename`` under itself, which is invalid and got rejected by
    every server, so the depth-DoS check silently never fired.
    """
    chain = _find_recursive_chain(schema)
    if not chain:
        # Without a schema we cannot build a valid recursive query, so probing
        # would be meaningless. Bail out honestly instead of sending an invalid
        # document that every server rejects.
        if schema is not None:
            log.warning("test_depth_dos: no recursive field chain found in schema — skipping")
        return (0, 0.0, False)
    last_success_depth = 0
    last_success_elapsed = 0.0
    timed_out = False
    for depth in range(step, max_depth + 1, step):
        query = _build_depth_query(chain, depth)
        t0 = time.perf_counter()
        status, j, text = await _post_query(client, endpoint, query)
        elapsed = time.perf_counter() - t0
        if status == 0:
            timed_out = True
            break
        errors = (j or {}).get("errors") or [] if isinstance(j, dict) else []
        err_str = json.dumps(errors).lower()
        if "depth" in err_str or "too deep" in err_str:
            # Depth limit enforced — good
            break
        if status == 200 and not errors:
            last_success_depth = depth
            last_success_elapsed = elapsed
        else:
            # Some other error — stop
            break
    return (last_success_depth, last_success_elapsed, timed_out)


async def enumerate_mutations(client, endpoint: str, schema: dict[str, Any] | None) -> list[GqlFinding]:
    """If introspection gave us the schema, list mutations and probe each
    with empty args. Flag any that return 200 without auth."""
    out: list[GqlFinding] = []
    if not schema:
        return out
    mutation_type = schema.get("mutationType") or {}
    if not mutation_type:
        return out
    # Get the Mutation type's fields from the schema's types list
    types = {t["name"]: t for t in schema.get("types", []) if isinstance(t, dict)}
    mut_type_def = types.get(mutation_type.get("name", ""))
    if not mut_type_def:
        return out
    fields = mut_type_def.get("fields") or []
    for f in fields:
        fname = f.get("name", "")
        if not fname:
            continue
        # Probe with no args — will likely fail with "missing required arg",
        # but if it returns 200, that's a finding
        query = f"mutation {{ {fname} }}"
        status, j, text = await _post_query(client, endpoint, query)
        if status == 200 and not (j.get("errors") or []):
            out.append(GqlFinding(
                endpoint=endpoint, test_type="mutation_noauth",
                severity="HIGH",
                title=f"GraphQL mutation '{fname}' callable without args/auth",
                detail=f"Mutation {fname} returned 200 with no errors when called with no arguments.",
                evidence=f"query: {query}\nstatus: {status}\nbody: {text[:300]}",
                extra={"mutation_name": fname},
            ))
    return out


async def scan_endpoint(endpoint: str, guard: scope_guard.ScopeGuard) -> list[GqlFinding]:
    """Run all graphql_deep checks against one endpoint."""
    try:
        guard.check_url(endpoint, source_tool="graphql_deep.py")
    except scope_guard.ScopeError as exc:
        log.warning("scope reject %s — %s", endpoint, exc)
        return []
    try:
        import httpx
    except ImportError:
        log.error("httpx required for graphql_deep.py")
        return []
    findings: list[GqlFinding] = []
    async with httpx.AsyncClient(timeout=20.0, verify=False, follow_redirects=True) as client:
        # 1. Introspection
        if not guard.acquire_token(timeout=20.0):
            return []
        try:
            introspection_on, schema, _ = await check_introspection(client, endpoint)
        finally:
            guard.release_token()
        if introspection_on:
            findings.append(GqlFinding(
                endpoint=endpoint, test_type="introspection_enabled",
                severity="MEDIUM",
                title="GraphQL introspection enabled",
                detail=f"Introspection is enabled at {endpoint}. Schema contains "
                       f"{len(schema.get('types', [])) if schema else 0} types.",
                evidence=f"POST {endpoint} with IntrospectionQuery → 200 + __schema",
                extra={"schema_types": len(schema.get("types", [])) if schema else 0},
            ))
        else:
            # 2. Schema recovery via suggestions
            log.info("introspection disabled — attempting field-suggestion recovery")
            if not guard.acquire_token(timeout=20.0):
                return findings
            try:
                recovered, raw_errors = await recover_schema_via_suggestions(client, endpoint)
            finally:
                guard.release_token()
            total_fields = sum(len(v) for v in recovered.values())
            if total_fields > 0:
                findings.append(GqlFinding(
                    endpoint=endpoint, test_type="schema_recovered",
                    severity="MEDIUM",
                    title=f"GraphQL schema partially recovered via field-suggestion ({total_fields} fields)",
                    detail=f"Introspection is disabled but the server leaks field names via 'Did you mean' "
                           f"suggestions. Recovered: {recovered}",
                    evidence="\n".join(raw_errors[:5]),
                    extra={"recovered_schema": recovered},
                ))
            schema = None  # disable mutation enumeration
        # 3. Batch / aliasing bypass
        if not guard.acquire_token(timeout=20.0):
            return findings
        try:
            bypass_ok, evidence = await test_batch_bypass(client, endpoint, batch_size=10)
        finally:
            guard.release_token()
        if bypass_ok:
            findings.append(GqlFinding(
                endpoint=endpoint, test_type="batch_bypass",
                severity="MEDIUM",
                title="GraphQL batching bypasses rate limit",
                detail=f"Sent 10 aliased copies of __typename in a single HTTP request — all 10 executed. "
                       f"This suggests the rate limiter counts requests, not operations, allowing bypass.",
                evidence=json.dumps(evidence, default=str)[:500],
                extra=evidence,
            ))
        # 4. Depth DoS
        if not guard.acquire_token(timeout=30.0):
            return findings
        try:
            max_depth, elapsed, timed_out = await test_depth_dos(
                client, endpoint, max_depth=50, step=5, schema=schema
            )
        finally:
            guard.release_token()
        if max_depth >= 20 and elapsed < 5.0 and not timed_out:
            findings.append(GqlFinding(
                endpoint=endpoint, test_type="depth_dos",
                severity="HIGH",
                title=f"GraphQL depth-DoS candidate (handled depth={max_depth} in {elapsed:.1f}s)",
                detail=f"Server accepted a nested query at depth {max_depth} in {elapsed:.1f}s — no depth "
                       f"limit appears enforced. An attacker can craft O(2^n) queries for resource exhaustion.",
                evidence=f"max_depth={max_depth} elapsed={elapsed:.2f}s timed_out_at_higher={timed_out}",
                extra={"max_depth": max_depth, "elapsed_s": elapsed, "timed_out": timed_out},
            ))
        # 5. Mutation enumeration
        if schema:
            mut_findings = await enumerate_mutations(client, endpoint, schema)
            findings.extend(mut_findings)
    return findings


def to_normalized(findings: list[GqlFinding]) -> list[dict[str, Any]]:
    from urllib.parse import urlparse
    out: list[dict[str, Any]] = []
    for f in findings:
        host = urlparse(f.endpoint).hostname or ""
        evidence = f"{f.endpoint}|{f.test_type}|{f.evidence[:200]}"
        fid = compute_finding_id("graphql_deep.py", host, "GQL_" + f.test_type.upper(),
                                 evidence, url=f.endpoint)
        out.append({
            "id": fid,
            "source_tool": "graphql_deep.py",
            "host": host,
            "url": f.endpoint,
            "vuln_class_key": "GQL_" + f.test_type.upper(),
            "severity": f.severity,
            "title": f.title,
            "detail": f.detail,
            "evidence": f.evidence,
            "remediation": (
                "Disable introspection in production. Enforce a query depth limit (e.g., max 10). "
                "Count batched/aliased operations against the rate limit individually. Require auth on all mutations."
            ),
            "raw": f.extra,
            "confidence": "candidate",
            "disposition": "new",
            "verified_by": None,
        })
    return out


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="graphql_deep.py",
        description="Deep GraphQL abuse testing. Extends js-extractor_3.py's introspection check.",
    )
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--url", help="direct GraphQL endpoint URL")
    src.add_argument("--input", "-i", help="jsreaper.py JSON output (uses graphql_ops)")
    ap.add_argument("--scope", help="scope.yaml path")
    ap.add_argument("--output", "-o", default="graphql-findings.json")
    ap.add_argument("--db", default="pipeline_state.db")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )

    endpoints: list[str] = []
    if args.url:
        endpoints = [args.url]
    else:
        in_path = Path(args.input)
        if not in_path.exists():
            log.error("input not found: %s", in_path)
            return 2
        data = json.loads(in_path.read_text(encoding="utf-8"))
        # jsreaper emits all_graphql: list[str]
        for u in data.get("all_graphql", []) or []:
            if isinstance(u, str):
                endpoints.append(u)
            elif isinstance(u, dict):
                endpoints.append(u.get("endpoint") or u.get("url", ""))
        # Also check host_results[].graphql_ops
        for hr in data.get("host_results", []) or []:
            host = hr.get("host", "")
            for op in hr.get("graphql_ops", []) or []:
                if isinstance(op, str) and op.startswith("http"):
                    endpoints.append(op)
                elif isinstance(op, dict):
                    endpoints.append(op.get("endpoint") or op.get("url", ""))
    endpoints = [e for e in endpoints if e]
    log.info("endpoints to scan: %d", len(endpoints))

    guard = scope_guard.ScopeGuard(args.scope) if args.scope else scope_guard.get_default()
    state = PipelineState(args.db)
    try:
        all_findings: list[GqlFinding] = []
        for ep in endpoints:
            log.info("scanning %s", ep)
            results = asyncio.run(scan_endpoint(ep, guard))
            all_findings.extend(results)
        normalized = to_normalized(all_findings)
        for f in normalized:
            state.upsert_finding(f)
        out_path = Path(args.output)
        out_path.write_text(
            json.dumps({
                "scan_time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                "endpoints_scanned": len(endpoints),
                "total_findings": len(all_findings),
                "findings": normalized,
            }, indent=2, default=str),
            encoding="utf-8",
        )
        log.info("wrote %s", out_path)
        return 0
    finally:
        state.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(0)
