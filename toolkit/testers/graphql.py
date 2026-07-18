#!/usr/bin/env python3
"""
graphql.py — GraphQL endpoint discovery & introspection detection (P2)
====================================================================
Probes discovered endpoints and common GraphQL paths with an introspection
query. If the server answers with schema metadata (``__schema`` / ``types`` /
``queryType``), introspection is enabled — an information-disclosure issue
that also exposes the full attack surface for further testing.

Pure checker is unit-testable; only ``run_graphql`` does I/O.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

try:
    from toolkit.infra.finding import NormalizedFinding
    _HAVE_FINDING = True
except Exception:  # pragma: no cover
    _HAVE_FINDING = False


COMMON_PATHS = ["/graphql", "/api/graphql", "/graphql/v1",
                "/v1/graphql", "/graphql/api", "/query"]
_INTROSPECTION = "query { __schema { types { name } queryType { name } } }"


def _detect_introspection(text: str) -> str:
    low = (text or "").lower()
    for s in ("\"__schema\"", "\"types\"", "\"querytype\"", "__schema",
              "typename"):
        if s in low:
            return s.strip('"')
    return ""


@dataclass
class GraphQLFinding:
    url: str
    method: str = "POST"
    technique: str = "introspection"
    evidence: str = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


async def _probe(client, url: str, *, timeout: float = 10.0) -> str:
    headers = {"User-Agent": "Mozilla/5.0 (compatible; BBTK-graphql/1.0)",
               "Content-Type": "application/json"}
    try:
        r = await client.request("POST", url, headers=headers,
                                 json={"query": _INTROSPECTION}, timeout=timeout)
        return getattr(r, "text", "") or ""
    except Exception:
        return ""


async def run_graphql(endpoints: list[Any], client: object, *,
                     timeout: float = 10.0, concurrency: int = 10) -> list[GraphQLFinding]:
    # Build candidate URLs: discovered endpoints + common paths per host.
    hosts = {urlparse(getattr(e, "url", "")).netloc for e in endpoints if getattr(e, "url", "")}
    candidates: list[str] = []
    for e in endpoints:
        u = getattr(e, "url", "")
        if u:
            candidates.append(u)
    for h in hosts:
        for p in COMMON_PATHS:
            candidates.append(f"http://{h}{p}" if not h.startswith("http") else f"{h}{p}")
    # dedupe preserving order
    seen = set()
    uniq = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            uniq.append(c)

    sem = asyncio.Semaphore(concurrency)
    out: list[GraphQLFinding] = []

    async def guarded(url):
        async with sem:
            body = await _probe(client, url, timeout=timeout)
            sig = _detect_introspection(body)
            if sig:
                out.append(GraphQLFinding(url, "POST", "introspection",
                                         f"GraphQL introspection enabled (matched '{sig}')"))
    await asyncio.gather(*[guarded(u) for u in uniq])
    return out


def to_normalized_findings(findings: list[GraphQLFinding],
                           source_tool: str = "graphql.py") -> list[dict]:
    out: list[dict] = []
    for f in findings:
        detail = (f"GraphQL endpoint with introspection enabled at {f.url} "
                  f"— exposes full schema/attack surface")
        if _HAVE_FINDING:
            nf = NormalizedFinding(source_tool=source_tool, host=_host(f.url), url=f.url,
                                   vuln_class_key="GRAPHQL_INTROSPECTION", severity="MEDIUM",
                                   title="GraphQL Introspection Enabled",
                                   detail=detail, evidence=f.evidence,
                                   confidence="confirmed")
            d = nf.to_dict()
            d["param"] = ""
        else:
            d = {"source_tool": source_tool, "host": _host(f.url), "url": f.url,
                 "param": "", "vuln_class_key": "GRAPHQL_INTROSPECTION", "severity": "MEDIUM",
                 "title": "GraphQL Introspection Enabled", "detail": detail,
                 "evidence": f.evidence, "confidence": "confirmed"}
        out.append(d)
    return out


def _host(url: str) -> str:
    return urlparse(url).netloc
