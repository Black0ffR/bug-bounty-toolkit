#!/usr/bin/env python3
"""
idor.py — Insecure Direct Object Reference surface detection (P2)
===============================================================
IDOR is fundamentally an authorization flaw that usually requires an
authenticated account to confirm. This module is a *prioritization* heuristic:
it flags endpoints whose parameters look like object references (numeric/id
style) so a human can test horizontal/vertical privilege escalation. It also
performs a light sequential-enumeration probe (id=1 vs id=2) and flags when
both return 200 with differing content — a classic IDOR signal.

Confidence is "unconfirmed": these are candidates, not confirmed vulns.
"""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Any

try:
    from toolkit.infra.finding import NormalizedFinding
    _HAVE_FINDING = True
except Exception:  # pragma: no cover
    _HAVE_FINDING = False


_ID_HINTS = ("id", "uid", "userid", "user_id", "account", "account_id",
             "doc", "document", "file", "order", "item", "pid", "cid",
             "tid", "oid", "profile", "customer")


def is_id_param(name: str) -> bool:
    n = (name or "").lower()
    if re.fullmatch(r"\d+", n):
        return True
    return any(h in n for h in _ID_HINTS)


@dataclass
class IdorFinding:
    url: str
    method: str
    param: str
    kind: str              # "surface" | "sequential-enum"
    evidence: str = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


async def _send(client, endpoint: Any, param: str, value: str, *,
                timeout: float = 10.0) -> tuple[int, str]:
    via = getattr(endpoint, "inject_via", "query")
    headers = {"User-Agent": "Mozilla/5.0 (compatible; BBTK-idor/1.0)"}
    try:
        if via == "body_form":
            r = await client.request(endpoint.method, endpoint.url, headers=headers,
                                     data={param: value}, timeout=timeout)
        elif via == "body_json":
            r = await client.request(endpoint.method, endpoint.url,
                                     headers={**headers, "Content-Type": "application/json"},
                                     json={param: value}, timeout=timeout)
        else:
            from toolkit.infra import inject
            full = inject.build_injection_url(endpoint.url, param, value)
            r = await client.request(endpoint.method, full, headers=headers, timeout=timeout)
        return int(getattr(r, "status_code", 0) or 0), getattr(r, "text", "") or ""
    except Exception:
        return 0, ""


async def test_endpoint(endpoint: Any, client: object, *,
                        timeout: float = 10.0) -> list[IdorFinding]:
    params = [p for p in (getattr(endpoint, "params", []) or []) if is_id_param(p)]
    if not params:
        return []
    out: list[IdorFinding] = []
    for param in params:
        # surface candidate
        out.append(IdorFinding(endpoint.url, endpoint.method, param, "surface",
                               "object-reference style parameter"))
        # light sequential enumeration probe
        s1, b1 = await _send(client, endpoint, param, "1", timeout=timeout)
        s2, b2 = await _send(client, endpoint, param, "2", timeout=timeout)
        if s1 == 200 and s2 == 200 and b1 and b2 and b1 != b2:
            out.append(IdorFinding(endpoint.url, endpoint.method, param,
                                   "sequential-enum",
                                   "id=1 and id=2 both returned 200 with differing content"))
    return out


async def run_idor(endpoints: list[Any], client: object, *,
                  timeout: float = 10.0, concurrency: int = 10) -> list[IdorFinding]:
    sem = asyncio.Semaphore(concurrency)

    async def guarded(ep):
        async with sem:
            return await test_endpoint(ep, client, timeout=timeout)
    results = await asyncio.gather(*[guarded(ep) for ep in endpoints])
    return [f for sub in results for f in sub]


def to_normalized_findings(findings: list[IdorFinding],
                           source_tool: str = "idor.py") -> list[dict]:
    out: list[dict] = []
    for f in findings:
        sev = "LOW" if f.kind == "surface" else "MEDIUM"
        detail = (f"Possible Insecure Direct Object Reference on parameter "
                  f"'{f.param}' ({f.method} {f.url}) — {f.kind}. "
                  f"Confirm with two authenticated identities.")
        if _HAVE_FINDING:
            nf = NormalizedFinding(source_tool=source_tool, host=_host(f.url), url=f.url,
                                   vuln_class_key="IDOR", severity=sev,
                                   title=f"Possible IDOR in {f.param} ({f.kind})",
                                   detail=detail, evidence=f.evidence,
                                   confidence="unconfirmed")
            d = nf.to_dict()
            d["param"] = f.param
        else:
            d = {"source_tool": source_tool, "host": _host(f.url), "url": f.url,
                 "param": f.param, "vuln_class_key": "IDOR", "severity": sev,
                 "title": f"Possible IDOR in {f.param} ({f.kind})", "detail": detail,
                 "evidence": f.evidence, "confidence": "unconfirmed"}
        out.append(d)
    return out


def _host(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).netloc
