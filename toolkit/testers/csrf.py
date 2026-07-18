#!/usr/bin/env python3
"""
csrf.py — Missing CSRF protection heuristic (P1)
================================================
For POST form endpoints (state-changing), checks whether the request surface
includes an apparent anti-CSRF token. Absence is flagged as a LOW/INFO
"possible missing CSRF protection" candidate — a prioritization signal, not a
confirmed vulnerability (false positives are expected; manual review needed).
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

try:
    from toolkit.infra.finding import NormalizedFinding
    _HAVE_FINDING = True
except Exception:  # pragma: no cover
    _HAVE_FINDING = False


_TOKEN_NAMES = ("csrf", "xsrf", "_token", "authenticity_token", "csrf_token",
                "csrfmiddlewaretoken", "_csrf", "token")


def _looks_like_token(name: str) -> bool:
    n = (name or "").lower()
    return any(t in n for t in _TOKEN_NAMES)


@dataclass
class CsrfFinding:
    url: str
    method: str
    param_count: int
    evidence: str = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


async def test_endpoint(endpoint: Any, client: object = None, *,
                        timeout: float = 10.0) -> list[CsrfFinding]:
    # Heuristic only needs the endpoint metadata (no I/O required).
    if getattr(endpoint, "method", "GET").upper() != "POST":
        return []
    params = list(getattr(endpoint, "params", []) or [])
    if not params:
        return []
    if any(_looks_like_token(p) for p in params):
        return []
    return [CsrfFinding(endpoint.url, "POST", len(params),
                        "POST form with no apparent anti-CSRF token parameter")]


async def run_csrf(endpoints: list[Any], client: object = None, *,
                   timeout: float = 10.0, concurrency: int = 10) -> list[CsrfFinding]:
    sem = asyncio.Semaphore(concurrency)

    async def guarded(ep):
        async with sem:
            return await test_endpoint(ep, client, timeout=timeout)
    results = await asyncio.gather(*[guarded(ep) for ep in endpoints])
    return [f for sub in results for f in sub]


def to_normalized_findings(findings: list[CsrfFinding],
                           source_tool: str = "csrf.py") -> list[dict]:
    out: list[dict] = []
    for f in findings:
        detail = (f"POST endpoint {f.url} accepts {f.param_count} parameters with "
                  f"no anti-CSRF token — possible missing CSRF protection (manual review)")
        if _HAVE_FINDING:
            nf = NormalizedFinding(source_tool=source_tool, host=_host(f.url), url=f.url,
                                   vuln_class_key="MISSING_CSRF", severity="LOW",
                                   title="Possible Missing CSRF Protection",
                                   detail=detail, evidence=f.evidence,
                                   confidence="unconfirmed")
            d = nf.to_dict()
            d["param"] = ""
        else:
            d = {"source_tool": source_tool, "host": _host(f.url), "url": f.url,
                 "param": "", "vuln_class_key": "MISSING_CSRF", "severity": "LOW",
                 "title": "Possible Missing CSRF Protection", "detail": detail,
                 "evidence": f.evidence, "confidence": "unconfirmed"}
        out.append(d)
    return out


def _host(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).netloc
