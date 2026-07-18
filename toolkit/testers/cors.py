#!/usr/bin/env python3
"""
cors.py — Cross-Origin Resource Sharing misconfiguration detection (P1)
======================================================================
Sends a cross-origin request (Origin: evil.example.com) and inspects the
CORS response headers. Flags two dangerous patterns:
  * reflected Origin + Access-Control-Allow-Credentials: true
  * wildcard ACAO (*) + Allow-Credentials: true
Pure checker is unit-testable; only ``test_endpoint``/``run_cors`` do I/O.
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


_EVIL = "https://evil.example.com"


def _detect_cors(headers: dict, sent_origin: str) -> str:
    acao = (headers.get("access-control-allow-origin") or "").strip()
    acac = (headers.get("access-control-allow-credentials") or "").strip().lower()
    if not acao:
        return ""
    if acao == "*" and acac == "true":
        return "wildcard-origin-with-credentials"
    if acao == sent_origin and acac == "true":
        return "reflected-origin-with-credentials"
    if acao == "null" and acac == "true":
        return "null-origin-with-credentials"
    return ""


@dataclass
class CorsFinding:
    url: str
    method: str
    pattern: str
    evidence: str = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


async def _send(client, endpoint: Any, *, timeout: float = 10.0) -> dict:
    headers = {"User-Agent": "Mozilla/5.0 (compatible; BBTK-cors/1.0)",
               "Origin": _EVIL}
    try:
        r = await client.request(endpoint.method, endpoint.url, headers=headers,
                                 timeout=timeout, follow_redirects=True)
        return dict(getattr(r, "headers", {}) or {})
    except Exception:
        return {}


async def test_endpoint(endpoint: Any, client: object, *,
                        timeout: float = 10.0) -> list[CorsFinding]:
    headers = await _send(client, endpoint, timeout=timeout)
    pat = _detect_cors(headers, _EVIL)
    if pat:
        return [CorsFinding(endpoint.url, endpoint.method, pat,
                            f"ACAO={headers.get('access-control-allow-origin')} "
                            f"ACAC={headers.get('access-control-allow-credentials')}")]
    return []


async def run_cors(endpoints: list[Any], client: object, *,
                   timeout: float = 10.0, concurrency: int = 10) -> list[CorsFinding]:
    sem = asyncio.Semaphore(concurrency)

    async def guarded(ep):
        async with sem:
            return await test_endpoint(ep, client, timeout=timeout)
    results = await asyncio.gather(*[guarded(ep) for ep in endpoints])
    return [f for sub in results for f in sub]


def to_normalized_findings(findings: list[CorsFinding],
                           source_tool: str = "cors.py") -> list[dict]:
    out: list[dict] = []
    for f in findings:
        detail = (f"CORS misconfiguration '{f.pattern}' on {f.method} {f.url} "
                  f"allows cross-origin credentialed access")
        sev = "MEDIUM"
        if _HAVE_FINDING:
            nf = NormalizedFinding(source_tool=source_tool, host=_host(f.url), url=f.url,
                                   vuln_class_key="CORS_MISCONFIG", severity=sev,
                                   title=f"CORS Misconfiguration ({f.pattern})",
                                   detail=detail, evidence=f.evidence,
                                   confidence="confirmed")
            d = nf.to_dict()
            d["param"] = ""
        else:
            d = {"source_tool": source_tool, "host": _host(f.url), "url": f.url,
                 "param": "", "vuln_class_key": "CORS_MISCONFIG", "severity": sev,
                 "title": f"CORS Misconfiguration ({f.pattern})", "detail": detail,
                 "evidence": f.evidence, "confidence": "confirmed"}
        out.append(d)
    return out


def _host(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).netloc
