#!/usr/bin/env python3
"""
openredirect.py — Open Redirect detection (P1)
=============================================
Sends off-site URLs into a parameter and checks whether the response
redirects (3xx) to the attacker-controlled host. Pure checker is
unit-testable; only ``test_endpoint``/``run_openredirect`` do I/O.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

try:
    from toolkit.infra.finding import NormalizedFinding
    from toolkit.infra import inject
    _HAVE_FINDING = True
except Exception:  # pragma: no cover
    _HAVE_FINDING = False


_EVIL = "https://evil.example.com"
_PAYLOADS = [
    "https://evil.example.com",
    "//evil.example.com",
    "/\\evil.example.com",
    "https:evil.example.com",
]


def _detect_redirect(status: int, location: str) -> bool:
    loc = (location or "").strip()
    if status < 300 or status > 399 or not loc:
        return False
    return loc.startswith(_EVIL) or loc.startswith("//evil.example.com") \
        or loc.startswith("https:evil.example.com")


@dataclass
class OpenRedirectFinding:
    url: str
    method: str
    param: str
    payload: str
    evidence: str = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


async def _send(client, endpoint: Any, param: str, value: str, *,
                timeout: float = 10.0) -> tuple[int, str]:
    via = getattr(endpoint, "inject_via", "query")
    headers = {"User-Agent": "Mozilla/5.0 (compatible; BBTK-or/1.0)"}
    try:
        if via == "body_form":
            r = await client.request(endpoint.method, endpoint.url, headers=headers,
                                     data={param: value}, timeout=timeout, follow_redirects=False)
        elif via == "body_json":
            r = await client.request(endpoint.method, endpoint.url,
                                     headers={**headers, "Content-Type": "application/json"},
                                     json={param: value}, timeout=timeout, follow_redirects=False)
        else:
            full = inject.build_injection_url(endpoint.url, param, value)
            r = await client.request(endpoint.method, full, headers=headers,
                                     timeout=timeout, follow_redirects=False)
        status = int(getattr(r, "status_code", 0) or 0)
        loc = getattr(r, "headers", {}).get("location", "") or ""
        return status, loc
    except Exception:
        return 0, ""


async def test_endpoint(endpoint: Any, client: object, *,
                        timeout: float = 10.0) -> list[OpenRedirectFinding]:
    params = list(getattr(endpoint, "params", []) or [])
    if not params:
        return []
    out: list[OpenRedirectFinding] = []
    seen: set[str] = set()
    for param in params:
        for p in _PAYLOADS:
            status, loc = await _send(client, endpoint, param, p, timeout=timeout)
            if _detect_redirect(status, loc):
                if param not in seen:
                    seen.add(param)
                    out.append(OpenRedirectFinding(endpoint.url, endpoint.method, param, p,
                                  f"redirects to {loc}"))
                break
    return out


async def run_openredirect(endpoints: list[Any], client: object, *,
                           timeout: float = 10.0, concurrency: int = 10) -> list[OpenRedirectFinding]:
    sem = asyncio.Semaphore(concurrency)

    async def guarded(ep):
        async with sem:
            return await test_endpoint(ep, client, timeout=timeout)
    results = await asyncio.gather(*[guarded(ep) for ep in endpoints])
    return [f for sub in results for f in sub]


def to_normalized_findings(findings: list[OpenRedirectFinding],
                           source_tool: str = "openredirect.py") -> list[dict]:
    out: list[dict] = []
    for f in findings:
        detail = (f"Open redirect via parameter '{f.param}' "
                  f"({f.method} {f.url}) -> attacker host")
        if _HAVE_FINDING:
            nf = NormalizedFinding(source_tool=source_tool, host=_host(f.url), url=f.url,
                                   vuln_class_key="OPEN_REDIRECT", severity="MEDIUM",
                                   title=f"Open Redirect in {f.param}",
                                   detail=detail, evidence=f"payload={f.payload} {f.evidence}",
                                   confidence="confirmed")
            d = nf.to_dict()
            d["param"] = f.param
        else:
            d = {"source_tool": source_tool, "host": _host(f.url), "url": f.url,
                 "param": f.param, "vuln_class_key": "OPEN_REDIRECT", "severity": "MEDIUM",
                 "title": f"Open Redirect in {f.param}", "detail": detail,
                 "evidence": f.payload, "confidence": "confirmed"}
        out.append(d)
    return out


def _host(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).netloc
