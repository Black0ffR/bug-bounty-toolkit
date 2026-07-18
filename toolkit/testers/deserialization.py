#!/usr/bin/env python3
"""
deserialization.py — Insecure Deserialization detection (P2)
===========================================================
Best-effort, error-signature based probe for server-side deserialization
sinks (Java ObjectInputStream, Python pickle, PHP unserialize, .NET).
Sends magic-prefixed payloads (Java `AC ED 00 05`, Python pickle
`\x80\x04`, PHP `O:`) and looks for framework deserialization error
strings in the response. Confirmation requires a working gadget chain, so
any signal here is "probable" and warrants manual follow-up.

Pure checker is unit-testable; only ``test_endpoint``/``run_deserialization``
do I/O.
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


_JAVA_MAGIC = b"\xac\xed\x00\x05"
_PY_PICKLE = b"\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x00"
_PHP_MAGIC = b"O:8:\"Exploit\":0:{}"

_ERROR_SIGS = ["java.io", "invalidclass", "objectinputstream", "streamcorrupted",
               "cannot be cast", "notserializable", "pickle", "unpicklingerror",
               "unsupportedoperation", "php unserialize", "unserialize()",
               "notice: unserialize", "magicquotes", "caused by: java"]


def _detect_deser_error(text: str) -> str:
    low = (text or "").lower()
    for s in _ERROR_SIGS:
        if s in low:
            return s
    return ""


@dataclass
class DeserFinding:
    url: str
    method: str
    fmt: str
    evidence: str = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


async def _send_bytes(client, endpoint: Any, ctype: str, payload: bytes, *,
                      timeout: float = 10.0) -> str:
    headers = {"User-Agent": "Mozilla/5.0 (compatible; BBTK-deser/1.0)",
               "Content-Type": ctype}
    try:
        r = await client.request(endpoint.method, endpoint.url, headers=headers,
                                 content=payload, timeout=timeout)
        return getattr(r, "text", "") or ""
    except Exception:
        return ""


async def test_endpoint(endpoint: Any, client: object, *,
                        timeout: float = 10.0) -> list[DeserFinding]:
    probes = [
        ("java", "application/x-java-serialized-object", _JAVA_MAGIC + b"\x00badclass"),
        ("python-pickle", "application/octet-stream", _PY_PICKLE + b"c__builtin__\ngetattr\n"),
        ("php", "application/octet-stream", _PHP_MAGIC),
    ]
    out: list[DeserFinding] = []
    seen: set[str] = set()
    for fmt, ctype, payload in probes:
        body = await _send_bytes(client, endpoint, ctype, payload, timeout=timeout)
        sig = _detect_deser_error(body)
        if sig and fmt not in seen:
            seen.add(fmt)
            out.append(DeserFinding(endpoint.url, endpoint.method, fmt,
                                    f"deserialization error signature '{sig}'"))
    return out


async def run_deserialization(endpoints: list[Any], client: object, *,
                              timeout: float = 10.0,
                              concurrency: int = 10) -> list[DeserFinding]:
    sem = asyncio.Semaphore(concurrency)

    async def guarded(ep):
        async with sem:
            return await test_endpoint(ep, client, timeout=timeout)
    results = await asyncio.gather(*[guarded(ep) for ep in endpoints])
    return [f for sub in results for f in sub]


def to_normalized_findings(findings: list[DeserFinding],
                           source_tool: str = "deserialization.py") -> list[dict]:
    out: list[dict] = []
    for f in findings:
        detail = (f"Possible insecure deserialization ({f.fmt}) on {f.method} {f.url} "
                  f"— {f.evidence}")
        if _HAVE_FINDING:
            nf = NormalizedFinding(source_tool=source_tool, host=_host(f.url), url=f.url,
                                   vuln_class_key="INSECURE_DESERIALIZATION", severity="MEDIUM",
                                   title=f"Possible Insecure Deserialization ({f.fmt})",
                                   detail=detail, evidence=f.evidence,
                                   confidence="probable")
            d = nf.to_dict()
            d["param"] = ""
        else:
            d = {"source_tool": source_tool, "host": _host(f.url), "url": f.url,
                 "param": "", "vuln_class_key": "INSECURE_DESERIALIZATION", "severity": "MEDIUM",
                 "title": f"Possible Insecure Deserialization ({f.fmt})", "detail": detail,
                 "evidence": f.evidence, "confidence": "probable"}
        out.append(d)
    return out


def _host(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).netloc
