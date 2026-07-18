#!/usr/bin/env python3
"""
access_control.py — Broken access control / auth-bypass heuristics (P2)
=====================================================================
Two dynamic heuristics for access-control issues:

  1. Forced browsing — sensitive paths (admin/dashboard/manage/console/...)
     that are reachable (HTTP 200) are flagged as "possible missing
     authentication" candidates (manual confirmation required).
  2. Privilege/debug override params — sending ``admin=true`` / ``debug=1`` /
     ``test=1`` and observing a status change (e.g. 403 -> 200) or a
     materially different response flags a possible insecure direct object /
     role override.

Confidence is "unconfirmed": prioritization signals, not confirmed vulns.
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


_SENSITIVE = ("admin", "dashboard", "manage", "console", "account",
              "profile", "settings", "phpmyadmin", "wp-admin", "config",
              "backup", "debug", "panel", "root")
_DEBUG_PARAMS = {"admin": "true", "debug": "1", "test": "1",
                 "dev": "true", "role": "admin"}


def _path_segments(url: str) -> list[str]:
    from urllib.parse import urlparse
    path = urlparse(url).path.strip("/")
    return [s.lower() for s in path.split("/") if s]


def is_sensitive_path(url: str) -> bool:
    segs = _path_segments(url)
    return any(any(s in seg for s in _SENSITIVE) for seg in segs)


@dataclass
class AccessControlFinding:
    url: str
    method: str
    kind: str
    param: str = ""
    evidence: str = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


async def _get(client, url: str, *, timeout: float = 10.0) -> tuple[int, str]:
    headers = {"User-Agent": "Mozilla/5.0 (compatible; BBTK-ac/1.0)"}
    try:
        r = await client.get(url, headers=headers, timeout=timeout,
                             follow_redirects=False)
        return int(getattr(r, "status_code", 0) or 0), getattr(r, "text", "") or ""
    except Exception:
        return 0, ""


async def test_endpoint(endpoint: Any, client: object, *,
                        timeout: float = 10.0) -> list[AccessControlFinding]:
    out: list[AccessControlFinding] = []
    url = endpoint.url

    # 1) forced browsing — only probe GET sensitive paths
    if is_sensitive_path(url) and getattr(endpoint, "method", "GET").upper() == "GET":
        status, _ = await _get(client, url, timeout=timeout)
        if status == 200:
            out.append(AccessControlFinding(url, "GET", "forced-browsing", "",
                            "sensitive path returns 200 (reachable without auth)"))

    # 2) debug/role override params (query-injected only)
    if getattr(endpoint, "inject_via", "query") == "query":
        from toolkit.infra import inject
        base_status, base_body = await _get(client, url, timeout=timeout)
        for p, v in _DEBUG_PARAMS.items():
            if p in (endpoint.params or []):
                continue
            probe = inject.build_injection_url(url, p, v)
            st, body = await _get(client, probe, timeout=timeout)
            if (base_status not in (200,)) and st == 200:
                out.append(AccessControlFinding(url, "GET", "override-param", p,
                                f"{p}={v} changed status {base_status} -> 200"))
            elif st == 200 and base_body and body and abs(len(body) - len(base_body)) > 50:
                out.append(AccessControlFinding(url, "GET", "override-param", p,
                                f"{p}={v} altered response body significantly"))
    return out


async def run_access_control(endpoints: list[Any], client: object, *,
                             timeout: float = 10.0,
                             concurrency: int = 10) -> list[AccessControlFinding]:
    sem = asyncio.Semaphore(concurrency)

    async def guarded(ep):
        async with sem:
            return await test_endpoint(ep, client, timeout=timeout)
    results = await asyncio.gather(*[guarded(ep) for ep in endpoints])
    return [f for sub in results for f in sub]


def to_normalized_findings(findings: list[AccessControlFinding],
                           source_tool: str = "access_control.py") -> list[dict]:
    out: list[dict] = []
    for f in findings:
        sev = "LOW"
        detail = (f"Possible broken access control ({f.kind}) on {f.method} {f.url}"
                  + (f" via param '{f.param}'" if f.param else "")
                  + " — manual confirmation required.")
        if _HAVE_FINDING:
            nf = NormalizedFinding(source_tool=source_tool, host=_host(f.url), url=f.url,
                                   vuln_class_key="BROKEN_ACCESS_CONTROL", severity=sev,
                                   title=f"Possible Access Control Issue ({f.kind})",
                                   detail=detail, evidence=f.evidence,
                                   confidence="unconfirmed")
            d = nf.to_dict()
            d["param"] = f.param
        else:
            d = {"source_tool": source_tool, "host": _host(f.url), "url": f.url,
                 "param": f.param, "vuln_class_key": "BROKEN_ACCESS_CONTROL",
                 "severity": sev, "title": f"Possible Access Control Issue ({f.kind})",
                 "detail": detail, "evidence": f.evidence, "confidence": "unconfirmed"}
        out.append(d)
    return out


def _host(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).netloc
