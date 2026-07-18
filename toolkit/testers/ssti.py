#!/usr/bin/env python3
"""
ssti.py — Server-Side Template Injection detection (P1)
======================================================
Sends a template-expression payload carrying a unique arithmetic marker and
checks whether the evaluated result is reflected in the response. Uses a
per-request random product so a benign page that happens to contain "49"
does not cause a false positive. Pure checkers are unit-testable;
only ``test_endpoint``/``run_ssti`` do I/O.
"""
from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass
from typing import Any

try:
    from toolkit.infra.finding import NormalizedFinding
    from toolkit.infra import inject
    _HAVE_FINDING = True
except Exception:  # pragma: no cover
    _HAVE_FINDING = False


# (template_literal, render_fn) — render_fn computes the expected reflection.
_ENGINES = [
    ("{{{{ {a} * {a} }}}}", lambda a: str(a * a)),            # Jinja2 / Twig / FreeMarker
    ("${{{a} * {a}}}", lambda a: str(a * a)),                 # Spring EL / Velocity
    ("#{7*7}", lambda _: "49"),                               # Thymeleaf
    ("<%= 7 * 7 %>", lambda _: "49"),                         # ERB
    ("{{{{ 7 * '7' }}}}", lambda _: "7777777"),               # string repeat
]


def _expected(template: str, render_fn, a: int) -> str:
    return render_fn(a) if "{" not in template or "a" in template else render_fn(a)


def _detect_ssti(orig_body: str, resp_body: str, expected: str) -> bool:
    # The expected evaluated result must appear AND not have been in the
    # baseline (avoids coincidental matches).
    return expected in resp_body and expected not in (orig_body or "")


@dataclass
class SstiFinding:
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
    headers = {"User-Agent": "Mozilla/5.0 (compatible; BBTK-ssti/1.0)"}
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
                        timeout: float = 10.0) -> list[SstiFinding]:
    params = list(getattr(endpoint, "params", []) or [])
    if not params:
        return []
    out: list[SstiFinding] = []
    seen: set[str] = set()
    for param in params:
        base = str(random.randint(1000, 9999))
        orig = await _send(client, endpoint, param, base, timeout=timeout)
        for template, render_fn in _ENGINES:
            a = random.randint(100000, 999999)
            if "a" in template:
                payload = template.format(a=a)
                expected = render_fn(a)
            else:
                payload = template
                expected = render_fn(a)
            resp = await _send(client, endpoint, param, payload, timeout=timeout)
            if _detect_ssti(orig, resp, expected):
                if param not in seen:
                    seen.add(param)
                    out.append(SstiFinding(endpoint.url, endpoint.method, param, payload,
                                          f"reflected evaluated expression '{expected}'"))
                break
    return out


async def run_ssti(endpoints: list[Any], client: object, *,
                   timeout: float = 10.0, concurrency: int = 10) -> list[SstiFinding]:
    sem = asyncio.Semaphore(concurrency)

    async def guarded(ep):
        async with sem:
            return await test_endpoint(ep, client, timeout=timeout)
    results = await asyncio.gather(*[guarded(ep) for ep in endpoints])
    return [f for sub in results for f in sub]


def to_normalized_findings(findings: list[SstiFinding],
                           source_tool: str = "ssti.py") -> list[dict]:
    out: list[dict] = []
    for f in findings:
        detail = (f"Server-Side Template Injection via parameter "
                  f"'{f.param}' ({f.method} {f.url})")
        if _HAVE_FINDING:
            nf = NormalizedFinding(source_tool=source_tool, host=_host(f.url), url=f.url,
                                   vuln_class_key="SSTI", severity="HIGH",
                                   title=f"SSTI in {f.param}",
                                   detail=detail, evidence=f"payload={f.payload} {f.evidence}",
                                   confidence="confirmed")
            d = nf.to_dict()
            d["param"] = f.param
        else:
            d = {"source_tool": source_tool, "host": _host(f.url), "url": f.url,
                 "param": f.param, "vuln_class_key": "SSTI", "severity": "HIGH",
                 "title": f"SSTI in {f.param}", "detail": detail,
                 "evidence": f.payload, "confidence": "confirmed"}
        out.append(d)
    return out


def _host(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).netloc
