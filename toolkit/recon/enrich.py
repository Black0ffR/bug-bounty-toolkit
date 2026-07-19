#!/usr/bin/env python3
"""Recon enrichment: confirm discovered hosts are live and fingerprint them.

Mirrors the httpx liveness-probe step from the web2-recon pipeline — turn a raw
list of subdomains into a confirmed, tech-fingerprinted attack surface so the
scanner spends requests only on hosts that answer.
"""
from __future__ import annotations

from urllib.parse import urlparse

from . import posture as posture_mod
from . import tech as tech_mod


async def live_check(hosts: list[str], client, timeout: float = 8.0) -> list[dict]:
    """Probe each host over https then http; return live hosts with signals.

    Each result: {host, url, status, live, tech, posture}.
    """
    out: list[dict] = []
    for host in hosts:
        host = host.strip()
        if not host:
            continue
        live = False
        final_url = ""
        headers: dict = {}
        status = None
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            try:
                r = await client.get(
                    url, timeout=timeout, follow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 (compatible; BBTK/1.0)"},
                )
            except Exception:
                continue
            status = getattr(r, "status_code", None)
            headers = dict(getattr(r, "headers", {}) or {})
            final_url = getattr(r, "url", url) or url
            live = status is not None and status < 500
            if live:
                break
        out.append({
            "host": host,
            "url": final_url or (f"https://{host}"),
            "status": status,
            "live": live,
            "tech": tech_mod.fingerprint(headers, "") if live else {},
            "posture": posture_mod.analyze_headers(headers) if live else [],
        })
    return out


def live_hosts_only(results: list[dict]) -> list[dict]:
    return [r for r in results if r.get("live")]
