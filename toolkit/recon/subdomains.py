#!/usr/bin/env python3
"""Passive subdomain enumeration sources for recon.

Sources require no API key and stay low-profile (single GET each). Results are
de-duplicated and filtered to the target domain suffix.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

CRTSH_URL = "https://crt.sh/"


async def crtsh_subdomains(domain: str, client, timeout: float = 12.0) -> list[str]:
    """Enumerate subdomains via the crt.sh certificate-transparency log."""
    q = f"%.{domain}"
    url = f"{CRTSH_URL}?q={q}&output=json"
    try:
        r = await client.get(
            url, timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (compatible; BBTK/1.0)"},
        )
    except Exception:
        return []
    if getattr(r, "status_code", 0) != 200:
        return []
    try:
        data = r.json()
    except Exception:
        return []
    seen: set[str] = set()
    for row in data or []:
        nv = row.get("name_value") or ""
        for name in nv.split("\n"):
            name = name.strip().lower()
            if name and "*" not in name:
                seen.add(name)
    return sorted(n for n in seen if n == domain or n.endswith("." + domain))


def _normalize_domain(host: str) -> str:
    host = host.strip().lower()
    if host.startswith("http://") or host.startswith("https://"):
        host = urlparse(host).netloc
    return host.split(":")[0]
