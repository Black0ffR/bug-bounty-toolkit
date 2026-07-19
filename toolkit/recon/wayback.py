#!/usr/bin/env python3
"""Historical URL harvesting via the Wayback Machine CDX API.

Cheap, passive, and excellent for discovering legacy endpoints, parameters and
files that the live crawler can no longer reach.
"""
from __future__ import annotations

WAYBACK_CDX = "https://web.archive.org/cdx/search/cdx"


async def wayback_urls(domain: str, client, limit: int = 5000,
                       timeout: float = 15.0) -> list[str]:
    url = (f"{WAYBACK_CDX}?url=*.{domain}/*&output=json"
           f"&collapse=urlkey&fl=original&limit={limit}")
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
        rows = r.json()
    except Exception:
        return []
    if not rows:
        return []
    # First row may be a header ["original"]; skip if so.
    out: list[str] = []
    for row in rows:
        if not row:
            continue
        if row == ["original"]:
            continue
        val = row[0]
        if val:
            out.append(val)
    return out
