#!/usr/bin/env python3
"""Recon orchestrator: ties passive + active discovery into one result.

Produces a structured dict consumed by `scripts/recon.py` and the scan CLI.
All network calls go through the supplied (optionally stealth) httpx client.
"""
from __future__ import annotations

from urllib.parse import urlparse

from . import enrich as enrich_mod
from . import js as js_mod
from . import posture as posture_mod
from . import subdomains as sub_mod
from . import tech as tech_mod
from . import wayback as wb_mod


async def run_recon(target_url: str, client, *, depth: int = 1,
                    wayback_limit: int = 5000, timeout: float = 12.0) -> dict:
    result: dict = {
        "target": target_url,
        "domain": urlparse(target_url).netloc,
        "tech": {},
        "posture": [],
        "js_sources": [],
        "js_endpoints": [],
        "js_secrets": [],
        "subdomains": [],
        "live_hosts": [],
        "wayback_urls": [],
        "js_error": None,
    }

    try:
        r = await client.get(target_url, timeout=timeout,
                             headers={"User-Agent": "Mozilla/5.0 (compatible; BBTK/1.0)"})
    except Exception as e:
        result["js_error"] = f"root fetch failed: {e}"
        r = None

    if r is not None:
        headers = dict(getattr(r, "headers", {}) or {})
        body = getattr(r, "text", "") or ""
        result["tech"] = tech_mod.fingerprint(headers, body)
        result["posture"] = posture_mod.analyze_headers(headers)

        try:
            sources = await js_mod.collect_js(body, target_url, client, timeout=timeout)
            result["js_sources"] = sources
            for src in sources[:30]:  # bound work; deep JS crawl is opt-in
                try:
                    jr = await client.get(src, timeout=timeout)
                except Exception:
                    continue
                js = getattr(jr, "text", "") or ""
                result["js_endpoints"].extend(js_mod.extract_endpoints(js))
                result["js_secrets"].extend(js_mod.extract_secrets(js))
        except Exception as e:
            result["js_error"] = str(e)
        result["js_endpoints"] = sorted(set(result["js_endpoints"]))
        result["js_secrets"] = result["js_secrets"]

    domain = result["domain"]
    if domain:
        result["subdomains"] = await sub_mod.enumerate_subdomains(
            domain, client, timeout=timeout)
        result["wayback_urls"] = await wb_mod.wayback_urls(
            domain, client, limit=wayback_limit, timeout=timeout)
        # Confirm which discovered hosts actually answer, with tech/posture.
        checks = await enrich_mod.live_check(result["subdomains"], client,
                                             timeout=timeout)
        result["live_hosts"] = enrich_mod.live_hosts_only(checks)

    return result


def recon_to_seeds(recon: dict, target_netloc: str) -> dict:
    """Convert a recon result into scanner seeds.

    Returns {"same_origin": [urls], "subdomain_hosts": [hosts]}:
      * ``same_origin`` — js_endpoints + wayback_urls that hit the target
        host; fed as extra crawl seeds so detectors test historical/JS paths.
      * ``subdomain_hosts`` — live subdomain hosts; each gets its own crawl.
    """
    same_origin: list[str] = []
    for url in list(recon.get("js_endpoints", [])) + list(recon.get("wayback_urls", [])):
        try:
            p = urlparse(url)
        except Exception:
            continue
        if p.netloc == target_netloc:
            same_origin.append(url)
        elif p.netloc == "" and url.startswith("/"):
            # relative JS/endpoint path -> resolve against the target
            same_origin.append(f"http://{target_netloc}{url}")
        elif p.netloc.endswith("." + target_netloc):
            same_origin.append(url)
    hosts = [h.get("host") for h in recon.get("live_hosts", []) if h.get("live")]
    return {"same_origin": sorted(set(same_origin)), "subdomain_hosts": sorted(set(hosts))}
