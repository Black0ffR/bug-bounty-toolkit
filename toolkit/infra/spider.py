#!/usr/bin/env python3
"""
spider.py — autonomous parameter-aware web crawler (P0)
=======================================================

Recursively discovers a target's attack surface so the detectors
(apifuzz, xss_context, ssrfprobe, sqli, ...) actually get fed endpoints
instead of requiring a hand-built ``--urls`` seed list.

The crawler:
  * follows same-origin ``<a href>``, ``<form action>``, ``<script src>``,
    ``<link href>``, ``<iframe src>``,
  * records form methods + parameter names (so POST/body injection is possible),
  * extracts query-string parameter names from every discovered URL,
  * deduplicates by (url-without-query, method, param-set),
  * is bounded by ``max_depth`` / ``max_urls`` / ``concurrency``.

Pure helpers (``extract_endpoints``, ``_normalize``) are testable without
network; only ``crawl`` performs I/O via an httpx-like async ``client``.

Author : Bug Bounty Toolkit / Layer 0
License : MIT (for authorized use only)
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

try:
    from toolkit.infra import scope_guard as _sg
    _HAVE_SG = True
except Exception:  # pragma: no cover - standalone fallback
    _HAVE_SG = False


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)
    inject_via: str = "query"
    source: str = ""          # "link" | "form" | "asset"


def _normalize(url: str) -> str:
    """Strip fragment and empty query; keep scheme/netloc/path/?query."""
    p = urlparse(url)
    q = p.query
    return urlunparse((p.scheme, p.netloc, p.path or "/", p.params, q, ""))


def _same_origin(a: str, b: str) -> bool:
    return urlparse(a).netloc == urlparse(b).netloc


def _endpoint_from_url(url: str, method: str = "GET", source: str = "link") -> Endpoint:
    u = _normalize(url)
    params = [k for k, _ in parse_qsl(urlparse(u).query)]
    return Endpoint(url=u, method=method, params=params,
                    inject_via="query" if method == "GET" else "body_form",
                    source=source)


def extract_endpoints(html: str, base_url: str) -> list[Endpoint]:
    """Parse an HTML body into discovered endpoints (no network)."""
    soup = BeautifulSoup(html or "", "html.parser")
    out: list[Endpoint] = []

    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith(("javascript:", "mailto:", "tel:", "data:")):
            continue
        out.append(_endpoint_from_url(urljoin(base_url, href), "GET", "link"))

    for f in soup.find_all("form"):
        action = f.get("action", "") or ""
        method = (f.get("method") or "GET").upper()
        target = urljoin(base_url, action) if action else base_url
        params = [i.get("name") for i in
                  f.find_all(["input", "select", "textarea"]) if i.get("name")]
        ep = Endpoint(url=_normalize(target), method=method, params=params,
                      inject_via="body_form" if method != "GET" else "query",
                      source="form")
        out.append(ep)

    for tag in soup.find_all(["script", "link", "iframe"], src=True):
        src = tag["src"].strip()
        if not src or src.startswith(("javascript:", "data:", "mailto:")):
            continue
        out.append(_endpoint_from_url(urljoin(base_url, src), "GET", "asset"))

    return _dedup(out)


def _dedup(eps: list[Endpoint]) -> list[Endpoint]:
    seen: dict[tuple[str, str, str], Endpoint] = {}
    for ep in eps:
        key = (ep.url, ep.method, ",".join(sorted(set(ep.params))))
        if key in seen:
            # merge param lists
            existing = seen[key]
            merged = sorted(set(existing.params) | set(ep.params))
            seen[key] = Endpoint(url=existing.url, method=existing.method,
                                 params=merged, inject_via=existing.inject_via,
                                 source=existing.source)
        else:
            seen[key] = ep
    return list(seen.values())


def _in_scope(url: str, guard, start_netloc: str, same_origin: bool) -> bool:
    if guard is not None:
        try:
            guard.check_url(url)
            return True
        except Exception:
            return False
    if same_origin:
        return _same_origin(url, start_netloc) or urlparse(url).netloc == start_netloc
    return True


async def crawl(
    start_url: str,
    client: object,
    *,
    max_depth: int = 2,
    max_urls: int = 200,
    concurrency: int = 10,
    same_origin: bool = True,
    timeout: float = 10.0,
    scope_path: str | None = None,
    seeds: list[str] | None = None,
) -> list[Endpoint]:
    """Bounded BFS crawl. ``client`` must expose an awaitable
    ``client.get(url, headers=..., timeout=...) -> resp`` with ``.text`` and
    ``.status_code``.

    ``seeds`` are URLs (e.g. historical Wayback paths, JS-discovered API
    routes, hidden endpoints) injected directly as endpoints (with their
    query params) and also enqueued for further crawling. This lets recon
    output feed the scanner without the live crawler having to link to them.

    Returns a deduplicated list of discovered ``Endpoint`` objects (links,
    forms, and asset URLs with their parameters).
    """
    guard = _sg.ScopeGuard(scope_path) if (scope_path and _HAVE_SG) else None
    start_netloc = urlparse(start_url).netloc

    visited: set[str] = set()
    collected: dict[tuple[str, str], Endpoint] = {}
    queue: list[str] = [_normalize(start_url)]

    for s in (seeds or []):
        s_n = _normalize(s)
        if not _in_scope(s_n, guard, start_netloc, same_origin):
            continue
        ep = _endpoint_from_url(s_n)
        key = (ep.url, ep.method)
        if key not in collected:
            collected[key] = ep
        if s_n not in visited:
            queue.append(s_n)

    sem = asyncio.Semaphore(concurrency)
    headers = {"User-Agent": "Mozilla/5.0 (compatible; BBTK-Spider/1.0)"}

    async def fetch(url: str) -> str:
        async with sem:
            try:
                r = await client.get(url, headers=headers, timeout=timeout)
                return getattr(r, "text", "") or ""
            except Exception:
                return ""

    level = 0
    while queue and level <= max_depth and len(visited) < max_urls:
        next_q: list[str] = []
        bodies = await asyncio.gather(*[fetch(u) for u in queue])
        for url, html in zip(queue, bodies):
            visited.add(url)
            for ep in extract_endpoints(html, url):
                if len(visited) + len(collected) >= max_urls:
                    break
                if not _in_scope(ep.url, guard, start_netloc, same_origin):
                    continue
                if ep.url not in visited:
                    next_q.append(ep.url)
                key = (ep.url, ep.method)
                if key in collected:
                    existing = collected[key]
                    merged = sorted(set(existing.params) | set(ep.params))
                    collected[key] = Endpoint(url=existing.url, method=existing.method,
                                              params=merged, inject_via=existing.inject_via,
                                              source=existing.source)
                else:
                    collected[key] = ep
        queue = [u for u in next_q if u not in visited][:max_urls]
        level += 1

    return list(collected.values())
