"""Shared httpx connection pool for the toolkit.
================================================

Tools that make outbound HTTP requests historically construct a brand-new
``httpx.AsyncClient`` per call/run. Under large scans this burns a TLS handshake
on every request. This module provides a single, reused ``AsyncClient`` per
event loop so connections stay warm (keep-alive) and handshake overhead drops.

Usage (library)
----------------
    from toolkit.infra.http_pool import shared_client

    async with shared_client() as client:
        r = await client.get(url)

Or, to reuse one client across many coroutines in a loop:

    client = await get_shared_client()
    try:
        ...  # many awaits
    finally:
        await close_shared_clients()

The pool is keyed by asyncio event-loop id, so each loop gets its own client
and ``close_shared_clients()`` cleans them all up at process exit.

Author : Bug Bounty Toolkit / Tier 1
License : MIT (for authorized use only)
"""

from __future__ import annotations

import asyncio
import httpx
from typing import Any


# Conservative defaults: high enough for parallel scans, low enough to avoid
# slamming a single host (scope_guard handles the per-host rate limiting).
DEFAULT_LIMITS = httpx.Limits(
    max_connections=100,
    max_keepalive_connections=20,
    keepalive_expiry=60.0,
)

DEFAULT_HEADERS: dict[str, str] = {
    "User-Agent": "Mozilla/5.0 (compatible; BBTK/1.0)",
    "Accept": "*/*",
}

# Pool state: one client per event loop, created lazily.
_shared_clients: dict[int, httpx.AsyncClient] = {}


def build_client(
    *,
    verify: bool = False,
    follow_redirects: bool = True,
    timeout: float = 30.0,
    limits: httpx.Limits | None = None,
    headers: dict[str, str] | None = None,
    proxy: str | None = None,
) -> httpx.AsyncClient:
    """Construct a configured AsyncClient. Pure factory — no I/O, safe to test."""
    return httpx.AsyncClient(
        verify=verify,
        follow_redirects=follow_redirects,
        timeout=timeout,
        limits=limits or DEFAULT_LIMITS,
        headers=headers or DEFAULT_HEADERS,
        proxy=proxy,
    )


def _loop_key() -> int:
    try:
        return id(asyncio.get_running_loop())
    except RuntimeError:
        # No running loop — fall back to the base event loop's id.
        return id(asyncio.get_event_loop())


async def get_shared_client(
    *,
    verify: bool = False,
    follow_redirects: bool = True,
    timeout: float = 30.0,
    limits: httpx.Limits | None = None,
    headers: dict[str, str] | None = None,
    proxy: str | None = None,
) -> httpx.AsyncClient:
    """Return the shared AsyncClient for the current event loop, creating it on
    first use. Subsequent calls in the same loop return the SAME instance
    (connection reuse across all tools running in that loop)."""
    key = _loop_key()
    client = _shared_clients.get(key)
    if client is None or client.is_closed:
        client = build_client(
            verify=verify, follow_redirects=follow_redirects,
            timeout=timeout, limits=limits, headers=headers, proxy=proxy,
        )
        _shared_clients[key] = client
    return client


class _SharedClientCM:
    """Async context manager that yields the shared client and only closes it
    when the loop's pool entry was created by this ``with`` block."""

    def __init__(self, **kwargs: Any) -> None:
        self._kwargs = kwargs
        self._client: httpx.AsyncClient | None = None
        self._owned = False

    async def __aenter__(self) -> httpx.AsyncClient:
        key = _loop_key()
        existing = _shared_clients.get(key)
        if existing is not None and not existing.is_closed:
            self._client = existing
            self._owned = False
        else:
            self._client = build_client(**self._kwargs)
            _shared_clients[key] = self._client
            self._owned = True
        return self._client

    async def __aexit__(self, *exc: Any) -> None:
        if self._owned and self._client is not None and not self._client.is_closed:
            await self._client.aclose()
            key = _loop_key()
            _shared_clients.pop(key, None)


def shared_client(**kwargs: Any) -> _SharedClientCM:
    """Async context-manager entry point: ``async with shared_client() as c:``."""
    return _SharedClientCM(**kwargs)


async def close_shared_clients() -> None:
    """Close every pooled client and clear the registry. Call at process exit."""
    for key, client in list(_shared_clients.items()):
        if not client.is_closed:
            try:
                await client.aclose()
            except Exception:
                pass
    _shared_clients.clear()
