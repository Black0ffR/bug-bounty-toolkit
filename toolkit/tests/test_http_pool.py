"""Tests for toolkit.infra.http_pool (Phase B: B19 shared connection pool)."""
from __future__ import annotations

import asyncio

import httpx

from toolkit.infra import http_pool


def test_build_client_configures_limits_and_timeout():
    limits = httpx.Limits(max_connections=5)
    c = http_pool.build_client(timeout=7.0, limits=limits)
    assert isinstance(c, httpx.AsyncClient)
    assert c.timeout.read == 7.0
    # DEFAULT_LIMITS is applied when none is supplied.
    default = http_pool.build_client()
    assert default.timeout.read == 30.0
    assert c.headers["User-Agent"].startswith("Mozilla")


def test_get_shared_client_reuses_same_instance():
    async def go():
        a = await http_pool.get_shared_client()
        b = await http_pool.get_shared_client()
        return a, b
    a, b = asyncio.run(go())
    assert a is b  # connection reuse across the loop
    assert not a.is_closed


def test_shared_client_cm_reuses_existing_and_does_not_close_it():
    async def go():
        owned = await http_pool.get_shared_client()
        async with http_pool.shared_client() as inner:
            reused = inner is owned
        # shared client must remain open (not owned by the CM)
        still_open = not owned.is_closed
        await http_pool.close_shared_clients()
        return reused, still_open
    reused, still_open = asyncio.run(go())
    assert reused is True
    assert still_open is True


def test_close_shared_clients_clears_pool():
    async def go():
        await http_pool.get_shared_client()
        await http_pool.close_shared_clients()
        return len(http_pool._shared_clients)
    assert asyncio.run(go()) == 0
