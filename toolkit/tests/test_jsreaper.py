"""Tests for scripts/jsreaper.py cookie/extra_headers propagation (Phase A: A8)."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_SCRIPTS = str(_REPO_ROOT / "scripts")
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)

import jsreaper  # noqa: E402


def test_fetch_propagates_cookie_and_extra_headers(mock_http_server):
    """fetch() must forward cookie + extra_headers so authenticated JS can be
    harvested (previously all requests were unauthenticated)."""
    base_url, server = mock_http_server
    server.routes = {("GET", "/asset.js"): {"status": 200, "body": "console.log(1)"}}

    async def _run():
        async with jsreaper.httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
            await jsreaper.fetch(
                f"{base_url}/asset.js", client=client,
                cookie="session=abc", extra_headers={"X-Custom": "1"},
            )

    asyncio.run(_run())
    recs = [r for r in server.recorded_requests if r["path"].endswith("/asset.js")]
    assert recs, "request was not recorded"
    headers = recs[0]["headers"]
    assert headers.get("Cookie") == "session=abc"
    assert headers.get("X-Custom") == "1"


def test_fetch_without_auth_sends_only_ua(mock_http_server):
    base_url, server = mock_http_server
    server.routes = {("GET", "/plain.js"): {"status": 200, "body": "x=1"}}

    async def _run():
        async with jsreaper.httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
            await jsreaper.fetch(f"{base_url}/plain.js", client=client)

    asyncio.run(_run())
    recs = [r for r in server.recorded_requests if r["path"].endswith("/plain.js")]
    assert recs
    headers = recs[0]["headers"]
    assert "Cookie" not in headers
    assert "X-Custom" not in headers


def test_user_agent_override_applied(mock_http_server):
    """--user-agent (C18) must override the UA sent on every request."""
    jsreaper.set_user_agent("CustomUA/9.9")
    try:
        base_url, server = mock_http_server
        server.routes = {("GET", "/ua.js"): {"status": 200, "body": "x"}}

        async def _run():
            async with jsreaper.httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
                await jsreaper.fetch(f"{base_url}/ua.js", client=client)

        asyncio.run(_run())
        recs = [r for r in server.recorded_requests if r["path"].endswith("/ua.js")]
        assert recs, "request was not recorded"
        sent_ua = recs[0]["headers"].get("user-agent") or recs[0]["headers"].get("User-Agent")
        assert sent_ua == "CustomUA/9.9"
    finally:
        jsreaper.set_user_agent("")  # reset to module default
