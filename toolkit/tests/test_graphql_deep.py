"""Tests for toolkit.testers.graphql_deep depth-DoS probe (Phase A: A7)."""
from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from toolkit.testers import graphql_deep


_RECURSIVE_SCHEMA = {
    "queryType": {"name": "Query"},
    "types": [
        {"name": "Query", "kind": "OBJECT",
         "fields": [{"name": "user", "type": {"kind": "OBJECT", "name": "User"}}]},
        {"name": "User", "kind": "OBJECT",
         "fields": [
             {"name": "id", "type": {"kind": "SCALAR", "name": "ID"}},
             {"name": "friends", "type": {"kind": "OBJECT", "name": "User"}},
         ]},
        {"name": "__Type", "kind": "OBJECT", "fields": []},
    ],
}


def test_find_recursive_chain_finds_cycle():
    chain = graphql_deep._find_recursive_chain(_RECURSIVE_SCHEMA)
    assert chain == ["user", "friends"]


def test_build_depth_query_is_valid_nested():
    chain = ["user", "friends"]
    q = graphql_deep._build_depth_query(chain, 5)
    assert q.startswith("{") and q.rstrip().endswith("}")
    # 5 levels of nesting
    assert q.count("{") == 5
    assert "user" in q and "friends" in q


def test_build_depth_query_no_chain_returns_empty_for_missing_schema():
    assert graphql_deep._build_depth_query([], 5) == "{}"  # guard against misuse
    assert graphql_deep._find_recursive_chain(None) == []


def test_depth_dos_flags_no_limit(mock_http_server):
    """A server that accepts arbitrarily deep valid queries is flagged."""
    base_url, server = mock_http_server

    def route(method, path, headers, body):
        return {"status": 200, "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"data": {"__typename": "OK"}})}

    server.routes = {("POST", "/graphql"): route}

    async def _run():
        async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
            return await graphql_deep.test_depth_dos(
                client, f"{base_url}/graphql", max_depth=50, step=5, schema=_RECURSIVE_SCHEMA
            )

    depth, _elapsed, timed_out = asyncio.run(_run())
    assert depth >= 20
    assert not timed_out


def test_depth_dos_detects_depth_limit(mock_http_server):
    """A server enforcing a depth limit breaks the probe early."""
    base_url, server = mock_http_server

    def route(method, path, headers, body):
        # Count nesting depth from the number of opening braces.
        depth = body.count("{")
        if depth > 15:
            return {"status": 200, "headers": {"Content-Type": "application/json"},
                    "body": json.dumps({"errors": [{"message": "max query depth exceeded"}]})}
        return {"status": 200, "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"data": {"__typename": "OK"}})}

    server.routes = {("POST", "/graphql"): route}

    async def _run():
        async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
            return await graphql_deep.test_depth_dos(
                client, f"{base_url}/graphql", max_depth=50, step=5, schema=_RECURSIVE_SCHEMA
            )

    depth, _elapsed, timed_out = asyncio.run(_run())
    assert depth < 20


def test_depth_dos_skips_without_schema(mock_http_server):
    """Without a schema there is no valid recursive query — probe returns 0
    instead of silently sending an invalid document."""
    base_url, server = mock_http_server
    server.routes = {("POST", "/graphql"): {
        "status": 200, "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"data": {"__typename": "OK"}})}}

    async def _run():
        async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
            return await graphql_deep.test_depth_dos(
                client, f"{base_url}/graphql", max_depth=50, step=5, schema=None
            )

    depth, _elapsed, timed_out = asyncio.run(_run())
    assert depth == 0
    assert not timed_out
