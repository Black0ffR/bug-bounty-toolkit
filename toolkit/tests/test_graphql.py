#!/usr/bin/env python3
"""Tests for graphql.py"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from toolkit.testers import graphql


class Resp:
    def __init__(self, text=""):
        self.text = text


class FakeClient:
    async def request(self, method, url, **kw):
        if "graphql" in url:
            return Resp('{"data":{"__schema":{"types":[{"name":"Query"}]}}}')
        return Resp("not found")


def _ep(url="http://t/api"):
    class E:
        pass
    E.url = url
    E.method = "POST"
    E.params = []
    E.inject_via = "query"
    return E()


def test_detect_introspection():
    assert graphql._detect_introspection('{"data":{"__schema":{}}}') == "__schema"
    assert graphql._detect_introspection('{"data":{"types":[]}}') == "types"
    assert graphql._detect_introspection("ok") == ""


def test_run_graphql_finds_endpoint():
    out = asyncio.run(graphql.run_graphql([_ep("http://t/api")], FakeClient()))
    # /api itself isn't a graphql path; common /graphql paths are probed
    assert len(out) >= 1
    assert all(f.url for f in out)


def test_normalized():
    nf = graphql.to_normalized_findings([graphql.GraphQLFinding("http://t/graphql", "POST")])
    assert nf[0]["vuln_class_key"] == "GRAPHQL_INTROSPECTION"
