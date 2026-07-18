#!/usr/bin/env python3
"""Tests for C15: scope_guard map_scope (resolved IN/OUT view of scope)."""

import textwrap

from toolkit.infra import scope_guard as m
from toolkit.infra.scope_guard import ScopeGuard, ScopeError


def _guard(tmp_path):
    scope = tmp_path / "scope.yaml"
    scope.write_text(textwrap.dedent("""
        in_scope:
          - "*.acme.com"
          - "acme.com"
        out_of_scope:
          - "*.evil.com"
        excluded_cidrs:
          - "10.0.0.0/8"
    """))
    return ScopeGuard(scope)


def test_map_scope_in_out_excluded(tmp_path):
    g = _guard(tmp_path)
    # Avoid real DNS lookups in the test
    g.resolve_dns = lambda host, **k: []
    rows = m.map_scope(g, ["www.acme.com", "www.evil.com", "api.other.com", "10.0.0.5"])
    by_host = {r["host"]: r["status"] for r in rows}
    assert by_host["www.acme.com"] == "IN"
    assert by_host["www.evil.com"] == "OUT"   # out_of_scope
    assert by_host["api.other.com"] == "OUT"  # not in scope
    assert by_host["10.0.0.5"] == "OUT"       # excluded CIDR


def test_map_scope_reason_populated(tmp_path):
    g = _guard(tmp_path)
    g.resolve_dns = lambda host, **k: []
    rows = m.map_scope(g, ["10.0.0.5"])
    assert rows[0]["status"] == "OUT"
    assert rows[0]["reason"]  # a ScopeError message is attached


def test_map_scope_empty(tmp_path):
    g = _guard(tmp_path)
    g.resolve_dns = lambda host, **k: []
    assert m.map_scope(g, []) == []
