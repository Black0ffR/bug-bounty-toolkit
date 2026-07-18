#!/usr/bin/env python3
"""Tests for C3: scope_guard DNS-resolved CIDR exclusion (5-min cache)."""

import socket
from pathlib import Path

from toolkit.infra import scope_guard as m


def _write_scope(tmp_path, body):
    p = tmp_path / "scope.yaml"
    p.write_text(body)
    return p


def test_excluded_cidr_blocks_resolved_host(tmp_path):
    scope = _write_scope(tmp_path, """
program: acme
in_scope:
  - "*.acme.com"
excluded_cidrs:
  - "10.0.0.0/8"
""")
    g = m.ScopeGuard(scope)
    # bypass real DNS by stubbing resolve_dns
    g.resolve_dns = lambda h, **k: ["10.1.2.3"]
    try:
        g.check_scope("api.acme.com", source_tool="t")
        assert False, "should have raised"
    except m.ScopeError as e:
        assert "excluded CIDR" in str(e)


def test_excluded_cidr_allows_clean_host(tmp_path):
    scope = _write_scope(tmp_path, """
program: acme
in_scope:
  - "*.acme.com"
excluded_cidrs:
  - "10.0.0.0/8"
""")
    g = m.ScopeGuard(scope)
    g.resolve_dns = lambda h, **k: ["93.184.216.34"]  # example.com public IP
    g.check_scope("api.acme.com", source_tool="t")  # no raise


def test_out_of_scope_cidr_folds_into_exclusion(tmp_path):
    scope = _write_scope(tmp_path, """
program: acme
in_scope:
  - "*.acme.com"
out_of_scope:
  - "192.168.0.0/16"
""")
    g = m.ScopeGuard(scope)
    g.resolve_dns = lambda h, **k: ["192.168.1.50"]
    try:
        g.check_scope("api.acme.com", source_tool="t")
        assert False, "should raise (resolved into out_of_scope CIDR)"
    except m.ScopeError:
        pass


def test_dns_cache_hits_within_ttl(tmp_path, monkeypatch):
    scope = _write_scope(tmp_path, """
program: acme
in_scope:
  - "*.acme.com"
excluded_cidrs:
  - "10.0.0.0/8"
""")
    g = m.ScopeGuard(scope)
    calls = {"n": 0}

    def fake_getaddrinfo(host, port):
        calls["n"] += 1
        # deterministic: first call returns excluded IP, should be cached
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.9.9.9", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    # first resolution
    ips1 = g.resolve_dns("host.acme.com")
    assert ips1 == ["10.9.9.9"]
    # second call within TTL must use cache (no new getaddrinfo call)
    ips2 = g.resolve_dns("host.acme.com")
    assert ips2 == ["10.9.9.9"]
    assert calls["n"] == 1


def test_dns_cache_expires_after_ttl(tmp_path, monkeypatch):
    scope = _write_scope(tmp_path, """
program: acme
in_scope:
  - "*.acme.com"
excluded_cidrs:
  - "10.0.0.0/8"
""")
    g = m.ScopeGuard(scope)
    states = {"n": 0}

    def fake_getaddrinfo(host, port):
        states["n"] += 1
        ip = "10.9.9.9" if states["n"] == 1 else "93.184.216.34"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    g.resolve_dns("h.acme.com")                       # call #1
    g._dns_cache["h.acme.com"] = (0.0, ["10.9.9.9"])  # expire by backdating ts
    ips2 = g.resolve_dns("h.acme.com")                 # call #2 (cache expired)
    assert ips2 == ["93.184.216.34"]
    assert states["n"] == 2


def test_no_exclusions_no_network(tmp_path):
    # Without excluded_cidrs / out_of_scope CIDR, check_scope must not touch DNS.
    scope = _write_scope(tmp_path, """
program: acme
in_scope:
  - "*.acme.com"
""")
    g = m.ScopeGuard(scope)
    g.resolve_dns = lambda h, **k: (_ for _ in ()).throw(RuntimeError("network should not be called"))
    g.check_scope("api.acme.com", source_tool="t")  # no network, no raise
