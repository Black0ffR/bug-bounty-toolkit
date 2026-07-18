"""Tests for toolkit.infra.proxy_rotator (Phase B: B21 proxy rotation)."""
from __future__ import annotations

from toolkit.infra.proxy_rotator import ProxyRotator


def test_round_robin_two_proxies():
    rot = ProxyRotator(["http://a:1", "socks5://b:2"])
    assert rot.count == 2
    got = [rot.next() for _ in range(4)]
    assert got == ["http://a:1", "socks5://b:2", "http://a:1", "socks5://b:2"]


def test_empty_returns_none():
    rot = ProxyRotator([])
    assert rot.next() is None
    assert list(rot.iter(limit=3)) == []


def test_iter_limit():
    rot = ProxyRotator(["p1", "p2", "p3"])
    out = list(rot.iter(limit=5))
    assert out == ["p1", "p2", "p3", "p1", "p2"]


def test_add_proxy():
    rot = ProxyRotator(["p1"])
    rot.add("p2")
    assert rot.count == 2
    rot.add("p1")  # dedupe
    assert rot.count == 2


def test_from_env(monkeypatch):
    monkeypatch.setenv("BBTK_PROXIES", "http://a:1, socks5://b:2 ,")
    rot = ProxyRotator.from_env()
    assert rot.count == 2
    assert rot.next() == "http://a:1"
