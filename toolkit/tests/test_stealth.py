#!/usr/bin/env python3
"""Tests for toolkit/infra/stealth.py"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from toolkit.infra import stealth


class _Stub:
    def __init__(self, status=200, text="ok"):
        self.status_code = status
        self.text = text
        self.headers = {}


class FakeInner:
    def __init__(self):
        self.calls = []
        self.robots_text = "User-agent: *\nDisallow: /secret\n"

    async def get(self, url, **kw):
        if url.endswith("/robots.txt"):
            return _Stub(200, self.robots_text)
        return _Stub(200, "ok")

    async def request(self, method, url, **kw):
        self.calls.append({"method": method, "url": url,
                            "headers": dict(kw.get("headers", {}) or {}),
                            "proxy": kw.get("proxy")})
        return _Stub(200, "ok")

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return None


def test_policy_defaults():
    p = stealth.StealthPolicy()
    assert p.rate == 1.0 and p.respect_robots is True


def test_robots_parse():
    txt = "User-agent: *\nDisallow: /admin\nDisallow: /private/\nAllow: /"
    rules = stealth.RobotsCache.parse(txt)
    assert "/admin" in rules and "/private/" in rules


def test_robots_allowed():
    rc = stealth.RobotsCache()
    rc.learn("h", "User-agent: *\nDisallow: /secret\n")
    assert rc.allowed("http://h/secret/x") is False
    assert rc.allowed("http://h/public") is True


def test_stealth_respects_robots():
    p = stealth.StealthPolicy(respect_robots=True, rate=0)
    fake = FakeInner()
    c = stealth.StealthClient(p, client_factory=lambda proxy, **kw: fake)
    out = asyncio.run(c.request("GET", "http://h/secret/page"))
    # disallowed path -> skipped stub (status 0), inner.request NOT called
    assert out.status_code == 0
    assert all("secret" not in call["url"] for call in fake.calls)


def test_stealth_ua_rotation():
    p = stealth.StealthPolicy(respect_robots=False, random_agent=True, rate=0,
                              rotate_agent_every=1)
    fake = FakeInner()
    c = stealth.StealthClient(p, client_factory=lambda proxy, **kw: fake)
    asyncio.run(c.request("GET", "http://h/a"))
    asyncio.run(c.request("GET", "http://h/b"))
    uas = [call["headers"].get("User-Agent") for call in fake.calls]
    assert len(uas) == 2 and uas[0] != uas[1]


def test_stealth_proxy_rotation():
    p = stealth.StealthPolicy(respect_robots=False, rate=0,
                              proxy_list=["http://p1", "http://p2"],
                              rotate_proxy_every=1)
    fake = FakeInner()
    c = stealth.StealthClient(p, client_factory=lambda proxy, **kw: fake)
    asyncio.run(c.request("GET", "http://h/a"))
    asyncio.run(c.request("GET", "http://h/b"))
    assert c._proxy_log[0] != c._proxy_log[1]
