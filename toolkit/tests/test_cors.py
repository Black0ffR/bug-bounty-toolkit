#!/usr/bin/env python3
"""Tests for cors.py"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from toolkit.testers import cors


class Resp:
    def __init__(self, headers=None):
        self.headers = headers or {}


class FakeClient:
    def __init__(self, headers):
        self._headers = headers

    async def request(self, method, url, **kw):
        return Resp(self._headers)


def _ep(url="http://t/api", method="GET"):
    class E:
        pass
    E.url = url; E.method = method
    return E()


def test_detect_cors():
    assert cors._detect_cors({"access-control-allow-origin": "https://evil.example.com",
                              "access-control-allow-credentials": "true"}, "https://evil.example.com")
    assert cors._detect_cors({"access-control-allow-origin": "*",
                              "access-control-allow-credentials": "true"}, "x")
    assert cors._detect_cors({"access-control-allow-origin": "https://evil.example.com"},
                             "https://evil.example.com") == ""


def test_cors_finding():
    c = FakeClient({"access-control-allow-origin": "https://evil.example.com",
                    "access-control-allow-credentials": "true"})
    out = asyncio.run(cors.test_endpoint(_ep(), c))
    assert len(out) == 1
    assert out[0].pattern == "reflected-origin-with-credentials"


def test_cors_none_on_safe():
    c = FakeClient({"access-control-allow-origin": "https://t"})
    out = asyncio.run(cors.test_endpoint(_ep(), c))
    assert out == []


def test_normalized():
    nf = cors.to_normalized_findings([cors.CorsFinding("u", "GET", "reflected-origin-with-credentials", "ev")])
    assert nf[0]["vuln_class_key"] == "CORS_MISCONFIG"
