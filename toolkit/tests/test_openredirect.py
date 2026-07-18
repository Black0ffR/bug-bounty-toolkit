#!/usr/bin/env python3
"""Tests for openredirect.py"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from toolkit.testers import openredirect


class Resp:
    def __init__(self, status=200, location=""):
        self.status_code = status
        self.headers = {"location": location} if location else {}


class FakeClient:
    def __init__(self):
        self.redirect = False

    async def request(self, method, url, **kw):
        val = ""
        data = kw.get("data") or {}
        if data:
            val = list(data.values())[0]
        if self.redirect and ("evil.example.com" in val):
            return Resp(302, "https://evil.example.com/land")
        return Resp(200)


def _ep(inject_via="body_form", params=("next",)):
    class E:
        pass
    E.url = "http://t/go"
    E.method = "GET"
    E.params = list(params)
    E.inject_via = inject_via
    return E()


def test_detect_redirect():
    assert openredirect._detect_redirect(302, "https://evil.example.com/x")
    assert openredirect._detect_redirect(301, "//evil.example.com")
    assert not openredirect._detect_redirect(200, "https://evil.example.com")
    assert not openredirect._detect_redirect(302, "https://t/inner")


def test_openredirect_finding():
    c = FakeClient(); c.redirect = True
    out = asyncio.run(openredirect.test_endpoint(_ep(), c))
    assert len(out) == 1
    assert out[0].param == "next"


def test_openredirect_none_on_clean():
    out = asyncio.run(openredirect.test_endpoint(_ep(), FakeClient()))
    assert out == []


def test_normalized_carries_param():
    nf = openredirect.to_normalized_findings(
        [openredirect.OpenRedirectFinding("u", "GET", "next", "p", "ev")])
    assert nf[0]["param"] == "next"
    assert nf[0]["vuln_class_key"] == "OPEN_REDIRECT"
