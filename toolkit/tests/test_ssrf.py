#!/usr/bin/env python3
"""Tests for ssrf.py"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from toolkit.testers import ssrf


class Resp:
    def __init__(self, text=""):
        self.text = text


class FakeClient:
    async def request(self, method, url, **kw):
        if "passwd" in url:
            return Resp("leaked root:x:0:0:root:/root:/bin/bash")
        if "169.254" in url:
            return Resp("could not connect to host 169.254.169.254")
        return Resp("ok")


def _ep(inject_via="query", params=("url",)):
    class E:
        pass
    E.url = "http://t/fetch"
    E.method = "GET"
    E.params = list(params)
    E.inject_via = inject_via
    return E()


def test_detect_ssrf():
    assert ssrf._detect_ssrf("root:x:0:0:").startswith("disclosure")
    assert ssrf._detect_ssrf("could not connect").startswith("error")
    assert ssrf._detect_ssrf("clean") == ""


def test_ssrf_disclosure():
    out = asyncio.run(ssrf.test_endpoint(_ep(), FakeClient()))
    assert len(out) == 1
    assert out[0].technique == "disclosure"
    assert out[0].param == "url"


def test_normalized():
    nf = ssrf.to_normalized_findings([ssrf.SsrfFinding("u", "GET", "url", "disclosure", "p", "ev")])
    assert nf[0]["vuln_class_key"] == "SSRF"
    assert nf[0]["severity"] == "HIGH"
