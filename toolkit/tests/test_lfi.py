#!/usr/bin/env python3
"""Tests for lfi.py"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from toolkit.testers import lfi


class Resp:
    def __init__(self, text="", status=200, headers=None):
        self.text = text
        self.status_code = status
        self.headers = headers or {}


class FakeClient:
    async def request(self, method, url, **kw):
        data = kw.get("data") or {}
        val = list(data.values())[0] if data else ""
        if "passwd" in val:
            return Resp("root:x:0:0:root:/root:/bin/bash")
        if "win.ini" in val:
            return Resp("[fonts]\n[extensions]")
        return Resp("ok")


def _ep(inject_via="body_form", params=("file",)):
    class E:
        pass
    E.url = "http://t/read"
    E.method = "GET"
    E.params = list(params)
    E.inject_via = inject_via
    return E()


def test_detect_disclosure():
    assert lfi._detect_disclosure("root:x:0:0:", "root:x:0:0:")
    assert not lfi._detect_disclosure("ok", "root:x:0:0:")


def test_lfi_finding():
    out = asyncio.run(lfi.test_endpoint(_ep(), FakeClient()))
    assert len(out) == 1
    assert out[0].param == "file"
    assert out[0].payload.endswith("etc/passwd")


def test_lfi_none_on_clean():
    async def req(method, url, **kw):
        return Resp("ok")
    c = FakeClient(); c.request = req
    out = asyncio.run(lfi.test_endpoint(_ep(), c))
    assert out == []


def test_normalized_carries_param():
    nf = lfi.to_normalized_findings([lfi.LfiFinding("u", "GET", "file", "p", "ev")])
    assert nf[0]["param"] == "file"
    assert nf[0]["vuln_class_key"] == "LOCAL_FILE_INCLUSION"
