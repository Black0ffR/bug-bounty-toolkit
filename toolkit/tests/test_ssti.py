#!/usr/bin/env python3
"""Tests for ssti.py"""
import asyncio
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from toolkit.testers import ssti


class Resp:
    def __init__(self, text=""):
        self.text = text


class FakeClient:
    async def request(self, method, url, **kw):
        data = kw.get("data") or {}
        val = list(data.values())[0] if data else ""
        m = re.search(r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}", val)
        if m:
            return Resp(str(int(m.group(1)) * int(m.group(2))))
        return Resp("baseline page content")


def _ep(inject_via="body_form", params=("name",)):
    class E:
        pass
    E.url = "http://t/page"
    E.method = "GET"
    E.params = list(params)
    E.inject_via = inject_via
    return E()


def test_detect_ssti():
    assert ssti._detect_ssti("baseline", "result 49 done", "49")
    assert not ssti._detect_ssti("has 49", "has 49", "49")


def test_ssti_finding():
    out = asyncio.run(ssti.test_endpoint(_ep(), FakeClient()))
    assert len(out) == 1
    assert out[0].param == "name"
    assert "{{" in out[0].payload


def test_ssti_none_on_clean():
    async def req(method, url, **kw):
        return Resp("baseline page content")
    c = FakeClient(); c.request = req
    out = asyncio.run(ssti.test_endpoint(_ep(), c))
    assert out == []


def test_normalized_carries_param():
    nf = ssti.to_normalized_findings([ssti.SstiFinding("u", "GET", "name", "p", "ev")])
    assert nf[0]["param"] == "name"
    assert nf[0]["vuln_class_key"] == "SSTI"
