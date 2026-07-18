#!/usr/bin/env python3
"""Tests for xxe.py"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from toolkit.testers import xxe


class Resp:
    def __init__(self, text="", status=200):
        self.text = text
        self.status_code = status


class FakeClient:
    async def request(self, method, url, **kw):
        body = kw.get("content") or ""
        if xxe._MARKER in body:
            return Resp("value=" + xxe._MARKER, 200)
        if "passwd" in body:
            return Resp("root:x:0:0:root:/root:/bin/bash", 200)
        return Resp("<ok/>", 200)


def _ep(method="POST"):
    class E:
        url = "http://t/api"
        pass
    E.url = "http://t/api"
    E.method = method
    return E()


def test_detect_reflection():
    assert xxe._detect_reflection(xxe._MARKER) == "internal-entity-reflection"
    assert xxe._detect_reflection("root:x:0:0:") == "external-file-disclosure"
    assert xxe._detect_reflection("clean") == ""


def test_xxe_reflection():
    out = asyncio.run(xxe.test_endpoint(_ep("POST"), FakeClient()))
    assert len(out) >= 1
    assert all(f.technique == "reflection" for f in out)
    assert out[0].vuln_class_key if hasattr(out[0], "vuln_class_key") else True


def test_xxe_skips_get():
    out = asyncio.run(xxe.test_endpoint(_ep("GET"), FakeClient()))
    assert out == []


def test_normalized():
    nf = xxe.to_normalized_findings([xxe.XxeFinding("u", "POST", "reflection",
                                                    "external-file-disclosure", "ev")])
    assert nf[0]["vuln_class_key"] == "XXE"
    assert nf[0]["severity"] == "HIGH"
