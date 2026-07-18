#!/usr/bin/env python3
"""Tests for deserialization.py"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from toolkit.testers import deserialization


class Resp:
    def __init__(self, text=""):
        self.text = text


class FakeClient:
    async def request(self, method, url, **kw):
        content = kw.get("content") or b""
        if content.startswith(deserialization._JAVA_MAGIC):
            return Resp("java.io.StreamCorruptedException: invalid stream header")
        if content.startswith(deserialization._PY_PICKLE):
            return Resp("pickle.UnpicklingError: invalid load key")
        if content.startswith(deserialization._PHP_MAGIC):
            return Resp("php unserialize(): Error")
        return Resp("ok")


def _ep(method="POST"):
    class E:
        url = "http://t/deser"
        pass
    E.url = "http://t/deser"
    E.method = method
    E.params = []
    E.inject_via = "query"
    return E()


def test_detect_deser_error():
    assert deserialization._detect_deser_error("java.io.StreamCorruptedException")
    assert deserialization._detect_deser_error("pickle.UnpicklingError")
    assert deserialization._detect_deser_error("clean") == ""


def test_deser_finding():
    out = asyncio.run(deserialization.test_endpoint(_ep(), FakeClient()))
    assert len(out) >= 1
    assert out[0].fmt == "java"


def test_normalized():
    nf = deserialization.to_normalized_findings(
        [deserialization.DeserFinding("u", "POST", "java", "ev")])
    assert nf[0]["vuln_class_key"] == "INSECURE_DESERIALIZATION"
    assert nf[0]["severity"] == "MEDIUM"
