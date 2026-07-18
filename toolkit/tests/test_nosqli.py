#!/usr/bin/env python3
"""Tests for nosqli.py"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from toolkit.testers import nosqli


class Resp:
    def __init__(self, text="", status=200):
        self.text = text
        self.status_code = status


class FakeClient:
    async def request(self, method, url, **kw):
        if kw.get("json") and isinstance(kw["json"], dict):
            # JSON body: operator object -> "welcome", else "denied"
            val = next(iter(kw["json"].values()))
            if isinstance(val, dict):
                return Resp("welcome")
            return Resp("denied")
        data = kw.get("data") or {}
        val = list(data.values())[0] if data else ""
        if "$gt" in val or "$where" in val:
            return Resp("MongoError: bad value")
        return Resp("ok")


def _ep(inject_via="body_json", params=("user",)):
    class E:
        pass
    E.url = "http://t/login"
    E.method = "POST"
    E.params = list(params)
    E.inject_via = inject_via
    return E()


def test_detect_nosql_error():
    assert nosqli._detect_nosql_error("MongoError: bad value") == "mongoerror"
    assert nosqli._detect_nosql_error("clean") == ""


def test_nosql_boolean_json():
    out = asyncio.run(nosqli.test_endpoint(_ep("body_json"), FakeClient()))
    kinds = {f.technique for f in out}
    assert "boolean" in kinds


def test_nosql_error_sig():
    out = asyncio.run(nosqli.test_endpoint(_ep("body_form"), FakeClient()))
    assert any(f.technique == "error" for f in out)


def test_normalized():
    nf = nosqli.to_normalized_findings([nosqli.NosqlFinding("u", "POST", "user", "boolean", "p", "ev")])
    assert nf[0]["vuln_class_key"] == "NOSQL_INJECTION"
