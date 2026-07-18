#!/usr/bin/env python3
"""Tests for idor.py"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from toolkit.testers import idor


class Resp:
    def __init__(self, text="", status=200):
        self.text = text
        self.status_code = status


class FakeClient:
    async def request(self, method, url, **kw):
        data = kw.get("data") or {}
        params = list(data.values())
        val = params[0] if params else url.split("=")[-1]
        if val == "1":
            return Resp("profile-data-for-1", 200)
        if val == "2":
            return Resp("profile-data-for-2", 200)
        return Resp("ok", 200)


def _ep(inject_via="query", params=("user_id",), method="GET"):
    class E:
        url = "http://t/user"
        pass
    E.url = "http://t/user"
    E.method = method
    E.params = list(params)
    E.inject_via = inject_via
    return E()


def test_is_id_param():
    assert idor.is_id_param("user_id")
    assert idor.is_id_param("123")
    assert not idor.is_id_param("name")


def test_idor_sequential():
    out = asyncio.run(idor.test_endpoint(_ep(), FakeClient()))
    kinds = {f.kind for f in out}
    assert "surface" in kinds
    assert "sequential-enum" in kinds


def test_idor_no_id_param():
    out = asyncio.run(idor.test_endpoint(_ep(params=("name",)), FakeClient()))
    assert out == []


def test_normalized():
    nf = idor.to_normalized_findings([idor.IdorFinding("u", "GET", "user_id", "surface", "ev")])
    assert nf[0]["vuln_class_key"] == "IDOR"
    assert nf[0]["param"] == "user_id"
