#!/usr/bin/env python3
"""Tests for access_control.py"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from toolkit.testers import access_control


class Resp:
    def __init__(self, text="", status=200):
        self.text = text
        self.status_code = status


class FakeClient:
    def __init__(self, mode="ok"):
        self.mode = mode

    async def get(self, url, **kw):
        if self.mode == "sensitive200":
            return Resp("admin panel html", 200)
        if self.mode == "override":
            # baseline 403, but with ?admin=true returns 200
            if "admin=true" in url:
                return Resp("granted", 200)
            return Resp("forbidden", 403)
        return Resp("ok", 200)


def _ep(url="http://t/admin", method="GET", inject_via="query"):
    class E:
        pass
    E.url = url
    E.method = method
    E.params = []
    E.inject_via = inject_via
    return E()


def test_is_sensitive_path():
    assert access_control.is_sensitive_path("http://t/admin/users")
    assert not access_control.is_sensitive_path("http://t/home")


def test_forced_browsing():
    out = asyncio.run(access_control.test_endpoint(_ep("http://t/admin"), FakeClient("sensitive200")))
    assert any(f.kind == "forced-browsing" for f in out)


def test_override_param():
    out = asyncio.run(access_control.test_endpoint(_ep("http://t/item"), FakeClient("override")))
    assert any(f.kind == "override-param" for f in out)


def test_normalized():
    nf = access_control.to_normalized_findings(
        [access_control.AccessControlFinding("u", "GET", "forced-browsing", "", "ev")])
    assert nf[0]["vuln_class_key"] == "BROKEN_ACCESS_CONTROL"
