#!/usr/bin/env python3
"""Tests for cmdi.py"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from toolkit.testers import cmdi


class Resp:
    def __init__(self, text="", status=200, headers=None):
        self.text = text
        self.status_code = status
        self.headers = headers or {}


class FakeClient:
    def __init__(self):
        self.sent = []

    async def request(self, method, url, **kw):
        data = kw.get("data") or {}
        params = list(data.values())
        val = params[0] if params else ""
        self.sent.append(val)
        if any(m in val for m in ("; id", "| id", "$(id)", "`id`", "cat /etc/passwd")):
            return Resp("uid=0(root) gid=0(root) groups=0(root)")
        return Resp("ok")


def _ep(inject_via="body_form", params=("q",)):
    class E:
        pass
    E.url = "http://t/list"
    E.method = "POST"
    E.params = list(params)
    E.inject_via = inject_via
    return E()


def test_detect_cmd_output():
    assert cmdi._detect_cmd_output("uid=0(root)") == "uid="
    assert cmdi._detect_cmd_output("no echo") == ""


def test_cmd_error_based():
    ep = _ep()
    out = asyncio.run(cmdi.test_endpoint(ep, FakeClient()))
    assert len(out) == 1
    assert out[0].technique == "output"
    assert out[0].param == "q"


def test_cmd_no_finding_on_clean():
    ep = _ep(params=("q",))
    c = FakeClient()

    # monkeypatch client to never echo command output
    async def req(method, url, **kw):
        return Resp("ok")
    c.request = req
    out = asyncio.run(cmdi.test_endpoint(ep, c))
    assert out == []


def test_normalized_carries_param():
    nf = cmdi.to_normalized_findings([cmdi.CmdFinding("u", "POST", "q", "output", "; id", "ev")])
    assert nf[0]["param"] == "q"
    assert nf[0]["vuln_class_key"] == "COMMAND_INJECTION"
