#!/usr/bin/env python3
"""Tests for csrf.py"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from toolkit.testers import csrf


def _ep(method="POST", params=("user", "pass")):
    class E:
        pass
    E.url = "http://t/login"
    E.method = method
    E.params = list(params)
    return E()


def test_csrf_missing_on_post():
    out = asyncio.run(csrf.test_endpoint(_ep("POST", ("user", "pass")), None))
    assert len(out) == 1
    assert out[0].url.endswith("/login")


def test_csrf_ok_with_token():
    out = asyncio.run(csrf.test_endpoint(_ep("POST", ("user", "pass", "csrf_token")), None))
    assert out == []


def test_csrf_skips_get():
    out = asyncio.run(csrf.test_endpoint(_ep("GET", ("q",)), None))
    assert out == []


def test_normalized():
    nf = csrf.to_normalized_findings([csrf.CsrfFinding("u", "POST", 2, "ev")])
    assert nf[0]["vuln_class_key"] == "MISSING_CSRF"
    assert nf[0]["severity"] == "LOW"
