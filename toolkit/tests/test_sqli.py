"""Tests for P0 SQLi: toolkit/testers/sqli.py"""

import asyncio
from urllib.parse import parse_qs, urlparse

from toolkit.infra import spider
from toolkit.testers import sqli


def _extract_value(url, data, json):
    if data:
        return list(data.values())[0]
    if json:
        return list(json.values())[0]
    q = parse_qs(urlparse(url).query)
    if q:
        return list(q.values())[0][0]
    return ""


class _R:
    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text


class _FakeClient:
    """mode controls simulated backend behaviour."""
    def __init__(self, mode):
        self.mode = mode

    async def request(self, method, url, headers=None, data=None, json=None, timeout=10.0):
        value = _extract_value(url, data, json)
        if self.mode == "time" and "SLEEP(2" in value:
            await asyncio.sleep(2)
            return _R(200, "ok")
        if self.mode == "error" and ("'" in value or '"' in value):
            return _R(200, "You have an error in your SQL syntax near ''")
        if self.mode == "boolean":
            if value.endswith("' AND '1'='2"):
                return _R(200, "DENY")
            return _R(200, "OK")
        return _R(200, "OK")


def _ep(params):
    return spider.Endpoint(url="http://t.com/login", method="POST",
                           params=params, inject_via="body_form")


def test_error_based_detection():
    ep = _ep(["username"])
    f = asyncio.run(sqli.test_endpoint(ep, _FakeClient("error")))
    assert len(f) == 1
    assert f[0].technique == "error"
    assert f[0].db_type == "MySQL"


def test_boolean_blind_detection():
    ep = _ep(["username"])
    f = asyncio.run(sqli.test_endpoint(ep, _FakeClient("boolean")))
    assert any(x.technique == "boolean" for x in f)


def test_time_based_detection():
    ep = _ep(["username"])
    f = asyncio.run(sqli.test_endpoint(ep, _FakeClient("time"), time_threshold=1.5))
    assert any(x.technique == "time" for x in f)


def test_safe_endpoint_no_false_positive():
    ep = _ep(["username"])
    f = asyncio.run(sqli.test_endpoint(ep, _FakeClient("safe")))
    assert f == []


def test_run_sqli_fanout_and_normalize():
    eps = [_ep(["u"]), _ep(["p"])]
    findings = asyncio.run(sqli.run_sqli(eps, _FakeClient("error"), concurrency=2))
    assert len(findings) == 2
    norm = sqli.to_normalized_findings(findings)
    assert len(norm) == 2
    assert norm[0]["vuln_class_key"] == "SQL_INJECTION"
    assert norm[0]["severity"] in ("HIGH", "MEDIUM")
    assert norm[0]["confidence"] == "confirmed"
