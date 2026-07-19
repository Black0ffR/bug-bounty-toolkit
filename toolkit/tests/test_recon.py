#!/usr/bin/env python3
"""Tests for toolkit/recon/*"""
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from toolkit.recon import subdomains, wayback, tech, js, posture, run, enrich


class FakeResp:
    def __init__(self, status=200, text="", json_data=None, headers=None):
        self.status_code = status
        self.text = text
        self._json = json_data
        self.headers = headers or {}

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json


class FakeClient:
    """Returns a canned response based on URL substring match."""
    def __init__(self, responses=None):
        self._responses = responses or {}
        self.calls = []

    async def get(self, url, **kw):
        self.calls.append(url)
        # pick the key whose match ends farthest right (so "/app.js" beats the
        # "https://example.com" prefix shared with the JS URL)
        best, best_end = None, -1
        for key, resp in self._responses.items():
            idx = url.rfind(key)
            if idx != -1 and idx + len(key) > best_end:
                best, best_end = resp, idx + len(key)
        return best if best is not None else FakeResp(200, "")


def test_crtsh_subdomains():
    data = [
        {"name_value": "a.example.com\n*.wild.example.com"},
        {"name_value": "b.example.com"},
        {"name_value": "evil.com"},
    ]
    client = FakeClient({"crt.sh": FakeResp(200, json_data=data)})
    out = asyncio.run(subdomains.crtsh_subdomains("example.com", client))
    assert out == ["a.example.com", "b.example.com"]


def test_crtsh_handles_errors():
    client = FakeClient({"crt.sh": FakeResp(500)})
    assert asyncio.run(subdomains.crtsh_subdomains("example.com", client)) == []


def test_wayback_urls():
    rows = [["original"], ["https://x.com/a"], ["https://x.com/b"]]
    client = FakeClient({"web.archive.org": FakeResp(200, json_data=rows)})
    out = asyncio.run(wayback.wayback_urls("example.com", client))
    assert out == ["https://x.com/a", "https://x.com/b"]


def test_tech_fingerprint():
    headers = {
        "server": "nginx/1.18",
        "x-powered-by": "PHP/5.6.40",
        "set-cookie": "PHPSESSID=abc; path=/",
    }
    t = tech.fingerprint(headers, "")
    assert t["server"].startswith("nginx")
    assert "PHP" in t["language"]


def test_js_extract_endpoints_and_secrets():
    js_text = '''
    fetch("/api/v1/users?active=1");
    var k = "AKIA1234567890ABCDEF";
    var t = "eyJhbGciOiJIUzI1Ni.eyJzdWIiOiIxMjM0NTY3ODk.wat";
    '''
    eps = js.extract_endpoints(js_text)
    assert any("/api/v1/users" in e for e in eps)
    secrets = js.extract_secrets(js_text)
    types = {s["type"] for s in secrets}
    assert "aws_access_key_id" in types and "jwt" in types


def test_collect_js_sources():
    html = ('<html><script src="/app.js"></script>'
            '<script src="https://cdn.x.com/lib.js"></script></html>')
    client = FakeClient()
    out = asyncio.run(js.collect_js(html, "https://example.com", client))
    assert "https://example.com/app.js" in out
    assert "https://cdn.x.com/lib.js" in out


def test_posture_missing_headers():
    findings = posture.analyze_headers({"server": "nginx"})
    issues = {f["issue"] for f in findings}
    assert "missing_csp" in issues and "missing_hsts" in issues
    # all present -> empty
    full = {
        "Content-Security-Policy": "...",
        "Strict-Transport-Security": "...",
        "X-Frame-Options": "...",
        "X-Content-Type-Options": "...",
        "Referrer-Policy": "...",
    }
    assert posture.analyze_headers(full) == []


def test_run_recon_integration():
    root_html = ('<html><script src="/app.js"></script></html>')
    js_body = 'fetch("/api/secret"); var k="AKIA1234567890ABCDEF";'
    crt = [{"name_value": "a.example.com"}]
    wb = [["original"], ["https://example.com/old"]]
    client = FakeClient({
        "https://example.com": FakeResp(200, root_html,
                                        headers={"server": "nginx"}),
        "/app.js": FakeResp(200, js_body),
        "crt.sh": FakeResp(200, json_data=crt),
        "web.archive.org": FakeResp(200, json_data=wb),
    })
    result = asyncio.run(run.run_recon("https://example.com", client,
                                       wayback_limit=10))
    assert result["domain"] == "example.com"
    assert result["subdomains"] == ["a.example.com"]
    assert "https://example.com/old" in result["wayback_urls"]
    assert any("/api/secret" in e for e in result["js_endpoints"])
    assert any(s["type"] == "aws_access_key_id" for s in result["js_secrets"])
    assert result["tech"]["server"].startswith("nginx")
    assert any(f["issue"] == "missing_csp" for f in result["posture"])


def test_alienvault_subdomains():
    data = {"passive_dns": [
        {"hostname": "api.example.com"},
        {"hostname": "*.wild.example.com"},
        {"hostname": "other.com"},
    ]}
    client = FakeClient({"otx.alienvault.com": FakeResp(200, json_data=data)})
    out = asyncio.run(subdomains.alienvault_subdomains("example.com", client))
    assert out == ["api.example.com"]


def test_enumerate_subdomains_aggregates():
    crt = [{"name_value": "a.example.com"}]
    otx = {"passive_dns": [{"hostname": "b.example.com"},
                           {"hostname": "a.example.com"}]}
    client = FakeClient({
        "crt.sh": FakeResp(200, json_data=crt),
        "otx.alienvault.com": FakeResp(200, json_data=otx),
    })
    out = asyncio.run(subdomains.enumerate_subdomains("example.com", client))
    assert out == ["a.example.com", "b.example.com"]


def test_live_check_probes_https_then_http():
    https = FakeResp(200, "ok", headers={"server": "nginx"})
    http = FakeResp(200, "ok")
    # first host: https live; second host: https fails, http live
    def router(url, **kw):
        if url == "https://up.example.com":
            return https
        if url == "https://httponly.example.com":
            raise Exception("conn refused")
        if url == "http://httponly.example.com":
            return http
        return FakeResp(0, "")
    class RouterClient:
        async def get(self, url, **kw):
            return router(url, **kw)
    res = asyncio.run(enrich.live_check(
        ["up.example.com", "httponly.example.com"], RouterClient()))
    up = next(r for r in res if r["host"] == "up.example.com")
    assert up["live"] and up["status"] == 200 and up["tech"]["server"].startswith("nginx")
    ho = next(r for r in res if r["host"] == "httponly.example.com")
    assert ho["live"] and ho["url"] == "http://httponly.example.com"


def test_recon_to_seeds_filters_scope():
    recon = {
        "js_endpoints": ["/api/x", "https://evil.com/p"],
        "wayback_urls": ["https://example.com/old?q=1",
                         "https://sub.example.com/s", "https://other.com/z"],
        "live_hosts": [{"host": "sub.example.com", "live": True},
                       {"host": "dead.example.com", "live": False}],
    }
    seeds = run.recon_to_seeds(recon, "example.com")
    assert "https://example.com/old?q=1" in seeds["same_origin"]
    assert "https://sub.example.com/s" in seeds["same_origin"]
    assert "https://evil.com/p" not in seeds["same_origin"]
    assert "https://other.com/z" not in seeds["same_origin"]
    assert seeds["subdomain_hosts"] == ["sub.example.com"]
