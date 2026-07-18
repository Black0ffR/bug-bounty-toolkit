#!/usr/bin/env python3
"""Tests for toolkit.discover.api_spec_harvest (TDD for B26)."""

import json

from toolkit.discover import api_spec_harvest as m


SAMPLE_SPEC = {
    "openapi": "3.0.0",
    "security": [{"bearer": []}],
    "paths": {
        "/users/{id}": {
            "get": {"operationId": "getUser",
                    "parameters": [{"name": "id", "in": "path"}]},
            "delete": {"operationId": "delUser",
                       "parameters": [{"name": "id", "in": "path"}]},
        },
        "/public/status": {
            "get": {"operationId": "status", "security": []},
        },
        "/admin/reindex": {
            "post": {"operationId": "reindex", "tags": ["admin"],
                     "summary": "reindex internal store"},
        },
    },
}


def test_parse_spec_extracts_endpoints():
    eps = m.parse_spec(SAMPLE_SPEC)
    assert len(eps) == 4
    methods = {(e.method, e.path) for e in eps}
    assert ("GET", "/users/{id}") in methods
    assert ("DELETE", "/users/{id}") in methods


def test_unauthenticated_flag():
    eps = m.parse_spec(SAMPLE_SPEC)
    public = [e for e in eps if e.path == "/public/status"][0]
    assert public.unauthenticated is True
    user_get = [e for e in eps if e.path == "/users/{id}" and e.method == "GET"][0]
    assert user_get.unauthenticated is False


def test_endpoint_risk_labels():
    eps = m.parse_spec(SAMPLE_SPEC)
    by = {(e.method, e.path): e for e in eps}
    del_ep = by[("DELETE", "/users/{id}")]
    assert "state-changing:DELETE" in m.endpoint_risk(del_ep)
    assert "risky-param:id" in m.endpoint_risk(del_ep)
    public = by[("GET", "/public/status")]
    assert "unauthenticated" in m.endpoint_risk(public)
    admin = by[("POST", "/admin/reindex")]
    assert "sensitive-keyword" in m.endpoint_risk(admin)


def test_to_normalized_filters_and_severity():
    eps = m.parse_spec(SAMPLE_SPEC)
    norm = m.to_normalized("https://api.example.com", eps, "https://api.example.com/openapi.json")
    # only risky ones flagged: DELETE users, public status (unauth GET), admin reindex
    assert len(norm) >= 3
    del_find = [n for n in norm if n["raw"]["method"] == "DELETE"][0]
    assert del_find["severity"] == "LOW"  # authed + state-changing
    public_find = [n for n in norm if n["raw"]["path"] == "/public/status"][0]
    assert public_find["severity"] == "MEDIUM"  # unauthenticated GET


def test_probe_spec_with_fake_client():
    import asyncio

    spec_text = json.dumps(SAMPLE_SPEC)

    class FakeResp:
        def __init__(self, text, status=200, ctype="application/json"):
            self.text = text
            self.status_code = status
            self.headers = {"content-type": ctype}

    class FakeClient:
        def __init__(self):
            self.got = []
        async def get(self, url, headers=None):
            self.got.append(url)
            if url.endswith("/openapi.json"):
                return FakeResp(spec_text)
            return FakeResp("nope", status=404)
        async def aclose(self):
            pass

    client = FakeClient()
    spec, url = asyncio.run(m.probe_spec("https://api.example.com", client=client))
    assert spec is not None
    assert url.endswith("/openapi.json")
    assert "paths" in spec
