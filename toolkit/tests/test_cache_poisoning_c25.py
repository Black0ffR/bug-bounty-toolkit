#!/usr/bin/env python3
"""Tests for C25: cache_poisoning unkeyed query-param probing."""

import asyncio

from toolkit.testers import cache_poisoning as m


class FakeResp:
    def __init__(self, text):
        self.text = text


class FakeClient:
    def __init__(self, seq):
        self._seq = seq
        self._i = 0
    async def get(self, url, headers=None):
        r = self._seq[self._i % len(self._seq)]
        self._i += 1
        return r
    async def aclose(self):
        pass


def test_param_probe_detects_poisoning():
    # baseline, poisoned (?cb=MARKER...), followup — marker reflected then re-served
    client = FakeClient([
        FakeResp("normal page"),
        FakeResp("page MARKER1234567890abc"),
        FakeResp("page MARKER1234567890abc"),
    ])
    results = asyncio.run(m.check_url(
        "http://x/?z=1", headers_to_try=[], params_to_try=["cb"],
        client=client, marker="MARKER1234567890"))
    assert len(results) == 1
    r = results[0]
    assert r.kind == "param"
    assert r.header == "cb"
    assert r.poisoned is True


def test_param_probe_clean_when_not_served():
    client = FakeClient([
        FakeResp("normal page"),
        FakeResp("page MARKER1234567890abc"),
        FakeResp("normal page"),  # followup does NOT contain marker
    ])
    results = asyncio.run(m.check_url(
        "http://x/", headers_to_try=[], params_to_try=["cb"],
        client=client, marker="MARKER1234567890"))
    assert results[0].poisoned is False


def test_to_normalized_param_title():
    client = FakeClient([
        FakeResp("normal page"),
        FakeResp("page MARKER1234567890abc"),
        FakeResp("page MARKER1234567890abc"),
    ])
    results = asyncio.run(m.check_url(
        "http://x/", headers_to_try=[], params_to_try=["cb"],
        client=client, marker="MARKER1234567890"))
    norm = m.to_normalized("http://x/", results)
    assert norm
    assert norm[0]["raw"]["kind"] == "param"
    assert "unkeyed param cb" in norm[0]["title"]


def test_param_separator_uses_amp_when_query_present():
    seen = {}
    class CaptureClient(FakeClient):
        async def get(self, url, headers=None):
            seen.setdefault("urls", []).append(url)
            return await super().get(url, headers)
    client = CaptureClient([
        FakeResp("a"), FakeResp("a MARKER1234567890"), FakeResp("a MARKER1234567890"),
    ])
    asyncio.run(m.check_url("http://x/?z=1", headers_to_try=[], params_to_try=["cb"],
                            client=client, marker="MARKER1234567890"))
    # poisoned request must use '?' + '&' already present -> '&cb='
    assert any("&cb=MARKER1234567890" in u for u in seen["urls"])
