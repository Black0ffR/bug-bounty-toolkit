#!/usr/bin/env python3
"""Tests for toolkit.testers.cache_poisoning (TDD for B25)."""

from toolkit.testers import cache_poisoning as m


def test_detect_poisoning_reflected_only():
    reflected, served = m.detect_poisoning(
        "base", "hello MARKER1234567890 world", "base", "MARKER1234567890")
    assert reflected is True
    assert served is False


def test_detect_poisoning_full_chain():
    marker = "ABCDEF1234567890"
    reflected, served = m.detect_poisoning(
        "normal page", f"value={marker}", f"value={marker}", marker)
    assert reflected and served


def test_build_result_poisoned_flag():
    marker = "XYZW1234567890ab"
    r = m.build_result("X-Forwarded-Host", marker, "base", f"host={marker}", f"host={marker}")
    assert r.poisoned is True
    assert r.reflected_in_poisoned and r.served_in_followup


def test_build_result_clean():
    r = m.build_result("X-Real-IP", "NOMATCH00000001", "base", "base", "base")
    assert r.poisoned is False


def test_to_normalized_only_poisoned():
    marker = "POISON0000000123"
    results = [
        m.build_result("X-Forwarded-Host", marker, "b", f"h={marker}", f"h={marker}"),
        m.build_result("X-Real-IP", "CLEAN0000000001", "b", "b", "b"),
    ]
    norm = m.to_normalized("https://example.com/page", results)
    assert len(norm) == 1
    assert norm[0]["vuln_class_key"] == "CACHE_POISONING"
    assert norm[0]["severity"] == "HIGH"
    assert norm[0]["host"] == "example.com"


def test_common_unkeyed_headers_present():
    assert "X-Forwarded-Host" in m.COMMON_UNKEYED_HEADERS
    assert "X-Original-URL" in m.COMMON_UNKEYED_HEADERS


def test_check_url_with_fake_client():
    import asyncio

    marker = "FAKECLIENT000001"

    class FakeResp:
        def __init__(self, text):
            self.text = text

    class FakeClient:
        def __init__(self):
            self.calls = []
            self.cache = None

        async def get(self, url, headers=None):
            self.calls.append(headers)
            # emulate an unkeyed-header cache: the poisoned header populates the
            # URL-keyed cache, which is then served to header-less follow-ups
            if headers and "X-Forwarded-Host" in headers:
                self.cache = f"host={marker}"
                return FakeResp(self.cache)
            if not headers:
                resp = self.cache if self.cache is not None else "normal"
                self.cache = None  # a header-less request consumes the cache
                return FakeResp(resp)
            return FakeResp("normal")

        async def aclose(self):
            pass

    client = FakeClient()
    results = asyncio.run(m.check_url(
        "https://example.com/p", ["X-Forwarded-Host", "X-Real-IP"],
        client=client, marker=marker))
    pois = [r for r in results if r.poisoned]
    assert len(pois) == 1
    assert pois[0].header == "X-Forwarded-Host"
