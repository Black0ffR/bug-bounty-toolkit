"""Tests for C17: ssrfprobe.py --oob-dns-only DNS-resolution probes."""

import asyncio
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_SCRIPTS = str(_REPO_ROOT / "scripts")
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)

import ssrfprobe  # noqa: E402


def test_build_oob_url_dns_only_flag():
    assert ssrfprobe.build_oob_url("abc", "oast.pro", dns_only=True) == "http://abc.oast.pro/"
    assert ssrfprobe.build_oob_url("abc", "oast.pro") == "http://abc.oast.pro/"


def _point():
    return ssrfprobe.InjectionPoint(
        host="api.test", base_url="https://api.test/v1/fetch",
        param_name="url", inject_via="query", original_value="https://x.com",
    )


async def _run_point(tester, point, send_return=(200, {}, "ok", 0.5)):
    # get_baseline returns fast; send_payload returns a 200 so OOB marks pending.
    async def fake_send(p, payload, timeout, extra_headers=None):
        return send_return
    async def fake_baseline(p, timeout):
        return (200, 10, 0.1)
    orig_send = ssrfprobe.send_payload
    orig_base = ssrfprobe.get_baseline
    ssrfprobe.send_payload = fake_send
    ssrfprobe.get_baseline = fake_baseline
    try:
        return await tester.test_point(point)
    finally:
        ssrfprobe.send_payload = orig_send
        ssrfprobe.get_baseline = orig_base


def test_oob_dns_only_evidence():
    tester = ssrfprobe.SSRFTester(
        domain="test", oob_domain="oast.pro", oob_dns_only=True)
    findings = asyncio.run(_run_point(tester, _point()))
    oob = [f for f in findings if f.payload_category == "oob"]
    assert oob, "expected an OOB finding"
    assert "DNS-only" in oob[0].evidence
    assert "oast.pro" in oob[0].evidence


def test_oob_default_evidence_mentions_dns_http():
    tester = ssrfprobe.SSRFTester(
        domain="test", oob_domain="oast.pro", oob_dns_only=False)
    findings = asyncio.run(_run_point(tester, _point()))
    oob = [f for f in findings if f.payload_category == "oob"]
    assert oob, "expected an OOB finding"
    assert "DNS/HTTP callback" in oob[0].evidence


def test_oob_dns_only_token_registered():
    tester = ssrfprobe.SSRFTester(
        domain="test", oob_domain="oast.pro", oob_dns_only=True)
    asyncio.run(_run_point(tester, _point()))
    assert tester._oob_tokens, "OOB token must be registered for correlation"
