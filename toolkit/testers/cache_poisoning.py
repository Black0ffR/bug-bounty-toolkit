#!/usr/bin/env python3
"""
cache_poisoning.py — Web Cache Poisoning detection
==================================================

Tier 3 tester.

Purpose
-------
Web cache poisoning (CWE-440) happens when a cache key omits an input that
still influences the response. An attacker injects a malicious value in an
*unkeyed* header (or query param); the origin reflects/acts on it, the cache
stores the response under the victim's key, and every subsequent visitor is
served the poisoned payload (XSS, redirect, defacement).

Detection strategy (Termux-native, no browser required)
-------------------------------------------------------
For each candidate unkeyed header:

  1. Capture BASELINE   = GET without the header.
  2. Capture POISONED   = GET with `Header: <marker>`.
  3. Capture FOLLOWUP   = GET *without* the header again, immediately after.

  If the marker appears in POISONED **and** re-appears in FOLLOWUP (served from
  cache to a header-less request), the header is unkeyed AND the response was
  cached → cache poisoning confirmed. This mirrors the classic
  unkeyed-header → reflected → cached chain.

The core `detect_poisoning` is a pure function (unit-testable); the live
`check_url` wraps it with httpx. The response diffing reuses the structural
comparison idea from `anomaly_baseline`.

Usage
-----
    python -m toolkit.testers.cache_poisoning --url https://target/page
    python -m toolkit.testers.cache_poisoning --url ... --header X-Forwarded-Host

Author : Bug Bounty Toolkit / Tier 3
License : MIT (for authorized use only)
"""

from __future__ import annotations

import argparse
import datetime
import json
import logging
import random
import re
import string
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import Any

log = logging.getLogger("cache_poisoning")

# Headers frequently mishandled as unkeyed by CDNs/origins.
COMMON_UNKEYED_HEADERS = [
    "X-Forwarded-Host", "X-Forwarded-For", "X-Host", "X-Original-URL",
    "X-Rewrite-URL", "X-Forwarded-Scheme", "X-Forwarded-Proto",
    "Forwarded", "X-Real-IP", "True-Client-IP", "X-HTTP-Method-Override",
]

_MARKER_RE = re.compile(r"[A-Za-z0-9]{16}")


def _random_marker() -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=16))


def _reflects(marker: str, text: str) -> bool:
    return marker in text


@dataclass
class PoisonResult:
    header: str
    marker: str
    reflected_in_poisoned: bool
    served_in_followup: bool
    poisoned_len: int
    followup_len: int
    baseline_len: int

    @property
    def poisoned(self) -> bool:
        """True only when the marker was reflected AND re-served to a
        header-less follow-up request (the actual cache-poisoning primitive)."""
        return self.reflected_in_poisoned and self.served_in_followup


def detect_poisoning(baseline_text: str, poisoned_text: str, followup_text: str,
                     marker: str) -> tuple[bool, bool]:
    """Pure detection core.

    Returns (reflected_in_poisoned, served_in_followup). Testable without
    network — pass raw response bodies."""
    reflected = _reflects(marker, poisoned_text)
    served = _reflects(marker, followup_text)
    return reflected, served


def build_result(header: str, marker: str, baseline: str, poisoned: str,
                 followup: str) -> PoisonResult:
    reflected, served = detect_poisoning(baseline, poisoned, followup, marker)
    return PoisonResult(header=header, marker=marker,
                        reflected_in_poisoned=reflected,
                        served_in_followup=served,
                        poisoned_len=len(poisoned), followup_len=len(followup),
                        baseline_len=len(baseline))


# ── Live checker ─────────────────────────────────────────────────────────────

async def check_url(url: str, headers_to_try: list[str] | None = None,
                   *, client=None, marker: str | None = None) -> list[PoisonResult]:
    """Send the 3-request probe for each candidate header. `client` is an
    httpx.AsyncClient (or any object with a `.get(url, headers=...)` async
    coroutine returning an object with `.text`)."""
    import httpx

    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(follow_redirects=False, timeout=15.0)

    results: list[PoisonResult] = []
    try:
        headers_to_try = headers_to_try or COMMON_UNKEYED_HEADERS
        baseline_resp = await client.get(url)
        baseline_text = baseline_resp.text
        for header in headers_to_try:
            mk = marker or _random_marker()
            poisoned_resp = await client.get(url, headers={header: mk})
            followup_resp = await client.get(url)
            results.append(build_result(
                header, mk, baseline_text, poisoned_resp.text, followup_resp.text))
    finally:
        if own_client:
            await client.aclose()
    return results


# ── Normalization ────────────────────────────────────────────────────────────

def to_normalized(url: str, results: list[PoisonResult],
                  source_tool: str = "cache_poisoning.py") -> list[dict[str, Any]]:
    from urllib.parse import urlparse
    from toolkit.infra.finding import compute_finding_id

    out: list[dict[str, Any]] = []
    host = urlparse(url).hostname or ""
    for r in results:
        if not r.poisoned:
            continue
        fid = compute_finding_id(source_tool, host, "CACHE_POISONING",
                                 f"{r.header}:{r.marker}")
        out.append({
            "id": fid,
            "source_tool": source_tool,
            "host": host,
            "url": url,
            "vuln_class_key": "CACHE_POISONING",
            "severity": "HIGH",
            "title": f"Web Cache Poisoning via unkeyed header {r.header}",
            "detail": f"Header `{r.header}` is unkeyed and the response was cached; "
                      f"marker `{r.marker}` was reflected and then served to a "
                      f"header-less follow-up request.",
            "evidence": f"header={r.header} marker={r.marker}",
            "raw": {"header": r.header, "marker": r.marker,
                    "baseline_len": r.baseline_len, "poisoned_len": r.poisoned_len,
                    "followup_len": r.followup_len},
            "confidence": "confirmed",
            "disposition": "new",
            "verified_by": None,
        })
    return out


def main() -> int:
    ap = argparse.ArgumentParser(prog="cache_poisoning.py",
                                 description="Web Cache Poisoning detection.")
    ap.add_argument("--url", "-u", required=True)
    ap.add_argument("--header", action="append", dest="headers",
                    help="specific header to test (repeatable); default = common set")
    ap.add_argument("--marker", help="fixed marker (else random)")
    ap.add_argument("--output", "-o", default="cache-poisoning-findings.json")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="[%(levelname)s] %(message)s")

    import asyncio
    results = asyncio.run(check_url(
        args.url, args.headers, marker=args.marker))

    confirmed = [r for r in results if r.poisoned]
    for r in results:
        status = "POISONED" if r.poisoned else (
            "reflected-only" if r.reflected_in_poisoned else "clean")
        log.info("%-22s -> %s", r.header, status)

    norm = to_normalized(args.url, results)
    out_path = Path(args.output)
    out_path.write_text(json.dumps({
        "scan_time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "url": args.url,
        "findings": norm,
        "probed": [{"header": r.header, "poisoned": r.poisoned,
                    "reflected": r.reflected_in_poisoned,
                    "served": r.served_in_followup} for r in results],
    }, indent=2), encoding="utf-8")
    log.info("wrote %s (%d poisoned)", out_path, len(confirmed))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(0)
