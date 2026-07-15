#!/usr/bin/env python3
"""
4xxbypass.py — HTTP 403/401 Access Control Bypass Tester
=========================================================
Author  : RareKez / security research tooling
License : MIT (for authorized use only)

Chains from : reconharvest.py (--recon) — uses probe_results with 403/401 status
              or a plain URL list (--urls)
Feeds into  : Manual exploitation, bug bounty reports

Pipeline:
  1. Collect all 403/401 URLs from reconharvest probe results
  2. For each URL, fire every known bypass technique:
       a. Path normalisation variants (14 techniques)
       b. HTTP method override headers (6 techniques)
       c. IP spoofing headers (12 headers)
       d. Host header injection (5 variants)
       e. Content-Type bypass (4 variants)
       f. Protocol-level tricks (chunked, HTTP/1.0, etc.)
  3. Diff every response against the baseline 403
     — detect status change, body size change, content appears
  4. Score each bypass attempt: HIGH / MEDIUM / LOW confidence
  5. Generate reproduction curl commands for every successful bypass
  6. Output JSON + HTML report with ready-to-submit bug bounty write-ups

Usage:
  python3 4xxbypass.py --recon recon-report-v2.json --domain eskimi.com --output bypass
  python3 4xxbypass.py --urls blocked.txt --domain eskimi.com --output bypass
  python3 4xxbypass.py --recon recon-report-v2.json --domain eskimi.com --techniques all
  python3 4xxbypass.py --urls blocked.txt --domain eskimi.com --min-confidence medium

LEGAL: Only use against targets you have explicit written authorization to test.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import json
import re
import socket
import sys
import time
import urllib.parse
from dataclasses import dataclass, field, asdict
from typing import Any

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import (
        Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    )
    from rich.panel import Panel
    from rich.markup import escape
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False
    console = None

import logging
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger("4xxbypass")
for _n in ("httpx", "httpcore"):
    logging.getLogger(_n).setLevel(logging.WARNING)


# ═════════════════════════════════════════════════════════════════════════════
# BYPASS TECHNIQUE DEFINITIONS
# Each technique is a function:
#   input : (url: str, baseline_headers: dict) → list[BypassAttempt]
# The attempt carries all data needed to replay and reproduce the bypass.
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class BypassAttempt:
    technique_group: str            # "path" | "method" | "ip_header" | "host" | "content_type" | "protocol"
    technique_name: str             # human-readable name
    url: str                        # exact URL to request
    method: str                     # HTTP method
    extra_headers: dict             # additional headers to send
    body: str | None = None         # request body (for POST/PUT)
    curl_command: str = ""          # auto-generated reproduction command


@dataclass
class BypassResult:
    attempt: BypassAttempt
    baseline_status: int
    bypass_status: int | None
    baseline_body_len: int
    bypass_body_len: int | None
    bypass_body_snippet: str
    bypass_headers: dict
    confidence: str                 # "HIGH" | "MEDIUM" | "LOW" | "NONE"
    reason: str                     # why this is considered a bypass


UA = "Mozilla/5.0 (compatible; 4xxBypass/1.0)"
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "NONE": 5}


# ─────────────────────────────────────────────────────────────────────────────
# GROUP A — Path normalisation / encoding tricks
# ─────────────────────────────────────────────────────────────────────────────

def _path_variants(url: str) -> list[BypassAttempt]:
    """
    Generate URL path variants. The web server / WAF may block /admin
    but the backend might still serve it under a normalised path variant.
    """
    from urllib.parse import urlparse, urlunparse
    parsed  = urlparse(url)
    path    = parsed.path.rstrip("/") or "/"
    base    = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))

    variants: list[tuple[str, str]] = [
        # (technique_name, modified_path)
        ("Double slash prefix",              "/" + path),
        ("Trailing slash",                   path + "/"),
        ("Dot segment suffix",               path + "/."),
        ("Trailing dot",                     path + "."),
        ("Semicolon injection",              path + ";/"),
        ("Semicolon with slash",             path + ";anything"),
        ("URL-encoded slash",                path.replace("/", "%2f", 1)),
        ("Double URL-encoded slash",         path.replace("/", "%252f", 1)),
        ("Path traversal prefix",            "/anything/.." + path),
        ("Dot-slash prefix",                 "/." + path),
        ("Null byte suffix",                 path + "%00"),
        ("Hash fragment",                    path + "#"),
        ("Question mark suffix",             path + "?"),
        ("Overlong UTF-8 slash (U+2215)",    path.replace("/", "\xe2\x88\x95", 1)),
    ]

    attempts: list[BypassAttempt] = []
    for name, vpath in variants:
        new_url = base + vpath
        if parsed.query:
            new_url += "?" + parsed.query
        attempts.append(BypassAttempt(
            technique_group="path",
            technique_name=name,
            url=new_url,
            method="GET",
            extra_headers={},
        ))
    return attempts


# ─────────────────────────────────────────────────────────────────────────────
# GROUP B — HTTP method override
# Some middleware checks the method, others honour override headers.
# ─────────────────────────────────────────────────────────────────────────────

METHOD_OVERRIDES: list[tuple[str, dict, str | None]] = [
    # (technique_name, headers, body)
    ("X-HTTP-Method-Override: GET",
     {"X-HTTP-Method-Override": "GET"},  None),
    ("X-Method-Override: GET",
     {"X-Method-Override": "GET"},       None),
    ("X-HTTP-Method: GET",
     {"X-HTTP-Method": "GET"},           None),
    ("_method=GET query param",
     {},                                 None),   # appended to URL
    ("HEAD method",
     {},                                 None),   # method=HEAD
    ("OPTIONS method",
     {},                                 None),   # method=OPTIONS
    ("TRACE method",
     {},                                 None),   # method=TRACE
    ("POST with X-HTTP-Method-Override GET",
     {"X-HTTP-Method-Override": "GET", "Content-Type": "application/x-www-form-urlencoded"},
     ""),
]

def _method_variants(url: str) -> list[BypassAttempt]:
    attempts: list[BypassAttempt] = []
    for name, hdrs, body in METHOD_OVERRIDES:
        method = "GET"
        test_url = url

        if "_method=GET" in name:
            sep = "&" if "?" in url else "?"
            test_url = url + sep + "_method=GET"
        elif "HEAD" in name:
            method = "HEAD"
        elif "OPTIONS" in name:
            method = "OPTIONS"
        elif "TRACE" in name:
            method = "TRACE"
        elif body is not None:
            method = "POST"

        attempts.append(BypassAttempt(
            technique_group="method",
            technique_name=name,
            url=test_url,
            method=method,
            extra_headers=hdrs,
            body=body,
        ))
    return attempts


# ─────────────────────────────────────────────────────────────────────────────
# GROUP C — IP spoofing headers
# Servers that trust client-supplied IP headers for access control are
# vulnerable to bypass by pretending to be 127.0.0.1.
# ─────────────────────────────────────────────────────────────────────────────

IP_SPOOF_HEADERS: list[tuple[str, str]] = [
    ("X-Forwarded-For",           "127.0.0.1"),
    ("X-Forwarded-For (private)", "192.168.1.1"),
    ("X-Real-IP",                 "127.0.0.1"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("X-Originating-IP",          "127.0.0.1"),
    ("X-Remote-IP",               "127.0.0.1"),
    ("X-Remote-Addr",             "127.0.0.1"),
    ("X-Cluster-Client-IP",       "127.0.0.1"),
    ("X-Client-IP",               "127.0.0.1"),
    ("True-Client-IP",            "127.0.0.1"),
    ("CF-Connecting-IP",          "127.0.0.1"),
    ("Forwarded (RFC 7239)",      "for=127.0.0.1"),
    ("X-Forwarded-For chain",     "127.0.0.1, 10.0.0.1"),
    ("X-Forwarded-For 10.x",      "10.0.0.1"),
]

def _ip_spoof_variants(url: str) -> list[BypassAttempt]:
    return [
        BypassAttempt(
            technique_group="ip_header",
            technique_name=f"{hdr}: {val}",
            url=url,
            method="GET",
            extra_headers={hdr.split(" ")[0]: val},
        )
        for hdr, val in IP_SPOOF_HEADERS
    ]


# ─────────────────────────────────────────────────────────────────────────────
# GROUP D — Host header injection
# Some servers route requests based on the Host header. Injecting
# localhost or an internal hostname may bypass access controls.
# ─────────────────────────────────────────────────────────────────────────────

def _host_variants(url: str) -> list[BypassAttempt]:
    from urllib.parse import urlparse
    parsed      = urlparse(url)
    original_host = parsed.netloc
    port          = parsed.port or (443 if parsed.scheme == "https" else 80)

    host_variants: list[tuple[str, str]] = [
        ("Host: localhost",         "localhost"),
        ("Host: 127.0.0.1",         "127.0.0.1"),
        ("Host: 0.0.0.0",           "0.0.0.0"),
        ("Host with port variation",f"{original_host}:{port}"),
        ("Host: internal",          "internal"),
        ("X-Forwarded-Host",        original_host),     # not a Host replacement, additive
        ("X-Host injection",        "localhost"),
        ("X-Original-URL",          parsed.path or "/"),
        ("X-Rewrite-URL",           parsed.path or "/"),
    ]

    attempts: list[BypassAttempt] = []
    for name, host_val in host_variants:
        if name.startswith("X-Forwarded-Host"):
            hdrs = {"X-Forwarded-Host": host_val}
        elif name.startswith("X-Host"):
            hdrs = {"X-Host": host_val}
        elif name.startswith("X-Original-URL"):
            hdrs = {"X-Original-URL": host_val}
        elif name.startswith("X-Rewrite-URL"):
            hdrs = {"X-Rewrite-URL": host_val}
        else:
            hdrs = {"Host": host_val}
        attempts.append(BypassAttempt(
            technique_group="host",
            technique_name=name,
            url=url,
            method="GET",
            extra_headers=hdrs,
        ))
    return attempts


# ─────────────────────────────────────────────────────────────────────────────
# GROUP E — Content-Type bypass
# Some endpoints check Content-Type and only parse/authorise certain types.
# ─────────────────────────────────────────────────────────────────────────────

CONTENT_TYPES: list[tuple[str, str]] = [
    ("Content-Type: application/json",              "application/json"),
    ("Content-Type: text/plain",                    "text/plain"),
    ("Content-Type: application/x-www-form-urlencoded", "application/x-www-form-urlencoded"),
    ("Content-Type: multipart/form-data",           "multipart/form-data; boundary=----FormBoundary"),
    ("Content-Type: application/xml",               "application/xml"),
    ("Content-Type: */*",                           "*/*"),
    ("Content-Type with charset",                   "application/json; charset=utf-8"),
]

def _content_type_variants(url: str) -> list[BypassAttempt]:
    return [
        BypassAttempt(
            technique_group="content_type",
            technique_name=name,
            url=url,
            method="POST",
            extra_headers={"Content-Type": ct},
            body="",
        )
        for name, ct in CONTENT_TYPES
    ]


# ─────────────────────────────────────────────────────────────────────────────
# GROUP F — Protocol / misc tricks
# ─────────────────────────────────────────────────────────────────────────────

def _protocol_variants(url: str) -> list[BypassAttempt]:
    from urllib.parse import urlparse, urlunparse
    parsed = urlparse(url)

    # Switch scheme
    alt_scheme = "http" if parsed.scheme == "https" else "https"
    alt_url    = urlunparse((alt_scheme,) + parsed[1:])

    return [
        BypassAttempt(
            technique_group="protocol",
            technique_name="Accept: application/json (force JSON response)",
            url=url, method="GET",
            extra_headers={"Accept": "application/json"},
        ),
        BypassAttempt(
            technique_group="protocol",
            technique_name="Accept-Language injection",
            url=url, method="GET",
            extra_headers={"Accept-Language": "en-US,en;q=0.9"},
        ),
        BypassAttempt(
            technique_group="protocol",
            technique_name="Referer: trusted domain",
            url=url, method="GET",
            extra_headers={"Referer": f"{parsed.scheme}://{parsed.netloc}/"},
        ),
        BypassAttempt(
            technique_group="protocol",
            technique_name="Referer: same URL",
            url=url, method="GET",
            extra_headers={"Referer": url},
        ),
        BypassAttempt(
            technique_group="protocol",
            technique_name="HTTP scheme downgrade (http://)",
            url=alt_url, method="GET",
            extra_headers={},
        ),
        BypassAttempt(
            technique_group="protocol",
            technique_name="User-Agent: Googlebot",
            url=url, method="GET",
            extra_headers={"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"},
        ),
        BypassAttempt(
            technique_group="protocol",
            technique_name="User-Agent: curl (no browser check)",
            url=url, method="GET",
            extra_headers={"User-Agent": "curl/7.68.0"},
        ),
        BypassAttempt(
            technique_group="protocol",
            technique_name="Cache-Control: no-cache (bypass CDN cache)",
            url=url, method="GET",
            extra_headers={"Cache-Control": "no-cache", "Pragma": "no-cache"},
        ),
        BypassAttempt(
            technique_group="protocol",
            technique_name="Range header (partial content bypass)",
            url=url, method="GET",
            extra_headers={"Range": "bytes=0-999"},
        ),
    ]


# ═════════════════════════════════════════════════════════════════════════════
# CURL COMMAND GENERATOR
# ═════════════════════════════════════════════════════════════════════════════

def build_curl(attempt: BypassAttempt) -> str:
    """Generate a copy-paste curl reproduction command."""
    parts = ["curl -sk -D -"]
    if attempt.method != "GET":
        parts.append(f"-X {attempt.method}")
    for k, v in attempt.extra_headers.items():
        parts.append(f'-H "{k}: {v}"')
    if attempt.body is not None:
        parts.append(f"--data-raw '{attempt.body}'")
    parts.append(f'"{attempt.url}"')
    return " \\\n  ".join(parts)


# ═════════════════════════════════════════════════════════════════════════════
# RESPONSE DIFFING — determines if a bypass succeeded
# ═════════════════════════════════════════════════════════════════════════════

# Words/phrases that indicate an authorised response was returned
AUTH_POSITIVE_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.I) for p in [
        r'"data"\s*:',                    # JSON data key
        r'"result"\s*:',                  # JSON result
        r'"success"\s*:\s*true',
        r'"status"\s*:\s*"ok"',
        r'"status"\s*:\s*200',
        r'<title>[^<]*(?:dashboard|admin|panel|portal|welcome|logged.in)',
        r'logout',                        # if logout link appears, user is logged in
        r'welcome,\s*\w+',               # personalised greeting
    ]
]

# Phrases that confirm we're still blocked
BLOCKED_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.I) for p in [
        r'access\s+denied',
        r'403\s+forbidden',
        r'not\s+authorized',
        r'unauthorized',
        r'permission\s+denied',
        r'you\s+don.t\s+have\s+permission',
        r'please\s+log\s+in',
        r'authentication\s+required',
    ]
]


def assess_bypass(
    baseline_status: int,
    bypass_status: int | None,
    baseline_len: int,
    bypass_len: int | None,
    bypass_body: str,
    bypass_headers: dict,
) -> tuple[str, str]:
    """
    Compare bypass response to baseline 403/401.
    Returns (confidence, reason).

    confidence: "HIGH" | "MEDIUM" | "LOW" | "NONE"
    """
    if bypass_status is None:
        return "NONE", "No response received"

    # ── Clear bypass signals ──────────────────────────────────────────────
    if bypass_status == 200:
        # Check body for positive auth signals
        if any(p.search(bypass_body) for p in AUTH_POSITIVE_PATTERNS):
            return "HIGH", f"HTTP 200 with authenticated content patterns (was {baseline_status})"
        # Check body for still-blocked signals
        if any(p.search(bypass_body) for p in BLOCKED_PATTERNS):
            return "LOW", f"HTTP 200 but body still shows blocked content"
        # Large body increase is a strong signal
        if bypass_len and bypass_len > baseline_len * 2 and bypass_len > 500:
            return "HIGH", (
                f"HTTP 200 with body {bypass_len} bytes "
                f"(was {baseline_len} bytes on 403)"
            )
        return "MEDIUM", f"HTTP 200 (was {baseline_status}) — verify response content manually"

    # Redirect to login page = still blocked (just redirected)
    if bypass_status in (301, 302, 307, 308):
        loc = bypass_headers.get("location", bypass_headers.get("Location", "")).lower()
        if "login" in loc or "auth" in loc or "signin" in loc:
            return "NONE", f"Redirect to login page — still blocked"
        # Redirect elsewhere might be interesting
        return "LOW", f"Redirected to {loc[:80]} — investigate manually"

    # 401 → 200 or lower status = interesting
    if baseline_status == 401 and bypass_status < 401:
        return "MEDIUM", f"Status changed from 401 to {bypass_status}"

    # Significant body size increase even without 200
    if (bypass_len and baseline_len and
            bypass_len > baseline_len * 3 and bypass_len > 1000 and
            bypass_status not in (400, 404, 500)):
        return "LOW", (
            f"Body grew from {baseline_len} to {bypass_len} bytes "
            f"(status {bypass_status})"
        )

    # 500 error sometimes means we got through ACL but hit a backend error
    if bypass_status == 500 and baseline_status in (403, 401):
        return "LOW", f"Status changed from {baseline_status} to 500 — may have bypassed ACL"

    return "NONE", f"No bypass detected (status {bypass_status}, was {baseline_status})"


# ═════════════════════════════════════════════════════════════════════════════
# HTTP REQUESTER
# ═════════════════════════════════════════════════════════════════════════════

async def send_attempt(
    attempt: BypassAttempt,
    timeout: float = 10.0,
) -> tuple[int | None, dict, str, int]:
    """
    Send a bypass attempt.
    Returns (status, headers, body_snippet, body_len).
    """
    if not HAS_HTTPX:
        return None, {}, "", 0
    hdrs = {
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/json,*/*;q=0.8",
        **attempt.extra_headers,
    }
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            verify=False,
            follow_redirects=False,   # don't follow — we want to see redirect targets
        ) as c:
            if attempt.method == "GET":
                resp = await c.get(attempt.url, headers=hdrs)
            elif attempt.method == "POST":
                resp = await c.post(
                    attempt.url, headers=hdrs,
                    content=attempt.body or "",
                )
            elif attempt.method == "HEAD":
                resp = await c.head(attempt.url, headers=hdrs)
            elif attempt.method == "OPTIONS":
                resp = await c.options(attempt.url, headers=hdrs)
            else:
                resp = await c.request(attempt.method, attempt.url, headers=hdrs)
            body = resp.text[:3000]
            return resp.status_code, dict(resp.headers), body, len(resp.content)
    except Exception as exc:
        log.debug(f"[Attempt] {attempt.technique_name}: {exc}")
        return None, {}, "", 0


async def get_baseline(url: str, timeout: float = 10.0) -> tuple[int, int, str]:
    """
    Fetch the URL with a plain GET and return (status, body_len, body_snippet).
    Used to establish what the 403 response looks like before testing bypasses.
    """
    if not HAS_HTTPX:
        return 403, 0, ""
    hdrs = {"User-Agent": UA}
    try:
        async with httpx.AsyncClient(
            timeout=timeout, verify=False,
            follow_redirects=False, headers=hdrs,
        ) as c:
            resp = await c.get(url)
            body = resp.text[:3000]
            return resp.status_code, len(resp.content), body
    except Exception:
        return 0, 0, ""


# ═════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class URLResult:
    url: str
    host: str
    original_status: int
    baseline_len: int
    total_attempts: int = 0
    bypasses: list[BypassResult] = field(default_factory=list)
    error: str = ""


@dataclass
class BypassReport:
    domain: str
    scan_time: str
    source_file: str
    total_urls: int = 0
    total_attempts: int = 0
    elapsed_seconds: float = 0.0
    url_results: list[URLResult] = field(default_factory=list)
    all_bypasses: list[BypassResult] = field(default_factory=list)


# ═════════════════════════════════════════════════════════════════════════════
# URL TESTER
# ═════════════════════════════════════════════════════════════════════════════

TECHNIQUE_GROUPS = {
    "path":         _path_variants,
    "method":       _method_variants,
    "ip_header":    _ip_spoof_variants,
    "host":         _host_variants,
    "content_type": _content_type_variants,
    "protocol":     _protocol_variants,
}

ALL_GROUPS = list(TECHNIQUE_GROUPS.keys())


class URLTester:
    def __init__(
        self,
        domain: str,
        timeout: float        = 10.0,
        concurrency: int      = 20,
        technique_groups: list[str] | None = None,
        min_confidence: str   = "LOW",
    ):
        self.domain            = domain
        self.timeout           = timeout
        self._sem              = asyncio.Semaphore(concurrency)
        self.groups            = technique_groups or ALL_GROUPS
        self.min_conf_order    = SEVERITY_ORDER.get(min_confidence.upper(), 3)

    async def test_url(self, url: str, host: str = "") -> URLResult:
        async with self._sem:
            return await self._run(url, host)

    async def _run(self, url: str, host: str) -> URLResult:
        if not host:
            from urllib.parse import urlparse
            host = urlparse(url).netloc

        # Establish baseline
        baseline_status, baseline_len, baseline_body = await get_baseline(url, self.timeout)
        result = URLResult(
            url=url,
            host=host,
            original_status=baseline_status,
            baseline_len=baseline_len,
        )

        # Only test URLs that are actually blocked
        if baseline_status not in (401, 403):
            log.debug(f"[Skip] {url} returned {baseline_status} (not 401/403)")
            return result

        # Collect all bypass attempts for this URL
        all_attempts: list[BypassAttempt] = []
        for group_name in self.groups:
            fn = TECHNIQUE_GROUPS.get(group_name)
            if fn:
                attempts = fn(url)
                for a in attempts:
                    a.curl_command = build_curl(a)
                all_attempts.extend(attempts)

        result.total_attempts = len(all_attempts)
        log.debug(f"[{host}] {url} → {len(all_attempts)} bypass attempts")

        # Fire all attempts concurrently (bounded by inner semaphore)
        attempt_sem = asyncio.Semaphore(10)

        async def run_one(attempt: BypassAttempt) -> BypassResult | None:
            async with attempt_sem:
                status, headers, body, body_len = await send_attempt(attempt, self.timeout)
                confidence, reason = assess_bypass(
                    baseline_status, status,
                    baseline_len, body_len,
                    body, headers,
                )
                if confidence == "NONE":
                    return None
                return BypassResult(
                    attempt=attempt,
                    baseline_status=baseline_status,
                    bypass_status=status,
                    baseline_body_len=baseline_len,
                    bypass_body_len=body_len,
                    bypass_body_snippet=body[:500],
                    bypass_headers=headers,
                    confidence=confidence,
                    reason=reason,
                )

        raw_results = await asyncio.gather(
            *[run_one(a) for a in all_attempts],
            return_exceptions=True,
        )

        for r in raw_results:
            if isinstance(r, BypassResult):
                conf_order = SEVERITY_ORDER.get(r.confidence.upper(), 9)
                if conf_order <= self.min_conf_order:
                    result.bypasses.append(r)

        # Sort bypasses: HIGH first
        result.bypasses.sort(
            key=lambda r: SEVERITY_ORDER.get(r.confidence.upper(), 9)
        )
        return result


# ═════════════════════════════════════════════════════════════════════════════
# INPUT PARSERS
# ═════════════════════════════════════════════════════════════════════════════

def load_from_recon(path: str, target_status: set[int] | None = None) -> list[tuple[str, str]]:
    """
    Extract all 403/401 URLs from reconharvest.py output.
    Returns list of (url, host).
    """
    if target_status is None:
        target_status = {401, 403}

    with open(path) as f:
        data = json.load(f)

    urls: list[tuple[str, str]] = []
    seen: set[str] = set()

    for hr in data.get("host_reports", []):
        host = hr.get("host", "")
        ip   = hr.get("ip", "")

        # Scan probe_results for blocked paths
        for pr in hr.get("probe_results", []):
            status = pr.get("http_status")
            if status not in target_status:
                continue
            path_val = pr.get("path", "")
            if not path_val:
                continue

            # Determine base URL from open ports
            open_ports = hr.get("open_ports", [])
            if not open_ports:
                continue
            best_port = next(
                (p for p in open_ports if p.get("scheme") == "https"),
                open_ports[0] if open_ports else None,
            )
            if not best_port:
                continue

            scheme = best_port.get("scheme", "http")
            port   = best_port.get("port", 80)
            if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
                base = f"{scheme}://{host}"
            else:
                base = f"{scheme}://{host}:{port}"

            full_url = base + path_val
            if full_url not in seen:
                seen.add(full_url)
                urls.append((full_url, host))

        # Also check findings for 403 paths mentioned in evidence
        for finding in hr.get("findings", []):
            ev = finding.get("evidence", "")
            m  = re.search(r'curl[^"]*"(https?://[^"]+)"', ev)
            if m:
                u = m.group(1)
                if u not in seen:
                    seen.add(u)
                    urls.append((u, host))

    log.info(f"[Parse] {len(urls)} 403/401 URLs from {path}")
    return urls


def load_from_urlfile(path: str, domain: str) -> list[tuple[str, str]]:
    """Load plain URL list. One URL per line."""
    urls: list[tuple[str, str]] = []
    seen: set[str] = set()
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            from urllib.parse import urlparse
            parsed = urlparse(line)
            host   = parsed.netloc or line
            if not parsed.scheme:
                line = "http://" + line
            if line not in seen:
                seen.add(line)
                urls.append((line, host))
    log.info(f"[Parse] {len(urls)} URLs from {path}")
    return urls


# ═════════════════════════════════════════════════════════════════════════════
# REPORTING
# ═════════════════════════════════════════════════════════════════════════════

CONF_COLOR = {"HIGH": "bold red", "MEDIUM": "bold yellow", "LOW": "cyan"}
CONF_EMOJI = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🔵"}


def print_report(report: BypassReport) -> None:
    high_bypasses   = [b for b in report.all_bypasses if b.confidence == "HIGH"]
    medium_bypasses = [b for b in report.all_bypasses if b.confidence == "MEDIUM"]
    low_bypasses    = [b for b in report.all_bypasses if b.confidence == "LOW"]

    if not HAS_RICH:
        print(f"\n=== 4xxBypass: {report.domain} ===")
        print(
            f"URLs tested: {report.total_urls}  "
            f"Attempts: {report.total_attempts}  "
            f"Elapsed: {report.elapsed_seconds:.1f}s"
        )
        print(
            f"Bypasses: HIGH={len(high_bypasses)} "
            f"MEDIUM={len(medium_bypasses)} LOW={len(low_bypasses)}"
        )
        for b in sorted(report.all_bypasses,
                        key=lambda x: SEVERITY_ORDER.get(x.confidence.upper(), 9)):
            print(f"\n[{b.confidence}] {b.attempt.technique_name}")
            print(f"  URL:      {b.attempt.url}")
            print(f"  Method:   {b.attempt.method}")
            print(f"  Reason:   {b.reason}")
            print(f"  Baseline: HTTP {b.baseline_status}")
            print(f"  Bypass:   HTTP {b.bypass_status}")
            print(f"  Curl:\n{b.attempt.curl_command}")
        print()
        return

    console.print()
    border = "red" if high_bypasses else "yellow" if medium_bypasses else "blue"
    console.print(Panel.fit(
        f"[white]Domain:[/] [cyan]{report.domain}[/]\n"
        f"[white]Scan time:[/] {report.scan_time}\n"
        f"[white]Elapsed:[/] {report.elapsed_seconds:.1f}s\n"
        f"[white]URLs tested:[/] {report.total_urls}    "
        f"[white]Total attempts:[/] {report.total_attempts:,}\n\n"
        f"[bold red]HIGH:[/] {len(high_bypasses)}    "
        f"[bold yellow]MEDIUM:[/] {len(medium_bypasses)}    "
        f"[cyan]LOW:[/] {len(low_bypasses)}",
        title="[bold]4xxBypass Report[/]",
        border_style=border,
    ))

    if not report.all_bypasses:
        console.print("[bold green]✓ No bypasses detected.[/]\n")
        return

    # ── Summary table ─────────────────────────────────────────────────────
    console.print("\n[bold cyan]── Bypass Summary ──[/]")
    tbl = Table(show_header=True, header_style="bold cyan", border_style="dim")
    tbl.add_column("Confidence",  justify="center")
    tbl.add_column("Technique",   style="yellow")
    tbl.add_column("Group",       style="dim")
    tbl.add_column("Baseline",    justify="center", style="dim")
    tbl.add_column("Bypass",      justify="center")
    tbl.add_column("Host",        style="cyan")
    tbl.add_column("Path",        style="dim", max_width=35)

    for b in sorted(report.all_bypasses,
                    key=lambda x: SEVERITY_ORDER.get(x.confidence.upper(), 9)):
        col = CONF_COLOR.get(b.confidence, "white")
        status_col = "green" if b.bypass_status == 200 else (
            "yellow" if b.bypass_status and b.bypass_status < 400 else "red"
        )
        from urllib.parse import urlparse
        parsed = urlparse(b.attempt.url)
        tbl.add_row(
            f"[{col}]{b.confidence}[/]",
            b.attempt.technique_name[:45],
            b.attempt.technique_group,
            str(b.baseline_status),
            f"[{status_col}]{b.bypass_status}[/]" if b.bypass_status else "—",
            b.attempt.url.split("/")[2] if "/" in b.attempt.url else b.attempt.url,
            parsed.path[:35],
        )
    console.print(tbl)

    # ── Detail per bypass ─────────────────────────────────────────────────
    for conf in ("HIGH", "MEDIUM", "LOW"):
        bps = [b for b in report.all_bypasses if b.confidence == conf]
        if not bps:
            continue
        col = CONF_COLOR.get(conf, "white")
        console.print(f"\n[{col}]── {CONF_EMOJI.get(conf,'')} {conf} Confidence ({len(bps)}) ──[/]")
        for i, b in enumerate(bps, 1):
            console.print(
                f"  [{col}][{i}][/] [white]{b.attempt.technique_name}[/]\n"
                f"      [dim]URL:[/]      {b.attempt.url}\n"
                f"      [dim]Method:[/]   {b.attempt.method}\n"
                f"      [dim]Headers:[/]  {b.attempt.extra_headers}\n"
                f"      [dim]Baseline:[/] HTTP {b.baseline_status} ({b.baseline_body_len} bytes)\n"
                f"      [dim]Bypass:[/]   HTTP {b.bypass_status} ({b.bypass_body_len} bytes)\n"
                f"      [dim]Reason:[/]   {b.reason}"
            )
            if b.attempt.curl_command:
                console.print(f"      [dim]Curl:[/]")
                for line in b.attempt.curl_command.split("\n"):
                    console.print(f"        [dim]{escape(line)}[/]")
            if i < len(bps):
                console.print()

    console.print()


def save_json(report: BypassReport, path: str) -> None:
    def _serialise(b: BypassResult) -> dict:
        return {
            "confidence":        b.confidence,
            "reason":            b.reason,
            "baseline_status":   b.baseline_status,
            "bypass_status":     b.bypass_status,
            "baseline_body_len": b.baseline_body_len,
            "bypass_body_len":   b.bypass_body_len,
            "body_snippet":      b.bypass_body_snippet[:300],
            "technique_group":   b.attempt.technique_group,
            "technique_name":    b.attempt.technique_name,
            "url":               b.attempt.url,
            "method":            b.attempt.method,
            "extra_headers":     b.attempt.extra_headers,
            "curl_command":      b.attempt.curl_command,
        }

    data = {
        "domain":          report.domain,
        "scan_time":       report.scan_time,
        "source_file":     report.source_file,
        "total_urls":      report.total_urls,
        "total_attempts":  report.total_attempts,
        "elapsed_seconds": report.elapsed_seconds,
        "summary": {
            c: len([b for b in report.all_bypasses if b.confidence == c])
            for c in ("HIGH", "MEDIUM", "LOW")
        },
        "bypasses": [_serialise(b) for b in sorted(
            report.all_bypasses,
            key=lambda b: SEVERITY_ORDER.get(b.confidence.upper(), 9)
        )],
        "url_results": [
            {
                "url":             ur.url,
                "host":            ur.host,
                "original_status": ur.original_status,
                "baseline_len":    ur.baseline_len,
                "total_attempts":  ur.total_attempts,
                "bypass_count":    len(ur.bypasses),
                "bypasses":        [_serialise(b) for b in ur.bypasses],
            }
            for ur in report.url_results if ur.bypasses
        ],
    }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    log.info(f"JSON report saved → {path}")
    log.info(
        f"  Bypasses: HIGH={data['summary']['HIGH']} "
        f"MEDIUM={data['summary']['MEDIUM']} "
        f"LOW={data['summary']['LOW']}"
    )


def save_html(report: BypassReport, path: str) -> None:
    high   = [b for b in report.all_bypasses if b.confidence == "HIGH"]
    medium = [b for b in report.all_bypasses if b.confidence == "MEDIUM"]
    low    = [b for b in report.all_bypasses if b.confidence == "LOW"]

    sc = {"HIGH": "#f85149", "MEDIUM": "#d29922", "LOW": "#58a6ff"}
    sb = {
        "HIGH":   "rgba(248,81,73,.12)",
        "MEDIUM": "rgba(210,153,34,.12)",
        "LOW":    "rgba(88,166,255,.10)",
    }

    bypass_html = ""
    for conf, blist in (("HIGH", high), ("MEDIUM", medium), ("LOW", low)):
        if not blist:
            continue
        bypass_html += (
            f'<div class="sev-section">'
            f'<h3 style="color:{sc[conf]}">{CONF_EMOJI.get(conf,"")} {conf} ({len(blist)})</h3>'
        )
        for i, b in enumerate(blist, 1):
            curl_escaped = b.attempt.curl_command.replace("<","&lt;").replace(">","&gt;")
            bypass_html += (
                f'<div class="finding" style="border-left:3px solid {sc[conf]};background:{sb[conf]}">'
                f'<div class="ft">[{i}] {b.attempt.technique_name}</div>'
                f'<div class="fm">'
                f'<span class="badge" style="color:{sc[conf]};background:{sb[conf]};border:1px solid {sc[conf]}">{conf}</span>'
                f'<span style="color:#58a6ff;font-size:.82em">{b.attempt.url}</span>'
                f'</div>'
                f'<div class="fd">'
                f'Baseline: HTTP {b.baseline_status} ({b.baseline_body_len} bytes)  →  '
                f'Bypass: HTTP {b.bypass_status} ({b.bypass_body_len} bytes)<br>'
                f'{b.reason}'
                f'</div>'
                f'<div class="ev"><span class="evl">Technique group:</span>'
                f'<code>{b.attempt.technique_group}</code>  '
                f'<span class="evl">Method:</span><code>{b.attempt.method}</code>  '
                f'<span class="evl">Headers:</span><code>{json.dumps(b.attempt.extra_headers)}</code>'
                f'</div>'
                f'<div class="ev"><span class="evl">Reproduce:</span>'
                f'<pre style="margin:4px 0 0 0;color:#a8dadc;font-size:.8em">{curl_escaped}</pre></div>'
                + (f'<div class="ev"><span class="evl">Body snippet:</span>'
                   f'<code>{b.bypass_body_snippet[:200]}</code></div>'
                   if b.bypass_body_snippet else "")
                + f'</div>'
            )
        bypass_html += "</div>"

    if not bypass_html:
        bypass_html = "<p style='color:#3fb950'>No bypasses detected.</p>"

    # Summary table
    rows = ""
    for b in sorted(report.all_bypasses, key=lambda x: SEVERITY_ORDER.get(x.confidence.upper(), 9)):
        col = sc.get(b.confidence, "#8b949e")
        status_col = "#3fb950" if b.bypass_status == 200 else (
            "#d29922" if b.bypass_status and b.bypass_status < 400 else "#f85149"
        )
        rows += (
            f"<tr>"
            f"<td style='color:{col};font-weight:bold'>{b.confidence}</td>"
            f"<td style='color:#d29922'>{b.attempt.technique_name}</td>"
            f"<td style='color:#627384'>{b.attempt.technique_group}</td>"
            f"<td style='color:#627384;text-align:center'>{b.baseline_status}</td>"
            f"<td style='color:{status_col};font-weight:bold;text-align:center'>{b.bypass_status}</td>"
            f"<td style='color:#58a6ff'>{b.attempt.url[:60]}</td>"
            f"</tr>"
        )

    html = f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>4xxBypass — {report.domain}</title>
<style>
:root{{--bg:#080c10;--sf:#0d1117;--sf2:#111820;--bd:#1e2d3d;--tx:#cdd6e0;--mt:#627384;}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--tx);font-family:'Consolas','Monaco',monospace;
     font-size:13px;line-height:1.7}}
body::before{{content:'';position:fixed;inset:0;
  background-image:linear-gradient(rgba(0,212,255,.012) 1px,transparent 1px),
                   linear-gradient(90deg,rgba(0,212,255,.012) 1px,transparent 1px);
  background-size:40px 40px;pointer-events:none;z-index:0}}
.wrap{{max-width:1400px;margin:0 auto;padding:32px 28px 80px;position:relative;z-index:1}}
h1{{font-family:system-ui,sans-serif;font-size:2em;font-weight:800;color:#fff;
   letter-spacing:-.03em;margin-bottom:6px}}
.sub{{color:var(--mt);font-size:.8em;margin-bottom:32px}}
.stats{{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));
        gap:10px;margin-bottom:28px}}
.stat{{background:var(--sf);border:1px solid var(--bd);border-radius:8px;
       padding:14px;text-align:center}}
.sv{{font-size:1.8em;font-weight:bold}}.sl{{color:var(--mt);font-size:.72em;margin-top:3px}}
.card{{background:var(--sf);border:1px solid var(--bd);border-radius:8px;
       padding:20px;margin-bottom:20px}}
h2{{font-family:system-ui,sans-serif;font-size:1.1em;font-weight:700;color:#fff;
   margin-bottom:14px}}
h3{{font-family:system-ui,sans-serif;font-size:.95em;font-weight:700;margin:16px 0 10px}}
table{{width:100%;border-collapse:collapse}}
th{{background:var(--sf2);color:var(--mt);text-align:left;padding:8px 12px;
   border:1px solid var(--bd);font-size:.72em;text-transform:uppercase;letter-spacing:.07em}}
td{{padding:8px 12px;border-bottom:1px solid var(--bd);vertical-align:top}}
tr:hover td{{background:rgba(88,166,255,.03)}}
.finding{{padding:14px 16px;border-radius:6px;margin-bottom:10px}}
.ft{{font-family:system-ui,sans-serif;font-weight:700;font-size:.9em;color:#fff;
    margin-bottom:8px}}
.fm{{display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap}}
.badge{{padding:2px 8px;border-radius:10px;font-size:.7em;font-weight:700;letter-spacing:.05em}}
.fd{{color:var(--mt);font-size:.83em;margin-bottom:8px;line-height:1.6}}
.ev{{background:rgba(0,0,0,.4);border:1px solid var(--bd);border-radius:4px;
     padding:8px 10px;margin-bottom:8px}}
.evl{{color:#39c5cf;font-size:.7em;font-weight:700;margin-right:6px}}
.ev code,.ev pre{{color:#a8dadc;font-size:.82em;word-break:break-all}}
.sev-section{{margin-bottom:20px}}
.footer{{text-align:center;color:var(--mt);font-size:.72em;margin-top:32px;
         padding-top:16px;border-top:1px solid var(--bd)}}
</style></head>
<body><div class="wrap">
<h1>4xxBypass</h1>
<p class="sub">{report.domain} &nbsp;·&nbsp; {report.scan_time} &nbsp;·&nbsp;
{report.elapsed_seconds:.1f}s &nbsp;·&nbsp; {report.total_urls} URLs tested &nbsp;·&nbsp;
{report.total_attempts:,} attempts</p>
<div class="stats">
<div class="stat"><div class="sv" style="color:#f85149">{len(high)}</div><div class="sl">HIGH</div></div>
<div class="stat"><div class="sv" style="color:#d29922">{len(medium)}</div><div class="sl">MEDIUM</div></div>
<div class="stat"><div class="sv" style="color:#58a6ff">{len(low)}</div><div class="sl">LOW</div></div>
<div class="stat"><div class="sv">{report.total_urls}</div><div class="sl">URLS TESTED</div></div>
<div class="stat"><div class="sv">{report.total_attempts:,}</div><div class="sl">ATTEMPTS</div></div>
</div>
<div class="card"><h2>📋 Bypass Summary</h2>
{"<table><thead><tr><th>Confidence</th><th>Technique</th><th>Group</th><th>Baseline</th><th>Bypass Status</th><th>URL</th></tr></thead><tbody>" + rows + "</tbody></table>" if rows else "<p style='color:#3fb950'>No bypasses detected.</p>"}
</div>
<div class="card"><h2>🔓 Bypass Details</h2>{bypass_html}</div>
<div class="footer">4xxBypass &nbsp;·&nbsp; For authorized security research only</div>
</div></body></html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    log.info(f"HTML report saved → {path}")


# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="4xxBypass — HTTP 403/401 Access Control Bypass Tester",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 4xxbypass.py --recon recon-report-v2.json --domain eskimi.com --output bypass
  python3 4xxbypass.py --urls blocked.txt --domain eskimi.com --output bypass
  python3 4xxbypass.py --recon recon-report-v2.json --domain eskimi.com --techniques path ip_header
  python3 4xxbypass.py --urls blocked.txt --domain eskimi.com --min-confidence medium

Technique groups:
  path          — URL path normalisation (14 variants)
  method        — HTTP method override headers (7 variants)
  ip_header     — IP spoofing headers (14 headers)
  host          — Host header injection (9 variants)
  content_type  — Content-Type bypass (7 types)
  protocol      — Protocol / misc tricks (9 tricks)
  all           — All of the above (default)

Chains from : reconharvest.py (--recon), plain URL list (--urls)
Output      : JSON + HTML report with curl reproduction commands
        """,
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--recon", metavar="FILE",
                     help="reconharvest.py JSON output (extracts 403/401 paths)")
    src.add_argument("--urls",  metavar="FILE",
                     help="Plain text URL list (one URL per line)")

    p.add_argument("--domain",          required=True,  help="Target root domain")
    p.add_argument("-o", "--output",    metavar="BASE",  help="Output base → BASE.json + BASE.html")
    p.add_argument("--techniques",      nargs="+",
                   choices=ALL_GROUPS + ["all"], default=["all"],
                   help="Technique groups to test (default: all)")
    p.add_argument("--min-confidence",  default="low",
                   choices=["high", "medium", "low"],
                   help="Minimum bypass confidence to report (default: low)")
    p.add_argument("--timeout",         type=float, default=10.0,
                   help="HTTP timeout per request (default: 10s)")
    p.add_argument("--concurrency",     type=int,   default=20,
                   help="Concurrent URL workers (default: 20)")
    p.add_argument("-v", "--verbose",   action="store_true", help="Verbose logging")
    return p.parse_args()


async def main() -> None:
    args = parse_args()
    if args.verbose:
        log.setLevel(logging.DEBUG)

    print("""
╔══════════════════════════════════════════════════════════════════╗
║       4xxBypass — HTTP 403/401 Access Control Bypass Tester      ║
║  For authorized penetration testing and bug bounty research only ║
╚══════════════════════════════════════════════════════════════════╝
""")

    if not HAS_HTTPX:
        log.error("httpx required: pip install httpx")
        sys.exit(1)

    # Resolve technique groups
    groups = (
        ALL_GROUPS
        if "all" in args.techniques
        else [g for g in args.techniques if g in TECHNIQUE_GROUPS]
    )
    log.info(f"[Config] Technique groups: {', '.join(groups)}")

    # Load URLs
    if args.recon:
        url_list = load_from_recon(args.recon)
        source   = args.recon
    else:
        url_list = load_from_urlfile(args.urls, args.domain)
        source   = args.urls

    if not url_list:
        log.error("No blocked URLs found in input.")
        sys.exit(1)

    # Count expected attempts
    sample_url   = url_list[0][0]
    sample_count = sum(
        len(TECHNIQUE_GROUPS[g](sample_url)) for g in groups
    )
    log.info(
        f"[Config] {len(url_list)} URLs × ~{sample_count} techniques "
        f"= ~{len(url_list) * sample_count:,} total HTTP requests"
    )

    report = BypassReport(
        domain=args.domain,
        scan_time=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        source_file=source,
        total_urls=len(url_list),
    )

    tester = URLTester(
        domain=args.domain,
        timeout=args.timeout,
        concurrency=args.concurrency,
        technique_groups=groups,
        min_confidence=args.min_confidence.upper(),
    )

    t0 = time.perf_counter()

    if HAS_RICH:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]Testing bypasses[/]"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("[dim]{task.fields[u]}[/]"),
            console=console,
        ) as prog:
            task = prog.add_task("bypass", total=len(url_list), u="")
            sem  = asyncio.Semaphore(args.concurrency)

            async def bounded(url: str, host: str) -> URLResult:
                async with sem:
                    prog.update(task, u=url[:50])
                    r = await tester.test_url(url, host)
                    prog.advance(task)
                    return r

            results = await asyncio.gather(
                *[bounded(u, h) for u, h in url_list],
                return_exceptions=True,
            )
    else:
        sem = asyncio.Semaphore(args.concurrency)

        async def bounded(url: str, host: str) -> URLResult:
            async with sem:
                return await tester.test_url(url, host)

        results = await asyncio.gather(
            *[bounded(u, h) for u, h in url_list],
            return_exceptions=True,
        )

    # Aggregate
    total_attempts = 0
    for r in results:
        if isinstance(r, URLResult):
            report.url_results.append(r)
            report.all_bypasses.extend(r.bypasses)
            total_attempts += r.total_attempts
        elif isinstance(r, Exception):
            log.warning(f"URL error: {r}")

    report.total_attempts  = total_attempts
    report.elapsed_seconds = round(time.perf_counter() - t0, 2)

    print_report(report)

    if args.output:
        out_base = args.output
        if out_base.endswith(".json"):
            out_base = out_base[:-5]
        if out_base.endswith(".html"):
            out_base = out_base[:-5]
        save_json(report, out_base + ".json")
        save_html(report, out_base + ".html")

    high = len([b for b in report.all_bypasses if b.confidence == "HIGH"])
    if high:
        log.warning(
            f"[!] {high} HIGH confidence bypass(es) found — "
            f"verify and submit to bug bounty program"
        )


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(0)
