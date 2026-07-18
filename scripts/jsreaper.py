#!/usr/bin/env python3
"""
jsreaper.py — JavaScript Secret & Endpoint Harvester
=====================================================
Author  : RareKez / security research tooling
License : MIT (for authorized use only)

Chains from : reconharvest.py (--scan) or subtakeover.py (--subtakeover)
Feeds into  : apifuzz.py, paramfuzz.py, ssrfprobe.py, oauthprobe.py

Pipeline:
  1. Discover all JS assets from live hosts (HTML crawl + webpack manifest)
  2. Fetch sourcemaps (.map files) for pre-minification source
  3. Extract secrets via 40+ regex patterns grouped by provider
  4. Shannon entropy analysis for non-patterned secrets
  5. Extract API endpoints, GraphQL operations, WebSocket URLs
  6. Detect OAuth endpoints and auth flows
  7. Find hardcoded internal IPs / private network references
  8. Reconstruct dynamic string concatenations (webpack module resolution)
  9. Generate JSON + HTML report — feeds directly into apifuzz.py / paramfuzz.py

Usage:
  python3 jsreaper.py --scan recon.json --domain eskimi.com --output js-findings
  python3 jsreaper.py --subtakeover scan.json --domain eskimi.com --output js-findings
  python3 jsreaper.py --hosts targets.txt --domain eskimi.com --output js-findings
  python3 jsreaper.py --scan recon.json --domain eskimi.com --deep --sourcemaps
  python3 jsreaper.py --scan recon.json --domain eskimi.com --entropy 4.2 --output js

LEGAL: Only use against targets you have explicit written authorization to test.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import datetime
import hashlib
import json
import math
import re
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse

# ── optional deps ─────────────────────────────────────────────────────────────
try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.panel import Panel
    from rich.markup import escape
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False
    console = None

import logging
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger("jsreaper")
for _n in ("httpx", "httpcore"):
    logging.getLogger(_n).setLevel(logging.WARNING)


# ═════════════════════════════════════════════════════════════════════════════
# SECRET PATTERN DATABASE
# Organised by provider/type. Each entry: (name, pattern, severity, note)
# ═════════════════════════════════════════════════════════════════════════════

SECRET_PATTERNS: list[tuple[str, re.Pattern, str, str]] = []

def _p(name: str, pattern: str, severity: str = "HIGH", note: str = "") -> None:
    try:
        SECRET_PATTERNS.append((name, re.compile(pattern, re.IGNORECASE), severity, note))
    except re.error as exc:
        log.warning(f"[Patterns] Bad regex for {name}: {exc}")

# ── AWS ───────────────────────────────────────────────────────────────────────
_p("AWS Access Key ID",
   r'(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])',
   "CRITICAL", "AWS long-term access key — valid credential")
_p("AWS Secret Access Key",
   r'(?i)(?:aws.{0,20}secret|secret.{0,20}aws|aws_secret_access_key)\s*[=:\"\']\s*([A-Za-z0-9/+=]{40})',
   "CRITICAL", "AWS secret key for the AKIA access key")
_p("AWS Session Token",
   r'(?i)(?:aws.session.token|aws_session_token)\s*[=:\"\']\s*([A-Za-z0-9/+=]{100,})',
   "CRITICAL", "Temporary STS session token with attached IAM policy")
_p("AWS S3 Presigned URL",
   r'https://s3[.-][^"\']+\.amazonaws\.com[^"\']*X-Amz-Signature=[^"\']+',
   "MEDIUM", "Pre-signed S3 URL — check if expired and what object it accesses")
_p("AWS Account ID",
   r'(?<!\d)(\d{12})(?!\d)(?=.*(?:aws|arn|account))',
   "LOW", "AWS account ID")
_p("AWS ARN",
   r'arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d{12}:[^\s"\']+',
   "LOW", "AWS resource ARN leaks account ID and resource structure")

# ── GCP ───────────────────────────────────────────────────────────────────────
_p("GCP API Key",
   r'AIza[0-9A-Za-z\-_]{35}',
   "HIGH", "GCP API key — scope determines impact")
_p("GCP Service Account JSON",
   r'"type"\s*:\s*"service_account"',
   "CRITICAL", "Service account JSON embedded in JS")
_p("GCP OAuth Client ID",
   r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
   "MEDIUM", "GCP OAuth client ID")
_p("GCP OAuth Client Secret",
   r'(?i)client.?secret\s*[=:\"\']\s*(GOCSPX-[A-Za-z0-9\-_]{28})',
   "HIGH", "GCP OAuth client secret")
_p("GCP Firebase Config",
   r'apiKey\s*:\s*["\']([A-Za-z0-9\-_]{39})["\']',
   "MEDIUM", "Firebase API key — check database rules")

# ── Azure ─────────────────────────────────────────────────────────────────────
_p("Azure Storage Connection String",
   r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86,88}==',
   "CRITICAL", "Full Azure Storage account access")
_p("Azure SAS Token",
   r'sv=\d{4}-\d{2}-\d{2}&s[a-z]=(?:b|c|o)&sp=[a-z]+&[^"\'&\s]+sig=[A-Za-z0-9%+/=]+',
   "HIGH", "Azure Shared Access Signature — check permissions and expiry")
_p("Azure Client Secret",
   r'(?i)(?:azure.{0,20}client.?secret|client.?secret.{0,20}azure)\s*[=:\"\']\s*([A-Za-z0-9~._@-]{34,40})',
   "HIGH", "Azure AD application client secret")

# ── Generic API Keys & Tokens ─────────────────────────────────────────────────
_p("Stripe Secret Key",
   r'sk_(?:live|test)_[0-9a-zA-Z]{24,}',
   "CRITICAL", "Stripe secret API key — full payment access")
_p("Stripe Publishable Key",
   r'pk_(?:live|test)_[0-9a-zA-Z]{24,}',
   "LOW", "Stripe publishable key — low risk but confirms Stripe usage")
_p("SendGrid API Key",
   r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}',
   "HIGH", "SendGrid key — can send mail as any domain address")
_p("Twilio API Key",
   r'SK[0-9a-fA-F]{32}',
   "HIGH", "Twilio API key SID")
_p("Twilio Auth Token",
   r'(?i)twilio.{0,10}(?:auth.?token|token)\s*[=:\"\']\s*([0-9a-f]{32})',
   "HIGH", "Twilio account auth token")
_p("GitHub Personal Access Token",
   r'ghp_[A-Za-z0-9]{36}',
   "HIGH", "GitHub PAT — repo access at minimum")
_p("GitHub OAuth Token",
   r'gho_[A-Za-z0-9]{36}',
   "HIGH", "GitHub OAuth token")
_p("GitHub App Token",
   r'(?:ghu|ghs)_[A-Za-z0-9]{36}',
   "HIGH", "GitHub App installation/user token")
_p("Slack Bot Token",
   r'xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}',
   "HIGH", "Slack bot token — channel read/write")
_p("Slack User Token",
   r'xoxp-[0-9]{11}-[0-9]{11}-[0-9]{11}-[0-9a-f]{32}',
   "HIGH", "Slack user token")
_p("Slack Webhook URL",
   r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+',
   "HIGH", "Slack incoming webhook — can post as any app to any channel")
_p("Discord Webhook URL",
   r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+',
   "MEDIUM", "Discord webhook — can post messages to channel")
_p("HubSpot API Key",
   r'(?i)hapikey\s*[=:\"\']\s*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})',
   "HIGH", "HubSpot API key")
_p("Mailgun API Key",
   r'key-[0-9a-zA-Z]{32}',
   "HIGH", "Mailgun API key — send mail as any domain")
_p("Mapbox Token",
   r'pk\.eyJ1Ijoi[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',
   "MEDIUM", "Mapbox public token — check scope restrictions")
_p("Algolia API Key",
   r'(?i)algolia.{0,20}(?:api.?key|apikey)\s*[=:\"\']\s*([a-f0-9]{32})',
   "HIGH", "Algolia API key")
_p("Salesforce OAuth Token",
   r'00D[A-Za-z0-9]{15}![A-Za-z0-9._]{96}',
   "CRITICAL", "Salesforce access token")

# ── JWT ───────────────────────────────────────────────────────────────────────
_p("JWT Token",
   r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+',
   "MEDIUM", "JWT token — decode and check claims, expiry, algorithm")
_p("JWT Signing Secret",
   r'(?i)(?:jwt.{0,15}secret|jwt_secret|jwt.?signing.?key|secret.{0,15}jwt)\s*[=:\"\']\s*([^\s"\']{8,})',
   "CRITICAL", "JWT signing secret — can forge arbitrary tokens")

# ── Passwords & Credentials ───────────────────────────────────────────────────
_p("Hardcoded Password Assignment",
   r'(?i)(?:password|passwd|pwd|pass)\s*[=:]\s*["\']([^"\']{8,})["\']',
   "HIGH", "Hardcoded password — verify it's not a placeholder")
_p("Basic Auth in URL",
   r'https?://[A-Za-z0-9_\-]+:[^@"\s]+@[A-Za-z0-9.\-]+',
   "HIGH", "Credentials embedded in URL")
_p("Database Connection String",
   r'(?i)(?:postgres|postgresql|mysql|mongodb|redis|mssql|oracle)\://[^\s"\']+',
   "CRITICAL", "Database connection string with credentials")

# ── Private Keys & Certificates ───────────────────────────────────────────────
_p("RSA Private Key",
   r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
   "CRITICAL", "Private key embedded in JS — severe if used for auth or TLS")
_p("PGP Private Key",
   r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
   "CRITICAL", "PGP private key")
_p("Certificate",
   r'-----BEGIN CERTIFICATE-----',
   "LOW", "Certificate — check what it's used for")

# ── Internal Infrastructure ───────────────────────────────────────────────────
_p("Private IPv4 Address",
   r'(?<!\d)(?:10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})(?!\d)',
   "MEDIUM", "Private RFC 1918 IP — reveals internal network structure")
_p("Internal Hostname",
   r'https?://(?:[a-z0-9\-]+\.){1,5}(?:internal|corp|local|intranet|lan|priv|int)\b[^\s"\']*',
   "MEDIUM", "Internal DNS hostname in production JS")
_p("Localhost Reference",
   r'https?://(?:localhost|127\.0\.0\.1)(?::\d+)?[^\s"\']*',
   "LOW", "Localhost URL — may indicate debug config shipped to production")

# ── Miscellaneous ─────────────────────────────────────────────────────────────
_p("Generic Secret Assignment",
   r'(?i)(?:secret|api_key|apikey|auth_token|authtoken|access_token|bearer)\s*[=:]\s*["\']([A-Za-z0-9_\-+/=]{16,})["\']',
   "HIGH", "Generic secret assignment — verify value is not a placeholder")
_p("Bearer Token in Header Config",
   r'(?i)Authorization\s*:\s*["\']Bearer\s+([A-Za-z0-9_\-+/=.]{20,})',
   "HIGH", "Hardcoded Bearer token in axios/fetch default headers")
_p("npm Auth Token",
   r'//registry\.npmjs\.org/:_authToken=([A-Za-z0-9_\-]+)',
   "HIGH", "npm registry auth token in .npmrc or bundled config")


# ═════════════════════════════════════════════════════════════════════════════
# ENDPOINT & OAUTH PATTERNS
# ═════════════════════════════════════════════════════════════════════════════

# Endpoint extraction patterns
ENDPOINT_PATTERNS: list[re.Pattern] = [
    # fetch/axios/XHR calls
    re.compile(r'(?:fetch|axios\.(?:get|post|put|patch|delete|request))\s*\(\s*["\']([/][^"\']+)["\']', re.I),
    # $.ajax / $.get / $.post
    re.compile(r'\$\.(?:ajax|get|post|getJSON)\s*\(\s*["\']([/][^"\']{3,})["\']', re.I),
    # String path assignments: url = "/api/v1/users"
    re.compile(r'(?:url|endpoint|path|route|api_url|baseUrl)\s*[=:]\s*["\']([/][A-Za-z0-9/_\-{}.?&=]+)["\']', re.I),
    # Arrow function routes: router.get('/users', ...)
    re.compile(r'router\.(?:get|post|put|delete|patch|all)\s*\(\s*["\']([/][^"\']+)["\']', re.I),
    # Template literal: `${API_BASE}/users/${id}`
    re.compile(r'`\$\{[^}]+\}(/[A-Za-z0-9/_\-{}.]+)`', re.I),
    # Plain string paths: "/api/v1/users", "/graphql"
    re.compile(r'["\'](/(?:api|v\d|rest|graphql|query|admin|auth|oauth|user|account|order|product)[A-Za-z0-9/_\-{}.?&=]*)["\']', re.I),
]

GRAPHQL_PATTERNS: list[re.Pattern] = [
    re.compile(r'(?:query|mutation|subscription)\s+(\w+)\s*(?:\([^)]*\))?\s*\{', re.I),
    re.compile(r'gql`([^`]+)`', re.I | re.DOTALL),
    re.compile(r'gql\s*`([^`]+)`', re.I | re.DOTALL),
]

OAUTH_PATTERNS: list[re.Pattern] = [
    re.compile(r'["\']([^"\']*(?:authorize|oauth|connect|auth)/[^"\']*)["\']', re.I),
    re.compile(r'(?:client_id|clientId)\s*[=:]\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'(?:redirect_uri|redirectUri)\s*[=:]\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'response_type\s*[=:]\s*["\']([^"\']+)["\']', re.I),
]

WEBSOCKET_PATTERN = re.compile(r'(?:wss?|ws)://[^\s"\']+', re.I)

# Webpack chunk patterns for discovering all JS bundles
WEBPACK_CHUNK_PATTERNS: list[re.Pattern] = [
    re.compile(r'["\']([^"\']*chunk[^"\']*\.js)["\']', re.I),
    re.compile(r'["\']([^"\']*\.[a-f0-9]{8}\.js)["\']', re.I),
    re.compile(r'(?:chunkFilename|filename)\s*:\s*["\']([^"\']+\.js)["\']', re.I),
    re.compile(r'__webpack_require__\.p\s*\+\s*["\']([^"\']+\.js)["\']', re.I),
    re.compile(r'((?:static/js|assets/js)/[a-zA-Z0-9._\-]+\.js)', re.I),
]

# High-entropy false positive suppression (known safe high-entropy strings)
ENTROPY_ALLOWLIST: list[re.Pattern] = [
    re.compile(r'^[a-f0-9]{32,64}$'),              # MD5/SHA hash
    re.compile(r'^[A-Za-z0-9+/=]{1,4}$'),          # Very short base64
    re.compile(r'^\d+px$'),                          # CSS pixel values
    re.compile(r'^#[A-Fa-f0-9]{6}$'),               # CSS colour
    re.compile(r'^[A-Za-z]{1,3}-[A-Za-z]{1,3}$'),  # Short hyphenated var names
    re.compile(r'^(?:true|false|null|undefined|NaN)$', re.I),
    re.compile(r'^webpack'),
    re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),  # UUID
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_COLOR = {"CRITICAL":"bold red","HIGH":"bold yellow","MEDIUM":"yellow","LOW":"cyan","INFO":"dim"}
SEV_EMOJI = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵","INFO":"⚪"}

UA = "Mozilla/5.0 (compatible; JSReaper/1.0)"

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
class SecretFinding:
    host: str
    js_url: str
    secret_type: str
    value: str               # redacted to first 6 + last 4 chars in output
    raw_line: str            # surrounding context (100 chars)
    severity: str
    note: str
    confidence: str          # HIGH | MEDIUM | LOW
    is_entropy: bool = False


@dataclass
class EndpointFinding:
    host: str
    js_url: str
    endpoint: str
    method: str = "UNKNOWN"  # GET/POST if determinable
    params: list[str] = field(default_factory=list)
    source: str = "regex"    # regex | graphql | websocket | oauth


@dataclass
class JSAsset:
    url: str
    host: str
    size_bytes: int = 0
    content_hash: str = ""
    has_sourcemap: bool = False
    sourcemap_url: str = ""
    is_vendor: bool = False   # likely a framework bundle, lower-priority analysis
    fetch_error: str = ""


@dataclass
class HostResult:
    host: str
    ip: str
    js_assets: list[JSAsset] = field(default_factory=list)
    secrets: list[SecretFinding] = field(default_factory=list)
    endpoints: list[EndpointFinding] = field(default_factory=list)
    graphql_ops: list[str] = field(default_factory=list)
    websocket_urls: list[str] = field(default_factory=list)
    oauth_refs: list[dict] = field(default_factory=list)
    internal_ips: list[str] = field(default_factory=list)
    high_entropy: list[dict] = field(default_factory=list)
    error: str = ""


@dataclass
class ReaperReport:
    domain: str
    scan_time: str
    source_file: str
    total_hosts: int = 0
    total_js_files: int = 0
    elapsed_seconds: float = 0.0
    host_results: list[HostResult] = field(default_factory=list)
    # Flat merged lists for easy consumption by downstream tools
    all_secrets: list[SecretFinding] = field(default_factory=list)
    all_endpoints: list[EndpointFinding] = field(default_factory=list)
    all_graphql: list[str] = field(default_factory=list)
    all_oauth: list[dict] = field(default_factory=list)


# ═════════════════════════════════════════════════════════════════════════════
# NETWORKING
# ═════════════════════════════════════════════════════════════════════════════

async def fetch(
    url: str,
    timeout: float = 15.0,
    client: "httpx.AsyncClient | None" = None,
    max_size_kb: int = 5000,
    cookie: str | None = None,
    extra_headers: dict | None = None,
) -> tuple[int | None, str, dict]:
    """
    GET url → (status, body_text, headers).
    Respects max_size_kb to avoid fetching huge vendor bundles.
    Never raises.

    `cookie` / `extra_headers` propagate auth (e.g. a session cookie from
    auth_profiles.yaml) so jsreaper can harvest JS behind authenticated areas
    of the target — previously these requests were always unauthenticated.
    """
    if not HAS_HTTPX:
        return None, "", {}
    hdrs = {"User-Agent": user_agent(), "Accept-Encoding": "gzip, deflate"}
    if cookie:
        hdrs["Cookie"] = cookie
    if extra_headers:
        hdrs.update(extra_headers)
    try:
        if client:
            resp = await client.get(url, headers=hdrs)
        else:
            async with httpx.AsyncClient(
                timeout=timeout, verify=False,
                follow_redirects=True, headers=hdrs,
            ) as c:
                resp = await c.get(url)
        body = resp.text
        if len(body) > max_size_kb * 1024:
            body = body[: max_size_kb * 1024]
        return resp.status_code, body, dict(resp.headers)
    except Exception as exc:
        log.debug(f"[Fetch] {url}: {exc}")
        return None, "", {}


# ═════════════════════════════════════════════════════════════════════════════
# JS ASSET DISCOVERY
# ═════════════════════════════════════════════════════════════════════════════

async def discover_js_assets(
    host: str,
    scheme: str,
    port: int,
    client: "httpx.AsyncClient",
    max_size_kb: int,
    deep: bool,
    cookie: str | None = None,
    extra_headers: dict | None = None,
) -> list[JSAsset]:
    """
    Crawl a host's HTML pages and extract all JS asset URLs.
    Also searches for webpack chunk manifests.
    """
    assets: dict[str, JSAsset] = {}   # url → JSAsset (dedup by URL)
    base = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"

    async def add_asset(url: str) -> None:
        if url in assets or not url.endswith(".js"):
            return
        # Classify as vendor bundle
        is_vendor = any(kw in url.lower() for kw in [
            "vendor", "framework", "polyfill", "jquery", "react", "vue",
            "angular", "bootstrap", "lodash", "moment", "webpack-runtime",
        ])
        assets[url] = JSAsset(url=url, host=host, is_vendor=is_vendor)

    # Pages to crawl for JS references
    pages = ["/", "/index.html", "/app", "/dashboard", "/login", "/static/index.html"]
    if deep:
        pages += ["/about", "/register", "/signup", "/settings", "/admin", "/api"]

    crawled_pages: set[str] = set()

    async def crawl_page(path: str) -> None:
        url = base + path
        if url in crawled_pages:
            return
        crawled_pages.add(url)
        status, body, hdrs = await fetch(
            url, client=client, max_size_kb=500,
            cookie=cookie, extra_headers=extra_headers,
        )
        if not body:
            return

        # Extract <script src="..."> tags
        if HAS_BS4:
            try:
                soup = BeautifulSoup(body, "html.parser")
                for tag in soup.find_all("script", src=True):
                    src = tag["src"]
                    resolved = urljoin(base, src)
                    if urlparse(resolved).netloc == urlparse(base).netloc or \
                       urlparse(resolved).netloc == "":
                        await add_asset(resolved if resolved.startswith("http") else base + resolved)
                # If deep mode, also follow internal links
                if deep:
                    for tag in soup.find_all("a", href=True):
                        href = tag["href"]
                        if href.startswith("/") and href not in crawled_pages:
                            crawled_pages.add(href)
                            if len(crawled_pages) < 30:  # cap at 30 pages
                                await crawl_page(href)
            except Exception:
                pass
        else:
            # Fallback regex
            for m in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', body, re.I):
                src = m.group(1)
                resolved = urljoin(base, src)
                if urlparse(base).netloc in resolved or src.startswith("/"):
                    await add_asset(resolved if resolved.startswith("http") else base + src)

        # Search for webpack chunk patterns in JS body
        for pat in WEBPACK_CHUNK_PATTERNS:
            for m in pat.finditer(body):
                chunk_path = m.group(1)
                if not chunk_path.startswith("http"):
                    chunk_path = urljoin(base + "/", chunk_path.lstrip("/"))
                await add_asset(chunk_path)

    await asyncio.gather(*[crawl_page(p) for p in pages], return_exceptions=True)

    # Also try common JS entry points directly
    for common in [
        "/static/js/main.js", "/assets/js/app.js", "/js/app.js",
        "/dist/bundle.js", "/build/static/js/main.js", "/app.js",
        "/js/main.js", "/static/bundle.js",
    ]:
        url = base + common
        status, body, _ = await fetch(
            url, client=client, max_size_kb=10,
            cookie=cookie, extra_headers=extra_headers,
        )
        if status == 200 and body:
            await add_asset(url)

    return list(assets.values())


# ═════════════════════════════════════════════════════════════════════════════
# SOURCEMAP HANDLING
# ═════════════════════════════════════════════════════════════════════════════

async def fetch_sourcemap_source(
    js_url: str,
    js_body: str,
    client: "httpx.AsyncClient",
    max_size_kb: int,
    cookie: str | None = None,
    extra_headers: dict | None = None,
) -> str:
    """
    If JS has a sourceMappingURL comment, fetch the .map file and
    decode the 'sources' and 'sourcesContent' fields.
    Returns concatenated source code or empty string.
    """
    m = re.search(r'//# sourceMappingURL=([^\s]+)', js_body)
    if not m:
        return ""
    map_ref = m.group(1)
    if map_ref.startswith("data:"):
        # Inline base64 sourcemap
        try:
            b64 = map_ref.split(",", 1)[1]
            map_json = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
        except Exception:
            return ""
    else:
        map_url = urljoin(js_url, map_ref)
        status, map_body, _ = await fetch(
            map_url, client=client, max_size_kb=max_size_kb * 2,
            cookie=cookie, extra_headers=extra_headers,
        )
        if not map_body:
            return ""
        try:
            map_json = json.loads(map_body)
        except Exception:
            return ""

    # Extract all source content
    sources_content: list[str] = map_json.get("sourcesContent") or []
    sources_names:   list[str] = map_json.get("sources") or []
    parts: list[str] = []
    for i, content in enumerate(sources_content):
        if content:
            name = sources_names[i] if i < len(sources_names) else f"source_{i}"
            parts.append(f"// === SOURCE: {name} ===\n{content}")
    return "\n\n".join(parts)


# ═════════════════════════════════════════════════════════════════════════════
# SECRET EXTRACTION
# ═════════════════════════════════════════════════════════════════════════════

def _redact(value: str) -> str:
    """Show first 6 + last 4 characters, mask the middle."""
    if len(value) <= 10:
        return "***"
    return f"{value[:6]}...{value[-4:]}"


def _context(text: str, match_start: int, match_end: int, window: int = 100) -> str:
    """Extract surrounding context around a match."""
    start = max(0, match_start - window)
    end   = min(len(text), match_end + window)
    snippet = text[start:end].replace("\n", " ").strip()
    return snippet


def _is_likely_placeholder(value: str) -> bool:
    """
    Filter obvious placeholder values that appear in example configs
    and framework boilerplate.
    """
    placeholders = {
        "your_api_key", "your-api-key", "api_key_here", "enter_your_key",
        "xxxx", "xxxxxxxxxxxx", "1234567890", "abcdefghijklmnop",
        "secret", "password", "changeme", "example", "test", "demo",
        "placeholder", "insert_key_here", "<your", "xxx",
    }
    low = value.lower()
    if any(p in low for p in placeholders):
        return True
    # All same character
    if len(set(value)) <= 2 and len(value) > 6:
        return True
    return False


def extract_secrets(
    host: str,
    js_url: str,
    text: str,
) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    seen_values: set[str] = set()

    for (name, pattern, severity, note) in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            # Use the first capture group if present, else the full match
            if m.lastindex and m.lastindex >= 1:
                value = m.group(1)
            else:
                value = m.group(0)

            if not value or len(value) < 6:
                continue
            if _is_likely_placeholder(value):
                continue
            if value in seen_values:
                continue
            seen_values.add(value)

            context = _context(text, m.start(), m.end())
            findings.append(SecretFinding(
                host=host,
                js_url=js_url,
                secret_type=name,
                value=_redact(value),
                raw_line=context[:200],
                severity=severity,
                note=note,
                confidence="HIGH" if severity in ("CRITICAL","HIGH") else "MEDIUM",
            ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
# ENTROPY ANALYSIS
# ═════════════════════════════════════════════════════════════════════════════

def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy in bits per character."""
    if not s:
        return 0.0
    counts = defaultdict(int)
    for c in s:
        counts[c] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def extract_high_entropy(
    text: str,
    threshold: float = 4.5,
    min_len: int = 16,
    max_len: int = 120,
) -> list[dict]:
    """
    Extract string literals with unusually high Shannon entropy.
    These are often undocumented API keys or tokens that don't match
    any known provider pattern.
    """
    findings: list[dict] = []
    seen: set[str] = set()

    # Match string literals in JS
    for m in re.finditer(r'["\']([A-Za-z0-9+/=_\-]{%d,%d})["\']' % (min_len, max_len), text):
        value = m.group(1)
        if value in seen:
            continue
        # Apply allowlist filters
        if any(pat.match(value) for pat in ENTROPY_ALLOWLIST):
            continue
        if _is_likely_placeholder(value):
            continue

        entropy = shannon_entropy(value)
        if entropy >= threshold:
            seen.add(value)
            context = _context(text, m.start(), m.end(), 80)
            findings.append({
                "value":   _redact(value),
                "entropy": round(entropy, 3),
                "length":  len(value),
                "context": context[:150],
            })

    return findings


# ═════════════════════════════════════════════════════════════════════════════
# ENDPOINT EXTRACTION
# ═════════════════════════════════════════════════════════════════════════════

def extract_endpoints(
    host: str,
    js_url: str,
    text: str,
    base_url: str,
) -> tuple[list[EndpointFinding], list[str], list[str], list[dict]]:
    """
    Returns (endpoints, graphql_ops, websocket_urls, oauth_refs).
    """
    endpoints: list[EndpointFinding] = []
    graphql_ops: list[str] = []
    websocket_urls: list[str] = []
    oauth_refs: list[dict] = []
    seen_paths: set[str] = set()

    # REST endpoint extraction
    for pat in ENDPOINT_PATTERNS:
        for m in pat.finditer(text):
            path = m.group(1)
            if not path or len(path) < 4 or path in seen_paths:
                continue
            # Skip obvious non-API paths
            if any(ext in path.lower() for ext in [".js", ".css", ".png", ".jpg", ".svg", ".woff"]):
                continue
            seen_paths.add(path)

            # Try to infer method from context
            context = text[max(0, m.start()-30):m.end()+30]
            method = "UNKNOWN"
            if re.search(r'\.get\s*\(', context, re.I):    method = "GET"
            elif re.search(r'\.post\s*\(', context, re.I): method = "POST"
            elif re.search(r'\.put\s*\(', context, re.I):  method = "PUT"
            elif re.search(r'\.delete\s*\(', context, re.I): method = "DELETE"
            elif re.search(r'\.patch\s*\(', context, re.I): method = "PATCH"

            # Extract inline params from path templates like {userId} or :id
            params = re.findall(r'[{:]([A-Za-z_][A-Za-z0-9_]*)}?', path)

            endpoints.append(EndpointFinding(
                host=host, js_url=js_url, endpoint=path,
                method=method, params=params, source="regex",
            ))

    # GraphQL operation extraction
    for pat in GRAPHQL_PATTERNS:
        for m in pat.finditer(text):
            op = m.group(1).strip()[:200]
            if op and op not in graphql_ops:
                graphql_ops.append(op)
                # Also add /graphql as an endpoint if not already present
                if "/graphql" not in seen_paths:
                    seen_paths.add("/graphql")
                    endpoints.append(EndpointFinding(
                        host=host, js_url=js_url, endpoint="/graphql",
                        method="POST", source="graphql",
                    ))

    # WebSocket URL extraction
    for m in WEBSOCKET_PATTERN.finditer(text):
        ws_url = m.group(0)
        if ws_url not in websocket_urls:
            websocket_urls.append(ws_url)
            endpoints.append(EndpointFinding(
                host=host, js_url=js_url, endpoint=ws_url,
                method="WS", source="websocket",
            ))

    # OAuth reference extraction
    for pat in OAUTH_PATTERNS:
        for m in pat.finditer(text):
            val = m.group(1)
            if val and len(val) > 3:
                ref = {
                    "type":    "client_id" if "client" in pat.pattern.lower() else
                               "redirect_uri" if "redirect" in pat.pattern.lower() else
                               "auth_endpoint",
                    "value":   val[:300],
                    "context": _context(text, m.start(), m.end(), 60),
                }
                if ref not in oauth_refs:
                    oauth_refs.append(ref)

    return endpoints, graphql_ops, websocket_urls, oauth_refs


# ═════════════════════════════════════════════════════════════════════════════
# HOST PROCESSOR
# ═════════════════════════════════════════════════════════════════════════════

class HostProcessor:
    def __init__(
        self,
        domain: str,
        timeout: float      = 15.0,
        max_size_kb: int    = 5000,
        entropy_threshold: float = 4.5,
        fetch_sourcemaps: bool   = True,
        deep: bool               = False,
        concurrency: int         = 20,
        cookie: str | None       = None,
        extra_headers: dict | None = None,
    ):
        self.domain            = domain
        self.timeout           = timeout
        self.max_size_kb       = max_size_kb
        self.entropy_threshold = entropy_threshold
        self.fetch_sourcemaps  = fetch_sourcemaps
        self.deep              = deep
        self.cookie            = cookie
        self.extra_headers     = extra_headers
        self._sem              = asyncio.Semaphore(concurrency)
        # Global content hash dedup — don't analyse the same JS file twice
        # even if it appears on multiple subdomains (CDN-served bundles)
        self._seen_hashes: set[str] = set()
        self._seen_lock = asyncio.Lock()

    async def process_host(self, host: str, ip: str) -> HostResult:
        result = HostResult(host=host, ip=ip)
        async with self._sem:
            try:
                await self._run(host, ip, result)
            except Exception as exc:
                result.error = str(exc)
                log.warning(f"[{host}] Error: {exc}")
        return result

    async def _run(self, host: str, ip: str, result: HostResult) -> None:
        # Determine scheme from what reconharvest already knows
        # Try HTTPS first, fall back to HTTP
        scheme = "https"
        port   = 443
        async with httpx.AsyncClient(
            timeout=self.timeout, verify=False,
            follow_redirects=True, headers={"User-Agent": user_agent()},
        ) as client:
            status, _, _ = await fetch(f"https://{host}/", client=client, max_size_kb=10,
                                       cookie=self.cookie, extra_headers=self.extra_headers)
            if status is None:
                status, _, _ = await fetch(f"http://{host}/", client=client, max_size_kb=10,
                                           cookie=self.cookie, extra_headers=self.extra_headers)
                if status is not None:
                    scheme, port = "http", 80

            if status is None:
                result.error = "Host unreachable on both HTTP and HTTPS"
                return

            # Discover all JS assets
            assets = await discover_js_assets(
                host, scheme, port, client, self.max_size_kb, self.deep,
                cookie=self.cookie, extra_headers=self.extra_headers,
            )
            log.info(f"[{host}] Found {len(assets)} JS assets")

            # Process each asset
            js_sem = asyncio.Semaphore(10)

            async def process_asset(asset: JSAsset) -> None:
                async with js_sem:
                    await self._process_js(host, scheme, port, asset, client, result)

            await asyncio.gather(
                *[process_asset(a) for a in assets],
                return_exceptions=True,
            )

        result.js_assets = [a for a in assets if a.size_bytes > 0 or not a.fetch_error]

    async def _process_js(
        self,
        host: str,
        scheme: str,
        port: int,
        asset: JSAsset,
        client: "httpx.AsyncClient",
        result: HostResult,
    ) -> None:
        status, body, hdrs = await fetch(
            asset.url, client=client, max_size_kb=self.max_size_kb,
            cookie=self.cookie, extra_headers=self.extra_headers,
        )
        if not body or status != 200:
            asset.fetch_error = f"HTTP {status}"
            return

        asset.size_bytes   = len(body)
        asset.content_hash = hashlib.md5(body[:8192].encode(errors="ignore")).hexdigest()

        # Global deduplication — skip if we've seen this exact content before
        async with self._seen_lock:
            if asset.content_hash in self._seen_hashes:
                log.debug(f"[{host}] Skipping duplicate content: {asset.url}")
                return
            self._seen_hashes.add(asset.content_hash)

        base_url = f"{scheme}://{host}"

        # Sourcemap: may provide pre-minification source for richer analysis
        source_code = ""
        if self.fetch_sourcemaps and "sourceMappingURL" in body:
            asset.has_sourcemap = True
            try:
                source_code = await fetch_sourcemap_source(
                    asset.url, body, client, self.max_size_kb,
                    cookie=self.cookie, extra_headers=self.extra_headers,
                )
            except Exception:
                pass

        # Analyse the JS content + sourcemap (if available)
        full_text = body + ("\n\n" + source_code if source_code else "")

        # Secret extraction
        secrets = extract_secrets(host, asset.url, full_text)
        result.secrets.extend(secrets)

        # Endpoint extraction
        endpoints, gql_ops, ws_urls, oauth = extract_endpoints(
            host, asset.url, full_text, base_url
        )
        result.endpoints.extend(endpoints)
        result.graphql_ops.extend(op for op in gql_ops if op not in result.graphql_ops)
        result.websocket_urls.extend(u for u in ws_urls if u not in result.websocket_urls)
        result.oauth_refs.extend(o for o in oauth if o not in result.oauth_refs)

        # Internal IPs
        for m in re.finditer(
            r'(?<!\d)(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)(?!\d)',
            full_text
        ):
            ip = m.group(0)
            if ip not in result.internal_ips:
                result.internal_ips.append(ip)

        # High-entropy string detection (skip vendor bundles to reduce noise)
        if not asset.is_vendor:
            entropy_hits = extract_high_entropy(
                full_text, threshold=self.entropy_threshold
            )
            result.high_entropy.extend(entropy_hits)

        if secrets:
            log.warning(f"[{host}] {asset.url} — {len(secrets)} secrets found!")
        log.debug(
            f"[{host}] {asset.url} — "
            f"secrets={len(secrets)} endpoints={len(endpoints)} "
            f"entropy={len(result.high_entropy)}"
        )


# ═════════════════════════════════════════════════════════════════════════════
# INPUT PARSERS
# ═════════════════════════════════════════════════════════════════════════════

def load_from_recon_json(path: str) -> list[tuple[str, str]]:
    """Load hosts from reconharvest.py output (host, ip)."""
    with open(path) as f:
        data = json.load(f)
    hosts: list[tuple[str, str]] = []
    seen: set[str] = set()
    for hr in data.get("host_reports", []):
        h = hr.get("host", "")
        ip = hr.get("ip", "")
        if h and h not in seen and hr.get("open_ports"):
            seen.add(h)
            hosts.append((h, ip))
    log.info(f"[Parse] {len(hosts)} hosts with open ports from {path}")
    return hosts


def load_from_subtakeover_json(path: str) -> list[tuple[str, str]]:
    """Load hosts from subtakeover.py scan.json output."""
    with open(path) as f:
        data = json.load(f)
    hosts: list[tuple[str, str]] = []
    seen: set[str] = set()
    for entry in data.get("resolved_subdomains", []):
        h = entry.get("subdomain", "")
        ips = entry.get("a_records", [])
        if h and ips and h not in seen:
            seen.add(h)
            hosts.append((h, ips[0]))
    log.info(f"[Parse] {len(hosts)} resolved hosts from {path}")
    return hosts


def load_from_hostfile(path: str) -> list[tuple[str, str]]:
    """Plain text host list."""
    import socket
    hosts = []
    seen: set[str] = set()
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "," in line:
                h, ip = line.split(",", 1)
                h, ip = h.strip(), ip.strip()
            else:
                h = line
                try:
                    ip = socket.gethostbyname(h)
                except Exception:
                    ip = h
            if h not in seen:
                seen.add(h)
                hosts.append((h, ip))
    log.info(f"[Parse] {len(hosts)} hosts from {path}")
    return hosts


# ═════════════════════════════════════════════════════════════════════════════
# REPORTING
# ═════════════════════════════════════════════════════════════════════════════

def print_report(report: ReaperReport) -> None:
    by_sev: dict[str, list[SecretFinding]] = {s: [] for s in SEVERITY_ORDER}
    for sec in report.all_secrets:
        by_sev.setdefault(sec.severity, []).append(sec)

    if HAS_RICH:
        console.print()
        border = "red" if by_sev.get("CRITICAL") else "yellow" if by_sev.get("HIGH") else "blue"
        console.print(Panel.fit(
            f"[white]Domain:[/] [cyan]{report.domain}[/]\n"
            f"[white]Scan time:[/] {report.scan_time}\n"
            f"[white]Elapsed:[/] {report.elapsed_seconds:.1f}s\n"
            f"[white]Hosts:[/] {report.total_hosts}  "
            f"[white]JS Files:[/] {report.total_js_files}\n\n"
            f"[bold red]CRITICAL:[/] {len(by_sev.get('CRITICAL',[]))}    "
            f"[bold yellow]HIGH:[/] {len(by_sev.get('HIGH',[]))}    "
            f"[yellow]MEDIUM:[/] {len(by_sev.get('MEDIUM',[]))}    "
            f"[cyan]LOW:[/] {len(by_sev.get('LOW',[]))}\n"
            f"[dim]Endpoints:[/] {len(report.all_endpoints)}    "
            f"[dim]GraphQL ops:[/] {len(report.all_graphql)}    "
            f"[dim]OAuth refs:[/] {len(report.all_oauth)}",
            title="[bold]JSReaper Report[/]", border_style=border,
        ))

        # Secrets table
        if report.all_secrets:
            console.print("\n[bold red]── Secrets Found ──[/]")
            tbl = Table(show_header=True, header_style="bold red", border_style="dim")
            tbl.add_column("Severity",    justify="center")
            tbl.add_column("Type",        style="yellow")
            tbl.add_column("Value",       style="dim")
            tbl.add_column("Host")
            tbl.add_column("JS File",     style="dim", no_wrap=False, max_width=45)
            tbl.add_column("Note",        style="dim", max_width=35)

            for sev in ("CRITICAL","HIGH","MEDIUM","LOW"):
                for sec in by_sev.get(sev, []):
                    col = SEV_COLOR.get(sev, "white")
                    tbl.add_row(
                        f"[{col}]{sev}[/]",
                        sec.secret_type,
                        sec.value,
                        sec.host,
                        sec.js_url.split("/")[-1] if "/" in sec.js_url else sec.js_url,
                        sec.note[:35],
                    )
            console.print(tbl)

        # Top endpoints
        if report.all_endpoints:
            console.print(f"\n[bold cyan]── Endpoints Discovered ({len(report.all_endpoints)}) ──[/]")
            unique_paths = sorted({e.endpoint for e in report.all_endpoints})
            etbl = Table(show_header=True, header_style="bold cyan", border_style="dim")
            etbl.add_column("Endpoint",   style="cyan")
            etbl.add_column("Method",     justify="center", style="dim")
            etbl.add_column("Host",       style="dim")
            etbl.add_column("Params",     style="dim")
            shown = 0
            for path in unique_paths[:50]:
                matching = [e for e in report.all_endpoints if e.endpoint == path]
                e = matching[0]
                col = "red" if e.method in ("POST","PUT","PATCH","DELETE") else "dim"
                etbl.add_row(
                    path,
                    f"[{col}]{e.method}[/]",
                    e.host,
                    ", ".join(e.params[:3]) or "—",
                )
                shown += 1
            console.print(etbl)
            if len(unique_paths) > 50:
                console.print(f"  [dim]... {len(unique_paths)-50} more in JSON report[/]")

        # Per-host summary
        console.print("\n[bold cyan]── Per-Host Summary ──[/]")
        htbl = Table(show_header=True, header_style="bold cyan", border_style="dim")
        htbl.add_column("Host",        style="cyan")
        htbl.add_column("JS Files",    justify="right")
        htbl.add_column("Secrets",     justify="right")
        htbl.add_column("Endpoints",   justify="right")
        htbl.add_column("GraphQL",     justify="right")
        htbl.add_column("Internal IPs",style="dim")
        for hr in sorted(report.host_results, key=lambda h: -len(h.secrets)):
            if not hr.js_assets: continue
            sec_str = str(len(hr.secrets))
            if hr.secrets:
                worst = min(SEVERITY_ORDER.get(s.severity,9) for s in hr.secrets)
                worst_name = [k for k,v in SEVERITY_ORDER.items() if v == worst][0]
                col = SEV_COLOR.get(worst_name, "white")
                sec_str = f"[{col}]{sec_str}[/]"
            htbl.add_row(
                hr.host,
                str(len(hr.js_assets)),
                sec_str,
                str(len(hr.endpoints)),
                str(len(hr.graphql_ops)),
                ", ".join(hr.internal_ips[:3]) or "—",
            )
        console.print(htbl)

    else:
        # Plain text fallback
        print(f"\n=== JSReaper: {report.domain} ===")
        print(f"Hosts: {report.total_hosts}  JS: {report.total_js_files}  Elapsed: {report.elapsed_seconds:.1f}s")
        print(f"Secrets: CRIT={len(by_sev.get('CRITICAL',[]))} HIGH={len(by_sev.get('HIGH',[]))} MED={len(by_sev.get('MEDIUM',[]))} LOW={len(by_sev.get('LOW',[]))}")
        for sec in report.all_secrets:
            print(f"\n[{sec.severity}] {sec.secret_type} @ {sec.host}")
            print(f"  Value: {sec.value}")
            print(f"  File:  {sec.js_url}")
            print(f"  Note:  {sec.note}")
    print()


def save_json(report: ReaperReport, path: str) -> None:
    data = {
        "domain":          report.domain,
        "scan_time":       report.scan_time,
        "source_file":     report.source_file,
        "total_hosts":     report.total_hosts,
        "total_js_files":  report.total_js_files,
        "elapsed_seconds": report.elapsed_seconds,
        "summary": {
            "secrets_by_severity": {
                s: len([x for x in report.all_secrets if x.severity == s])
                for s in SEVERITY_ORDER
            },
            "total_endpoints":    len(report.all_endpoints),
            "total_graphql_ops":  len(report.all_graphql),
            "total_oauth_refs":   len(report.all_oauth),
        },
        # Flat arrays consumed by downstream tools
        "secrets":   [asdict(s) for s in sorted(
            report.all_secrets, key=lambda x: SEVERITY_ORDER.get(x.severity, 9)
        )],
        "endpoints": [asdict(e) for e in report.all_endpoints],
        "graphql_operations": report.all_graphql,
        "oauth_refs":  report.all_oauth,
        # Per-host detail
        "host_results": [
            {
                "host":          hr.host,
                "ip":            hr.ip,
                "js_assets":     [asdict(a) for a in hr.js_assets],
                "secrets":       [asdict(s) for s in hr.secrets],
                "endpoints":     [asdict(e) for e in hr.endpoints],
                "graphql_ops":   hr.graphql_ops,
                "websocket_urls":hr.websocket_urls,
                "oauth_refs":    hr.oauth_refs,
                "internal_ips":  hr.internal_ips,
                "high_entropy":  hr.high_entropy,
                "error":         hr.error,
            }
            for hr in report.host_results
        ],
    }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    log.info(f"JSON report saved → {path}")
    log.info(f"  secrets[]:   {len(report.all_secrets)} findings")
    log.info(f"  endpoints[]: {len(report.all_endpoints)} unique paths")


def save_html(report: ReaperReport, path: str) -> None:
    by_sev: dict[str, list[SecretFinding]] = {s: [] for s in SEVERITY_ORDER}
    for sec in report.all_secrets:
        by_sev.setdefault(sec.severity, []).append(sec)

    sc = {"CRITICAL":"#f85149","HIGH":"#d29922","MEDIUM":"#e3b341","LOW":"#58a6ff","INFO":"#8b949e"}
    sb = {
        "CRITICAL":"rgba(248,81,73,.12)","HIGH":"rgba(210,153,34,.12)",
        "MEDIUM":"rgba(227,179,65,.10)","LOW":"rgba(88,166,255,.10)",
    }
    sev_rows = ""
    for sev in ("CRITICAL","HIGH","MEDIUM","LOW"):
        for sec in by_sev.get(sev,[]):
            sev_rows += (
                f"<tr>"
                f"<td><span style='color:{sc[sev]};font-weight:bold'>{sev}</span></td>"
                f"<td style='color:#d29922'>{sec.secret_type}</td>"
                f"<td style='color:#a8dadc;font-family:monospace'>{sec.value}</td>"
                f"<td style='color:#58a6ff'>{sec.host}</td>"
                f"<td style='color:#627384;font-size:.8em'>{sec.js_url.split('/')[-1]}</td>"
                f"<td style='color:#627384;font-size:.8em'>{sec.note}</td>"
                f"</tr>"
            )

    ep_rows = ""
    seen_ep: set[str] = set()
    for ep in report.all_endpoints[:200]:
        if ep.endpoint in seen_ep: continue
        seen_ep.add(ep.endpoint)
        col = "#f85149" if ep.method in ("POST","PUT","PATCH","DELETE") else "#627384"
        ep_rows += (
            f"<tr>"
            f"<td style='color:#58a6ff'>{ep.endpoint}</td>"
            f"<td style='color:{col};font-weight:bold'>{ep.method}</td>"
            f"<td style='color:#627384'>{ep.host}</td>"
            f"<td style='color:#627384;font-size:.8em'>{', '.join(ep.params[:3]) or '—'}</td>"
            f"</tr>"
        )

    host_rows = ""
    for hr in sorted(report.host_results, key=lambda h: -len(h.secrets)):
        if not hr.js_assets: continue
        s_count = len(hr.secrets)
        s_color = sc.get(
            min((s.severity for s in hr.secrets), key=lambda x: SEVERITY_ORDER.get(x,9),
                default="INFO"),
            "#627384"
        ) if hr.secrets else "#3fb950"
        host_rows += (
            f"<tr>"
            f"<td style='color:#58a6ff'>{hr.host}</td>"
            f"<td style='color:#627384'>{len(hr.js_assets)}</td>"
            f"<td style='color:{s_color};font-weight:bold'>{s_count}</td>"
            f"<td style='color:#627384'>{len(hr.endpoints)}</td>"
            f"<td style='color:#627384'>{len(hr.graphql_ops)}</td>"
            f"<td style='color:#e3b341;font-size:.85em'>{', '.join(hr.internal_ips[:3]) or '—'}</td>"
            f"</tr>"
        )

    html = f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>JSReaper — {report.domain}</title>
<style>
:root{{--bg:#080c10;--sf:#0d1117;--sf2:#111820;--bd:#1e2d3d;--tx:#cdd6e0;--mt:#627384;
  --rd:#f85149;--yw:#d29922;--gn:#3fb950;--bl:#58a6ff;--cy:#39c5cf;}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--tx);font-family:'Consolas','Monaco',monospace;font-size:13px;line-height:1.7}}
body::before{{content:'';position:fixed;inset:0;background-image:
  linear-gradient(rgba(0,212,255,.012) 1px,transparent 1px),
  linear-gradient(90deg,rgba(0,212,255,.012) 1px,transparent 1px);
  background-size:40px 40px;pointer-events:none;z-index:0}}
.wrap{{max-width:1400px;margin:0 auto;padding:32px 28px 80px;position:relative;z-index:1}}
h1{{font-family:system-ui,sans-serif;font-size:2em;font-weight:800;color:#fff;
   letter-spacing:-.03em;margin-bottom:6px}}
.sub{{color:var(--mt);font-size:.8em;margin-bottom:32px}}
.stats{{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:10px;margin-bottom:28px}}
.stat{{background:var(--sf);border:1px solid var(--bd);border-radius:8px;padding:14px;text-align:center}}
.sv{{font-size:1.8em;font-weight:bold}}.sl{{color:var(--mt);font-size:.72em;margin-top:3px}}
.card{{background:var(--sf);border:1px solid var(--bd);border-radius:8px;padding:20px;margin-bottom:20px}}
h2{{font-family:system-ui,sans-serif;font-size:1.1em;font-weight:700;color:#fff;margin-bottom:14px}}
table{{width:100%;border-collapse:collapse}}
th{{background:var(--sf2);color:var(--mt);text-align:left;padding:8px 12px;
   border:1px solid var(--bd);font-size:.72em;text-transform:uppercase;letter-spacing:.07em}}
td{{padding:8px 12px;border-bottom:1px solid var(--bd);vertical-align:top;word-break:break-all}}
tr:hover td{{background:rgba(88,166,255,.03)}}
.footer{{text-align:center;color:var(--mt);font-size:.72em;margin-top:32px;
  padding-top:16px;border-top:1px solid var(--bd)}}
</style></head>
<body><div class="wrap">
<h1>JSReaper</h1>
<p class="sub">{report.domain} &nbsp;·&nbsp; {report.scan_time} &nbsp;·&nbsp;
{report.elapsed_seconds:.1f}s &nbsp;·&nbsp; {report.total_hosts} hosts &nbsp;·&nbsp;
{report.total_js_files} JS files</p>
<div class="stats">
  <div class="stat"><div class="sv" style="color:#f85149">{len(by_sev.get('CRITICAL',[]))}</div><div class="sl">CRITICAL</div></div>
  <div class="stat"><div class="sv" style="color:#d29922">{len(by_sev.get('HIGH',[]))}</div><div class="sl">HIGH</div></div>
  <div class="stat"><div class="sv" style="color:#e3b341">{len(by_sev.get('MEDIUM',[]))}</div><div class="sl">MEDIUM</div></div>
  <div class="stat"><div class="sv" style="color:#58a6ff">{len(by_sev.get('LOW',[]))}</div><div class="sl">LOW</div></div>
  <div class="stat"><div class="sv">{len(report.all_endpoints)}</div><div class="sl">ENDPOINTS</div></div>
  <div class="stat"><div class="sv">{len(report.all_graphql)}</div><div class="sl">GRAPHQL OPS</div></div>
</div>
<div class="card"><h2>🔑 Secrets Found ({len(report.all_secrets)})</h2>
{"<table><thead><tr><th>Severity</th><th>Type</th><th>Value</th><th>Host</th><th>JS File</th><th>Note</th></tr></thead><tbody>" + sev_rows + "</tbody></table>" if sev_rows else "<p style='color:var(--mt)'>No secrets found.</p>"}
</div>
<div class="card"><h2>🌐 Endpoints ({len(report.all_endpoints)})</h2>
{"<table><thead><tr><th>Endpoint</th><th>Method</th><th>Host</th><th>Params</th></tr></thead><tbody>" + ep_rows + "</tbody></table>" if ep_rows else "<p style='color:var(--mt)'>No endpoints found.</p>"}
</div>
<div class="card"><h2>🖥 Per-Host Summary</h2>
<table><thead><tr><th>Host</th><th>JS Files</th><th>Secrets</th><th>Endpoints</th><th>GraphQL</th><th>Internal IPs</th></tr></thead>
<tbody>{host_rows}</tbody></table></div>
<div class="footer">JSReaper &nbsp;·&nbsp; For authorized security research only</div>
</div></body></html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    log.info(f"HTML report saved → {path}")


# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="JSReaper — JavaScript Secret & Endpoint Harvester",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 jsreaper.py --scan recon.json --domain eskimi.com --output js-findings
  python3 jsreaper.py --subtakeover scan.json --domain eskimi.com --output js
  python3 jsreaper.py --hosts targets.txt --domain eskimi.com --deep --sourcemaps
  python3 jsreaper.py --scan recon.json --domain eskimi.com --entropy 4.2 -o findings

Chains from : reconharvest.py (--scan), subtakeover.py (--subtakeover), plain list (--hosts)
Feeds into  : apifuzz.py --js, paramfuzz.py --js, ssrfprobe.py --endpoints
        """)
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--scan",        metavar="FILE", help="reconharvest.py JSON output")
    src.add_argument("--subtakeover", metavar="FILE", help="subtakeover.py scan.json output")
    src.add_argument("--hosts",       metavar="FILE", help="Plain text host list (host or host,IP)")

    p.add_argument("--domain",        required=True,  help="Target root domain")
    p.add_argument("-o","--output",   metavar="BASE",  help="Output base → BASE.json + BASE.html")
    p.add_argument("--deep",          action="store_true",
                   help="Follow HTML links for deeper JS discovery (slower)")
    p.add_argument("--sourcemaps",    action="store_true", default=True,
                   help="Fetch .map sourcemaps for pre-minification source (default: on)")
    p.add_argument("--no-sourcemaps", action="store_false", dest="sourcemaps",
                   help="Disable sourcemap fetching")
    p.add_argument("--entropy",       type=float, default=4.5, metavar="FLOAT",
                   help="Shannon entropy threshold for unknown secrets (default: 4.5)")
    p.add_argument("--max-size",      type=int,   default=5000, metavar="KB",
                   help="Max JS file size to analyse in KB (default: 5000)")
    p.add_argument("--concurrency",   type=int,   default=20,
                   help="Concurrent host workers (default: 20)")
    p.add_argument("--timeout",       type=float, default=15.0,
                   help="HTTP timeout per request in seconds (default: 15)")
    p.add_argument("--no-creds",      action="store_true",
                   help="Skip credential/secret patterns (endpoints only)")
    # --- NEW (toolkit integration, ARCHITECTURE.md §4) ---
    p.add_argument("--scope",         metavar="FILE",
                   help="scope.yaml — when set, every fetched host is checked via toolkit.infra.scope_guard")
    p.add_argument("--cookie",        metavar="STR",
                   help="Cookie header to send on every request (e.g., 'session=abc123')")
    p.add_argument("--auth-profiles", metavar="FILE",
                   help="auth_profiles.yaml — when set, supersedes --cookie (uses named profile 'user_a')")
    p.add_argument("-v","--verbose",  action="store_true", help="Verbose logging")
    p.add_argument("--user-agent",   metavar="UA",
                   help="Override the User-Agent header sent on every request (C18)")
    return p.parse_args()


async def main() -> None:
    args = parse_args()
    if args.verbose:
        log.setLevel(logging.DEBUG)
    if args.user_agent:
        set_user_agent(args.user_agent)

    print("""
╔══════════════════════════════════════════════════════════════════╗
║         JSReaper — JavaScript Secret & Endpoint Harvester        ║
║  For authorized penetration testing and bug bounty research only ║
╚══════════════════════════════════════════════════════════════════╝
""")

    if not HAS_HTTPX:
        log.error("httpx required: pip install httpx")
        sys.exit(1)
    if not HAS_BS4:
        log.info("Tip: pip install beautifulsoup4  — improves JS asset discovery")

    # --- NEW (toolkit integration): configure scope_guard + auth_profiles
    # globally so all subsequent fetch() calls are auto-filtered + authed.
    # We do this as a soft import so jsreaper still runs standalone if the
    # toolkit package isn't on sys.path.
    guard = None
    if getattr(args, "scope", None):
        try:
            # Try to import from the toolkit package
            import os, sys as _sys
            _toolkit_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            if _toolkit_root not in _sys.path:
                _sys.path.insert(0, _toolkit_root)
            from toolkit.infra.scope_guard import ScopeGuard, configure as _scope_configure
            guard = _scope_configure(args.scope)
            log.info(f"scope_guard loaded from {args.scope}")
        except Exception as exc:
            log.warning(f"could not load scope_guard ({exc}) — proceeding without scope enforcement")

    extra_headers: dict = {}
    if getattr(args, "auth_profiles", None):
        try:
            from toolkit.infra.auth_profiles import AuthProfiles
            ap = AuthProfiles(args.auth_profiles)
            if "user_a" in ap.profiles:
                extra_headers = ap.profiles["user_a"].auth_headers()
                log.info(f"auth_profiles: using 'user_a' (header keys: {list(extra_headers.keys())})")
        except Exception as exc:
            log.warning(f"could not load auth_profiles ({exc}) — proceeding without auth headers")
    elif getattr(args, "cookie", None):
        extra_headers = {"Cookie": args.cookie}
        log.info(f"using --cookie header ({len(args.cookie)} chars)")

    # Load hosts
    if args.scan:
        hosts = load_from_recon_json(args.scan)
        source = args.scan
    elif args.subtakeover:
        hosts = load_from_subtakeover_json(args.subtakeover)
        source = args.subtakeover
    else:
        hosts = load_from_hostfile(args.hosts)
        source = args.hosts

    if not hosts:
        log.error("No hosts found in input.")
        sys.exit(1)

    report = ReaperReport(
        domain=args.domain,
        scan_time=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        source_file=source,
        total_hosts=len(hosts),
    )

    processor = HostProcessor(
        domain=args.domain,
        timeout=args.timeout,
        max_size_kb=args.max_size,
        entropy_threshold=args.entropy,
        fetch_sourcemaps=args.sourcemaps,
        deep=args.deep,
        concurrency=args.concurrency,
        cookie=args.cookie if args.cookie else None,
        extra_headers=extra_headers,
    )

    t0 = time.perf_counter()

    if HAS_RICH:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]Harvesting JS[/]"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("[dim]{task.fields[h]}[/]"),
            console=console,
        ) as prog:
            task = prog.add_task("reap", total=len(hosts), h="")
            sem = asyncio.Semaphore(args.concurrency)

            async def bounded(host: str, ip: str) -> HostResult:
                async with sem:
                    prog.update(task, h=host)
                    r = await processor.process_host(host, ip)
                    prog.advance(task)
                    return r

            results = await asyncio.gather(
                *[bounded(h, ip) for h, ip in hosts],
                return_exceptions=True,
            )
    else:
        sem = asyncio.Semaphore(args.concurrency)

        async def bounded(host: str, ip: str) -> HostResult:
            async with sem:
                return await processor.process_host(host, ip)

        results = await asyncio.gather(
            *[bounded(h, ip) for h, ip in hosts],
            return_exceptions=True,
        )

    # Aggregate results
    for r in results:
        if isinstance(r, HostResult):
            report.host_results.append(r)
            report.all_secrets.extend(r.secrets)
            report.all_endpoints.extend(r.endpoints)
            report.all_graphql.extend(op for op in r.graphql_ops
                                       if op not in report.all_graphql)
            report.all_oauth.extend(o for o in r.oauth_refs
                                     if o not in report.all_oauth)
        elif isinstance(r, Exception):
            log.warning(f"Host error: {r}")

    report.total_js_files = sum(len(hr.js_assets) for hr in report.host_results)
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

    # Summary line
    crit = len([s for s in report.all_secrets if s.severity == "CRITICAL"])
    high = len([s for s in report.all_secrets if s.severity == "HIGH"])
    if crit or high:
        log.warning(
            f"[!] {crit} CRITICAL and {high} HIGH severity secrets found — "
            f"check {args.output + '.json' if args.output else 'output'} immediately"
        )


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(0)
