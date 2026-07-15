#!/usr/bin/env python3
"""
headeraudit.py — Security Header & CORS Misconfiguration Analyzer
==================================================================
Author  : RareKez / security research tooling
License : MIT (for authorized use only)

Chains from : subtakeover.py (--subtakeover), reconharvest.py (--scan),
              or plain host list (--hosts)
Feeds into  : Bug bounty reports (standalone findings)

Pipeline:
  1. Probe every live host for all 10 modern security headers
  2. Score header quality beyond simple presence/absence
     (e.g. CSP with unsafe-inline = weaker than CSP without)
  3. Test 8 CORS attack patterns per host / endpoint
  4. Map CORS findings to actual exploitability
     (CORS + ACAC:true + cookies = account takeover)
  5. Audit every Set-Cookie header for Secure/HttpOnly/SameSite
  6. Generate PoC HTML for exploitable CORS findings
  7. Output JSON (feeds downstream tools) + HTML report

Usage:
  python3 headeraudit.py --scan recon-report-v2.json --domain eskimi.com --output headers
  python3 headeraudit.py --subtakeover scan.json --domain eskimi.com --output headers
  python3 headeraudit.py --hosts targets.txt --domain eskimi.com --output headers
  python3 headeraudit.py --scan recon-report-v2.json --domain eskimi.com --cors-deep

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
from dataclasses import dataclass, field, asdict
from typing import Any
from urllib.parse import urlparse

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
log = logging.getLogger("headeraudit")
for _n in ("httpx", "httpcore"):
    logging.getLogger(_n).setLevel(logging.WARNING)


# ═════════════════════════════════════════════════════════════════════════════
# SECURITY HEADER DEFINITIONS
# Each header: name, severity_if_missing, quality_checks[], docs_url
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class HeaderRule:
    name: str                      # canonical lowercase header name
    display: str                   # human-readable name
    severity_missing: str          # severity when absent
    severity_weak: str             # severity when present but misconfigured
    description: str               # what it protects against
    recommendation: str            # remediation
    required_on: str               # "all" | "authenticated" | "html_only"
    cvss_missing: str = ""


HEADER_RULES: list[HeaderRule] = [
    HeaderRule(
        name="content-security-policy",
        display="Content-Security-Policy",
        severity_missing="MEDIUM",
        severity_weak="LOW",
        description=(
            "CSP restricts which resources (scripts, styles, frames, etc.) the browser "
            "may load. Absence means any XSS payload can load arbitrary scripts."
        ),
        recommendation=(
            "Implement a strict CSP: "
            "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
            "base-uri 'self'; form-action 'self'."
        ),
        required_on="html_only",
        cvss_missing="5.4 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)",
    ),
    HeaderRule(
        name="strict-transport-security",
        display="Strict-Transport-Security",
        severity_missing="MEDIUM",
        severity_weak="LOW",
        description=(
            "HSTS forces all future requests to use HTTPS. Without it, "
            "a downgrade attack can intercept traffic even if the site supports HTTPS."
        ),
        recommendation=(
            "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        ),
        required_on="all",
        cvss_missing="5.9 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N)",
    ),
    HeaderRule(
        name="x-frame-options",
        display="X-Frame-Options",
        severity_missing="MEDIUM",
        severity_weak="LOW",
        description=(
            "Prevents the page from being embedded in iframes. Absence enables "
            "clickjacking attacks where the page is overlaid on an attacker-controlled site."
        ),
        recommendation=(
            "X-Frame-Options: DENY  (or use CSP frame-ancestors 'none' instead, "
            "which is more flexible and supersedes this header in modern browsers)."
        ),
        required_on="html_only",
        cvss_missing="6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)",
    ),
    HeaderRule(
        name="x-content-type-options",
        display="X-Content-Type-Options",
        severity_missing="LOW",
        severity_weak="LOW",
        description=(
            "nosniff prevents browsers from MIME-sniffing a response away from the "
            "declared Content-Type. Absence can allow content injection via "
            "MIME confusion attacks."
        ),
        recommendation="X-Content-Type-Options: nosniff",
        required_on="all",
    ),
    HeaderRule(
        name="referrer-policy",
        display="Referrer-Policy",
        severity_missing="LOW",
        severity_weak="LOW",
        description=(
            "Controls how much referrer information is sent with requests. "
            "Without this header, sensitive URL parameters can leak to third parties "
            "via Referer headers."
        ),
        recommendation=(
            "Referrer-Policy: strict-origin-when-cross-origin  "
            "(or no-referrer for maximum privacy)"
        ),
        required_on="all",
    ),
    HeaderRule(
        name="permissions-policy",
        display="Permissions-Policy",
        severity_missing="LOW",
        severity_weak="INFO",
        description=(
            "Restricts which browser APIs (camera, microphone, geolocation, etc.) "
            "the page and embedded frames may use."
        ),
        recommendation=(
            "Permissions-Policy: camera=(), microphone=(), geolocation=(), "
            "payment=(), usb=(), interest-cohort=()"
        ),
        required_on="html_only",
    ),
    HeaderRule(
        name="cross-origin-opener-policy",
        display="Cross-Origin-Opener-Policy",
        severity_missing="LOW",
        severity_weak="INFO",
        description=(
            "Isolates the browser context from cross-origin windows. "
            "Required for enabling cross-origin isolation (SharedArrayBuffer, "
            "high-resolution timers). Absence enables Spectre-style attacks."
        ),
        recommendation="Cross-Origin-Opener-Policy: same-origin",
        required_on="html_only",
    ),
    HeaderRule(
        name="cross-origin-resource-policy",
        display="Cross-Origin-Resource-Policy",
        severity_missing="LOW",
        severity_weak="INFO",
        description=(
            "Prevents other origins from loading this resource (images, scripts, etc.) "
            "to prevent cross-origin information leaks."
        ),
        recommendation="Cross-Origin-Resource-Policy: same-origin",
        required_on="all",
    ),
    HeaderRule(
        name="x-permitted-cross-domain-policies",
        display="X-Permitted-Cross-Domain-Policies",
        severity_missing="INFO",
        severity_weak="INFO",
        description=(
            "Restricts Adobe Flash/PDF from loading cross-domain content. "
            "Less critical than other headers but part of a complete hardening posture."
        ),
        recommendation="X-Permitted-Cross-Domain-Policies: none",
        required_on="all",
    ),
    HeaderRule(
        name="cache-control",
        display="Cache-Control (on auth pages)",
        severity_missing="MEDIUM",
        severity_weak="LOW",
        description=(
            "Authenticated pages without cache control directives can be cached by "
            "browsers and proxies, allowing access to sensitive content after logout "
            "or by other users on shared machines."
        ),
        recommendation=(
            "Cache-Control: no-store, no-cache, must-revalidate  "
            "(on all authenticated endpoints)"
        ),
        required_on="authenticated",
    ),
]

# ── CSP quality checks ────────────────────────────────────────────────────────
CSP_WEAKNESSES: list[tuple[str, str, str]] = [
    # (pattern, display_name, severity)
    (r"'unsafe-inline'",   "unsafe-inline in script-src", "MEDIUM"),
    (r"'unsafe-eval'",     "unsafe-eval in script-src",   "MEDIUM"),
    (r"script-src\s+\*",   "wildcard in script-src",      "HIGH"),
    (r"default-src\s+\*",  "wildcard default-src",        "HIGH"),
    (r"script-src\s+https:", "HTTPS-only script-src (too broad)", "LOW"),
    (r"(?<!frame-ancestors)'none'.*frame-ancestors", "frame-ancestors missing", "MEDIUM"),
    (r"^(?!.*base-uri)",   "base-uri missing (dangling base injection)", "LOW"),
    (r"^(?!.*form-action)", "form-action missing",         "LOW"),
    (r"^(?!.*default-src)", "default-src missing",         "MEDIUM"),
    (r"data:",             "data: URI source (XSS bypass vector)", "MEDIUM"),
    (r"http://",           "HTTP source in CSP (scheme downgrade)", "LOW"),
]

# ── HSTS quality checks ───────────────────────────────────────────────────────
HSTS_MIN_AGE = 31536000  # 1 year

# ── CORS test patterns ────────────────────────────────────────────────────────
# Each: (origin_to_send, description, is_dangerous_if_reflected)
CORS_ORIGINS: list[tuple[str, str, bool]] = [
    ("https://evil.com",                        "Arbitrary origin reflection",        True),
    ("null",                                    "Null origin (sandbox iframe bypass)", True),
    ("https://evil.TARGET.com",                 "Subdomain wildcard bypass",           True),
    ("http://TARGET.com",                       "HTTP protocol downgrade",             True),
    ("https://TARGET.com.evil.com",             "Pre-domain match bypass",             True),
    ("https://evilTARGET.com",                  "Post-domain (suffix) match bypass",   True),
    ("https://not_exist.TARGET.com",            "Underscore subdomain bypass",         True),
    ("https://TARGET.com\x00.evil.com",         "Null-byte injection in origin",       True),
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_COLOR = {
    "CRITICAL": "bold red", "HIGH": "bold yellow",
    "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim",
}
SEV_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}
UA = "Mozilla/5.0 (compatible; HeaderAudit/1.0)"


# ═════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class HeaderFinding:
    host: str
    url: str
    header: str                        # canonical name
    status: str                        # "missing" | "weak" | "present"
    severity: str
    title: str
    detail: str
    evidence: str                      # the actual header value (or absence)
    recommendation: str
    cvss_estimate: str = ""


@dataclass
class CORSFinding:
    host: str
    url: str
    origin_sent: str
    acao: str                          # Access-Control-Allow-Origin returned
    acac: bool                         # Access-Control-Allow-Credentials: true
    severity: str
    title: str
    detail: str
    is_exploitable: bool               # ACAO reflected + ACAC:true
    poc_html: str = ""                 # ready-to-use PoC
    affected_cookies: list[str] = field(default_factory=list)


@dataclass
class CookieFinding:
    host: str
    url: str
    cookie_name: str
    issues: list[str]                  # list of missing flags
    severity: str
    raw_header: str


@dataclass
class HostAudit:
    host: str
    ip: str
    base_url: str
    http_status: int | None = None
    final_url: str = ""
    response_headers: dict = field(default_factory=dict)
    header_findings: list[HeaderFinding] = field(default_factory=list)
    cors_findings: list[CORSFinding] = field(default_factory=list)
    cookie_findings: list[CookieFinding] = field(default_factory=list)
    score: int = 100                   # starts at 100, deducted per finding
    grade: str = "A"
    error: str = ""


@dataclass
class AuditReport:
    domain: str
    scan_time: str
    source_file: str
    total_hosts: int = 0
    elapsed_seconds: float = 0.0
    host_audits: list[HostAudit] = field(default_factory=list)
    all_header_findings: list[HeaderFinding] = field(default_factory=list)
    all_cors_findings: list[CORSFinding] = field(default_factory=list)
    all_cookie_findings: list[CookieFinding] = field(default_factory=list)


# ═════════════════════════════════════════════════════════════════════════════
# HTTP CLIENT
# ═════════════════════════════════════════════════════════════════════════════

async def get_with_origin(
    url: str,
    origin: str,
    timeout: float = 10.0,
) -> tuple[int | None, dict, str]:
    """GET with custom Origin header. Returns (status, headers, body_snippet)."""
    if not HAS_HTTPX:
        return None, {}, ""
    hdrs = {
        "User-Agent":   UA,
        "Origin":       origin,
        "Accept":       "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    try:
        async with httpx.AsyncClient(
            timeout=timeout, verify=False,
            follow_redirects=True, headers=hdrs,
        ) as c:
            resp = await c.get(url)
            return resp.status_code, dict(resp.headers), resp.text[:2000]
    except Exception:
        return None, {}, ""


async def get_base(
    url: str,
    timeout: float = 10.0,
) -> tuple[int | None, dict, str, str]:
    """
    Plain GET, follow redirects.
    Returns (status, headers, body_snippet, final_url).
    """
    if not HAS_HTTPX:
        return None, {}, "", url
    try:
        async with httpx.AsyncClient(
            timeout=timeout, verify=False,
            follow_redirects=True,
            headers={"User-Agent": UA,
                     "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"},
        ) as c:
            resp = await c.get(url)
            return resp.status_code, dict(resp.headers), resp.text[:4000], str(resp.url)
    except Exception:
        return None, {}, "", url


# ═════════════════════════════════════════════════════════════════════════════
# HEADER ANALYSIS
# ═════════════════════════════════════════════════════════════════════════════

def _hl(headers: dict) -> dict[str, str]:
    """Return headers dict with lowercase keys."""
    return {k.lower(): v for k, v in headers.items()}


def _is_html_response(headers: dict, body: str) -> bool:
    ct = _hl(headers).get("content-type", "")
    return "text/html" in ct or "<!doctype" in body[:100].lower() or "<html" in body[:200].lower()


def _looks_authenticated(url: str, headers: dict, body: str) -> bool:
    """Heuristic: does this look like an authenticated endpoint?"""
    auth_indicators = [
        "/dashboard", "/admin", "/account", "/profile", "/settings",
        "/api/", "/portal", "/user", "/manage",
    ]
    parsed = urlparse(url)
    if any(ind in parsed.path.lower() for ind in auth_indicators):
        return True
    # Has session cookie in response
    for k, v in headers.items():
        if k.lower() == "set-cookie" and any(
            tok in v.lower() for tok in ("session", "auth", "token", "jwt")
        ):
            return True
    return False


def audit_headers(
    host: str,
    url: str,
    headers: dict,
    body: str,
    status: int | None,
) -> list[HeaderFinding]:
    """
    Check all security header rules against the response headers.
    Returns list of HeaderFinding for every issue found.
    """
    findings: list[HeaderFinding] = []
    hl = _hl(headers)
    is_html = _is_html_response(headers, body)
    is_auth = _looks_authenticated(url, headers, body)

    for rule in HEADER_RULES:
        # Skip HTML-only headers on non-HTML responses
        if rule.required_on == "html_only" and not is_html:
            continue
        # Skip authenticated-only headers on non-auth pages
        if rule.required_on == "authenticated" and not is_auth:
            continue

        val = hl.get(rule.name)

        if val is None:
            findings.append(HeaderFinding(
                host=host, url=url,
                header=rule.display,
                status="missing",
                severity=rule.severity_missing,
                title=f"{rule.display} Header Missing",
                detail=rule.description,
                evidence=f"Response does not include '{rule.display}' header.",
                recommendation=rule.recommendation,
                cvss_estimate=rule.cvss_missing,
            ))
            continue

        # Header present — check quality
        quality_issues: list[str] = []

        # ── CSP quality checks ────────────────────────────────────────────
        if rule.name == "content-security-policy":
            for pattern, display_name, sev in CSP_WEAKNESSES:
                if re.search(pattern, val, re.IGNORECASE):
                    quality_issues.append(f"{display_name} [{sev}]")
            if quality_issues:
                findings.append(HeaderFinding(
                    host=host, url=url,
                    header=rule.display,
                    status="weak",
                    severity="MEDIUM",
                    title=f"Content-Security-Policy Present but Weakly Configured",
                    detail=(
                        f"CSP is present but contains directives that reduce its effectiveness: "
                        f"{', '.join(quality_issues)}."
                    ),
                    evidence=f"Content-Security-Policy: {val[:300]}",
                    recommendation=(
                        "Review and tighten the CSP. Remove unsafe-inline and unsafe-eval. "
                        "Use nonces or hashes for inline scripts instead."
                    ),
                ))

        # ── HSTS quality checks ───────────────────────────────────────────
        elif rule.name == "strict-transport-security":
            hsts_issues: list[str] = []
            max_age_m = re.search(r'max-age=(\d+)', val, re.I)
            if max_age_m:
                age = int(max_age_m.group(1))
                if age < HSTS_MIN_AGE:
                    hsts_issues.append(
                        f"max-age={age} is less than 1 year (recommend {HSTS_MIN_AGE})"
                    )
            else:
                hsts_issues.append("max-age directive missing")
            if "includesubdomains" not in val.lower():
                hsts_issues.append("includeSubDomains missing")
            if "preload" not in val.lower():
                hsts_issues.append("preload missing (cannot be added to HSTS preload list)")
            if hsts_issues:
                findings.append(HeaderFinding(
                    host=host, url=url,
                    header=rule.display,
                    status="weak",
                    severity="LOW",
                    title="Strict-Transport-Security Present but Weakly Configured",
                    detail=(
                        f"HSTS is enabled but not optimally configured: "
                        f"{'; '.join(hsts_issues)}."
                    ),
                    evidence=f"Strict-Transport-Security: {val}",
                    recommendation=rule.recommendation,
                ))

        # ── X-Frame-Options ────────────────────────────────────────────────
        elif rule.name == "x-frame-options":
            if val.upper() not in ("DENY", "SAMEORIGIN"):
                findings.append(HeaderFinding(
                    host=host, url=url,
                    header=rule.display,
                    status="weak",
                    severity="MEDIUM",
                    title="X-Frame-Options Has Invalid Value",
                    detail=(
                        f"X-Frame-Options value '{val}' is not a recognised directive. "
                        f"Valid values are DENY and SAMEORIGIN. Browsers may ignore this."
                    ),
                    evidence=f"X-Frame-Options: {val}",
                    recommendation=rule.recommendation,
                ))
            # ALLOW-FROM is deprecated and not universally supported
            elif "allow-from" in val.lower():
                findings.append(HeaderFinding(
                    host=host, url=url,
                    header=rule.display,
                    status="weak",
                    severity="LOW",
                    title="X-Frame-Options Uses Deprecated ALLOW-FROM Directive",
                    detail=(
                        "ALLOW-FROM is deprecated and not supported by Chrome/Edge/Firefox. "
                        "Use CSP frame-ancestors directive instead."
                    ),
                    evidence=f"X-Frame-Options: {val}",
                    recommendation=(
                        "Replace with: Content-Security-Policy: frame-ancestors 'self'"
                    ),
                ))

        # ── X-Content-Type-Options ─────────────────────────────────────────
        elif rule.name == "x-content-type-options":
            if val.lower().strip() != "nosniff":
                findings.append(HeaderFinding(
                    host=host, url=url,
                    header=rule.display,
                    status="weak",
                    severity="LOW",
                    title="X-Content-Type-Options Has Incorrect Value",
                    detail=(
                        f"Value '{val}' is not valid. Only 'nosniff' is accepted."
                    ),
                    evidence=f"X-Content-Type-Options: {val}",
                    recommendation="X-Content-Type-Options: nosniff",
                ))

        # ── Cache-Control on auth pages ────────────────────────────────────
        elif rule.name == "cache-control" and is_auth:
            cc_lower = val.lower()
            missing: list[str] = []
            if "no-store" not in cc_lower:
                missing.append("no-store")
            if "no-cache" not in cc_lower and "max-age=0" not in cc_lower:
                missing.append("no-cache")
            if missing:
                findings.append(HeaderFinding(
                    host=host, url=url,
                    header=rule.display,
                    status="weak",
                    severity="MEDIUM",
                    title="Cache-Control Missing no-store/no-cache on Authenticated Endpoint",
                    detail=(
                        f"Authenticated endpoint is missing cache control directives: "
                        f"{', '.join(missing)}. Sensitive content may be cached by browsers "
                        f"or intermediate proxies and accessible after logout."
                    ),
                    evidence=f"Cache-Control: {val}  (on {url})",
                    recommendation=rule.recommendation,
                ))

    # ── Server header information disclosure ──────────────────────────────
    server = hl.get("server", "")
    if server and re.search(r'\d', server):   # server header with version number
        findings.append(HeaderFinding(
            host=host, url=url,
            header="Server",
            status="weak",
            severity="INFO",
            title="Server Header Discloses Version Information",
            detail=(
                f"The Server header reveals the web server software and version: '{server}'. "
                f"This enables targeted CVE research by attackers."
            ),
            evidence=f"Server: {server}",
            recommendation=(
                "Suppress the Server header version. In nginx: server_tokens off; "
                "In Apache: ServerTokens Prod; ServerSignature Off."
            ),
        ))

    # ── X-Powered-By disclosure ────────────────────────────────────────────
    powered_by = hl.get("x-powered-by", "")
    if powered_by:
        findings.append(HeaderFinding(
            host=host, url=url,
            header="X-Powered-By",
            status="weak",
            severity="INFO",
            title="X-Powered-By Header Discloses Technology Stack",
            detail=(
                f"X-Powered-By reveals the application framework: '{powered_by}'. "
                f"This should be removed in production."
            ),
            evidence=f"X-Powered-By: {powered_by}",
            recommendation=(
                "Remove X-Powered-By. In Express.js: app.disable('x-powered-by'); "
                "In PHP: expose_php = Off in php.ini."
            ),
        ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
# CORS TESTING
# ═════════════════════════════════════════════════════════════════════════════

def _extract_cookies_from_headers(headers: dict) -> list[str]:
    """Extract all Set-Cookie cookie names."""
    names: list[str] = []
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            m = re.match(r'([^=]+)=', v)
            if m:
                names.append(m.group(1).strip())
    return names


def _build_poc_html(url: str, origin: str) -> str:
    """Generate a ready-to-use PoC HTML page for CORS + credentials."""
    return f"""<!DOCTYPE html>
<html>
<head><title>CORS PoC — {url}</title></head>
<body>
<h1>CORS Exploit PoC</h1>
<p>This page demonstrates Cross-Origin Resource Sharing misconfiguration on:</p>
<code>{url}</code>
<pre id="output">Sending request...</pre>
<script>
fetch('{url}', {{
  method: 'GET',
  credentials: 'include',   // sends victim's cookies
  headers: {{ 'Accept': 'application/json, text/plain, */*' }},
}})
.then(r => r.text())
.then(data => {{
  document.getElementById('output').textContent =
    'STATUS: ' + 'OK' + '\\n\\nRESPONSE:\\n' + data;
}})
.catch(e => {{
  document.getElementById('output').textContent = 'ERROR: ' + e;
}});
</script>
</body>
</html>"""


async def test_cors(
    host: str,
    url: str,
    target_domain: str,
    timeout: float = 10.0,
    deep: bool = False,
) -> list[CORSFinding]:
    """
    Test 8 CORS attack patterns against a URL.
    Returns CORSFinding for every reflected/exploitable CORS configuration.
    """
    findings: list[CORSFinding] = []

    for origin_template, description, is_dangerous in CORS_ORIGINS:
        # Substitute TARGET placeholder with actual domain
        origin = origin_template.replace("TARGET", target_domain)

        status, resp_headers, body = await get_with_origin(url, origin, timeout)
        if status is None:
            continue

        hl = _hl(resp_headers)
        acao = hl.get("access-control-allow-origin", "")
        acac = hl.get("access-control-allow-credentials", "").lower() == "true"

        # Check if our injected origin was reflected
        is_reflected = (
            acao == origin
            or (acao == "*" and origin != "null")
        )
        is_null_accepted = (origin == "null" and acao == "null")

        if not is_reflected and not is_null_accepted:
            continue  # Not vulnerable to this pattern

        # Determine exploitability
        # CORS is only exploitable for data theft if credentials can be sent
        # (cookies, HTTP auth). With ACAC:false and non-wildcard, impact is lower.
        is_exploitable = (is_reflected or is_null_accepted) and acac

        if acao == "*" and acac:
            # This is actually invalid per spec but some servers do it
            severity = "HIGH"
        elif is_exploitable:
            severity = "HIGH"
        elif is_reflected:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # Get affected cookies from a baseline request
        base_status, base_hdrs, _, _ = await get_base(url, timeout)
        affected_cookies = _extract_cookies_from_headers(base_hdrs) if base_status else []

        poc = _build_poc_html(url, origin) if is_exploitable else ""

        findings.append(CORSFinding(
            host=host,
            url=url,
            origin_sent=origin,
            acao=acao,
            acac=acac,
            severity=severity,
            title=(
                f"CORS Misconfiguration — {'Exploitable (with credentials)' if is_exploitable else 'Reflected'}: "
                f"{description}"
            ),
            detail=(
                f"When Origin: {origin} is sent to {url}, the server responds with "
                f"Access-Control-Allow-Origin: {acao}"
                + (f" and Access-Control-Allow-Credentials: true" if acac else "")
                + f". {description}. "
                + (
                    "With ACAC:true, a malicious page can make credentialed cross-origin "
                    "requests and read the response, enabling session theft or data exfiltration."
                    if is_exploitable else
                    "Without ACAC:true, cookie-based session theft is not possible, "
                    "but unauthenticated cross-origin reads may still be a concern."
                )
            ),
            is_exploitable=is_exploitable,
            poc_html=poc,
            affected_cookies=affected_cookies,
        ))

        # If fully exploitable, no need to test other origins
        if is_exploitable and not deep:
            break

    return findings


# ═════════════════════════════════════════════════════════════════════════════
# COOKIE AUDIT
# ═════════════════════════════════════════════════════════════════════════════

def audit_cookies(
    host: str,
    url: str,
    headers: dict,
) -> list[CookieFinding]:
    """Check every Set-Cookie header for missing security flags."""
    findings: list[CookieFinding] = []

    for k, v in headers.items():
        if k.lower() != "set-cookie":
            continue

        v_lower = v.lower()
        name_m  = re.match(r'([^=;]+)', v)
        name    = name_m.group(1).strip() if name_m else "unknown"
        issues: list[str] = []

        # Secure flag
        if "secure" not in v_lower:
            issues.append("Missing Secure flag — cookie transmitted over HTTP")

        # HttpOnly flag
        if "httponly" not in v_lower:
            issues.append("Missing HttpOnly flag — accessible via document.cookie (XSS theft)")

        # SameSite
        if "samesite" not in v_lower:
            issues.append("Missing SameSite flag — vulnerable to CSRF")
        elif "samesite=none" in v_lower and "secure" not in v_lower:
            issues.append("SameSite=None without Secure is invalid (RFC 6265bis)")

        # Overly broad domain
        domain_m = re.search(r'domain=([^;]+)', v_lower)
        if domain_m:
            cookie_domain = domain_m.group(1).strip().lstrip(".")
            # If the cookie domain is the root domain, it's shared across all subdomains
            # This is only a concern for session cookies
            if any(tok in name.lower() for tok in ("session", "auth", "token", "jwt", "sid")):
                issues.append(
                    f"Session cookie with domain=.{cookie_domain} — shared across all subdomains"
                )

        if issues:
            # Determine severity based on issue types
            if "HttpOnly" in " ".join(issues) and "Secure" in " ".join(issues):
                severity = "MEDIUM"
            elif "HttpOnly" in " ".join(issues):
                severity = "MEDIUM"
            elif "Secure" in " ".join(issues):
                severity = "MEDIUM"
            else:
                severity = "LOW"

            findings.append(CookieFinding(
                host=host,
                url=url,
                cookie_name=name,
                issues=issues,
                severity=severity,
                raw_header=v[:200],
            ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
# SCORING
# ═════════════════════════════════════════════════════════════════════════════

SEVERITY_DEDUCTIONS = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5, "INFO": 0}

GRADE_THRESHOLDS = [
    (95, "A+"), (85, "A"), (75, "B+"), (65, "B"),
    (50, "C"), (35, "D"), (0,  "F"),
]


def compute_grade(score: int) -> str:
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


def compute_score(audit: HostAudit) -> tuple[int, str]:
    score = 100
    for f in audit.header_findings:
        score -= SEVERITY_DEDUCTIONS.get(f.severity, 0)
    for f in audit.cors_findings:
        score -= SEVERITY_DEDUCTIONS.get(f.severity, 0)
    for f in audit.cookie_findings:
        score -= SEVERITY_DEDUCTIONS.get(f.severity, 0)
    score = max(0, score)
    return score, compute_grade(score)


# ═════════════════════════════════════════════════════════════════════════════
# HOST AUDITOR
# ═════════════════════════════════════════════════════════════════════════════

class HostAuditor:
    def __init__(
        self,
        domain: str,
        timeout: float   = 10.0,
        concurrency: int = 25,
        cors_deep: bool  = False,
    ):
        self.domain      = domain
        self.timeout     = timeout
        self._sem        = asyncio.Semaphore(concurrency)
        self.cors_deep   = cors_deep

    async def audit(self, host: str, ip: str) -> HostAudit:
        result = HostAudit(host=host, ip=ip, base_url="")
        async with self._sem:
            try:
                await self._run(host, ip, result)
            except Exception as exc:
                result.error = str(exc)
                log.debug(f"[{host}] Audit error: {exc}")
        return result

    async def _run(self, host: str, ip: str, result: HostAudit) -> None:
        # Determine best URL (HTTPS preferred)
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}/"
            status, headers, body, final_url = await get_base(url, self.timeout)
            if status is not None:
                result.base_url        = url
                result.http_status     = status
                result.final_url       = final_url
                result.response_headers = headers
                break

        if result.http_status is None:
            result.error = "Host unreachable"
            return

        url     = result.base_url
        headers = result.response_headers
        body_str = ""   # body already consumed via get_base

        # Re-fetch body for HTML detection (get_base only returns snippet)
        _, headers2, body_str, _ = await get_base(url, self.timeout)
        headers = headers2 if headers2 else headers

        # ── Security header audit ──────────────────────────────────────────
        result.header_findings = audit_headers(
            host, url, headers, body_str, result.http_status
        )

        # ── Cookie audit ───────────────────────────────────────────────────
        result.cookie_findings = audit_cookies(host, url, headers)

        # ── CORS testing ───────────────────────────────────────────────────
        # Test on base URL first, then common API paths if deep mode
        cors_urls = [url]
        if self.cors_deep:
            cors_urls += [
                f"{result.base_url.rstrip('/')}/api/",
                f"{result.base_url.rstrip('/')}/api/v1/",
                f"{result.base_url.rstrip('/')}/api/user",
                f"{result.base_url.rstrip('/')}/graphql",
            ]

        for cors_url in cors_urls:
            cors_findings = await test_cors(
                host, cors_url, self.domain, self.timeout, self.cors_deep
            )
            result.cors_findings.extend(cors_findings)

        # ── Score ──────────────────────────────────────────────────────────
        result.score, result.grade = compute_score(result)

        log.debug(
            f"[{host}] Grade={result.grade} Score={result.score} "
            f"Headers={len(result.header_findings)} "
            f"CORS={len(result.cors_findings)} "
            f"Cookies={len(result.cookie_findings)}"
        )


# ═════════════════════════════════════════════════════════════════════════════
# INPUT PARSERS
# ═════════════════════════════════════════════════════════════════════════════

def load_from_recon(path: str) -> list[tuple[str, str]]:
    with open(path) as f:
        data = json.load(f)
    hosts: list[tuple[str, str]] = []
    seen: set[str] = set()
    for hr in data.get("host_reports", []):
        h  = hr.get("host", "")
        ip = hr.get("ip", "")
        if h and h not in seen and hr.get("open_ports"):
            seen.add(h)
            hosts.append((h, ip))
    log.info(f"[Parse] {len(hosts)} hosts with open ports from {path}")
    return hosts


def load_from_subtakeover(path: str) -> list[tuple[str, str]]:
    with open(path) as f:
        data = json.load(f)
    hosts: list[tuple[str, str]] = []
    seen: set[str] = set()
    for entry in data.get("resolved_subdomains", []):
        h   = entry.get("subdomain", "")
        ips = entry.get("a_records", [])
        if h and ips and h not in seen:
            seen.add(h)
            hosts.append((h, ips[0]))
    log.info(f"[Parse] {len(hosts)} resolved hosts from {path}")
    return hosts


def load_from_hostfile(path: str) -> list[tuple[str, str]]:
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

def _grade_color(grade: str) -> str:
    if grade.startswith("A"): return "bold green"
    if grade.startswith("B"): return "bold cyan"
    if grade.startswith("C"): return "bold yellow"
    if grade.startswith("D"): return "bold red"
    return "bold red"


def print_report(report: AuditReport) -> None:
    all_f = sorted(
        report.all_header_findings + report.all_cors_findings,
        key=lambda f: SEVERITY_ORDER.get(f.severity, 9),
    )
    by_sev = {s: [f for f in all_f if f.severity == s] for s in SEVERITY_ORDER}

    if not HAS_RICH:
        print(f"\n=== HeaderAudit: {report.domain} ===")
        print(f"Hosts: {report.total_hosts}  Elapsed: {report.elapsed_seconds:.1f}s")
        for f in all_f:
            print(f"\n[{f.severity}] {f.title}")
            print(f"  {getattr(f,'host','')} — {f.detail[:150]}")
        print()
        return

    console.print()
    border = "red" if by_sev.get("HIGH") or by_sev.get("CRITICAL") else "yellow"
    console.print(Panel.fit(
        f"[white]Domain:[/] [cyan]{report.domain}[/]\n"
        f"[white]Scan time:[/] {report.scan_time}\n"
        f"[white]Elapsed:[/] {report.elapsed_seconds:.1f}s\n"
        f"[white]Hosts:[/] {report.total_hosts}\n\n"
        f"[bold red]CRITICAL:[/] {len(by_sev.get('CRITICAL',[]))}    "
        f"[bold yellow]HIGH:[/] {len(by_sev.get('HIGH',[]))}    "
        f"[yellow]MEDIUM:[/] {len(by_sev.get('MEDIUM',[]))}    "
        f"[cyan]LOW:[/] {len(by_sev.get('LOW',[]))}    "
        f"[dim]INFO:[/] {len(by_sev.get('INFO',[]))}\n"
        f"[dim]CORS exploitable:[/] {sum(1 for f in report.all_cors_findings if f.is_exploitable)}    "
        f"[dim]Cookie issues:[/] {len(report.all_cookie_findings)}",
        title="[bold]HeaderAudit Report[/]",
        border_style=border,
    ))

    # ── Per-host grade table ──────────────────────────────────────────────
    console.print("\n[bold cyan]── Host Security Grades ──[/]")
    gtbl = Table(show_header=True, header_style="bold cyan", border_style="dim")
    gtbl.add_column("Host",        style="cyan", no_wrap=True)
    gtbl.add_column("Grade",       justify="center")
    gtbl.add_column("Score",       justify="right")
    gtbl.add_column("Header Issues", justify="right")
    gtbl.add_column("CORS Issues", justify="right")
    gtbl.add_column("Cookie Issues", justify="right")
    gtbl.add_column("Top Issue",   style="dim")

    for ha in sorted(report.host_audits, key=lambda h: h.score):
        if ha.error and not ha.header_findings:
            continue
        gc  = _grade_color(ha.grade)
        top = ""
        all_issues = ha.header_findings + ha.cors_findings
        if all_issues:
            worst = min(all_issues, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
            top = worst.title[:45] + ("..." if len(worst.title) > 45 else "")

        cors_exp = sum(1 for f in ha.cors_findings if f.is_exploitable)
        cors_str = str(len(ha.cors_findings))
        if cors_exp:
            cors_str = f"[red]{cors_str} ({cors_exp} exploitable)[/]"

        gtbl.add_row(
            ha.host,
            f"[{gc}]{ha.grade}[/]",
            str(ha.score),
            str(len(ha.header_findings)),
            cors_str,
            str(len(ha.cookie_findings)),
            top,
        )
    console.print(gtbl)

    # ── Findings detail ───────────────────────────────────────────────────
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        sf = by_sev.get(sev, [])
        if not sf:
            continue
        col = SEV_COLOR.get(sev, "white")
        console.print(f"\n[{col}]── {SEV_EMOJI.get(sev,'')} {sev} ({len(sf)}) ──[/]")
        for i, f in enumerate(sf, 1):
            host_str = getattr(f, "host", "")
            detail   = getattr(f, "detail", "")
            evidence = getattr(f, "evidence", "")
            rec      = getattr(f, "recommendation", "")
            console.print(
                f"  [{col}][{i}][/] [white]{f.title}[/]\n"
                f"      [dim]Host:[/] {host_str}\n"
                f"      [dim]Detail:[/] {detail[:200]}{'...' if len(detail)>200 else ''}"
            )
            if evidence:
                console.print(f"      [dim]Evidence:[/] {escape(evidence[:160])}")
            if rec:
                console.print(f"      [dim]Fix:[/] {rec[:160]}")
            cvss = getattr(f, "cvss_estimate", "")
            if cvss:
                console.print(f"      [dim]CVSS:[/] {cvss}")
            if i < len(sf):
                console.print()

    # ── CORS exploitability section ───────────────────────────────────────
    exploitable = [f for f in report.all_cors_findings if f.is_exploitable]
    if exploitable:
        console.print("\n[bold red]── Exploitable CORS Findings (PoC Available) ──[/]")
        for cf in exploitable:
            console.print(
                f"  [red]●[/] [white]{cf.url}[/]\n"
                f"    Origin sent: [yellow]{cf.origin_sent}[/]\n"
                f"    ACAO: [red]{cf.acao}[/]   ACAC: [red]{'true' if cf.acac else 'false'}[/]\n"
                f"    Affected cookies: [cyan]{', '.join(cf.affected_cookies) or 'none detected'}[/]\n"
                f"    PoC saved to JSON output as poc_html field."
            )

    console.print()


def save_json(report: AuditReport, path: str) -> None:
    data = {
        "domain":          report.domain,
        "scan_time":       report.scan_time,
        "source_file":     report.source_file,
        "total_hosts":     report.total_hosts,
        "elapsed_seconds": report.elapsed_seconds,
        "summary": {
            s: len([f for f in report.all_header_findings + report.all_cors_findings
                    if f.severity == s])
            for s in SEVERITY_ORDER
        },
        "cors_exploitable": sum(1 for f in report.all_cors_findings if f.is_exploitable),
        "cookie_issues":    len(report.all_cookie_findings),
        "header_findings":  [asdict(f) for f in sorted(
            report.all_header_findings,
            key=lambda f: SEVERITY_ORDER.get(f.severity, 9)
        )],
        "cors_findings":    [asdict(f) for f in sorted(
            report.all_cors_findings,
            key=lambda f: SEVERITY_ORDER.get(f.severity, 9)
        )],
        "cookie_findings":  [asdict(f) for f in report.all_cookie_findings],
        "host_audits": [
            {
                "host":             ha.host,
                "ip":               ha.ip,
                "base_url":         ha.base_url,
                "http_status":      ha.http_status,
                "score":            ha.score,
                "grade":            ha.grade,
                "header_findings":  [asdict(f) for f in ha.header_findings],
                "cors_findings":    [asdict(f) for f in ha.cors_findings],
                "cookie_findings":  [asdict(f) for f in ha.cookie_findings],
            }
            for ha in report.host_audits
        ],
    }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    log.info(f"JSON report saved → {path}")
    log.info(
        f"  header_findings[]: {len(report.all_header_findings)}  "
        f"cors_findings[]: {len(report.all_cors_findings)}  "
        f"cookie_findings[]: {len(report.all_cookie_findings)}"
    )


def save_html(report: AuditReport, path: str) -> None:
    all_f = sorted(
        report.all_header_findings + report.all_cors_findings,
        key=lambda f: SEVERITY_ORDER.get(f.severity, 9),
    )
    by_sev = {s: [f for f in all_f if f.severity == s] for s in SEVERITY_ORDER}

    sc = {
        "CRITICAL": "#f85149", "HIGH": "#d29922",
        "MEDIUM": "#e3b341", "LOW": "#58a6ff", "INFO": "#8b949e",
    }
    sb = {
        "CRITICAL": "rgba(248,81,73,.12)", "HIGH": "rgba(210,153,34,.12)",
        "MEDIUM": "rgba(227,179,65,.10)", "LOW": "rgba(88,166,255,.10)",
        "INFO": "rgba(139,148,158,.08)",
    }
    grade_col = {"A+": "#3fb950", "A": "#3fb950", "B+": "#39c5cf", "B": "#39c5cf",
                 "C": "#d29922", "D": "#f85149", "F": "#f85149"}

    # Host grade table rows
    host_rows = ""
    for ha in sorted(report.host_audits, key=lambda h: h.score):
        if ha.error and not ha.header_findings:
            continue
        gc = grade_col.get(ha.grade, "#8b949e")
        cors_exp = sum(1 for f in ha.cors_findings if f.is_exploitable)
        host_rows += (
            f"<tr><td style='color:#58a6ff'>{ha.host}</td>"
            f"<td style='color:{gc};font-weight:bold;text-align:center'>{ha.grade}</td>"
            f"<td style='text-align:right'>{ha.score}</td>"
            f"<td style='text-align:right'>{len(ha.header_findings)}</td>"
            "<td style='text-align:right;color:" + ("#f85149" if cors_exp else "inherit") + "'>"
            f"{len(ha.cors_findings)}" + (f' ({cors_exp} exploitable)' if cors_exp else '') + "</td>"
            f"<td style='text-align:right'>{len(ha.cookie_findings)}</td></tr>"
        )

    # Findings detail
    findings_html = ""
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        sf = by_sev.get(sev, [])
        if not sf:
            continue
        findings_html += (
            f'<div class="sev-section">'
            f'<h3 style="color:{sc[sev]}">{SEV_EMOJI.get(sev,"")} {sev} ({len(sf)})</h3>'
        )
        for i, f in enumerate(sf, 1):
            host_str = getattr(f, "host", "")
            detail   = getattr(f, "detail", "")
            evidence = getattr(f, "evidence", "")
            rec      = getattr(f, "recommendation", "")
            cvss     = getattr(f, "cvss_estimate", "")
            findings_html += (
                f'<div class="finding" style="border-left:3px solid {sc[sev]};background:{sb[sev]}">'
                f'<div class="ft">[{i}] {f.title}</div>'
                f'<div class="fm">'
                f'<span class="badge" style="color:{sc[sev]};background:{sb[sev]};border:1px solid {sc[sev]}">{sev}</span>'
                f'<span style="color:#58a6ff;font-size:.82em">{host_str}</span>'
                + (f'<span style="color:#d29922;font-size:.78em">{cvss}</span>' if cvss else "")
                + f'</div>'
                f'<div class="fd">{detail}</div>'
                + (f'<div class="ev"><span class="evl">Evidence:</span><code>{evidence[:250]}</code></div>' if evidence else "")
                + (f'<div class="rec"><span class="recl">Fix:</span> {rec}</div>' if rec else "")
                + f'</div>'
            )
        findings_html += "</div>"

    # CORS exploitable PoC section
    exploitable = [f for f in report.all_cors_findings if f.is_exploitable]
    cors_poc_html = ""
    if exploitable:
        cors_poc_html = '<div class="card"><h2>🎯 Exploitable CORS — Proof of Concept</h2>'
        for cf in exploitable:
            poc_escaped = cf.poc_html.replace("<", "&lt;").replace(">", "&gt;")
            cors_poc_html += (
                f'<div style="background:rgba(248,81,73,.08);border:1px solid #f85149;'
                f'border-radius:6px;padding:14px;margin-bottom:12px">'
                f'<div style="color:#fff;font-weight:bold;margin-bottom:8px">{cf.url}</div>'
                f'<div style="color:#627384;font-size:.82em">Origin sent: '
                f'<span style="color:#d29922">{cf.origin_sent}</span>  '
                f'ACAO: <span style="color:#f85149">{cf.acao}</span>  '
                f'ACAC: <span style="color:#f85149">{"true" if cf.acac else "false"}</span></div>'
                f'<details style="margin-top:8px"><summary style="cursor:pointer;color:#39c5cf">Show PoC HTML</summary>'
                f'<pre style="background:#020508;padding:10px;border-radius:4px;font-size:.78em;color:#a8dadc;overflow-x:auto">'
                f'{poc_escaped}</pre></details></div>'
            )
        cors_poc_html += "</div>"

    html = f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>HeaderAudit — {report.domain}</title>
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
.stats{{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));
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
.badge{{padding:2px 8px;border-radius:10px;font-size:.7em;font-weight:700;
        letter-spacing:.05em}}
.fd{{color:var(--mt);font-size:.83em;margin-bottom:8px;line-height:1.6}}
.ev{{background:rgba(0,0,0,.4);border:1px solid var(--bd);border-radius:4px;
     padding:8px 10px;margin-bottom:8px}}
.evl{{color:#39c5cf;font-size:.7em;font-weight:700;margin-right:6px}}
.ev code{{color:#a8dadc;font-size:.82em;word-break:break-all}}
.rec{{color:#3fb950;font-size:.8em}}.recl{{font-weight:700;margin-right:4px}}
.sev-section{{margin-bottom:20px}}
.footer{{text-align:center;color:var(--mt);font-size:.72em;margin-top:32px;
         padding-top:16px;border-top:1px solid var(--bd)}}
</style></head>
<body><div class="wrap">
<h1>HeaderAudit</h1>
<p class="sub">{report.domain} &nbsp;·&nbsp; {report.scan_time} &nbsp;·&nbsp;
{report.elapsed_seconds:.1f}s &nbsp;·&nbsp; {report.total_hosts} hosts</p>
<div class="stats">
<div class="stat"><div class="sv" style="color:#f85149">{len(by_sev.get('CRITICAL',[]))}</div><div class="sl">CRITICAL</div></div>
<div class="stat"><div class="sv" style="color:#d29922">{len(by_sev.get('HIGH',[]))}</div><div class="sl">HIGH</div></div>
<div class="stat"><div class="sv" style="color:#e3b341">{len(by_sev.get('MEDIUM',[]))}</div><div class="sl">MEDIUM</div></div>
<div class="stat"><div class="sv" style="color:#58a6ff">{len(by_sev.get('LOW',[]))}</div><div class="sl">LOW</div></div>
<div class="stat"><div class="sv" style="color:#f85149">{sum(1 for f in report.all_cors_findings if f.is_exploitable)}</div><div class="sl">CORS EXPLOITABLE</div></div>
<div class="stat"><div class="sv">{len(report.all_cookie_findings)}</div><div class="sl">COOKIE ISSUES</div></div>
</div>
<div class="card"><h2>🏆 Host Security Grades</h2>
<table><thead><tr>
<th>Host</th><th>Grade</th><th>Score</th>
<th>Header Issues</th><th>CORS Issues</th><th>Cookie Issues</th>
</tr></thead><tbody>{host_rows}</tbody></table></div>
{cors_poc_html}
<div class="card"><h2>🔎 All Findings</h2>{findings_html}</div>
<div class="footer">HeaderAudit &nbsp;·&nbsp; For authorized security research only</div>
</div></body></html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    log.info(f"HTML report saved → {path}")


# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="HeaderAudit — Security Header & CORS Misconfiguration Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 headeraudit.py --scan recon-report-v2.json --domain eskimi.com --output headers
  python3 headeraudit.py --subtakeover scan.json --domain eskimi.com --output headers
  python3 headeraudit.py --hosts targets.txt --domain eskimi.com --cors-deep -o headers

Chains from : reconharvest.py (--scan), subtakeover.py (--subtakeover), plain list (--hosts)
Output feeds: standalone bug bounty reports (JSON + HTML with PoC)
        """,
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--scan",        metavar="FILE", help="reconharvest.py JSON output")
    src.add_argument("--subtakeover", metavar="FILE", help="subtakeover.py scan.json output")
    src.add_argument("--hosts",       metavar="FILE", help="Plain text host list")

    p.add_argument("--domain",        required=True,  help="Target root domain")
    p.add_argument("-o","--output",   metavar="BASE",  help="Output base → BASE.json + BASE.html")
    p.add_argument("--cors-deep",     action="store_true",
                   help="Test CORS on multiple API paths per host (slower, more coverage)")
    p.add_argument("--timeout",       type=float, default=10.0,
                   help="HTTP timeout per request (default: 10s)")
    p.add_argument("--concurrency",   type=int,   default=25,
                   help="Concurrent host workers (default: 25)")
    p.add_argument("-v","--verbose",  action="store_true", help="Verbose logging")
    return p.parse_args()


async def main() -> None:
    args = parse_args()
    if args.verbose:
        log.setLevel(logging.DEBUG)

    print("""
╔══════════════════════════════════════════════════════════════════╗
║     HeaderAudit — Security Header & CORS Analyzer                ║
║  For authorized penetration testing and bug bounty research only ║
╚══════════════════════════════════════════════════════════════════╝
""")

    if not HAS_HTTPX:
        log.error("httpx required: pip install httpx")
        sys.exit(1)

    # Load hosts
    if args.scan:
        hosts  = load_from_recon(args.scan)
        source = args.scan
    elif args.subtakeover:
        hosts  = load_from_subtakeover(args.subtakeover)
        source = args.subtakeover
    else:
        hosts  = load_from_hostfile(args.hosts)
        source = args.hosts

    if not hosts:
        log.error("No hosts found in input.")
        sys.exit(1)

    report = AuditReport(
        domain=args.domain,
        scan_time=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        source_file=source,
        total_hosts=len(hosts),
    )

    auditor = HostAuditor(
        domain=args.domain,
        timeout=args.timeout,
        concurrency=args.concurrency,
        cors_deep=args.cors_deep,
    )

    t0 = time.perf_counter()

    if HAS_RICH:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]Auditing headers[/]"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("[dim]{task.fields[h]}[/]"),
            console=console,
        ) as prog:
            task = prog.add_task("audit", total=len(hosts), h="")
            sem  = asyncio.Semaphore(args.concurrency)

            async def bounded(host: str, ip: str) -> HostAudit:
                async with sem:
                    prog.update(task, h=host)
                    r = await auditor.audit(host, ip)
                    prog.advance(task)
                    return r

            results = await asyncio.gather(
                *[bounded(h, ip) for h, ip in hosts],
                return_exceptions=True,
            )
    else:
        sem = asyncio.Semaphore(args.concurrency)

        async def bounded(host: str, ip: str) -> HostAudit:
            async with sem:
                return await auditor.audit(host, ip)

        results = await asyncio.gather(
            *[bounded(h, ip) for h, ip in hosts],
            return_exceptions=True,
        )

    # Aggregate
    for r in results:
        if isinstance(r, HostAudit):
            report.host_audits.append(r)
            report.all_header_findings.extend(r.header_findings)
            report.all_cors_findings.extend(r.cors_findings)
            report.all_cookie_findings.extend(r.cookie_findings)
        elif isinstance(r, Exception):
            log.warning(f"Host error: {r}")

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

    # Alert on exploitable CORS
    exploitable = [f for f in report.all_cors_findings if f.is_exploitable]
    if exploitable:
        log.warning(
            f"[!] {len(exploitable)} exploitable CORS findings — "
            f"PoC HTML available in JSON output (poc_html field)"
        )


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(0)
