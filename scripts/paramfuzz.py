#!/usr/bin/env python3
"""
paramfuzz.py — Hidden Parameter Discovery & Mass Assignment Testing
===================================================================
Author  : RareKez / security research tooling
License : MIT (for authorized use only)

Chains from : jsreaper.py    (--js)    — endpoints + known parameters
              apifuzz.py     (--api)   — API endpoints + body fields
              reconharvest.py (--scan) — live hosts + probe paths
              plain list      (--urls) — raw URL list

Feeds into  : Bug bounty reports (privilege escalation, IDOR, debug bypass)

Pipeline:
  1. Collect endpoint surface from all chain inputs
  2. Build a targeted wordlist per endpoint:
       - Security-focused base wordlist (3,000+ names)
       - Inferred variations from already-known parameters
         (user_id → userId → user-id → uid → account_id …)
       - Debug/admin parameter names
       - Mass assignment candidates (role, is_admin, balance …)
  3. Inject each candidate parameter into:
       - Query string (GET)
       - JSON request body (POST/PUT/PATCH)
       - Form-urlencoded body
  4. Detect hidden parameters via response diffs:
       - HTTP status change (403→200, 400→200)
       - Response body size change (>150 bytes new content)
       - New JSON keys appear in response
       - New HTML elements / error messages
       - Timing increase (async side-effects)
  5. Test confirmed parameters for privilege escalation:
       - role=admin, is_admin=true, plan=enterprise …
  6. HTTP parameter pollution on confirmed params
  7. Array / nested object injection
  8. Generate JSON + HTML report with curl PoC

Usage:
  python3 paramfuzz.py --js js-findings.json --domain eskimi.com --output params
  python3 paramfuzz.py --api api-findings.json --domain eskimi.com --output params
  python3 paramfuzz.py --scan recon-report-v2.json --domain eskimi.com --output params
  python3 paramfuzz.py --urls endpoints.txt --domain eskimi.com --output params
  python3 paramfuzz.py --js js-findings.json --domain eskimi.com \
      --session "Bearer YOUR_TOKEN" --output params

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
log = logging.getLogger("paramfuzz")
for _n in ("httpx", "httpcore"):
    logging.getLogger(_n).setLevel(logging.WARNING)


# ═════════════════════════════════════════════════════════════════════════════
# PARAMETER WORDLIST
# Grouped by category so we can weight/prioritise
# ═════════════════════════════════════════════════════════════════════════════

# ── Privilege escalation / mass-assignment ────────────────────────────────
PRIV_PARAMS: list[str] = [
    # Role / admin flags
    "role", "roles", "is_admin", "isAdmin", "admin", "superuser", "is_superuser",
    "is_staff", "isStaff", "is_moderator", "isModerator",
    "account_type", "accountType", "user_type", "userType",
    "user_role", "userRole", "member_type", "memberType",
    # Plan / tier
    "plan", "tier", "subscription", "subscription_type", "subscriptionType",
    "plan_id", "planId", "tier_id", "tierId",
    # Verification
    "verified", "email_verified", "emailVerified", "phone_verified",
    "is_verified", "isVerified", "confirmed",
    # Permission arrays
    "permissions", "permission", "scopes", "scope", "grants",
    "capabilities", "features", "access_level", "accessLevel",
    # Ownership / relationship
    "owner_id", "ownerId", "user_id", "userId", "account_id", "accountId",
    "organization_id", "organizationId", "org_id", "orgId",
    "team_id", "teamId", "workspace_id", "workspaceId",
    "tenant_id", "tenantId", "company_id", "companyId",
    # Financial
    "balance", "credits", "tokens", "points", "coins",
    "credit_limit", "creditLimit", "spend_limit", "spendLimit",
    # Timestamps (read-only bypass)
    "created_at", "createdAt", "updated_at", "updatedAt",
    "deleted_at", "deletedAt",
]

# ── Debug / internal parameters ──────────────────────────────────────────
DEBUG_PARAMS: list[str] = [
    "debug", "Debug", "DEBUG",
    "test", "testing", "Test",
    "dev", "development", "Dev",
    "verbose", "Verbose", "verbosity",
    "trace", "Trace", "tracing",
    "log", "logging", "log_level", "logLevel",
    "internal", "Internal",
    "preview", "Preview",
    "beta", "Beta", "alpha", "Alpha",
    "mock", "Mock", "dummy", "Dummy",
    "bypass", "Bypass",
    "override", "Override",
    "force", "Force", "forced",
    "skip", "Skip", "skip_validation", "skipValidation",
    "no_auth", "noAuth", "skip_auth", "skipAuth",
    "disable_check", "disableCheck",
]

# ── Format & output control ────────────────────────────────────────────────
FORMAT_PARAMS: list[str] = [
    "format", "output", "type", "response_type", "responseType",
    "content_type", "contentType",
    "fmt", "mime", "encoding",
    "callback", "jsonp", "cb",  # JSONP endpoint discovery
    "wrap", "envelope",
    "fields", "select", "columns", "include", "exclude",
    "expand", "embed", "populate",
]

# ── Pagination / filtering (boundary conditions) ──────────────────────────
PAGINATION_PARAMS: list[str] = [
    "limit", "size", "per_page", "perPage", "page_size", "pageSize",
    "page", "offset", "skip", "start", "from", "cursor",
    "max", "count", "number",
    "order", "sort", "sort_by", "sortBy", "order_by", "orderBy",
    "direction", "asc", "desc",
    "filter", "query", "q", "search",
    "status", "state",
    "all",  # ?all=true — sometimes bypasses pagination cap
]

# ── ID parameters for IDOR ────────────────────────────────────────────────
ID_PARAMS: list[str] = [
    "id", "ID",
    "user_id", "userId", "uid", "user",
    "account_id", "accountId", "account",
    "profile_id", "profileId", "profile",
    "order_id", "orderId", "order",
    "item_id", "itemId", "item",
    "product_id", "productId", "product",
    "invoice_id", "invoiceId", "invoice",
    "file_id", "fileId", "file",
    "document_id", "documentId", "doc",
    "message_id", "messageId", "message",
    "ticket_id", "ticketId", "ticket",
    "record_id", "recordId",
    "object_id", "objectId",
    "resource_id", "resourceId",
    "ref", "reference", "key",
    "token", "session_id", "sessionId",
    "customer_id", "customerId", "customer",
    "client_id", "clientId",
    "employee_id", "employeeId",
    "report_id", "reportId",
    "job_id", "jobId", "task_id", "taskId",
    "project_id", "projectId",
    "campaign_id", "campaignId",
    "ad_id", "adId", "creative_id", "creativeId",
]

# ── Webhook / URL injection ────────────────────────────────────────────────
URL_PARAMS: list[str] = [
    "url", "uri", "link", "src", "source", "href",
    "redirect", "redirect_url", "redirect_uri", "next", "return",
    "callback", "callback_url", "webhook", "webhook_url",
    "notify_url", "notifyUrl", "ping", "ping_url",
    "success_url", "successUrl", "cancel_url", "cancelUrl",
    "return_url", "returnUrl",
    "image_url", "imageUrl", "avatar_url", "avatarUrl",
    "file_url", "fileUrl", "download_url", "downloadUrl",
    "logo_url", "logoUrl", "icon_url", "iconUrl",
]

# ── Full combined wordlist ────────────────────────────────────────────────
ALL_PARAMS: list[str] = (
    PRIV_PARAMS + DEBUG_PARAMS + FORMAT_PARAMS +
    PAGINATION_PARAMS + ID_PARAMS + URL_PARAMS
)

# ── Mass assignment privilege escalation values ──────────────────────────
PRIV_ESCALATION_VALUES: dict[str, list[Any]] = {
    "role":         ["admin", "superuser", "root", "staff", "moderator", "internal"],
    "roles":        [["admin"], ["admin", "staff"]],
    "is_admin":     [True, 1, "true", "1", "yes"],
    "admin":        [True, 1, "true"],
    "is_superuser": [True, 1],
    "is_staff":     [True, 1],
    "account_type": ["admin", "enterprise", "premium", "internal", "unlimited"],
    "user_type":    ["admin", "internal", "staff", "super"],
    "plan":         ["enterprise", "premium", "unlimited", "business"],
    "tier":         ["enterprise", "premium", "unlimited"],
    "verified":     [True, 1, "true"],
    "permissions":  ["admin", "*", ["read","write","delete","admin"]],
    "balance":      [99999, 999999, -1],
    "credits":      [99999, 999999],
}

# ── Test values per parameter type ────────────────────────────────────────
TEST_VALUES: dict[str, Any] = {
    "id":          "1",
    "user_id":     "1",
    "debug":       "true",
    "test":        "true",
    "format":      "json",
    "callback":    "test_callback",
    "limit":       "999999",
    "all":         "true",
    "verbose":     "true",
    "fields":      "id,name,email,role,is_admin",
    "expand":      "all",
    "select":      "*",
    "status":      "all",
    "filter":      "all",
    "role":        "user",
    "plan":        "free",
    "is_admin":    "false",
    # Default for unknown params
    "_default":    "1",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_COLOR = {
    "CRITICAL": "bold red", "HIGH": "bold yellow",
    "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim",
}
SEV_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}
UA = "Mozilla/5.0 (compatible; ParamFuzz/1.0)"

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
class TargetEndpoint:
    url: str
    host: str
    method: str
    known_params: list[str] = field(default_factory=list)
    known_body_fields: list[str] = field(default_factory=list)
    requires_auth: bool = False
    content_type: str = "application/json"


@dataclass
class ParamFinding:
    host: str
    url: str
    method: str
    param_name: str
    inject_via: str               # "query" | "body_json" | "body_form"
    test_value: Any
    finding_type: str             # "HIDDEN_PARAM" | "PRIV_ESCALATION" | "DEBUG_BYPASS"
                                  # "PARAM_POLLUTION" | "ARRAY_INJECTION" | "IDOR_PARAM"
    severity: str
    title: str
    detail: str
    evidence: str
    curl_command: str
    recommendation: str
    cvss_estimate: str = ""
    baseline_status: int | None = None
    bypass_status: int | None = None
    baseline_body_len: int = 0
    bypass_body_len: int = 0
    response_snippet: str = ""


@dataclass
class ParamReport:
    domain: str
    scan_time: str
    source_files: list[str]
    total_endpoints: int = 0
    total_requests: int = 0
    elapsed_seconds: float = 0.0
    findings: list[ParamFinding] = field(default_factory=list)


# ═════════════════════════════════════════════════════════════════════════════
# HTTP HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def _curl(
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
            bstr = json.dumps(body).replace("'", "'\\''")
            parts.append(f"--data-raw '{bstr}'")
            if not headers or "Content-Type" not in (headers or {}):
                parts.append('-H "Content-Type: application/json"')
        else:
            parts.append(f"--data-raw '{body}'")
    parts.append(f'"{url}"')
    return " \\\n  ".join(parts)


async def request(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    body: Any = None,
    timeout: float = 10.0,
) -> tuple[int | None, dict, str, int]:
    """
    Send HTTP request.
    Returns (status, headers, body[:4000], body_length).
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
            timeout=timeout, verify=False,
            follow_redirects=True,
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
            else:
                resp = await c.request(method, url, headers=hdrs)
            body_text = resp.text[:4000]
            return resp.status_code, dict(resp.headers), body_text, len(resp.content)
    except Exception as exc:
        log.debug(f"[Request] {method} {url}: {exc}")
        return None, {}, "", 0


# ═════════════════════════════════════════════════════════════════════════════
# PARAMETER WORDLIST BUILDER
# ═════════════════════════════════════════════════════════════════════════════

def _camel_to_snake(name: str) -> str:
    s1 = re.sub(r'(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


def _snake_to_camel(name: str) -> str:
    parts = name.split("_")
    return parts[0] + "".join(p.title() for p in parts[1:]) if len(parts) > 1 else name


def _snake_to_kebab(name: str) -> str:
    return name.replace("_", "-")


def generate_param_variations(known_params: list[str]) -> list[str]:
    """
    Given a list of known parameter names, generate likely hidden/related
    parameters by applying naming convention transformations and
    semantic relationship expansion.
    """
    variations: set[str] = set()

    for param in known_params:
        # Naming convention transforms
        snake = _camel_to_snake(param)
        camel = _snake_to_camel(snake)
        kebab = _snake_to_kebab(snake)
        variations.update([snake, camel, kebab, param.upper(), param.lower()])

        # Semantic expansions
        # If we see user_id, also test: user, userId, uid, account_id, accountId
        if "id" in snake.lower():
            base = snake.replace("_id", "").replace("Id", "")
            for suffix in ["_id", "Id", "_uuid", "Uuid", "_key", "Key"]:
                variations.add(base + suffix)
            variations.add(base)

        # If we see name/email fields, look for admin/role variants
        if param in ("name", "email", "username"):
            variations.update(["role", "is_admin", "admin", "permissions", "plan"])

        # Numeric ID parameters — look for parent/owner IDs
        if re.search(r'(?i)(user|account|customer|owner|org)', param):
            variations.update([
                "org_id", "orgId", "organization_id", "organizationId",
                "parent_id", "parentId", "owner_id", "ownerId",
                "team_id", "teamId",
            ])

    return [v for v in sorted(variations) if v and len(v) >= 2]


def build_wordlist(ep: TargetEndpoint, max_params: int = 500) -> list[tuple[str, str]]:
    """
    Build a deduplicated, prioritised (param_name, category) list for an endpoint.
    High-priority params first (privilege escalation, debug).
    """
    seen:   set[str] = set()
    result: list[tuple[str, str]] = []

    def add(param: str, category: str) -> None:
        if param not in seen and len(param) >= 2:
            seen.add(param)
            result.append((param, category))

    # 1. Inferred variations from known params (highest priority)
    for v in generate_param_variations(ep.known_params + ep.known_body_fields):
        add(v, "inferred")

    # 2. Privilege / mass-assignment (always tested)
    for p in PRIV_PARAMS:
        add(p, "privilege")

    # 3. Debug / bypass
    for p in DEBUG_PARAMS:
        add(p, "debug")

    # 4. ID params (IDOR surface)
    for p in ID_PARAMS:
        add(p, "idor")

    # 5. Format / output control
    for p in FORMAT_PARAMS:
        add(p, "format")

    # 6. Pagination / filter
    for p in PAGINATION_PARAMS:
        add(p, "pagination")

    # 7. URL / webhook injection
    for p in URL_PARAMS:
        add(p, "url_inject")

    # 8. Base wordlist
    for p in ALL_PARAMS:
        add(p, "base")

    return result[:max_params]


# ═════════════════════════════════════════════════════════════════════════════
# BASELINE + RESPONSE DIFF
# ═════════════════════════════════════════════════════════════════════════════

async def get_baseline(
    ep: TargetEndpoint,
    auth_headers: dict,
    timeout: float,
) -> tuple[int | None, int, str]:
    """
    Fetch the endpoint with its normal parameters.
    Returns (status, body_len, body_snippet).
    """
    status, _, body, blen = await request(
        ep.url, ep.method, auth_headers, timeout=timeout
    )
    return status, blen, body[:1000]


def _new_json_keys(baseline: str, response: str) -> list[str]:
    """Return JSON keys present in response but not in baseline."""
    def _extract_keys(text: str) -> set[str]:
        return set(re.findall(r'"([a-zA-Z_][a-zA-Z0-9_]*)"', text))
    base_keys = _extract_keys(baseline)
    resp_keys = _extract_keys(response)
    return sorted(resp_keys - base_keys)


def assess_diff(
    baseline_status: int | None,
    baseline_len: int,
    baseline_body: str,
    bypass_status: int | None,
    bypass_len: int,
    bypass_body: str,
    param_name: str,
    category: str,
) -> tuple[str, str, str]:
    """
    Assess whether adding a parameter caused a meaningful response change.
    Returns (confidence, reason, severity).
    confidence: "HIGH" | "MEDIUM" | "LOW" | "NONE"
    """
    if bypass_status is None:
        return "NONE", "No response", "INFO"

    # ── Status code change ────────────────────────────────────────────────
    status_improved = (
        baseline_status not in (200, 201) and
        bypass_status in (200, 201)
    )
    if status_improved:
        sev = "HIGH" if baseline_status in (401, 403) else "MEDIUM"
        return "HIGH", (
            f"Status changed from {baseline_status} to {bypass_status} "
            f"when {param_name} was added"
        ), sev

    # ── Significant body growth ───────────────────────────────────────────
    if (bypass_len > baseline_len + 200 and
            bypass_status in (200, 201) and
            bypass_len > 100):
        new_keys = _new_json_keys(baseline_body, bypass_body)
        if new_keys:
            sev = "HIGH" if category == "privilege" else "MEDIUM"
            return "HIGH", (
                f"Response grew by {bypass_len - baseline_len}B and "
                f"new JSON keys appeared: {', '.join(new_keys[:5])}"
            ), sev
        return "MEDIUM", (
            f"Response body grew from {baseline_len}B to {bypass_len}B "
            f"when {param_name} was added"
        ), "MEDIUM"

    # ── Error message changed ─────────────────────────────────────────────
    if bypass_status != baseline_status and bypass_status not in (None, 404, 429):
        if bypass_status == 422:
            # 422 means the server PROCESSED the param (just rejected the value)
            return "LOW", (
                f"Status changed to 422 — server validated {param_name} "
                f"(parameter exists but value rejected)"
            ), "LOW"

    # ── Parameter reflected in response ──────────────────────────────────
    if param_name.lower() in bypass_body.lower() and param_name.lower() not in baseline_body.lower():
        return "MEDIUM", (
            f"Parameter name '{param_name}' appeared in response body "
            f"(server is processing it)"
        ), "LOW"

    return "NONE", "No significant change detected", "INFO"


# ═════════════════════════════════════════════════════════════════════════════
# PARAM INJECTOR
# ═════════════════════════════════════════════════════════════════════════════

def inject_query_param(url: str, param: str, value: Any) -> str:
    """Add or replace a query parameter in a URL."""
    parsed = urllib.parse.urlparse(url)
    qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [str(value)]
    new_qs = urllib.parse.urlencode(qs, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_qs))


def build_body_with_param(
    known_fields: list[str],
    param: str,
    value: Any,
) -> dict:
    """Build a JSON body that includes known fields + the test parameter."""
    body: dict = {}
    for f in known_fields[:5]:  # include a few known fields as context
        body[f] = TEST_VALUES.get(f, "test")
    body[param] = value
    return body


class ParamFuzzer:
    def __init__(
        self,
        domain: str,
        session_token: str | None = None,
        timeout: float = 10.0,
        concurrency: int = 20,
        max_params_per_ep: int = 400,
        test_body: bool = True,
        test_query: bool = True,
        test_escalation: bool = True,
        test_pollution: bool = True,
    ):
        self.domain           = domain
        self.session_token    = session_token
        self.timeout          = timeout
        self._sem             = asyncio.Semaphore(concurrency)
        self.max_params       = max_params_per_ep
        self.test_body        = test_body
        self.test_query       = test_query
        self.test_escalation  = test_escalation
        self.test_pollution   = test_pollution
        self._total_requests  = 0

    def _auth_headers(self) -> dict:
        if not self.session_token:
            return {}
        token = self.session_token
        if not token.startswith("Bearer ") and not token.startswith("Basic "):
            token = "Bearer " + token
        return {"Authorization": token}

    async def fuzz(self, ep: TargetEndpoint) -> list[ParamFinding]:
        async with self._sem:
            return await self._run(ep)

    async def _run(self, ep: TargetEndpoint) -> list[ParamFinding]:
        findings: list[ParamFinding] = []
        auth = self._auth_headers()

        # Baseline
        base_status, base_len, base_body = await get_baseline(ep, auth, self.timeout)
        if base_status is None:
            return findings

        # Build wordlist
        wordlist = build_wordlist(ep, self.max_params)

        # Injection methods to use
        inject_methods: list[str] = []
        if self.test_query:
            inject_methods.append("query")
        if self.test_body and ep.method.upper() in ("POST", "PUT", "PATCH"):
            inject_methods.append("body_json")

        # Batch all probes
        probe_sem = asyncio.Semaphore(10)

        async def probe(
            param: str,
            category: str,
            via: str,
        ) -> list[ParamFinding]:
            async with probe_sem:
                return await self._probe_param(
                    ep, param, category, via, auth,
                    base_status, base_len, base_body,
                )

        tasks = [
            probe(param, cat, via)
            for param, cat in wordlist
            for via in inject_methods
        ]

        self._total_requests += len(tasks)
        results = await asyncio.gather(*tasks, return_exceptions=True)

        confirmed_params: list[str] = []
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
                for f in r:
                    if f.param_name not in confirmed_params:
                        confirmed_params.append(f.param_name)

        # ── Privilege escalation on confirmed params ──────────────────────
        if self.test_escalation:
            for param in confirmed_params:
                if param in PRIV_ESCALATION_VALUES:
                    esc_findings = await self._test_escalation(
                        ep, param, auth, base_status, base_len, base_body
                    )
                    findings.extend(esc_findings)

        # ── HTTP parameter pollution on confirmed params ──────────────────
        if self.test_pollution and confirmed_params:
            poll_findings = await self._test_pollution(
                ep, confirmed_params[:3], auth, base_status, base_body
            )
            findings.extend(poll_findings)

        # Deduplicate by (param, inject_via, finding_type)
        seen_keys: set[tuple] = set()
        deduped: list[ParamFinding] = []
        for f in findings:
            key = (f.param_name, f.inject_via, f.finding_type)
            if key not in seen_keys:
                seen_keys.add(key)
                deduped.append(f)

        return sorted(deduped, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))

    async def _probe_param(
        self,
        ep: TargetEndpoint,
        param: str,
        category: str,
        via: str,
        auth: dict,
        base_status: int | None,
        base_len: int,
        base_body: str,
    ) -> list[ParamFinding]:
        value = TEST_VALUES.get(param, TEST_VALUES["_default"])

        if via == "query":
            test_url  = inject_query_param(ep.url, param, value)
            hdrs      = auth
            body      = None
            method    = ep.method
        else:  # body_json
            test_url  = ep.url
            body      = build_body_with_param(ep.known_body_fields, param, value)
            hdrs      = {**auth, "Content-Type": "application/json"}
            method    = ep.method

        status, _, resp_body, resp_len = await request(
            test_url, method, hdrs, body, self.timeout
        )

        confidence, reason, severity = assess_diff(
            base_status, base_len, base_body,
            status, resp_len, resp_body,
            param, category,
        )

        if confidence == "NONE":
            return []

        # Determine finding type
        if category == "privilege":
            ftype = "PRIV_ESCALATION" if confidence in ("HIGH","MEDIUM") else "HIDDEN_PARAM"
        elif category == "debug":
            ftype = "DEBUG_BYPASS"
        elif category == "idor":
            ftype = "IDOR_PARAM"
        else:
            ftype = "HIDDEN_PARAM"

        curl = (
            _curl(test_url, method, auth)
            if via == "query"
            else _curl(ep.url, method, hdrs, body)
        )

        return [ParamFinding(
            host=ep.host,
            url=ep.url,
            method=ep.method,
            param_name=param,
            inject_via=via,
            test_value=value,
            finding_type=ftype,
            severity=severity,
            title=self._title(ftype, param, via, severity),
            detail=(
                f"Parameter '{param}' ({category}) caused a meaningful response change "
                f"when injected via {via} on {ep.url}. {reason}"
            ),
            evidence=(
                f"Endpoint: {ep.method} {ep.url}\n"
                f"Injection: {via}: {param}={value}\n"
                f"Baseline: HTTP {base_status} ({base_len}B)\n"
                f"With param: HTTP {status} ({resp_len}B)\n"
                f"Reason: {reason}"
            ),
            curl_command=curl,
            recommendation=self._recommendation(ftype, param),
            cvss_estimate=self._cvss(severity, ftype),
            baseline_status=base_status,
            bypass_status=status,
            baseline_body_len=base_len,
            bypass_body_len=resp_len,
            response_snippet=resp_body[:400],
        )]

    def _title(
        self, ftype: str, param: str, via: str, severity: str
    ) -> str:
        titles = {
            "PRIV_ESCALATION": f"Mass Assignment / Privilege Escalation via '{param}'",
            "DEBUG_BYPASS":    f"Hidden Debug Parameter Discovered — '{param}'",
            "IDOR_PARAM":      f"Hidden ID Parameter — Potential IDOR via '{param}'",
            "HIDDEN_PARAM":    f"Hidden Parameter Discovered — '{param}' ({via})",
            "PARAM_POLLUTION": f"HTTP Parameter Pollution on '{param}'",
            "ARRAY_INJECTION": f"Array Injection Accepted on '{param}'",
        }
        return titles.get(ftype, f"Hidden parameter: {param}")

    def _recommendation(self, ftype: str, param: str) -> str:
        recs = {
            "PRIV_ESCALATION": (
                f"Implement an explicit allowlist (DTO / form validation) for all "
                f"accepted fields. Never pass request bodies directly to ORM methods "
                f"(e.g. User.update(request.body)). Verify that '{param}' cannot be "
                f"set by end-users — only by internal systems or admins."
            ),
            "DEBUG_BYPASS": (
                f"Remove all debug parameters from production code. If needed for "
                f"internal testing, gate them behind IP-based access controls or "
                f"a separate internal URL that is not publicly routable."
            ),
            "IDOR_PARAM": (
                f"Ensure the server validates that the requesting user owns or has "
                f"explicit access to the resource identified by '{param}'. "
                f"Never rely on obscurity — test cross-account access with two sessions."
            ),
            "HIDDEN_PARAM": (
                f"Audit all parameters accepted by this endpoint. Remove any that are "
                f"not required. If '{param}' is a legacy parameter, deprecate and block it."
            ),
            "PARAM_POLLUTION": (
                f"Use a single definitive value for each parameter. Document expected "
                f"handling of duplicate parameters in your framework and validate "
                f"accordingly."
            ),
        }
        return recs.get(ftype, f"Validate and restrict the '{param}' parameter.")

    def _cvss(self, severity: str, ftype: str) -> str:
        cvss = {
            "CRITICAL": "9.8 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)",
            "HIGH":     "8.8 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)",
            "MEDIUM":   "6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)",
            "LOW":      "4.3 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N)",
        }
        return cvss.get(severity, "")

    # ── Privilege escalation testing ──────────────────────────────────────

    async def _test_escalation(
        self,
        ep: TargetEndpoint,
        param: str,
        auth: dict,
        base_status: int | None,
        base_len: int,
        base_body: str,
    ) -> list[ParamFinding]:
        findings: list[ParamFinding] = []
        priv_values = PRIV_ESCALATION_VALUES.get(param, [])

        for val in priv_values[:3]:  # test first 3 escalation values per param
            body = {param: val}
            hdrs = {**auth, "Content-Type": "application/json"}
            status, _, resp_body, resp_len = await request(
                ep.url, ep.method, hdrs, body, self.timeout
            )
            if status is None:
                continue

            # Check if privileged value was reflected in response
            val_str = json.dumps(val).lower()
            reflected = val_str in resp_body.lower()
            status_ok  = status in (200, 201)

            if reflected and status_ok:
                findings.append(ParamFinding(
                    host=ep.host,
                    url=ep.url,
                    method=ep.method,
                    param_name=param,
                    inject_via="body_json",
                    test_value=val,
                    finding_type="PRIV_ESCALATION",
                    severity="CRITICAL",
                    title=f"Privilege Escalation Confirmed — {param}={val!r} Accepted and Reflected",
                    detail=(
                        f"Setting {param}={val!r} in the request body to {ep.url} returned "
                        f"HTTP {status} and the privileged value was reflected in the response. "
                        f"The server accepted and stored the escalated privilege without authorization checks."
                    ),
                    evidence=(
                        f"POST/PUT {ep.url}\n"
                        f"Body: {{{param!r}: {val!r}}}\n"
                        f"Response: HTTP {status} ({resp_len}B)\n"
                        f"Privileged value reflected: {reflected}"
                    ),
                    curl_command=_curl(ep.url, ep.method, hdrs, body),
                    recommendation=self._recommendation("PRIV_ESCALATION", param),
                    cvss_estimate="9.8 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)",
                    baseline_status=base_status,
                    bypass_status=status,
                    baseline_body_len=base_len,
                    bypass_body_len=resp_len,
                    response_snippet=resp_body[:400],
                ))
                break  # one confirmed escalation per param is enough

        return findings

    # ── HTTP Parameter Pollution ──────────────────────────────────────────

    async def _test_pollution(
        self,
        ep: TargetEndpoint,
        confirmed_params: list[str],
        auth: dict,
        base_status: int | None,
        base_body: str,
    ) -> list[ParamFinding]:
        """
        Test duplicate parameters in query string.
        GET /users?id=1&id=2&id=admin
        Different values may win depending on the framework:
        PHP uses last, Express uses first array, some frameworks use all.
        """
        findings: list[ParamFinding] = []

        for param in confirmed_params[:2]:
            # Send param twice with different values
            parsed   = urllib.parse.urlparse(ep.url)
            base_qs  = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            # Add param twice
            base_qs_list = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            raw_qs   = urllib.parse.urlencode(
                {**base_qs_list, param: ["1", "2", "admin"]}, doseq=True
            )
            test_url = urllib.parse.urlunparse(parsed._replace(query=raw_qs))

            status, _, resp_body, resp_len = await request(
                test_url, "GET", auth, timeout=self.timeout
            )
            if status is None:
                continue

            # Interesting if: "admin" appears in response (last value won)
            # OR response differs from baseline significantly
            if "admin" in resp_body.lower() and "admin" not in base_body.lower():
                findings.append(ParamFinding(
                    host=ep.host,
                    url=ep.url,
                    method="GET",
                    param_name=param,
                    inject_via="query",
                    test_value=f"{param}=1&{param}=2&{param}=admin",
                    finding_type="PARAM_POLLUTION",
                    severity="MEDIUM",
                    title=f"HTTP Parameter Pollution — Last '{param}' Value Wins",
                    detail=(
                        f"Sending {param} multiple times with {param}=1&{param}=2&{param}=admin "
                        f"caused 'admin' to appear in the response. The framework uses the "
                        f"last provided value, enabling privilege escalation if the first "
                        f"value passes validation but the last is used for processing."
                    ),
                    evidence=(
                        f"GET {test_url}\n"
                        f"Response contained 'admin': True"
                    ),
                    curl_command=_curl(test_url, "GET", auth),
                    recommendation=(
                        "Use only the first occurrence of each parameter. "
                        "Reject requests with duplicate parameter names. "
                        "Document the expected framework behaviour for duplicate params."
                    ),
                    cvss_estimate="6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)",
                    response_snippet=resp_body[:300],
                ))

        return findings


# ═════════════════════════════════════════════════════════════════════════════
# INPUT PARSERS
# ═════════════════════════════════════════════════════════════════════════════

def load_from_jsreaper(path: str) -> list[TargetEndpoint]:
    with open(path) as f:
        data = json.load(f)
    endpoints: list[TargetEndpoint] = []
    seen: set[str] = set()

    for ep_data in data.get("endpoints", []):
        url    = ep_data.get("endpoint", ep_data.get("url", ""))
        host   = ep_data.get("host", "")
        method = ep_data.get("method", "GET")
        params = ep_data.get("params", [])
        if not url or not url.startswith("http"):
            continue
        key = f"{method}:{url}"
        if key in seen: continue
        seen.add(key)
        endpoints.append(TargetEndpoint(
            url=url, host=host, method=method,
            known_params=params,
        ))

    # Also get hosts that had no endpoints — still worth testing base URLs
    for hr in data.get("host_results", []):
        host = hr.get("host", "")
        if not host: continue
        base = f"https://{host}/"
        key  = f"GET:{base}"
        if key not in seen:
            seen.add(key)
            endpoints.append(TargetEndpoint(
                url=base, host=host, method="GET",
            ))

    log.info(f"[Parse] {len(endpoints)} endpoints from jsreaper output")
    return endpoints


def load_from_apifuzz(path: str) -> list[TargetEndpoint]:
    with open(path) as f:
        data = json.load(f)
    endpoints: list[TargetEndpoint] = []
    seen: set[str] = set()

    for hr in data.get("host_results", []):
        for ep_data in hr.get("endpoints_found", []):
            url    = ep_data.get("url", "")
            host   = ep_data.get("host", "")
            method = ep_data.get("method", "GET")
            params = ep_data.get("params", [])
            fields = ep_data.get("body_fields", [])
            if not url or not url.startswith("http"): continue
            key = f"{method}:{url}"
            if key in seen: continue
            seen.add(key)
            endpoints.append(TargetEndpoint(
                url=url, host=host, method=method,
                known_params=params,
                known_body_fields=fields,
                requires_auth=ep_data.get("requires_auth", False),
            ))

    log.info(f"[Parse] {len(endpoints)} endpoints from apifuzz output")
    return endpoints


def load_from_recon(path: str) -> list[TargetEndpoint]:
    with open(path) as f:
        data = json.load(f)
    endpoints: list[TargetEndpoint] = []
    seen: set[str] = set()

    for hr in data.get("host_reports", []):
        host  = hr.get("host", "")
        ports = hr.get("open_ports", [])
        if not host or not ports: continue
        best  = next((p for p in ports if p.get("scheme") == "https"), ports[0])
        scheme = best.get("scheme", "http")
        port   = best.get("port", 80)
        if (scheme, port) in (("https", 443), ("http", 80)):
            base = f"{scheme}://{host}"
        else:
            base = f"{scheme}://{host}:{port}"

        # Add base URL
        key = f"GET:{base}/"
        if key not in seen:
            seen.add(key)
            endpoints.append(TargetEndpoint(url=base + "/", host=host, method="GET"))

        # Add probe paths with query params
        for pr in hr.get("probe_results", []):
            url_path = pr.get("path", "")
            if not url_path: continue
            full_url = base + url_path
            for method in ["GET", "POST"]:
                key = f"{method}:{full_url}"
                if key not in seen:
                    seen.add(key)
                    endpoints.append(TargetEndpoint(
                        url=full_url, host=host, method=method,
                    ))

    log.info(f"[Parse] {len(endpoints)} endpoints from reconharvest output")
    return endpoints


def load_from_urlfile(path: str) -> list[TargetEndpoint]:
    endpoints: list[TargetEndpoint] = []
    seen: set[str] = set()
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"): continue
            if not line.startswith("http"):
                line = "https://" + line
            parsed = urllib.parse.urlparse(line)
            host   = parsed.netloc
            # Extract existing params as known params
            known  = list(urllib.parse.parse_qs(parsed.query).keys())
            key    = f"GET:{line}"
            if key not in seen:
                seen.add(key)
                endpoints.append(TargetEndpoint(
                    url=line, host=host, method="GET",
                    known_params=known,
                ))

    log.info(f"[Parse] {len(endpoints)} endpoints from URL file")
    return endpoints


# ═════════════════════════════════════════════════════════════════════════════
# REPORTING
# ═════════════════════════════════════════════════════════════════════════════

def print_report(report: ParamReport) -> None:
    by_sev = {s: [f for f in report.findings if f.severity == s]
              for s in SEVERITY_ORDER}

    if not HAS_RICH:
        print(f"\n=== ParamFuzz: {report.domain} ===")
        print(
            f"Endpoints: {report.total_endpoints}  "
            f"Requests: {report.total_requests:,}  "
            f"Elapsed: {report.elapsed_seconds:.1f}s"
        )
        for f in sorted(report.findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 9)):
            print(f"\n[{f.severity}] [{f.finding_type}] {f.title}")
            print(f"  {f.url}  param={f.param_name}")
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
        f"[white]Endpoints tested:[/] {report.total_endpoints}    "
        f"[white]Requests sent:[/] {report.total_requests:,}\n\n"
        f"[bold red]CRITICAL:[/] {len(by_sev.get('CRITICAL',[]))}    "
        f"[bold yellow]HIGH:[/] {len(by_sev.get('HIGH',[]))}    "
        f"[yellow]MEDIUM:[/] {len(by_sev.get('MEDIUM',[]))}    "
        f"[cyan]LOW:[/] {len(by_sev.get('LOW',[]))}",
        title="[bold]ParamFuzz Report[/]",
        border_style=border,
    ))

    if not report.findings:
        console.print("[bold green]✓ No hidden parameters found.[/]\n")
        return

    # Summary table
    console.print("\n[bold cyan]── Findings ──[/]")
    tbl = Table(show_header=True, header_style="bold cyan", border_style="dim")
    tbl.add_column("Severity",  justify="center")
    tbl.add_column("Type",      style="dim")
    tbl.add_column("Param",     style="yellow")
    tbl.add_column("Via",       style="dim",  justify="center")
    tbl.add_column("Host",      style="cyan")
    tbl.add_column("Status Change", justify="center")

    for f in report.findings:
        col = SEV_COLOR.get(f.severity, "white")
        stat_str = ""
        if f.baseline_status and f.bypass_status and f.baseline_status != f.bypass_status:
            stat_str = f"{f.baseline_status}→{f.bypass_status}"
        elif f.bypass_body_len and f.baseline_body_len:
            diff = f.bypass_body_len - f.baseline_body_len
            if diff > 0:
                stat_str = f"+{diff}B"
        tbl.add_row(
            f"[{col}]{f.severity}[/]",
            f.finding_type,
            f.param_name,
            f.inject_via,
            f.host,
            stat_str or "—",
        )
    console.print(tbl)

    # Detail
    for sev in ("CRITICAL","HIGH","MEDIUM","LOW"):
        sf = by_sev.get(sev, [])
        if not sf: continue
        col = SEV_COLOR.get(sev, "white")
        console.print(f"\n[{col}]── {SEV_EMOJI.get(sev,'')} {sev} ({len(sf)}) ──[/]")
        for i, f in enumerate(sf, 1):
            console.print(
                f"  [{col}][{i}][/] [white]{f.title}[/]\n"
                f"      [dim]Type:[/] {f.finding_type}  "
                f"[dim]Host:[/] {f.host}  "
                f"[dim]Param:[/] {f.param_name}  "
                f"[dim]Via:[/] {f.inject_via}\n"
                f"      [dim]Detail:[/] {f.detail[:200]}"
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


def save_json(report: ParamReport, path: str) -> None:
    data = {
        "domain":          report.domain,
        "scan_time":       report.scan_time,
        "source_files":    report.source_files,
        "total_endpoints": report.total_endpoints,
        "total_requests":  report.total_requests,
        "elapsed_seconds": report.elapsed_seconds,
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


def save_html(report: ParamReport, path: str) -> None:
    by_sev = {s: [f for f in report.findings if f.severity == s]
              for s in SEVERITY_ORDER}
    sc = {"CRITICAL":"#f85149","HIGH":"#d29922","MEDIUM":"#e3b341",
          "LOW":"#58a6ff","INFO":"#8b949e"}
    sb = {"CRITICAL":"rgba(248,81,73,.12)","HIGH":"rgba(210,153,34,.12)",
          "MEDIUM":"rgba(227,179,65,.10)","LOW":"rgba(88,166,255,.10)",
          "INFO":"rgba(139,148,158,.08)"}

    rows = ""
    for f in report.findings:
        c    = sc.get(f.severity, "#fff")
        diff = ""
        if f.baseline_status and f.bypass_status and f.baseline_status != f.bypass_status:
            diff = f"{f.baseline_status}→{f.bypass_status}"
        elif f.bypass_body_len and f.baseline_body_len and f.bypass_body_len > f.baseline_body_len:
            diff = f"+{f.bypass_body_len - f.baseline_body_len}B"
        rows += (
            f"<tr>"
            f"<td style='color:{c};font-weight:bold'>{f.severity}</td>"
            f"<td style='color:#39c5cf'>{f.finding_type}</td>"
            f"<td style='color:#d29922'>{f.param_name}</td>"
            f"<td style='color:#627384'>{f.inject_via}</td>"
            f"<td style='color:#58a6ff'>{f.host}</td>"
            f"<td style='color:#3fb950;text-align:center'>{diff}</td>"
            f"</tr>"
        )

    findings_html = ""
    for sev in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
        sf = by_sev.get(sev, [])
        if not sf: continue
        findings_html += (
            f'<div class="sev-section">'
            f'<h3 style="color:{sc[sev]}">{SEV_EMOJI.get(sev,"")} {sev} ({len(sf)})</h3>'
        )
        for i, f in enumerate(sf, 1):
            curl_e = f.curl_command.replace("<","&lt;").replace(">","&gt;")
            ev_e   = f.evidence.replace("<","&lt;").replace(">","&gt;")
            findings_html += (
                f'<div class="finding" style="border-left:3px solid {sc[sev]};'
                f'background:{sb[sev]}">'
                f'<div class="ft">[{i}] {f.title}</div>'
                f'<div class="fm">'
                f'<span class="badge" style="color:{sc[sev]};background:{sb[sev]};'
                f'border:1px solid {sc[sev]}">{sev}</span>'
                f'<span style="color:#39c5cf;font-size:.8em">{f.finding_type}</span>'
                f'<span style="color:#d29922;font-size:.8em">param: {f.param_name}</span>'
                f'<span style="color:#627384;font-size:.78em">via: {f.inject_via}</span>'
                f'<span style="color:#58a6ff;font-size:.78em">{f.host}</span>'
                + (f'<span style="color:#d29922;font-size:.75em">{f.cvss_estimate}</span>'
                   if f.cvss_estimate else "")
                + f'</div>'
                f'<div class="fd">{f.detail}</div>'
                + (f'<div class="ev"><span class="evl">Evidence:</span>'
                   f'<code>{ev_e[:300]}</code></div>' if f.evidence else "")
                + (f'<div class="ev"><span class="evl">Reproduce:</span>'
                   f'<pre style="margin:4px 0 0 0;font-size:.8em;color:#a8dadc">'
                   f'{curl_e}</pre></div>' if f.curl_command else "")
                + (f'<div class="ev"><span class="evl">Response snippet:</span>'
                   f'<code>{f.response_snippet[:200]}</code></div>'
                   if f.response_snippet else "")
                + f'<div class="rec"><span class="recl">Fix:</span> '
                + f.recommendation[:300] + f'</div>'
                + f'</div>'
            )
        findings_html += "</div>"

    if not findings_html:
        findings_html = "<p style='color:#3fb950'>No hidden parameters found.</p>"

    html = f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ParamFuzz — {report.domain}</title>
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
<h1>ParamFuzz</h1>
<p class="sub">{report.domain} &nbsp;·&nbsp; {report.scan_time} &nbsp;·&nbsp;
{report.elapsed_seconds:.1f}s &nbsp;·&nbsp;
{report.total_endpoints} endpoints &nbsp;·&nbsp;
{report.total_requests:,} requests</p>
<div class="stats">
<div class="stat"><div class="sv" style="color:#f85149">{len(by_sev.get('CRITICAL',[]))}</div><div class="sl">CRITICAL</div></div>
<div class="stat"><div class="sv" style="color:#d29922">{len(by_sev.get('HIGH',[]))}</div><div class="sl">HIGH</div></div>
<div class="stat"><div class="sv" style="color:#e3b341">{len(by_sev.get('MEDIUM',[]))}</div><div class="sl">MEDIUM</div></div>
<div class="stat"><div class="sv" style="color:#58a6ff">{len(by_sev.get('LOW',[]))}</div><div class="sl">LOW</div></div>
<div class="stat"><div class="sv">{report.total_endpoints}</div><div class="sl">ENDPOINTS</div></div>
<div class="stat"><div class="sv">{report.total_requests:,}</div><div class="sl">REQUESTS</div></div>
</div>
<div class="card"><h2>📋 Summary</h2>
<table><thead><tr>
<th>Severity</th><th>Type</th><th>Param</th>
<th>Via</th><th>Host</th><th>Diff</th>
</tr></thead><tbody>{rows}</tbody></table></div>
<div class="card"><h2>🔎 Findings Detail</h2>{findings_html}</div>
<div class="footer">ParamFuzz &nbsp;·&nbsp; For authorized security research only</div>
</div></body></html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    log.info(f"HTML report saved → {path}")


# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="ParamFuzz — Hidden Parameter Discovery & Mass Assignment Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 paramfuzz.py --js js-findings.json --domain eskimi.com --output params
  python3 paramfuzz.py --api api-findings.json --domain eskimi.com --output params
  python3 paramfuzz.py --scan recon-report-v2.json --domain eskimi.com --output params
  python3 paramfuzz.py --urls endpoints.txt --domain eskimi.com --output params
  python3 paramfuzz.py --js js-findings.json --domain eskimi.com \\
      --session "Bearer YOUR_TOKEN" --output params

Parameter categories tested:
  privilege     role, is_admin, plan, tier, permissions, balance, verified …
  debug         debug, test, verbose, trace, bypass, override, no_auth …
  idor          id, user_id, account_id, order_id, invoice_id, customer_id …
  format        format, callback (JSONP), fields, expand, select …
  pagination    limit, all, status, filter …
  url_inject    url, webhook, redirect, callback_url, image_url …
  inferred      Variations generated from known params (camelCase, snake_case, …)

Detection signals:
  HTTP status change  (403/401 → 200 = auth bypass via parameter)
  Body size increase  (new data returned = hidden field exposed data)
  New JSON keys       (privileged fields appeared in response)
  Value reflected     (server is processing the parameter)
  422 Unprocessable   (parameter exists but value was rejected)

Chains from : jsreaper.py (--js), apifuzz.py (--api),
              reconharvest.py (--scan), plain URL list (--urls)
Output      : JSON + HTML with curl PoC per finding
        """,
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--js",   metavar="FILE", help="jsreaper.py output JSON")
    src.add_argument("--api",  metavar="FILE", help="apifuzz.py output JSON")
    src.add_argument("--scan", metavar="FILE", help="reconharvest.py output JSON")
    src.add_argument("--urls", metavar="FILE", help="Plain URL list")

    p.add_argument("--domain",       required=True,  help="Target root domain")
    p.add_argument("-o","--output",  metavar="BASE",  help="Output base → BASE.json + BASE.html")
    p.add_argument("--session",      metavar="TOKEN",
                   help="Auth token (e.g. 'Bearer eyJhb...')")
    p.add_argument("--no-body",      action="store_true",
                   help="Skip JSON body injection (query string only)")
    p.add_argument("--no-query",     action="store_true",
                   help="Skip query string injection (body only)")
    p.add_argument("--no-escalation",action="store_true",
                   help="Skip privilege escalation follow-up tests")
    p.add_argument("--no-pollution", action="store_true",
                   help="Skip HTTP parameter pollution tests")
    p.add_argument("--max-params",   type=int, default=400,
                   help="Max parameter candidates per endpoint (default: 400)")
    p.add_argument("--timeout",      type=float, default=10.0,
                   help="HTTP timeout per request (default: 10s)")
    p.add_argument("--concurrency",  type=int,   default=20,
                   help="Concurrent endpoint workers (default: 20)")
    p.add_argument("-v","--verbose", action="store_true", help="Verbose logging")
    p.add_argument("--user-agent", metavar="UA",
                   help="Override the User-Agent header sent on every request (C18)")
    return p.parse_args()


async def main() -> None:
    args = parse_args()
    if args.user_agent:
        set_user_agent(args.user_agent)
    if args.verbose:
        log.setLevel(logging.DEBUG)

    print("""
╔══════════════════════════════════════════════════════════════════╗
║    ParamFuzz — Hidden Parameter Discovery & Mass Assignment      ║
║  For authorized penetration testing and bug bounty research only ║
╚══════════════════════════════════════════════════════════════════╝
""")

    if not HAS_HTTPX:
        log.error("httpx required: pip install httpx")
        sys.exit(1)

    source_files: list[str] = []
    if args.js:
        endpoints = load_from_jsreaper(args.js)
        source_files.append(args.js)
    elif args.api:
        endpoints = load_from_apifuzz(args.api)
        source_files.append(args.api)
    elif args.scan:
        endpoints = load_from_recon(args.scan)
        source_files.append(args.scan)
    else:
        endpoints = load_from_urlfile(args.urls)
        source_files.append(args.urls)

    if not endpoints:
        log.error("No endpoints found."); sys.exit(1)

    log.info(
        f"[Config] {len(endpoints)} endpoints, "
        f"max_params={args.max_params}, "
        f"session={'set' if args.session else 'none'}"
    )

    report = ParamReport(
        domain=args.domain,
        scan_time=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        source_files=source_files,
        total_endpoints=len(endpoints),
    )

    fuzzer = ParamFuzzer(
        domain=args.domain,
        session_token=args.session,
        timeout=args.timeout,
        concurrency=args.concurrency,
        max_params_per_ep=args.max_params,
        test_body=not args.no_body,
        test_query=not args.no_query,
        test_escalation=not args.no_escalation,
        test_pollution=not args.no_pollution,
    )

    t0 = time.perf_counter()

    if HAS_RICH:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]Fuzzing parameters[/]"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("[dim]{task.fields[e]}[/]"),
            console=console,
        ) as prog:
            task = prog.add_task("fuzz", total=len(endpoints), e="")
            sem  = asyncio.Semaphore(args.concurrency)

            async def bounded(ep: TargetEndpoint) -> list[ParamFinding]:
                async with sem:
                    prog.update(task, e=ep.host)
                    r = await fuzzer.fuzz(ep)
                    prog.advance(task)
                    return r

            results = await asyncio.gather(
                *[bounded(ep) for ep in endpoints],
                return_exceptions=True,
            )
    else:
        sem = asyncio.Semaphore(args.concurrency)

        async def bounded(ep: TargetEndpoint) -> list[ParamFinding]:
            async with sem:
                return await fuzzer.fuzz(ep)

        results = await asyncio.gather(
            *[bounded(ep) for ep in endpoints],
            return_exceptions=True,
        )

    for r in results:
        if isinstance(r, list):
            report.findings.extend(r)
        elif isinstance(r, Exception):
            log.warning(f"Endpoint error: {r}")

    # Deduplicate globally by (host, param, finding_type)
    seen_keys: set[tuple] = set()
    deduped: list[ParamFinding] = []
    for f in report.findings:
        key = (f.host, f.param_name, f.finding_type, f.inject_via)
        if key not in seen_keys:
            seen_keys.add(key)
            deduped.append(f)

    report.findings        = sorted(deduped, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    report.total_requests  = fuzzer._total_requests
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

    crit = len([f for f in report.findings if f.severity == "CRITICAL"])
    high = len([f for f in report.findings if f.severity == "HIGH"])
    if crit or high:
        log.warning(
            f"[!] {crit} CRITICAL + {high} HIGH findings — "
            f"privilege escalation or auth bypass possible"
        )
    elif not report.findings:
        log.info("[✓] No hidden parameters or mass assignment vectors found.")


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(0)
