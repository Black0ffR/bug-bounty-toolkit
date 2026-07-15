#!/usr/bin/env python3
"""
nuclei-harvest.py — Intelligent Nuclei Wrapper & Bug Bounty Report Generator
=============================================================================
Author  : RareKez / security research tooling
License : MIT (for authorized use only)

Chains from : ALL previous tools in the pipeline
              subtakeover.py  → scan.json
              reconharvest.py → recon-report-v2.json
              jsreaper.py     → js-findings.json
              headeraudit.py  → headers.json
              4xxbypass.py    → bypass.json
              apifuzz.py      → api-findings.json
              cloudexpose.py  → cloud-findings.json
              ssrfprobe.py    → ssrf-findings.json
              oauthprobe.py   → oauth-findings.json
              gitdump.py      → git-findings.json
              paramfuzz.py    → params.json

Pipeline:
  1. Aggregate all findings from every pipeline tool (JSON merge)
  2. Deduplicate by (host, vulnerability_class, evidence_key)
  3. Correlate: find findings on the same host that chain together
     (e.g. subdomain takeover + OAuth redirect_uri = CRITICAL escalation)
  4. Map each finding to a CWE, CVSS score, and bug bounty impact tier
  5. Run Nuclei (if installed) with service-specific template selection:
       - Jenkins → nuclei -t cves/jenkins/ -t default-logins/jenkins/
       - Grafana  → nuclei -t cves/grafana/ -t default-logins/grafana/
       - Generic  → exposed-panels, misconfiguration, info (no fuzzing/dos)
  6. Merge Nuclei output with pipeline findings
  7. Score and rank all findings for submission order (payout potential)
  8. Generate formatted bug bounty reports:
       - HackerOne Markdown format
       - Bugcrowd plain text format
       - Generic JSON for any platform
       - HTML dashboard with full finding detail
  9. Produce remediation tracking spreadsheet (CSV)
 10. Group duplicate findings across hosts into a single combined report

Usage:
  python3 nuclei-harvest.py --domain eskimi.com --output final
  python3 nuclei-harvest.py --domain eskimi.com --all-findings findings/ --output final
  python3 nuclei-harvest.py --domain eskimi.com \\
      --scan recon-report-v2.json \\
      --js js-findings.json \\
      --headers headers.json \\
      --bypass bypass.json \\
      --api api-findings.json \\
      --cloud cloud-findings.json \\
      --ssrf ssrf-findings.json \\
      --oauth oauth-findings.json \\
      --git git-findings.json \\
      --params params.json \\
      --nuclei-output nuclei-raw.json \\
      --output final

LEGAL: Only use against targets you have explicit written authorization to test.
"""

from __future__ import annotations

import argparse
import csv
import datetime
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.markup import escape
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False
    console = None

import logging
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger("nuclei-harvest")


# ═════════════════════════════════════════════════════════════════════════════
# VULNERABILITY CLASSIFICATION
# Maps each tool's finding type to CWE, impact tier, payout range
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class VulnClass:
    name: str
    cwe: str
    cvss_base: float
    severity: str
    impact_tier: str          # P1 / P2 / P3 / P4 / P5 (bug bounty tiers)
    typical_payout: str       # typical range on major programs
    owasp: str                # OWASP Top 10 2021 category
    description: str


VULN_CLASSES: dict[str, VulnClass] = {
    # ── Critical ─────────────────────────────────────────────────────────
    "SUBDOMAIN_TAKEOVER": VulnClass(
        "Subdomain Takeover", "CWE-290", 9.3, "CRITICAL", "P1",
        "$500–$10,000",
        "A05:2021-Security Misconfiguration",
        "Attacker takes control of a subdomain to phish users or steal auth tokens",
    ),
    "GIT_EXPOSED": VulnClass(
        "Exposed Git Repository", "CWE-538", 9.1, "CRITICAL", "P1",
        "$500–$5,000",
        "A02:2021-Cryptographic Failures",
        "Source code and credentials leaked via exposed .git directory",
    ),
    "JWT_NONE": VulnClass(
        "JWT Algorithm Confusion (none)", "CWE-347", 9.1, "CRITICAL", "P1",
        "$2,000–$20,000",
        "A02:2021-Cryptographic Failures",
        "JWT tokens can be forged by setting alg=none",
    ),
    "PRIV_ESCALATION": VulnClass(
        "Privilege Escalation / Mass Assignment", "CWE-269", 9.0, "CRITICAL", "P1",
        "$1,000–$15,000",
        "A03:2021-Injection",
        "User can set privileged fields (role=admin) via unvalidated request body",
    ),
    "SSRF_CLOUD_METADATA": VulnClass(
        "SSRF to Cloud Metadata", "CWE-918", 9.8, "CRITICAL", "P1",
        "$3,000–$30,000",
        "A10:2021-Server-Side Request Forgery",
        "SSRF reaching cloud instance metadata exposes IAM credentials",
    ),
    "OAUTH_REDIRECT_TAKEOVER": VulnClass(
        "OAuth redirect_uri + Subdomain Takeover", "CWE-601", 9.6, "CRITICAL", "P1",
        "$5,000–$50,000",
        "A01:2021-Broken Access Control",
        "Chained: takeover + redirect_uri bypass = steal auth codes from any user",
    ),
    "DYNAMIC_REGISTRATION": VulnClass(
        "Unauthenticated OAuth Client Registration", "CWE-306", 9.1, "CRITICAL", "P1",
        "$2,000–$20,000",
        "A07:2021-Identification and Authentication Failures",
        "Attacker registers evil.com as a valid OAuth redirect_uri",
    ),
    "FIREBASE_WRITE": VulnClass(
        "Firebase Unauthenticated Write", "CWE-284", 9.8, "CRITICAL", "P1",
        "$1,000–$10,000",
        "A01:2021-Broken Access Control",
        "Firebase database allows unauthenticated data modification",
    ),
    "S3_WRITE": VulnClass(
        "S3 Bucket Publicly Writable", "CWE-284", 9.1, "CRITICAL", "P1",
        "$500–$5,000",
        "A05:2021-Security Misconfiguration",
        "Unauthenticated PUT to S3 enables content injection and supply chain risk",
    ),
    "DB_EXPOSED_UNAUTH": VulnClass(
        "Unauthenticated Database Exposed", "CWE-306", 9.8, "CRITICAL", "P1",
        "$1,000–$20,000",
        "A05:2021-Security Misconfiguration",
        "Database (Redis, MongoDB, Elasticsearch) accessible without auth",
    ),
    "SECRET_IN_GIT": VulnClass(
        "Credential Exposed in Git History", "CWE-312", 9.8, "CRITICAL", "P1",
        "$500–$10,000",
        "A02:2021-Cryptographic Failures",
        "API key, password or private key found in git repository or history",
    ),

    # ── High ─────────────────────────────────────────────────────────────
    "BOLA_CONFIRMED": VulnClass(
        "BOLA / IDOR (Cross-User Confirmed)", "CWE-639", 8.8, "HIGH", "P2",
        "$500–$10,000",
        "A01:2021-Broken Access Control",
        "Confirmed cross-user object access with two sessions",
    ),
    "BOLA_POSSIBLE": VulnClass(
        "Possible IDOR (Single Session)", "CWE-639", 7.5, "HIGH", "P2",
        "$200–$5,000",
        "A01:2021-Broken Access Control",
        "Predictable ID access returned data — needs cross-session verification",
    ),
    "AUTH_BYPASS": VulnClass(
        "Authentication Bypass", "CWE-287", 8.6, "HIGH", "P2",
        "$500–$10,000",
        "A07:2021-Identification and Authentication Failures",
        "Endpoint returns data without valid credentials",
    ),
    "SSRF_INTERNAL": VulnClass(
        "SSRF to Internal Network", "CWE-918", 8.8, "HIGH", "P2",
        "$1,000–$10,000",
        "A10:2021-Server-Side Request Forgery",
        "SSRF probing internal services (Redis, databases, admin panels)",
    ),
    "CORS_EXPLOITABLE": VulnClass(
        "Exploitable CORS Misconfiguration", "CWE-942", 8.1, "HIGH", "P2",
        "$200–$3,000",
        "A05:2021-Security Misconfiguration",
        "CORS + ACAC:true enables cross-origin session theft",
    ),
    "OAUTH_STATE_CSRF": VulnClass(
        "OAuth CSRF (Missing State)", "CWE-352", 8.8, "HIGH", "P2",
        "$200–$3,000",
        "A07:2021-Identification and Authentication Failures",
        "Authorization flow completable via CSRF without state parameter",
    ),
    "OAUTH_REDIRECT_BYPASS": VulnClass(
        "OAuth redirect_uri Bypass", "CWE-601", 7.1, "HIGH", "P2",
        "$200–$5,000",
        "A01:2021-Broken Access Control",
        "redirect_uri validation can be bypassed to steal auth codes",
    ),
    "FOURXX_BYPASS": VulnClass(
        "403/401 Access Control Bypass", "CWE-284", 8.6, "HIGH", "P2",
        "$200–$5,000",
        "A01:2021-Broken Access Control",
        "Protected endpoint accessible via path normalisation or IP header injection",
    ),
    "SCOPE_ESCALATION": VulnClass(
        "OAuth Scope Escalation", "CWE-269", 7.1, "HIGH", "P2",
        "$200–$5,000",
        "A01:2021-Broken Access Control",
        "Admin scopes accepted without validation",
    ),
    "S3_LIST": VulnClass(
        "S3 Bucket Publicly Listable", "CWE-200", 7.5, "HIGH", "P2",
        "$100–$2,000",
        "A05:2021-Security Misconfiguration",
        "Bucket listing exposes all stored object keys",
    ),
    "SVN_EXPOSED": VulnClass(
        "Exposed SVN Repository", "CWE-538", 8.6, "HIGH", "P2",
        "$200–$3,000",
        "A02:2021-Cryptographic Failures",
        "Source code recoverable via exposed .svn directory",
    ),
    "RATE_LIMIT_AUTH": VulnClass(
        "No Rate Limiting on Auth Endpoint", "CWE-307", 7.5, "HIGH", "P2",
        "$100–$2,000",
        "A07:2021-Identification and Authentication Failures",
        "Brute-force attack possible on login/OTP/reset endpoints",
    ),

    # ── Medium ────────────────────────────────────────────────────────────
    "CSP_MISSING": VulnClass(
        "Missing Content-Security-Policy", "CWE-693", 5.4, "MEDIUM", "P3",
        "$50–$500",
        "A05:2021-Security Misconfiguration",
        "No CSP means XSS payloads can load arbitrary scripts",
    ),
    "HSTS_MISSING": VulnClass(
        "Missing Strict-Transport-Security", "CWE-319", 5.9, "MEDIUM", "P3",
        "$50–$500",
        "A02:2021-Cryptographic Failures",
        "HSTS absence enables protocol downgrade attacks",
    ),
    "CORS_REFLECTED": VulnClass(
        "CORS Origin Reflected (No Credentials)", "CWE-942", 5.3, "MEDIUM", "P3",
        "$50–$500",
        "A05:2021-Security Misconfiguration",
        "Origin reflected but ACAC:false — unauthenticated cross-origin reads",
    ),
    "HIDDEN_PARAM": VulnClass(
        "Hidden Parameter Discovered", "CWE-284", 6.5, "MEDIUM", "P3",
        "$100–$1,000",
        "A01:2021-Broken Access Control",
        "Undocumented parameter affects server-side behaviour",
    ),
    "DEBUG_BYPASS": VulnClass(
        "Debug Parameter Active in Production", "CWE-489", 6.5, "MEDIUM", "P3",
        "$100–$1,000",
        "A05:2021-Security Misconfiguration",
        "Debug flag bypasses validation or exposes internal data",
    ),
    "TLS_EXPIRY": VulnClass(
        "TLS Certificate Expiring", "CWE-295", 5.9, "MEDIUM", "P3",
        "$50–$500",
        "A02:2021-Cryptographic Failures",
        "Certificate expires within 14 days — imminent service disruption",
    ),
    "INTERNAL_IP_LEAK": VulnClass(
        "Internal IP Disclosure", "CWE-200", 5.3, "MEDIUM", "P3",
        "$50–$300",
        "A05:2021-Security Misconfiguration",
        "Backend IP addresses exposed via proxy error messages",
    ),
    "CONFIG_FILE_EXPOSED": VulnClass(
        "Sensitive Config File Accessible", "CWE-538", 7.5, "MEDIUM", "P3",
        "$100–$2,000",
        "A05:2021-Security Misconfiguration",
        "Configuration file (.env, wp-config.php etc.) accessible from web",
    ),
    "GQL_INTROSPECTION": VulnClass(
        "GraphQL Introspection Enabled", "CWE-200", 5.3, "MEDIUM", "P3",
        "$50–$500",
        "A05:2021-Security Misconfiguration",
        "Full API schema exposed to unauthenticated users",
    ),
    "PKCE_ABSENT": VulnClass(
        "PKCE Not Required (Public Client)", "CWE-345", 6.8, "MEDIUM", "P3",
        "$100–$1,000",
        "A07:2021-Identification and Authentication Failures",
        "Authorization codes can be intercepted without PKCE",
    ),
    "IMPLICIT_FLOW": VulnClass(
        "OAuth Implicit Flow Supported", "CWE-312", 5.4, "MEDIUM", "P3",
        "$50–$500",
        "A07:2021-Identification and Authentication Failures",
        "Tokens in URL fragment expose them to browser history and Referer leaks",
    ),
    "GQL_BATCH": VulnClass(
        "GraphQL Batch Query Abuse", "CWE-770", 5.3, "MEDIUM", "P3",
        "$50–$500",
        "A05:2021-Security Misconfiguration",
        "Batch requests bypass per-request rate limiting",
    ),
    "RATE_LIMIT_API": VulnClass(
        "No Rate Limiting on API Endpoint", "CWE-770", 5.3, "MEDIUM", "P3",
        "$50–$300",
        "A05:2021-Security Misconfiguration",
        "API endpoints accept unlimited requests",
    ),

    # ── Low ──────────────────────────────────────────────────────────────
    "XFRAME_MISSING": VulnClass(
        "Missing X-Frame-Options", "CWE-1021", 6.1, "LOW", "P4",
        "$50–$200",
        "A05:2021-Security Misconfiguration",
        "Clickjacking possible via iframe embedding",
    ),
    "COOKIE_FLAGS": VulnClass(
        "Cookie Missing Security Flags", "CWE-614", 4.3, "LOW", "P4",
        "$50–$200",
        "A02:2021-Cryptographic Failures",
        "Cookies missing Secure/HttpOnly/SameSite flags",
    ),
    "SERVER_VERSION": VulnClass(
        "Server Version Disclosure", "CWE-200", 2.7, "LOW", "P5",
        "$0–$100",
        "A05:2021-Security Misconfiguration",
        "Server header exposes software version enabling CVE targeting",
    ),
    "SSRF_TIMING": VulnClass(
        "Possible Blind SSRF (Timing)", "CWE-918", 6.4, "MEDIUM", "P3",
        "$200–$3,000",
        "A10:2021-Server-Side Request Forgery",
        "Timing anomaly suggests outbound connection attempted",
    ),
    "OPEN_REDIRECT": VulnClass(
        "Open Redirect", "CWE-601", 6.1, "MEDIUM", "P3",
        "$50–$500",
        "A01:2021-Broken Access Control",
        "User can be redirected to arbitrary external URL",
    ),
}

# ── Finding type → VulnClass key mapping ─────────────────────────────────
FINDING_TYPE_MAP: dict[str, str] = {
    # subtakeover
    "VULNERABLE":         "SUBDOMAIN_TAKEOVER",
    "POTENTIAL":          "SUBDOMAIN_TAKEOVER",
    # jsreaper
    "AWS Access Key":     "SECRET_IN_GIT",
    "Stripe Secret Key":  "SECRET_IN_GIT",
    "DB Connection String": "SECRET_IN_GIT",
    # headeraudit
    "Content-Security-Policy Header Missing": "CSP_MISSING",
    "Strict-Transport-Security Header Missing": "HSTS_MISSING",
    "X-Frame-Options Header Missing": "XFRAME_MISSING",
    "CORS Misconfiguration": "CORS_EXPLOITABLE",
    # 4xxbypass
    "HIGH":  "FOURXX_BYPASS",
    "MEDIUM": "FOURXX_BYPASS",
    # apifuzz
    "BOLA":           "BOLA_CONFIRMED",
    "AUTH_BYPASS":    "AUTH_BYPASS",
    "JWT_NONE":       "JWT_NONE",
    "JWT_ROLE_ELEVATION": "JWT_NONE",
    "MASS_ASSIGN":    "PRIV_ESCALATION",
    "RATE_LIMIT":     "RATE_LIMIT_AUTH",
    "GQL_INTROSPECTION": "GQL_INTROSPECTION",
    "GQL_BATCH":      "GQL_BATCH",
    # cloudexpose
    "S3":     "S3_LIST",
    "GCS":    "S3_LIST",
    "AZURE":  "S3_LIST",
    "FIREBASE": "FIREBASE_WRITE",
    "DATABASE": "DB_EXPOSED_UNAUTH",
    # ssrfprobe
    "metadata":     "SSRF_CLOUD_METADATA",
    "internal":     "SSRF_INTERNAL",
    "obfuscation":  "SSRF_INTERNAL",
    "scheme":       "SSRF_INTERNAL",
    # oauthprobe
    "CSRF_STATE":         "OAUTH_STATE_CSRF",
    "REDIRECT_URI_BYPASS":"OAUTH_REDIRECT_BYPASS",
    "PKCE_ABSENT":        "PKCE_ABSENT",
    "IMPLICIT_FLOW":      "IMPLICIT_FLOW",
    "SCOPE_ESCALATION":   "SCOPE_ESCALATION",
    "DYNAMIC_REGISTRATION":"DYNAMIC_REGISTRATION",
    # gitdump
    "GIT_EXPOSED":        "GIT_EXPOSED",
    "SVN_EXPOSED":        "SVN_EXPOSED",
    "HG_EXPOSED":         "SVN_EXPOSED",
    "CONFIG_FILE":        "CONFIG_FILE_EXPOSED",
    "SECRET":             "SECRET_IN_GIT",
    # paramfuzz
    "PRIV_ESCALATION":    "PRIV_ESCALATION",
    "DEBUG_BYPASS":       "DEBUG_BYPASS",
    "HIDDEN_PARAM":       "HIDDEN_PARAM",
    "IDOR_PARAM":         "BOLA_POSSIBLE",
    "PARAM_POLLUTION":    "HIDDEN_PARAM",
}

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
class NormalizedFinding:
    """
    A single vulnerability finding normalised across all pipeline tools.

    PATCHED (toolkit integration): added confidence, disposition, first_seen,
    last_seen, verified_by fields per ARCHITECTURE.md §3.1. Defaults preserve
    legacy behavior — existing callers that don't set these get 'candidate'
    confidence and 'new' disposition, matching pre-patch output.
    """
    id: str                          # unique ID for deduplication / tracking
    source_tool: str                 # which tool found it
    host: str
    url: str
    vuln_class_key: str              # key into VULN_CLASSES
    severity: str
    title: str
    detail: str
    evidence: str
    steps_to_reproduce: str
    remediation: str
    curl_command: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cwe: str = ""
    owasp: str = ""
    impact_tier: str = ""
    typical_payout: str = ""
    allows_write: bool = False
    chain_ids: list[str] = field(default_factory=list)  # IDs of related findings
    nuclei_template: str = ""
    raw: dict = field(default_factory=dict)             # original finding dict

    # --- NEW fields (ARCHITECTURE.md §3.1) ---
    confidence: str = "candidate"        # candidate | probable | confirmed
    disposition: str = "new"             # new | reviewed | submitted | rejected | duplicate_of
    first_seen: str = ""                 # ISO 8601 UTC, set by pipeline_state.upsert_finding
    last_seen: str = ""                  # ISO 8601 UTC
    verified_by: str | None = None       # tool name if a Layer 4 verifier confirmed it


@dataclass
class ChainFinding:
    """A combined critical finding formed by chaining two or more findings."""
    chain_id: str
    components: list[str]            # IDs of component findings
    severity: str
    title: str
    impact: str
    steps_to_reproduce: str
    hosts: list[str] = field(default_factory=list)


@dataclass
class HarvestReport:
    domain: str
    scan_time: str
    source_tools: list[str]
    elapsed_seconds: float = 0.0
    findings: list[NormalizedFinding] = field(default_factory=list)
    chains: list[ChainFinding] = field(default_factory=list)
    nuclei_findings: list[dict] = field(default_factory=list)
    total_hosts: int = 0


# ═════════════════════════════════════════════════════════════════════════════
# FINDING PARSERS — one per upstream tool
# ═════════════════════════════════════════════════════════════════════════════

def _mk_id(tool: str, host: str, title: str) -> str:
    raw  = f"{tool}:{host}:{title}"
    return raw[:8].replace("/","-").replace(".","_").replace(" ","_") + \
           "_" + str(abs(hash(raw)) % 100000)


def _classify(finding_type: str, fallback_severity: str = "MEDIUM") -> tuple[str, VulnClass]:
    """Map a raw finding type string to a VulnClass key + object."""
    for key_fragment, vclass_key in FINDING_TYPE_MAP.items():
        if key_fragment.lower() in finding_type.lower():
            vc = VULN_CLASSES.get(vclass_key)
            if vc:
                return vclass_key, vc
    # Fallback: construct minimal VulnClass from severity
    fallback_key = f"UNKNOWN_{fallback_severity}"
    return fallback_key, VulnClass(
        name=finding_type, cwe="", cvss_base=5.0,
        severity=fallback_severity, impact_tier="P3",
        typical_payout="$0–$500", owasp="",
        description=finding_type,
    )


def _norm(
    tool: str, host: str, url: str,
    finding_type: str, severity: str,
    title: str, detail: str, evidence: str,
    curl: str = "", raw: dict | None = None,
    extra_steps: str = "",
    allows_write: bool = False,
) -> NormalizedFinding:
    vck, vc = _classify(finding_type, severity)
    return NormalizedFinding(
        id=_mk_id(tool, host, title),
        source_tool=tool,
        host=host, url=url,
        vuln_class_key=vck,
        severity=vc.severity if vc.severity != "INFO" else severity,
        title=title, detail=detail, evidence=evidence,
        steps_to_reproduce=extra_steps or (
            f"1. Identify the endpoint: {url}\n"
            f"2. {detail[:300]}\n"
            f"3. Observe the response and confirm the behaviour."
        ),
        remediation=vc.description,
        curl_command=curl,
        cvss_score=vc.cvss_base,
        cwe=vc.cwe, owasp=vc.owasp,
        impact_tier=vc.impact_tier,
        typical_payout=vc.typical_payout,
        allows_write=allows_write,
        raw=raw or {},
    )


def parse_subtakeover(path: str) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    with open(path) as f:
        data = json.load(f)
    for fi in data.get("findings", []):
        verdict = fi.get("verdict", "")
        if verdict not in ("VULNERABLE", "POTENTIAL"):
            continue
        sub = fi.get("subdomain", "")
        svc = fi.get("service", "")
        findings.append(_norm(
            "subtakeover", sub, f"https://{sub}/",
            "SUBDOMAIN_TAKEOVER", "CRITICAL" if verdict == "VULNERABLE" else "HIGH",
            f"Subdomain Takeover — {sub} ({verdict})",
            f"Subdomain {sub} points to {svc} via CNAME but the service account has been deleted. "
            f"An attacker can register this service account and serve content from {sub}.",
            f"Verdict: {verdict}\nService: {svc}\nCNAME chain: {fi.get('cname_chain','unknown')}",
            f'curl -I "https://{sub}/"',
            raw=fi,
        ))
    log.info(f"[Parse] subtakeover: {len(findings)} findings")
    return findings


def parse_headeraudit(path: str) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    with open(path) as f:
        data = json.load(f)
    for fi in data.get("header_findings", []) + data.get("cors_findings", []) + data.get("cookie_findings", []):
        host    = fi.get("host", "")
        url     = fi.get("url", "")
        title   = fi.get("title", "")
        detail  = fi.get("detail", "")
        sev     = fi.get("severity", "MEDIUM")
        ev      = fi.get("evidence", "")
        rec     = fi.get("recommendation", "")
        header  = fi.get("header", fi.get("test_type", ""))
        curl    = f'curl -sk -D - -I "{url}"'
        findings.append(_norm(
            "headeraudit", host, url,
            title, sev, title, detail, ev, curl, raw=fi,
        ))
    log.info(f"[Parse] headeraudit: {len(findings)} findings")
    return findings


def parse_bypass(path: str) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    with open(path) as f:
        data = json.load(f)
    for fi in data.get("bypasses", []):
        host  = fi.get("url","").split("/")[2] if "/" in fi.get("url","") else ""
        url   = fi.get("url","")
        title = f"403 Bypass — {fi.get('technique_name','')[:60]}"
        findings.append(_norm(
            "4xxbypass", host, url,
            fi.get("confidence","MEDIUM"), fi.get("confidence","MEDIUM"),
            title,
            f"HTTP 403 bypass via: {fi.get('technique_name','')}. "
            f"Baseline: {fi.get('baseline_status')} → Bypass: {fi.get('bypass_status')}",
            f"Technique group: {fi.get('technique_group','')}\n"
            f"Headers: {fi.get('extra_headers',{})}\n"
            f"Body snippet: {fi.get('body_snippet','')[:100]}",
            fi.get("curl_command",""), raw=fi,
        ))
    log.info(f"[Parse] 4xxbypass: {len(findings)} findings")
    return findings


def parse_apifuzz(path: str) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    with open(path) as f:
        data = json.load(f)
    for fi in data.get("findings", []):
        host  = fi.get("host","")
        url   = fi.get("url","")
        ttype = fi.get("test_type","")
        findings.append(_norm(
            "apifuzz", host, url,
            ttype, fi.get("severity","MEDIUM"),
            fi.get("title",""),
            fi.get("detail",""),
            fi.get("evidence",""),
            fi.get("curl_command",""), raw=fi,
        ))
    log.info(f"[Parse] apifuzz: {len(findings)} findings")
    return findings


def parse_cloudexpose(path: str) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    with open(path) as f:
        data = json.load(f)
    for fi in data.get("findings", []):
        host = fi.get("resource_name","")
        url  = fi.get("url","")
        rtype = fi.get("resource_type","")
        findings.append(_norm(
            "cloudexpose", host, url,
            rtype, fi.get("severity","HIGH"),
            fi.get("title",""),
            fi.get("detail",""),
            fi.get("evidence",""),
            fi.get("curl_command",""), raw=fi,
            allows_write=fi.get("allows_write", False),
        ))
    log.info(f"[Parse] cloudexpose: {len(findings)} findings")
    return findings


def parse_ssrfprobe(path: str) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    with open(path) as f:
        data = json.load(f)
    for fi in data.get("findings", []):
        host = fi.get("host","")
        url  = fi.get("url","")
        cat  = fi.get("payload_category","internal")
        findings.append(_norm(
            "ssrfprobe", host, url,
            cat, fi.get("severity","HIGH"),
            fi.get("title",""),
            fi.get("detail",""),
            fi.get("evidence",""),
            fi.get("curl_command",""), raw=fi,
        ))
    log.info(f"[Parse] ssrfprobe: {len(findings)} findings")
    return findings


def parse_oauthprobe(path: str) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    with open(path) as f:
        data = json.load(f)
    for fi in data.get("findings", []):
        host  = fi.get("host","")
        ep    = fi.get("endpoint","")
        ttype = fi.get("test_type","")
        findings.append(_norm(
            "oauthprobe", host, ep,
            ttype, fi.get("severity","HIGH"),
            fi.get("title",""),
            fi.get("detail",""),
            fi.get("evidence",""),
            fi.get("poc_url",""), raw=fi,
            extra_steps=fi.get("steps_to_reproduce",""),
        ))
    log.info(f"[Parse] oauthprobe: {len(findings)} findings")
    return findings


def parse_gitdump(path: str) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    with open(path) as f:
        data = json.load(f)
    for fi in data.get("findings", []):
        host = fi.get("host","")
        url  = fi.get("url","")
        cat  = fi.get("category","CONFIG_FILE")
        # If secrets were found, promote to SECRET finding
        secrets = fi.get("secrets", [])
        if secrets:
            for sec in secrets[:3]:
                findings.append(_norm(
                    "gitdump", host, url,
                    "SECRET", sec.get("severity","HIGH"),
                    f"{sec.get('secret_type','')} Found in {sec.get('source_path','Git Repository')}",
                    fi.get("detail",""),
                    f"Secret type: {sec.get('secret_type','')}\n"
                    f"Value (redacted): {sec.get('value_redacted','')}\n"
                    f"Context: {sec.get('context','')[:150]}",
                    fi.get("curl_command",""), raw=fi,
                ))
        findings.append(_norm(
            "gitdump", host, url,
            cat, fi.get("severity","HIGH"),
            fi.get("title",""),
            fi.get("detail",""),
            fi.get("evidence",""),
            fi.get("curl_command",""), raw=fi,
        ))
    log.info(f"[Parse] gitdump: {len(findings)} findings")
    return findings


def parse_paramfuzz(path: str) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    with open(path) as f:
        data = json.load(f)
    for fi in data.get("findings", []):
        host  = fi.get("host","")
        url   = fi.get("url","")
        ftype = fi.get("finding_type","HIDDEN_PARAM")
        findings.append(_norm(
            "paramfuzz", host, url,
            ftype, fi.get("severity","MEDIUM"),
            fi.get("title",""),
            fi.get("detail",""),
            fi.get("evidence",""),
            fi.get("curl_command",""), raw=fi,
        ))
    log.info(f"[Parse] paramfuzz: {len(findings)} findings")
    return findings


def parse_nuclei_json(path: str) -> list[dict]:
    """Parse raw Nuclei JSONL output."""
    results: list[dict] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except Exception:
                pass
    log.info(f"[Parse] nuclei: {len(results)} raw results")
    return results


def nuclei_to_normalized(raw_results: list[dict]) -> list[NormalizedFinding]:
    """Convert Nuclei raw JSONL findings to NormalizedFinding."""
    findings: list[NormalizedFinding] = []
    for r in raw_results:
        sev = r.get("info", {}).get("severity", "info").upper()
        if sev == "INFORMATIONAL":
            sev = "INFO"
        host     = r.get("host", "")
        url      = r.get("matched-at", host)
        template = r.get("template-id", "")
        title    = r.get("info", {}).get("name", template)
        detail   = r.get("info", {}).get("description", "")
        evidence = r.get("extracted-results", "")
        if isinstance(evidence, list):
            evidence = "\n".join(str(e) for e in evidence[:5])
        cwe_list = r.get("info", {}).get("classification", {}).get("cwe-id", [])
        cwe      = cwe_list[0] if cwe_list else ""
        findings.append(NormalizedFinding(
            id=_mk_id("nuclei", host, title),
            source_tool="nuclei",
            host=host, url=url,
            vuln_class_key="NUCLEI_" + sev,
            severity=sev,
            title=title, detail=detail,
            evidence=str(evidence)[:500],
            steps_to_reproduce=(
                f"1. Target: {url}\n"
                f"2. Template: {template}\n"
                f"3. {detail[:200]}"
            ),
            remediation=detail,
            cwe=cwe,
            nuclei_template=template,
            raw=r,
        ))
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# DEDUPLICATION
# ═════════════════════════════════════════════════════════════════════════════

def deduplicate(findings: list[NormalizedFinding]) -> list[NormalizedFinding]:
    """
    Deduplicate by (host, vuln_class_key) — keeping the highest-severity
    instance of each vulnerability class per host.
    If multiple tools found the same vulnerability, keep the most detailed one.
    """
    # Group by (host, vuln_class_key)
    groups: dict[tuple, list[NormalizedFinding]] = {}
    for f in findings:
        key = (f.host, f.vuln_class_key)
        groups.setdefault(key, []).append(f)

    deduped: list[NormalizedFinding] = []
    for key, group in groups.items():
        # Keep the one with most evidence/detail
        best = max(group, key=lambda f: (
            -SEVERITY_ORDER.get(f.severity, 9),  # higher severity first
            len(f.evidence) + len(f.detail),       # most detail
        ))
        # Merge additional evidence from duplicates
        if len(group) > 1:
            extra_tools = set(f.source_tool for f in group if f != best)
            if extra_tools:
                best.detail += f"\n\n[Also detected by: {', '.join(extra_tools)}]"
        deduped.append(best)

    return sorted(deduped, key=lambda f: (
        SEVERITY_ORDER.get(f.severity, 9),
        f.host,
    ))


# ═════════════════════════════════════════════════════════════════════════════
# CHAIN DETECTION
# Finds combinations of findings that escalate each other's impact
# ═════════════════════════════════════════════════════════════════════════════

def detect_chains(findings: list[NormalizedFinding]) -> list[ChainFinding]:
    """
    Detect high-impact finding chains. Examples:
    - Subdomain takeover + OAuth redirect_uri bypass = account takeover
    - SSRF + cloud metadata = credential theft
    - Git exposed + DB connection string = database compromise
    - Debug param + admin endpoint = auth bypass
    """
    chains: list[ChainFinding] = []
    by_host: dict[str, list[NormalizedFinding]] = {}
    for f in findings:
        by_host.setdefault(f.host, []).append(f)

    # Also check across all hosts for domain-wide chains
    all_findings = findings
    takeover_hosts = {
        f.host for f in all_findings
        if f.vuln_class_key == "SUBDOMAIN_TAKEOVER"
    }
    oauth_redirect_findings = [
        f for f in all_findings
        if f.vuln_class_key in ("OAUTH_REDIRECT_BYPASS",)
    ]

    # ── Chain 1: Subdomain takeover + OAuth redirect_uri ─────────────────
    for oauth_f in oauth_redirect_findings:
        if takeover_hosts:
            chain_id = f"CHAIN_OAUTH_TAKEOVER_{oauth_f.host[:20]}"
            chains.append(ChainFinding(
                chain_id=chain_id,
                components=[oauth_f.id] + [
                    f.id for f in all_findings
                    if f.vuln_class_key == "SUBDOMAIN_TAKEOVER"
                ][:3],
                severity="CRITICAL",
                title=(
                    f"ACCOUNT TAKEOVER CHAIN: "
                    f"OAuth redirect_uri Bypass + Subdomain Takeover on {oauth_f.host}"
                ),
                impact=(
                    f"Combining subdomain takeover of "
                    f"{', '.join(list(takeover_hosts)[:2])} with the OAuth redirect_uri "
                    f"bypass on {oauth_f.host} enables full account takeover of any user "
                    f"who visits a crafted authorization URL. The attacker can:\n"
                    f"1. Control the taken-over subdomain to receive auth codes\n"
                    f"2. Exchange stolen auth codes for access tokens\n"
                    f"3. Log in as the victim without their password"
                ),
                steps_to_reproduce=(
                    f"1. Complete subdomain takeover of one of: {', '.join(list(takeover_hosts)[:3])}\n"
                    f"2. Use the OAuth redirect_uri bypass to set redirect_uri to the takeover domain\n"
                    f"3. Send the victim a crafted authorization URL\n"
                    f"4. When the victim clicks and authorizes, the code is sent to your takeover domain\n"
                    f"5. Exchange the code for tokens at the token endpoint\n"
                    f"6. Use tokens to access the victim's account"
                ),
                hosts=list(takeover_hosts) + [oauth_f.host],
            ))

    # ── Chain 2: SSRF + cloud metadata ───────────────────────────────────
    ssrf_findings = [f for f in all_findings if f.vuln_class_key in ("SSRF_CLOUD_METADATA","SSRF_INTERNAL")]
    cloud_hosts   = set()
    for f in all_findings:
        if "gcp" in f.host.lower() or "aws" in f.host.lower() or "34." in f.host:
            cloud_hosts.add(f.host)

    if ssrf_findings:
        for ssrf_f in ssrf_findings[:2]:
            chain_id = f"CHAIN_SSRF_CRED_{ssrf_f.host[:20]}"
            chains.append(ChainFinding(
                chain_id=chain_id,
                components=[ssrf_f.id],
                severity="CRITICAL",
                title=f"CREDENTIAL THEFT CHAIN: SSRF → Cloud Metadata on {ssrf_f.host}",
                impact=(
                    f"SSRF on {ssrf_f.host} (param: {ssrf_f.raw.get('param','?')}) "
                    f"can reach the cloud instance metadata endpoint "
                    f"(169.254.169.254/latest/meta-data/). This returns IAM role credentials "
                    f"(AccessKeyId + SecretAccessKey + Token) that can be used to access "
                    f"any AWS/GCP/Azure resources the instance has permission for."
                ),
                steps_to_reproduce=(
                    f"1. Identify the SSRF injection point: "
                    f"{ssrf_f.url} ?{ssrf_f.raw.get('param','param')}=\n"
                    f"2. Inject: ?{ssrf_f.raw.get('param','url')}"
                    f"=http://169.254.169.254/latest/meta-data/iam/security-credentials/\n"
                    f"3. The response contains IAM role names\n"
                    f"4. Fetch: .../security-credentials/ROLE_NAME for temporary credentials\n"
                    f"5. Use credentials with AWS CLI: "
                    f"AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=... "
                    f"aws s3 ls"
                ),
                hosts=[ssrf_f.host],
            ))

    # ── Chain 3: Git exposed + secrets in history ─────────────────────────
    git_findings = [f for f in all_findings if f.vuln_class_key == "GIT_EXPOSED"]
    secret_findings = [f for f in all_findings if f.vuln_class_key == "SECRET_IN_GIT"]

    for git_f in git_findings:
        related_secrets = [s for s in secret_findings if s.host == git_f.host]
        if related_secrets:
            chain_id = f"CHAIN_GIT_SECRET_{git_f.host[:20]}"
            chains.append(ChainFinding(
                chain_id=chain_id,
                components=[git_f.id] + [s.id for s in related_secrets[:5]],
                severity="CRITICAL",
                title=f"SOURCE CODE + CREDENTIAL EXPOSURE on {git_f.host}",
                impact=(
                    f"The exposed .git repository on {git_f.host} contains "
                    f"{len(related_secrets)} credentials in the file tree or commit history. "
                    f"These include: "
                    f"{', '.join(s.title[:40] for s in related_secrets[:3])}. "
                    f"Combined with the full source code, an attacker has complete knowledge "
                    f"of the application's architecture and all credentials."
                ),
                steps_to_reproduce=(
                    f"1. git clone {git_f.url.replace('/.git/HEAD','')} /tmp/recovered_repo\n"
                    f"   (or use gitdump.py to reconstruct without git binary)\n"
                    f"2. Search for credentials: grep -r 'password|secret|api_key' /tmp/recovered_repo\n"
                    f"3. Use git log -p to find credentials deleted from history\n"
                    f"4. Credentials found: {related_secrets[0].title if related_secrets else 'see secrets'}"
                ),
                hosts=[git_f.host],
            ))

    log.info(f"[Chains] Detected {len(chains)} finding chains")
    return chains


# ═════════════════════════════════════════════════════════════════════════════
# NUCLEI RUNNER
# ═════════════════════════════════════════════════════════════════════════════

NUCLEI_SERVICE_TEMPLATES: dict[str, list[str]] = {
    "jenkins":      ["cves/jenkins", "default-logins/jenkins", "exposed-panels/jenkins"],
    "grafana":      ["cves/grafana", "default-logins/grafana", "exposed-panels/grafana"],
    "sonarqube":    ["cves/sonarqube", "default-logins/sonarqube", "exposed-panels/sonarqube"],
    "elasticsearch":["cves/elasticsearch", "misconfiguration/elasticsearch"],
    "kibana":       ["cves/kibana", "exposed-panels/kibana"],
    "gitlab":       ["cves/gitlab", "exposed-panels/gitlab", "vulnerabilities/gitlab"],
    "github":       ["exposed-panels/github", "misconfiguration/github"],
    "wordpress":    ["cves/wordpress", "exposed-panels/wordpress", "vulnerabilities/wordpress"],
    "joomla":       ["cves/joomla", "vulnerabilities/joomla"],
    "drupal":       ["cves/drupal", "vulnerabilities/drupal"],
    "apache":       ["cves/apache", "misconfiguration/apache"],
    "nginx":        ["misconfiguration/nginx", "exposed-panels/nginx"],
    "spring":       ["cves/spring", "vulnerabilities/springboot"],
    "tomcat":       ["cves/apache-tomcat", "default-logins/tomcat"],
    "phpmyadmin":   ["cves/phpmyadmin", "default-logins/phpmyadmin"],
    "redis":        ["cves/redis", "misconfiguration/redis"],
    "mongodb":      ["misconfiguration/mongodb"],
    "s3":           ["misconfiguration/aws", "exposures/configs"],
    "firebase":     ["misconfiguration/firebase"],
    "kubernetes":   ["misconfiguration/kubernetes", "cves/kubernetes"],
    "n8n":          ["cves/n8n", "exposed-panels/n8n"],
    "netbird":      ["exposed-panels"],
    "argocd":       ["exposed-panels/argocd", "cves/argocd"],
    "general":      [
        "exposed-panels", "misconfiguration",
        "default-logins", "exposures/configs",
        "technologies",
    ],
}

NUCLEI_EXCLUDE_TAGS = [
    "dos", "fuzz", "dast", "blind", "oast", "out-of-band",
    "intrusive", "brute-force", "network",
]


def build_nuclei_command(
    hosts: list[str],
    services: dict[str, str],  # host → detected_service
    output_file: str,
    nuclei_path: str = "nuclei",
    rate_limit: int = 50,
) -> list[str]:
    """
    Build a nuclei command that selects templates based on detected services.
    """
    # Collect all relevant template paths
    template_paths: set[str] = set()
    for host in hosts:
        service = services.get(host, "general").lower()
        for keyword, templates in NUCLEI_SERVICE_TEMPLATES.items():
            if keyword in service or keyword in host.lower():
                template_paths.update(templates)
    if not template_paths:
        template_paths.update(NUCLEI_SERVICE_TEMPLATES["general"])

    cmd = [
        nuclei_path,
        "-l", "/dev/stdin",           # hosts from stdin
        "-j",                          # JSON output
        "-o", output_file,
        "-rl", str(rate_limit),
        "-timeout", "10",
        "-no-color",
        "-silent",
    ]

    for tp in sorted(template_paths):
        cmd += ["-t", tp]

    for tag in NUCLEI_EXCLUDE_TAGS:
        cmd += ["-etags", tag]

    return cmd


def detect_services_from_recon(path: str) -> dict[str, str]:
    """
    Build a host → service_name mapping from reconharvest output.
    Used for targeted Nuclei template selection.
    """
    services: dict[str, str] = {}
    try:
        with open(path) as f:
            data = json.load(f)
        for hr in data.get("host_reports", []):
            host = hr.get("host", "")
            svc  = hr.get("service", hr.get("service_version", ""))
            if host and svc:
                services[host] = svc.lower()
    except Exception:
        pass
    return services


def run_nuclei(
    hosts: list[str],
    services: dict[str, str],
    output_file: str,
    nuclei_path: str = "nuclei",
    rate_limit: int = 50,
) -> list[dict]:
    """
    Run Nuclei if installed. Returns list of parsed JSONL results.
    """
    # Check if nuclei is installed
    try:
        result = subprocess.run(
            [nuclei_path, "-version"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            log.info("[Nuclei] Not found or error — skipping")
            return []
    except (FileNotFoundError, subprocess.TimeoutExpired):
        log.info("[Nuclei] Not installed — skipping (install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)")
        return []

    cmd = build_nuclei_command(hosts, services, output_file, nuclei_path, rate_limit)
    hosts_input = "\n".join(hosts)

    log.info(f"[Nuclei] Running against {len(hosts)} hosts...")
    log.info(f"[Nuclei] Command: {' '.join(cmd[:8])} ...")

    try:
        proc = subprocess.run(
            cmd,
            input=hosts_input,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minutes max
        )
        log.info(f"[Nuclei] Finished. Return code: {proc.returncode}")
        if proc.stderr:
            log.debug(f"[Nuclei] Stderr: {proc.stderr[:200]}")
    except subprocess.TimeoutExpired:
        log.warning("[Nuclei] Timed out after 5 minutes")
        return []
    except Exception as exc:
        log.warning(f"[Nuclei] Error: {exc}")
        return []

    if not Path(output_file).exists():
        return []

    return parse_nuclei_json(output_file)


# ═════════════════════════════════════════════════════════════════════════════
# REPORT WRITERS
# ═════════════════════════════════════════════════════════════════════════════

def write_hackerone_report(
    finding: NormalizedFinding,
    vc: VulnClass | None,
    chains: list[ChainFinding],
) -> str:
    """
    Generate a HackerOne-formatted Markdown bug report for a finding.
    """
    chain_section = ""
    related_chains = [c for c in chains if finding.id in c.components]
    if related_chains:
        c = related_chains[0]
        chain_section = f"""

## 🔗 Attack Chain

**{c.title}**

{c.impact}

### Chain Steps
{c.steps_to_reproduce}
"""

    return f"""## Summary

{finding.detail}

{chain_section}

## Vulnerability Details

**URL:** `{finding.url}`
**Parameter / Location:** `{finding.raw.get('param', finding.raw.get('param_name', 'See evidence'))}`
**Tool detected by:** {finding.source_tool}

## Steps to Reproduce

{finding.steps_to_reproduce}

## Evidence

```
{finding.evidence[:800]}
```

{"**Reproduce with curl:**" + chr(10) + "```bash" + chr(10) + finding.curl_command[:400] + chr(10) + "```" if finding.curl_command else ""}

## Impact

This vulnerability allows an attacker to:
{_impact_statement(finding, vc)}

## Remediation

{finding.remediation}
{vc.description if vc else ""}

## Classification

- **CWE:** {finding.cwe or (vc.cwe if vc else "N/A")}
- **OWASP:** {finding.owasp or (vc.owasp if vc else "N/A")}
- **CVSS Score:** {finding.cvss_score} {finding.cvss_vector}
"""


def _impact_statement(f: NormalizedFinding, vc: VulnClass | None) -> str:
    impact_map = {
        "SUBDOMAIN_TAKEOVER":  "- Host phishing users via the taken-over subdomain\n- Steal OAuth tokens by registering as redirect URI\n- Serve malware under a trusted domain name",
        "GIT_EXPOSED":         "- Recover complete application source code\n- Extract credentials from .env files and configuration\n- Map internal infrastructure from Dockerfile and k8s manifests",
        "SSRF_CLOUD_METADATA": "- Retrieve AWS/GCP/Azure IAM credentials\n- Pivot to other cloud services using the instance's permissions\n- Access S3 buckets, databases, and internal services",
        "OAUTH_REDIRECT_BYPASS":"- Steal authorization codes from victim users\n- Exchange codes for access tokens\n- Log in as any victim who clicks a crafted authorization link",
        "PRIV_ESCALATION":     "- Escalate account privileges to administrator\n- Access admin-only features and data\n- Modify other users' account settings",
        "BOLA_CONFIRMED":      "- Access any other user's private data\n- Modify or delete other users' resources\n- Enumerate all user IDs for bulk data exfiltration",
        "DB_EXPOSED_UNAUTH":   "- Read all database contents including PII and credentials\n- Modify or delete database records\n- Use as a pivot point for internal network access",
    }
    return impact_map.get(f.vuln_class_key,
        f"- Compromise the security of {f.host}\n"
        f"- Access data or functionality not intended for this user\n"
        f"- Potentially pivot to further attacks against the infrastructure"
    )


def write_bugcrowd_report(finding: NormalizedFinding, vc: VulnClass | None) -> str:
    """Plain-text Bugcrowd format."""
    return f"""VULNERABILITY REPORT
====================
Title: {finding.title}
Severity: {finding.severity}
URL: {finding.url}
Tool: {finding.source_tool}

DESCRIPTION
-----------
{finding.detail}

STEPS TO REPRODUCE
------------------
{finding.steps_to_reproduce}

EVIDENCE
--------
{finding.evidence[:600]}

IMPACT
------
{_impact_statement(finding, vc)}

REMEDIATION
-----------
{finding.remediation}

CLASSIFICATION
--------------
CWE: {finding.cwe or (vc.cwe if vc else "N/A")}
CVSS: {finding.cvss_score}
"""


# ═════════════════════════════════════════════════════════════════════════════
# TERMINAL REPORT
# ═════════════════════════════════════════════════════════════════════════════

def print_report(report: HarvestReport) -> None:
    by_sev = {s: [f for f in report.findings if f.severity == s]
              for s in SEVERITY_ORDER}
    total = len(report.findings)
    chains = report.chains

    if not HAS_RICH:
        print(f"\n=== NucleiHarvest: {report.domain} ===")
        print(f"Total findings: {total}  Chains: {len(chains)}  Elapsed: {report.elapsed_seconds:.1f}s")
        for sev in ("CRITICAL","HIGH","MEDIUM","LOW"):
            sf = by_sev.get(sev, [])
            if not sf: continue
            print(f"\n── {sev} ({len(sf)}) ──")
            for f in sf:
                print(f"  [{f.source_tool}] {f.title}")
                print(f"    {f.host} | {f.typical_payout} | {f.cwe}")
        print()
        return

    border = "red" if by_sev.get("CRITICAL") else "yellow" if by_sev.get("HIGH") else "blue"
    console.print()
    console.print(Panel.fit(
        f"[white]Domain:[/] [cyan]{report.domain}[/]\n"
        f"[white]Scan time:[/] {report.scan_time}\n"
        f"[white]Elapsed:[/] {report.elapsed_seconds:.1f}s\n"
        f"[white]Source tools:[/] {', '.join(sorted(set(f.source_tool for f in report.findings)))}\n\n"
        f"[bold red]CRITICAL:[/] {len(by_sev.get('CRITICAL',[]))}    "
        f"[bold yellow]HIGH:[/] {len(by_sev.get('HIGH',[]))}    "
        f"[yellow]MEDIUM:[/] {len(by_sev.get('MEDIUM',[]))}    "
        f"[cyan]LOW:[/] {len(by_sev.get('LOW',[]))}\n"
        f"[dim]Attack chains:[/] {len(chains)}    "
        f"[dim]Unique hosts affected:[/] {len(set(f.host for f in report.findings))}",
        title="[bold]NucleiHarvest — Final Report[/]",
        border_style=border,
    ))

    # Attack chains — most important section
    if chains:
        console.print("\n[bold red]══ ATTACK CHAINS (HIGHEST PRIORITY) ══[/]")
        for c in chains:
            console.print(
                f"\n  [bold red]⛓  {c.title}[/]\n"
                f"  [dim]Severity:[/] [bold red]{c.severity}[/]  "
                f"[dim]Hosts:[/] {', '.join(c.hosts[:3])}\n"
                f"  [dim]Impact:[/] {c.impact[:300]}{'...' if len(c.impact)>300 else ''}\n"
                f"  [dim]Components:[/] {len(c.components)} findings involved"
            )

    # Sorted findings table
    console.print("\n[bold cyan]── All Findings (ranked by payout potential) ──[/]")
    tbl = Table(show_header=True, header_style="bold cyan", border_style="dim")
    tbl.add_column("Sev",     justify="center", width=8)
    tbl.add_column("Tool",    style="dim",      width=12)
    tbl.add_column("Host",    style="cyan",     width=30)
    tbl.add_column("Tier",    justify="center", width=4)
    tbl.add_column("Payout",  style="dim",      width=14)
    tbl.add_column("CWE",     style="dim",      width=10)
    tbl.add_column("Title",   max_width=50)

    for f in report.findings:
        col = SEV_COLOR.get(f.severity, "white")
        tbl.add_row(
            f"[{col}]{f.severity[:4]}[/]",
            f.source_tool,
            f.host[:30],
            f.impact_tier,
            f.typical_payout,
            f.cwe or "—",
            f.title[:50],
        )
    console.print(tbl)
    console.print()


# ═════════════════════════════════════════════════════════════════════════════
# OUTPUT WRITERS
# ═════════════════════════════════════════════════════════════════════════════

def save_json_report(report: HarvestReport, path: str) -> None:
    data = {
        "domain":          report.domain,
        "scan_time":       report.scan_time,
        "source_tools":    report.source_tools,
        "elapsed_seconds": report.elapsed_seconds,
        "summary": {s: len([f for f in report.findings if f.severity == s])
                    for s in SEVERITY_ORDER},
        "attack_chains": [
            {
                "chain_id":    c.chain_id,
                "severity":    c.severity,
                "title":       c.title,
                "impact":      c.impact,
                "hosts":       c.hosts,
                "components":  c.components,
                "steps":       c.steps_to_reproduce,
            }
            for c in report.chains
        ],
        "findings": [
            {
                "id":            f.id,
                "source_tool":   f.source_tool,
                "host":          f.host,
                "url":           f.url,
                "vuln_class_key": f.vuln_class_key,
                "severity":      f.severity,
                "title":         f.title,
                "detail":        f.detail,
                "evidence":      f.evidence,
                "steps":         f.steps_to_reproduce,
                "remediation":   f.remediation,
                "curl":          f.curl_command,
                "cvss_score":    f.cvss_score,
                "cvss_vector":   f.cvss_vector,
                "cwe":           f.cwe,
                "owasp":         f.owasp,
                "impact_tier":   f.impact_tier,
                "typical_payout":f.typical_payout,
                "chain_ids":     f.chain_ids,
                "nuclei_template":f.nuclei_template,
                # --- NEW fields (ARCHITECTURE.md §3.1) ---
                "confidence":    getattr(f, "confidence", "candidate"),
                "disposition":   getattr(f, "disposition", "new"),
                "first_seen":    getattr(f, "first_seen", ""),
                "last_seen":     getattr(f, "last_seen", ""),
                "verified_by":   getattr(f, "verified_by", None),
            }
            for f in report.findings
        ],
    }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    log.info(f"Master JSON report → {path}")


def save_html_report(report: HarvestReport, path: str) -> None:
    by_sev = {s: [f for f in report.findings if f.severity == s]
              for s in SEVERITY_ORDER}
    sc = {"CRITICAL":"#f85149","HIGH":"#d29922","MEDIUM":"#e3b341",
          "LOW":"#58a6ff","INFO":"#8b949e"}
    sb = {"CRITICAL":"rgba(248,81,73,.12)","HIGH":"rgba(210,153,34,.12)",
          "MEDIUM":"rgba(227,179,65,.10)","LOW":"rgba(88,166,255,.10)",
          "INFO":"rgba(139,148,158,.08)"}

    # Chain cards
    chain_html = ""
    for c in report.chains:
        chain_html += (
            f'<div style="background:rgba(248,81,73,.08);border:2px solid #f85149;'
            f'border-radius:8px;padding:16px;margin-bottom:14px">'
            f'<div style="font-family:system-ui;font-weight:800;font-size:.95em;'
            f'color:#fff;margin-bottom:8px">⛓ {c.title}</div>'
            f'<div style="color:#f85149;font-weight:700;font-size:.8em;margin-bottom:8px">'
            f'{c.severity} &nbsp;·&nbsp; {len(c.hosts)} host(s)</div>'
            f'<div style="color:#cdd6e0;font-size:.83em;margin-bottom:8px">{c.impact[:400]}</div>'
            f'<div style="color:#627384;font-size:.78em">'
            f'<strong style="color:#39c5cf">Steps:</strong><br>'
            + c.steps_to_reproduce.replace("\n","<br>")
            + f'</div></div>'
        )
    if not chain_html:
        chain_html = "<p style='color:#3fb950'>No attack chains detected.</p>"

    # Findings detail
    findings_html = ""
    for sev in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
        sf = by_sev.get(sev, [])
        if not sf: continue
        findings_html += (
            f'<div class="sev-section">'
            f'<h3 style="color:{sc[sev]}">{SEV_EMOJI.get(sev,"")} {sev} ({len(sf)})</h3>'
        )
        for i, f in enumerate(sf, 1):
            ev_e    = f.evidence.replace("<","&lt;").replace(">","&gt;")
            curl_e  = f.curl_command.replace("<","&lt;").replace(">","&gt;")
            steps_e = f.steps_to_reproduce.replace("<","&lt;").replace(">","&gt;").replace("\n","<br>")
            findings_html += (
                f'<div class="finding" style="border-left:3px solid {sc[sev]};background:{sb[sev]}">'
                f'<div class="ft">[{i}] {f.title}</div>'
                f'<div class="fm">'
                f'<span class="badge" style="color:{sc[sev]};background:{sb[sev]};border:1px solid {sc[sev]}">{sev}</span>'
                f'<span style="color:#39c5cf;font-size:.78em">{f.source_tool}</span>'
                f'<span style="color:#58a6ff;font-size:.78em">{f.host}</span>'
                f'<span style="color:#3fb950;font-size:.75em">{f.impact_tier}</span>'
                f'<span style="color:#d29922;font-size:.75em">{f.typical_payout}</span>'
                + (f'<span style="color:#627384;font-size:.72em">{f.cwe}</span>' if f.cwe else "")
                + f'</div>'
                f'<div class="fd">{f.detail[:300]}</div>'
                + (f'<div class="ev"><span class="evl">Steps:</span>'
                   f'<div style="color:#a8dadc;font-size:.8em;margin-top:2px">{steps_e[:400]}</div></div>'
                   if f.steps_to_reproduce else "")
                + (f'<div class="ev"><span class="evl">Evidence:</span>'
                   f'<code>{ev_e[:300]}</code></div>' if f.evidence else "")
                + (f'<div class="ev"><span class="evl">Reproduce:</span>'
                   f'<pre style="margin:4px 0 0 0;font-size:.8em;color:#a8dadc">{curl_e[:250]}</pre></div>'
                   if f.curl_command else "")
                + f'<div class="rec"><span class="recl">Fix:</span> {f.remediation[:200]}</div>'
                + f'</div>'
            )
        findings_html += "</div>"

    # Summary bar chart by severity
    total = len(report.findings)
    def bar(sev: str) -> str:
        cnt  = len(by_sev.get(sev,[]))
        pct  = int(cnt/total*200) if total else 0
        return f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">' \
               f'<span style="width:60px;color:{sc.get(sev,"#fff")};font-weight:bold;font-size:.8em">{sev}</span>' \
               f'<div style="background:{sc.get(sev,"#fff")};height:12px;width:{pct}px;border-radius:2px"></div>' \
               f'<span style="color:#627384;font-size:.8em">{cnt}</span></div>'

    html = f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NucleiHarvest — {report.domain}</title>
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
<h1>NucleiHarvest</h1>
<p class="sub">{report.domain} &nbsp;·&nbsp; {report.scan_time} &nbsp;·&nbsp;
{report.elapsed_seconds:.1f}s &nbsp;·&nbsp;
{total} findings from {', '.join(sorted(set(f.source_tool for f in report.findings)))}</p>
<div class="stats">
<div class="stat"><div class="sv" style="color:#f85149">{len(by_sev.get('CRITICAL',[]))}</div><div class="sl">CRITICAL</div></div>
<div class="stat"><div class="sv" style="color:#d29922">{len(by_sev.get('HIGH',[]))}</div><div class="sl">HIGH</div></div>
<div class="stat"><div class="sv" style="color:#e3b341">{len(by_sev.get('MEDIUM',[]))}</div><div class="sl">MEDIUM</div></div>
<div class="stat"><div class="sv" style="color:#58a6ff">{len(by_sev.get('LOW',[]))}</div><div class="sl">LOW</div></div>
<div class="stat"><div class="sv" style="color:#f85149">{len(report.chains)}</div><div class="sl">CHAINS</div></div>
<div class="stat"><div class="sv">{len(set(f.host for f in report.findings))}</div><div class="sl">HOSTS</div></div>
</div>
<div class="card"><h2>⛓ Attack Chains</h2>{chain_html}</div>
<div class="card"><h2>📊 Severity Distribution</h2>
{bar("CRITICAL")}{bar("HIGH")}{bar("MEDIUM")}{bar("LOW")}
</div>
<div class="card"><h2>🔎 All Findings</h2>{findings_html}</div>
<div class="footer">NucleiHarvest &nbsp;·&nbsp; For authorized security research only</div>
</div></body></html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    log.info(f"HTML dashboard → {path}")


def save_bounty_reports(
    report: HarvestReport,
    base_path: str,
) -> None:
    """
    Generate individual HackerOne and Bugcrowd formatted reports
    for every finding at P1 or P2 tier.
    """
    reports_dir = Path(base_path + "-reports")
    reports_dir.mkdir(exist_ok=True)

    h1_count = bc_count = 0
    for f in report.findings:
        if f.impact_tier not in ("P1", "P2"):
            continue
        vc = VULN_CLASSES.get(f.vuln_class_key)

        # HackerOne report
        h1_text = write_hackerone_report(f, vc, report.chains)
        safe_title = re.sub(r'[^\w\-_]', '_', f.title[:40])
        h1_path = reports_dir / f"h1_{f.severity}_{safe_title}_{f.id[:8]}.md"
        with open(h1_path, "w") as fh:
            fh.write(h1_text)
        h1_count += 1

        # Bugcrowd report
        bc_text = write_bugcrowd_report(f, vc)
        bc_path = reports_dir / f"bc_{f.severity}_{safe_title}_{f.id[:8]}.txt"
        with open(bc_path, "w") as fh:
            fh.write(bc_text)
        bc_count += 1

    log.info(
        f"Bug bounty reports saved → {reports_dir}/ "
        f"({h1_count} HackerOne .md + {bc_count} Bugcrowd .txt)"
    )


def save_csv_tracker(report: HarvestReport, path: str) -> None:
    """
    Generate a CSV remediation tracker for sharing with the security team.
    Columns: ID, Title, Severity, Host, CWE, Payout, Tool, Status, Notes
    """
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=[
            "ID", "Severity", "Tier", "Title", "Host", "URL",
            "CWE", "CVSS", "Typical Payout", "Tool", "Status",
            "Chain", "Notes",
        ])
        writer.writeheader()
        for f in report.findings:
            chain_flag = "YES" if any(f.id in c.components for c in report.chains) else ""
            writer.writerow({
                "ID":             f.id,
                "Severity":       f.severity,
                "Tier":           f.impact_tier,
                "Title":          f.title[:80],
                "Host":           f.host,
                "URL":            f.url[:100],
                "CWE":            f.cwe,
                "CVSS":           f.cvss_score,
                "Typical Payout": f.typical_payout,
                "Tool":           f.source_tool,
                "Status":         "Open",
                "Chain":          chain_flag,
                "Notes":          "",
            })
    log.info(f"CSV tracker → {path}")


# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="NucleiHarvest — Pipeline Aggregator & Bug Bounty Report Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full pipeline aggregation:
  python3 nuclei-harvest.py --domain eskimi.com \\
      --scan     recon-report-v2.json \\
      --headers  headers.json \\
      --bypass   bypass.json \\
      --api      api-findings.json \\
      --cloud    cloud-findings.json \\
      --ssrf     ssrf-findings.json \\
      --oauth    oauth-findings.json \\
      --git      git-findings.json \\
      --params   params.json \\
      --output   final

  # Auto-discover all JSON files in a directory:
  python3 nuclei-harvest.py --domain eskimi.com \\
      --all-findings ./   --output final

  # Also run Nuclei if installed:
  python3 nuclei-harvest.py --domain eskimi.com \\
      --scan recon-report-v2.json --run-nuclei --output final

Outputs:
  final.json          — Master findings JSON (all tools merged + deduplicated)
  final.html          — Interactive HTML dashboard
  final.csv           — Remediation tracker spreadsheet
  final-reports/      — Individual bug bounty reports
    h1_CRITICAL_*.md  — HackerOne Markdown format
    bc_HIGH_*.txt     — Bugcrowd plain text format

Install Nuclei (optional):
  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  nuclei -update-templates
        """,
    )
    p.add_argument("--domain",         required=True)
    p.add_argument("-o","--output",    metavar="BASE", required=True)
    # Individual tool outputs
    p.add_argument("--subtakeover",    metavar="FILE")
    p.add_argument("--scan",           metavar="FILE", help="reconharvest.py output")
    p.add_argument("--headers",        metavar="FILE", help="headeraudit.py output")
    p.add_argument("--bypass",         metavar="FILE", help="4xxbypass.py output")
    p.add_argument("--api",            metavar="FILE", help="apifuzz.py output")
    p.add_argument("--cloud",          metavar="FILE", help="cloudexpose.py output")
    p.add_argument("--ssrf",           metavar="FILE", help="ssrfprobe.py output")
    p.add_argument("--oauth",          metavar="FILE", help="oauthprobe.py output")
    p.add_argument("--git",            metavar="FILE", help="gitdump.py output")
    p.add_argument("--params",         metavar="FILE", help="paramfuzz.py output")
    p.add_argument("--nuclei-output",  metavar="FILE", help="Existing Nuclei JSONL output")
    # Auto-discovery mode
    p.add_argument("--all-findings",   metavar="DIR",
                   help="Directory to auto-discover all *-findings.json files")
    # Nuclei execution
    p.add_argument("--run-nuclei",     action="store_true",
                   help="Run Nuclei if installed (requires nuclei in PATH)")
    p.add_argument("--nuclei-rate",    type=int, default=50,
                   help="Nuclei requests per second (default: 50)")
    p.add_argument("--nuclei-path",    default="nuclei",
                   help="Path to nuclei binary (default: nuclei)")
    p.add_argument("-v","--verbose",   action="store_true")
    return p.parse_args()


def auto_discover_files(directory: str) -> dict[str, str]:
    """
    Auto-discover tool output files in a directory by filename patterns.
    Returns dict of tool_name → file_path.
    """
    patterns = {
        "subtakeover":  ["scan.json", "*subtakeover*.json"],
        "scan":         ["recon-report*.json", "*reconharvest*.json"],
        "headers":      ["headers.json", "*header*.json"],
        "bypass":       ["bypass.json", "*bypass*.json"],
        "api":          ["api-findings.json", "*apifuzz*.json", "*api*.json"],
        "cloud":        ["cloud-findings.json", "*cloud*.json"],
        "ssrf":         ["ssrf-findings.json", "*ssrf*.json"],
        "oauth":        ["oauth-findings.json", "*oauth*.json"],
        "git":          ["git-findings.json", "*git*.json"],
        "params":       ["params.json", "*param*.json"],
    }
    found: dict[str, str] = {}
    d = Path(directory)

    for tool, globs in patterns.items():
        for glob in globs:
            matches = list(d.glob(glob))
            if matches:
                found[tool] = str(matches[0])
                break

    log.info(f"[Auto-discover] Found: {', '.join(found.keys())}")
    return found


async def main() -> None:
    args = parse_args()
    if args.verbose:
        log.setLevel(logging.DEBUG)

    print("""
╔══════════════════════════════════════════════════════════════════╗
║    NucleiHarvest — Pipeline Aggregator & Report Generator        ║
║  For authorized penetration testing and bug bounty research only ║
╚══════════════════════════════════════════════════════════════════╝
""")

    t0 = time.perf_counter()

    # Auto-discover if --all-findings directory provided
    if args.all_findings:
        discovered = auto_discover_files(args.all_findings)
        for key, path in discovered.items():
            if not getattr(args, key.replace("-", "_"), None):
                setattr(args, key.replace("-", "_"), path)

    # Aggregate findings from all pipeline tools
    all_findings: list[NormalizedFinding] = []
    source_tools: list[str] = []

    parsers = {
        "subtakeover": (args.subtakeover, parse_subtakeover),
        "headers":     (args.headers,     parse_headeraudit),
        "bypass":      (args.bypass,      parse_bypass),
        "api":         (args.api,         parse_apifuzz),
        "cloud":       (args.cloud,       parse_cloudexpose),
        "ssrf":        (args.ssrf,        parse_ssrfprobe),
        "oauth":       (args.oauth,       parse_oauthprobe),
        "git":         (args.git,         parse_gitdump),
        "params":      (args.params,      parse_paramfuzz),
    }

    for tool_name, (file_path, parser_fn) in parsers.items():
        if not file_path:
            continue
        if not Path(file_path).exists():
            log.warning(f"[{tool_name}] File not found: {file_path}")
            continue
        try:
            findings = parser_fn(file_path)
            all_findings.extend(findings)
            if findings:
                source_tools.append(tool_name)
        except Exception as exc:
            log.warning(f"[{tool_name}] Parse error: {exc}")

    # Run Nuclei if requested
    nuclei_raw: list[dict] = []
    if args.nuclei_output and Path(args.nuclei_output).exists():
        nuclei_raw = parse_nuclei_json(args.nuclei_output)
    elif args.run_nuclei and all_findings:
        hosts  = sorted(set(f.host for f in all_findings))
        services = detect_services_from_recon(args.scan) if args.scan else {}
        nuclei_out = out_base + "-nuclei-raw.json"
        nuclei_raw = run_nuclei(hosts, services, nuclei_out, args.nuclei_path, args.nuclei_rate)

    if nuclei_raw:
        nuclei_findings = nuclei_to_normalized(nuclei_raw)
        all_findings.extend(nuclei_findings)
        if nuclei_findings:
            source_tools.append("nuclei")

    out_base = args.output
    if out_base.endswith(".json"):
        out_base = out_base[:-5]

    if not all_findings:
        log.error(
            "No findings to aggregate. "
            "Provide at least one tool output file or use --all-findings DIR"
        )
        all_findings = []
        deduped = []
        chains = []
        report = HarvestReport(
            domain=args.domain,
            scan_time=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source_tools=[],
            findings=[],
            chains=[],
            nuclei_findings=[],
            total_hosts=0,
            elapsed_seconds=round(time.perf_counter() - t0, 2),
        )
        save_json_report(report, out_base + ".json")
        return

    log.info(f"[Aggregate] {len(all_findings)} raw findings from {len(source_tools)} tools")

    # Deduplicate
    deduped = deduplicate(all_findings)
    log.info(f"[Deduplicate] {len(deduped)} findings after deduplication")

    # Chain detection
    chains = detect_chains(deduped)

    # Build report
    hosts_from_recon: list[str] = []
    if args.scan and Path(args.scan).exists():
        try:
            with open(args.scan) as f:
                rdata = json.load(f)
            hosts_from_recon = [
                hr["host"] for hr in rdata.get("host_reports", [])
                if hr.get("open_ports")
            ]
        except Exception:
            pass

    report = HarvestReport(
        domain=args.domain,
        scan_time=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        source_tools=source_tools,
        findings=deduped,
        chains=chains,
        nuclei_findings=nuclei_raw,
        total_hosts=len(set(f.host for f in deduped)),
        elapsed_seconds=round(time.perf_counter() - t0, 2),
    )

    print_report(report)

    # Write all outputs
    save_json_report(report, out_base + ".json")
    save_html_report(report, out_base + ".html")
    save_csv_tracker(report, out_base + ".csv")
    save_bounty_reports(report, out_base)

    # Summary
    crit = len([f for f in deduped if f.severity == "CRITICAL"])
    high = len([f for f in deduped if f.severity == "HIGH"])
    p1_p2 = len([f for f in deduped if f.impact_tier in ("P1","P2")])

    if HAS_RICH:
        console.print(Panel.fit(
            f"[white]Total findings:[/] {len(deduped)}\n"
            f"[bold red]CRITICAL:[/] {crit}    "
            f"[bold yellow]HIGH:[/] {high}\n"
            f"[dim]P1/P2 (submittable):[/] {p1_p2}\n"
            f"[dim]Attack chains:[/] {len(chains)}\n\n"
            f"[white]Outputs:[/]\n"
            f"  [cyan]{args.output}.json[/] — master findings\n"
            f"  [cyan]{args.output}.html[/] — dashboard\n"
            f"  [cyan]{args.output}.csv[/] — remediation tracker\n"
            f"  [cyan]{args.output}-reports/[/] — {p1_p2} formatted reports\n\n"
            + ("[bold red]Submit chains first — they represent the highest-severity findings.[/]"
               if chains else "[green]No chains detected.[/]"),
            title="[bold]Scan Complete[/]",
            border_style="red" if crit else "yellow" if high else "green",
        ))


if __name__ == "__main__":
    import asyncio
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(0)
