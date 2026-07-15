#!/usr/bin/env python3
"""
subtakeover.py — Advanced Subdomain Takeover Detection Framework
================================================================
Author  : RareKez / security research tooling
License : MIT (for authorized use only)

IMPORTANT: Only run against targets you have explicit written
           authorization to test. Unauthorized scanning is illegal.

Features:
  Detection:   NS/MX delegation takeover, AAAA records,
               IP-range cloud takeover, domain expiry (RDAP)
  Recon:       CT logs, Wayback CDX, HackerTarget, VirusTotal,
               SecurityTrails, subdomain permutation engine
  Accuracy:    Response clustering/dedup, TLS cert analysis,
               JS/HTML asset correlation
  Output:      Nuclei YAML, Burp XML, self-contained HTML report,
               Slack/Discord webhook alerts
  Persistence: SQLite history DB, scan resume/checkpoint,
               continuous monitoring mode
  Hardening:   Scope file, input normalization, DNS jitter,
               batch mode for large wordlists
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import hashlib
import ipaddress
import json
import logging
import random
import re
import socket
import sqlite3
import ssl
import string
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# ── optional deps ─────────────────────────────────────────────────────────────
try:
    import yaml; HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    import dns.resolver, dns.exception; HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    import dns.asyncresolver, dns.rdatatype; HAS_ASYNC_DNS = True
except ImportError:
    HAS_ASYNC_DNS = False

try:
    import aiodns; HAS_AIODNS = True
except ImportError:
    HAS_AIODNS = False

try:
    import httpx; HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.panel import Panel
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False; console = None

try:
    from bs4 import BeautifulSoup; HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

# ── logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger("subtakeover")
for _n in ("httpx","httpcore","httpcore.connection","httpcore.http11"):
    logging.getLogger(_n).setLevel(logging.WARNING)

# ═════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_NAMESERVERS = [
    "8.8.8.8","8.8.4.4","1.1.1.1","1.0.0.1","9.9.9.9","208.67.222.222",
]

CLOUD_IP_SOURCES = {
    "AWS": "https://ip-ranges.amazonaws.com/ip-ranges.json",
    "GCP": "https://www.gstatic.com/ipranges/cloud.json",
}

CVE_MAP: dict[str, str] = {
    "GitHub Pages":      "https://hackerone.com/reports/263902",
    "AWS S3":            "https://hackerone.com/reports/207576",
    "Heroku":            "https://hackerone.com/reports/159156",
    "Shopify":           "https://hackerone.com/reports/1125129",
    "Fastly":            "https://hackerone.com/reports/298605",
    "Azure / Microsoft": "https://blog.malwarebytes.com/security-world/2021/01/subdomain-takeover/",
    "Zendesk":           "https://hackerone.com/reports/392797",
    "Netlify":           "https://hackerone.com/reports/655825",
    "Vercel":            "https://hackerone.com/reports/1281002",
}

PERM_ENVS     = ["dev","staging","test","qa","uat","prod","beta","demo","sandbox","old","new"]
PERM_SUFFIXES = ["-api","-v1","-v2","-v3","-old","-new","-beta","-dev","-test","2","3"]
PERM_PREFIXES = ["api-","dev-","test-","staging-","old-","new-"]

BUILTIN_FP = """
providers:
  - name: AWS S3
    cname: ['\\.s3\\.amazonaws\\.com$','\\.s3-website.*\\.amazonaws\\.com$','\\.s3\\.dualstack\\..*\\.amazonaws\\.com$']
    fingerprints: ["NoSuchBucket","The specified bucket does not exist"]
    status_codes: [404,403]
    can_claim: true
    docs: "https://docs.aws.amazon.com/AmazonS3/latest/userguide/WebsiteHosting.html"
  - name: AWS CloudFront
    cname: ['\\.cloudfront\\.net$']
    fingerprints: ["Bad request.","ERROR: The request could not be satisfied"]
    status_codes: [403]
    can_claim: false
    docs: "https://aws.amazon.com/cloudfront/"
  - name: GitHub Pages
    cname: ['\\.github\\.io$','\\.github\\.com$']
    fingerprints: ["There isn't a GitHub Pages site here.","For root URLs (like http://example.com/) you must provide an index.html"]
    status_codes: [404]
    can_claim: true
    docs: "https://pages.github.com/"
  - name: Heroku
    cname: ['\\.herokudns\\.com$','\\.herokuapp\\.com$','\\.herokussl\\.com$']
    fingerprints: ["No such app","herokucdn.com/error-pages/no-such-app.html"]
    status_codes: [404]
    can_claim: true
    docs: "https://devcenter.heroku.com/articles/custom-domains"
  - name: Shopify
    cname: ['\\.myshopify\\.com$','shops\\.myshopify\\.com$']
    fingerprints: ["Sorry, this shop is currently unavailable.","Only one step left!"]
    status_codes: [404]
    can_claim: true
    docs: "https://help.shopify.com/en/manual/domains"
  - name: Fastly
    cname: ['\\.fastly\\.net$','\\.fastlylb\\.net$']
    fingerprints: ["Fastly error: unknown domain","Please check that this domain has been added to a service"]
    status_codes: [500,503]
    can_claim: false
    docs: "https://developer.fastly.com/reference/api/services/domain/"
  - name: Pantheon
    cname: ['\\.pantheonsite\\.io$','\\.pantheon\\.io$']
    fingerprints: ["404 error unknown site!","The gods are wise, but do not know of the site which you seek."]
    status_codes: [404]
    can_claim: true
    docs: "https://docs.pantheon.io/guides/domains"
  - name: Azure / Microsoft
    cname: ['\\.azurewebsites\\.net$','\\.cloudapp\\.net$','\\.cloudapp\\.azure\\.com$','\\.trafficmanager\\.net$','\\.blob\\.core\\.windows\\.net$','\\.azure-api\\.net$']
    fingerprints: ["404 Web Site not found","This web app is stopped.","Microsoft Azure App Service"]
    status_codes: [404]
    can_claim: true
    docs: "https://docs.microsoft.com/en-us/azure/app-service"
  - name: Zendesk
    cname: ['\\.zendesk\\.com$']
    fingerprints: ["Help Center Closed","Oops, this help center no longer exists"]
    status_codes: [404]
    can_claim: true
    docs: "https://support.zendesk.com/hc/en-us/articles/203664356"
  - name: Netlify
    cname: ['\\.netlify\\.app$','\\.netlify\\.com$']
    fingerprints: ["Not Found - Request ID:","netlify-dns-challenge"]
    status_codes: [404]
    can_claim: true
    docs: "https://docs.netlify.com/domains-https/custom-domains/"
  - name: Vercel
    cname: ['\\.vercel\\.app$','\\.now\\.sh$']
    fingerprints: ["The deployment you are trying to access does not exist.","This Deployment has been deleted"]
    status_codes: [404]
    can_claim: true
    docs: "https://vercel.com/docs/concepts/projects/domains"
  - name: Surge.sh
    cname: ['\\.surge\\.sh$']
    fingerprints: ["project not found"]
    status_codes: [404]
    can_claim: true
    docs: "https://surge.sh/help/adding-a-custom-domain"
  - name: WP Engine
    cname: ['\\.wpengine\\.com$']
    fingerprints: ["The site you were looking for couldn't be found."]
    status_codes: [404]
    can_claim: true
    docs: "https://wpengine.com/support/add-domain-wpengine/"
  - name: Ghost
    cname: ['\\.ghost\\.io$']
    fingerprints: ["The thing you were looking for is no longer here"]
    status_codes: [404]
    can_claim: true
    docs: "https://ghost.org/docs/hosting/"
  - name: Cargo Collective
    cname: ['\\.cargocollective\\.com$']
    fingerprints: ["If you're the owner of this website"]
    status_codes: [404]
    can_claim: true
    docs: "https://support.cargo.site/Using-a-Custom-Domain"
  - name: Statuspage (Atlassian)
    cname: ['\\.statuspage\\.io$']
    fingerprints: ["You are being redirected","Status Page"]
    status_codes: [404]
    can_claim: true
    docs: "https://support.atlassian.com/statuspage/"
  - name: Tumblr
    cname: ['\\.tumblr\\.com$']
    fingerprints: ["There's nothing here.","Whatever you were looking for doesn't currently exist"]
    status_codes: [404]
    can_claim: true
    docs: "https://help.tumblr.com/hc/en-us/articles/230664368-Custom-Domains"
  - name: Squarespace
    cname: ['\\.squarespace\\.com$']
    fingerprints: ["No Such Account","squarespace error page"]
    status_codes: [404]
    can_claim: true
    docs: "https://support.squarespace.com/hc/en-us/articles/205812378"
trusted_cdns:
  - akamai.net
  - akamaiedge.net
  - edgekey.net
  - edgesuite.net
  - cloudflare.com
  - cloudflare.net
  - cf-dns.com
  - incapdns.net
  - sucuri.net
  - imperva.com
  - stackpathcdn.com
  - highwinds.com
  - edgecast.net
  - cedexis.net
  - footprint.net
  - llnwd.net
  - llnw.net
"""


# ═════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class SubdomainResult:
    subdomain: str
    cname_chain: list[str]          = field(default_factory=list)
    a_records: list[str]            = field(default_factory=list)
    aaaa_records: list[str]         = field(default_factory=list)
    ns_records: list[str]           = field(default_factory=list)
    mx_records: list[str]           = field(default_factory=list)
    is_resolvable: bool             = False
    is_wildcard_match: bool         = False
    is_trusted_cdn: bool            = False
    provider_match: str | None      = None
    fingerprint_matched: list[str]  = field(default_factory=list)
    http_status: int | None         = None
    http_body_snippet: str          = ""
    body_hash: str                  = ""
    tls_info: dict                  = field(default_factory=dict)
    asset_refs: list[str]           = field(default_factory=list)
    ns_takeover: list[dict]         = field(default_factory=list)
    ip_takeover: dict               = field(default_factory=dict)
    verdict: str                    = "SAFE"
    confidence: int                 = 0
    notes: list[str]                = field(default_factory=list)
    deep_probe_result: dict         = field(default_factory=dict)


@dataclass
class ScanReport:
    target_domain: str
    scan_time: str
    total_subdomains: int           = 0
    ct_subdomains_found: int        = 0
    passive_dns_found: int          = 0
    permutations_added: int         = 0
    ct_names: list[str]             = field(default_factory=list)
    wildcard_base_ips: list[str]    = field(default_factory=list)
    elapsed_seconds: float          = 0.0
    stats: dict                     = field(default_factory=dict)
    results: list[SubdomainResult]  = field(default_factory=list)
    ns_findings: list[dict]         = field(default_factory=list)
    scan_id: int | None             = None
    resolved_subdomains: list[dict] = field(default_factory=list)

    def vulnerable(self)   -> list[SubdomainResult]:
        return [r for r in self.results if r.verdict == "VULNERABLE"]
    def potential(self)    -> list[SubdomainResult]:
        return [r for r in self.results if r.verdict == "POTENTIAL"]
    def ns_takeovers(self) -> list[SubdomainResult]:
        return [r for r in self.results if r.verdict == "NS_TAKEOVER"]
    def all_findings(self) -> list[SubdomainResult]:
        return [r for r in self.results
                if r.verdict in ("VULNERABLE","POTENTIAL","NS_TAKEOVER")]

# ═════════════════════════════════════════════════════════════════════════════
# DATABASE
# ═════════════════════════════════════════════════════════════════════════════

class DatabaseManager:
    def __init__(self, db_path: str = "subtakeover.db"):
        self.path = db_path
        self._init()

    def _conn(self):
        return sqlite3.connect(self.path, timeout=10)

    def _init(self):
        with self._conn() as c:
            c.executescript("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL, scan_time TEXT NOT NULL,
                    elapsed REAL, total INTEGER,
                    vulnerable INTEGER DEFAULT 0, potential INTEGER DEFAULT 0,
                    ns_takeovers INTEGER DEFAULT 0, stats_json TEXT);
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL, subdomain TEXT NOT NULL,
                    verdict TEXT NOT NULL, provider TEXT, confidence INTEGER,
                    cname_chain TEXT, http_status INTEGER,
                    fingerprint TEXT, first_seen TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(id));
                CREATE TABLE IF NOT EXISTS checkpoints (
                    domain TEXT NOT NULL, list_hash TEXT NOT NULL,
                    completed TEXT NOT NULL, updated_at TEXT NOT NULL,
                    PRIMARY KEY (domain, list_hash));
            """)

    def save_scan(self, report: ScanReport) -> int:
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO scans (domain,scan_time,elapsed,total,vulnerable,"
                "potential,ns_takeovers,stats_json) VALUES (?,?,?,?,?,?,?,?)",
                (report.target_domain, report.scan_time, report.elapsed_seconds,
                 report.total_subdomains, len(report.vulnerable()),
                 len(report.potential()), len(report.ns_takeovers()),
                 json.dumps(report.stats)))
            sid = cur.lastrowid
            for r in report.all_findings():
                c.execute(
                    "INSERT INTO findings (scan_id,subdomain,verdict,provider,"
                    "confidence,cname_chain,http_status,fingerprint,first_seen) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (sid, r.subdomain, r.verdict, r.provider_match, r.confidence,
                     " -> ".join(r.cname_chain), r.http_status,
                     "; ".join(r.fingerprint_matched), report.scan_time))
        return sid

    def get_previous_findings(self, domain: str) -> set[str]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT DISTINCT f.subdomain FROM findings f "
                "JOIN scans s ON f.scan_id=s.id WHERE s.domain=? "
                "AND f.verdict IN ('VULNERABLE','POTENTIAL','NS_TAKEOVER')",
                (domain,)).fetchall()
        return {r[0] for r in rows}

    def get_scan_history(self, domain: str, limit: int = 10) -> list[dict]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT id,scan_time,elapsed,total,vulnerable,potential "
                "FROM scans WHERE domain=? ORDER BY id DESC LIMIT ?",
                (domain, limit)).fetchall()
        return [dict(zip(["id","scan_time","elapsed","total","vulnerable","potential"],r))
                for r in rows]

    def save_checkpoint(self, domain: str, lhash: str, done: set[str]):
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO checkpoints "
                "(domain,list_hash,completed,updated_at) VALUES (?,?,?,?)",
                (domain, lhash, json.dumps(sorted(done)),
                 datetime.datetime.now(datetime.timezone.utc).isoformat()))

    def load_checkpoint(self, domain: str, lhash: str) -> set[str]:
        with self._conn() as c:
            row = c.execute(
                "SELECT completed FROM checkpoints WHERE domain=? AND list_hash=?",
                (domain, lhash)).fetchone()
        return set(json.loads(row[0])) if row else set()

    def clear_checkpoint(self, domain: str, lhash: str):
        with self._conn() as c:
            c.execute("DELETE FROM checkpoints WHERE domain=? AND list_hash=?",
                      (domain, lhash))

# ═════════════════════════════════════════════════════════════════════════════
# INPUT PROCESSING
# ═════════════════════════════════════════════════════════════════════════════

class ScopeFilter:
    """Parse HackerOne/Bugcrowd scope files: *.target.com, !out.target.com"""
    def __init__(self, path: str | None = None):
        self.includes: list[re.Pattern] = []
        self.excludes: list[re.Pattern] = []
        if path:
            with open(path) as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    excl = line.startswith("!")
                    pat  = line.lstrip("!").lstrip("*.")
                    rx   = re.compile(r"(^|\.)?" + re.escape(pat) + r"$", re.IGNORECASE)
                    (self.excludes if excl else self.includes).append(rx)
            log.info(f"[Scope] {len(self.includes)} includes, {len(self.excludes)} excludes")

    def ok(self, sub: str) -> bool:
        if not self.includes:
            return True
        if any(x.search(sub) for x in self.excludes):
            return False
        return any(i.search(sub) for i in self.includes)


class InputNormalizer:
    @staticmethod
    def normalize(subs: list[str], domain: str, scope: ScopeFilter) -> list[str]:
        """
        Normalize and deduplicate a subdomain list against the target domain.

        Handles two common wordlist formats:
          Bare prefixes : "www", "api", "mail"
            -> expanded to "www.domain.com", "api.domain.com", etc.
            SecLists, Assetnote, and most community wordlists use this format.
          FQDNs         : "www.domain.com", "staging.other.com"
            -> kept only if they belong to the target domain; others discarded.
            CT logs, subfinder, amass output use this format.
        """
        seen: set[str] = set()
        out: list[str] = []
        dl = domain.lower()
        for s in subs:
            s = s.strip().lower().lstrip("*.").rstrip(".")
            if not s:
                continue
            # Bare prefix (no dot) — expand to FQDN for the target domain.
            # e.g. "www" -> "www.upspaceconsulting.com"
            if "." not in s:
                s = f"{s}.{dl}"
            # FQDN that doesn't belong to the target domain — skip.
            elif not (s == dl or s.endswith(f".{dl}")):
                continue
            if s in seen:
                continue
            if not scope.ok(s):
                continue
            seen.add(s)
            out.append(s)
        return out

    @staticmethod
    def list_hash(subs: list[str]) -> str:
        return hashlib.md5("\n".join(sorted(subs)).encode()).hexdigest()


# ═════════════════════════════════════════════════════════════════════════════
# DNS PROBER
# ═════════════════════════════════════════════════════════════════════════════

class DNSProber:
    def __init__(self, timeout: float = 1.5,
                 nameservers: list[str] | None = None, jitter: float = 0.0):
        self.timeout     = timeout
        self.nameservers = nameservers or DEFAULT_NAMESERVERS
        self.jitter      = jitter
        if not HAS_DNSPYTHON:
            self._sync_res = self._async_res = self._aiodns = None
            return

        def _mk(cls):
            try:   r = cls(configure=False)
            except TypeError: r = cls()
            r.nameservers = self.nameservers
            r.timeout     = timeout
            r.lifetime    = timeout * 1.2
            try:   r.retry_servfail = False
            except AttributeError: pass
            return r

        self._sync_res  = _mk(dns.resolver.Resolver)
        self._async_res = _mk(dns.asyncresolver.Resolver) if HAS_ASYNC_DNS else None
        self._aiodns    = (
            aiodns.DNSResolver(nameservers=self.nameservers, timeout=timeout)
            if HAS_AIODNS else None)

    async def _jit(self):
        if self.jitter > 0:
            await asyncio.sleep(random.uniform(0, self.jitter))

    async def probe_async(self, host: str) -> tuple[list[str], list[str]]:
        """Single A query → (cname_chain, a_records)"""
        await self._jit()
        if HAS_AIODNS and self._aiodns:
            return await self._aiodns_probe(host)
        if self._async_res:
            return await self._dnspy_probe(host)
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._sync_probe, host)

    async def _aiodns_probe(self, host: str) -> tuple[list[str], list[str]]:
        try:
            res    = await self._aiodns.query(host, "A")
            a_recs = [r.host for r in res]
            cnames: list[str] = []
            try:
                cr = await self._aiodns.query(host, "CNAME")
                if cr: cnames = [str(cr[0].cname).rstrip(".")]
            except Exception:
                pass
            return cnames, a_recs
        except Exception:
            return [], []

    async def _dnspy_probe(self, host: str) -> tuple[list[str], list[str]]:
        try:
            ans    = await self._async_res.resolve(host, "A", raise_on_no_answer=False)
            a_recs = [str(r) for r in ans if r.rdtype == dns.rdatatype.A]
            cnames: list[str] = []
            if ans.response:
                for rrs in ans.response.answer:
                    if rrs.rdtype == dns.rdatatype.CNAME:
                        cnames.append(str(list(rrs)[0].target).rstrip("."))
            return cnames, a_recs
        except Exception:
            return [], []

    def _sync_probe(self, host: str) -> tuple[list[str], list[str]]:
        try:
            ans    = self._sync_res.resolve(host, "A", raise_on_no_answer=False)
            a_recs = [str(r) for r in ans if r.rdtype == dns.rdatatype.A]
            cnames: list[str] = []
            if ans.response:
                for rrs in ans.response.answer:
                    if rrs.rdtype == dns.rdatatype.CNAME:
                        cnames.append(str(list(rrs)[0].target).rstrip("."))
            return cnames, a_recs
        except Exception:
            return [], []

    async def resolve_aaaa(self, host: str) -> list[str]:
        await self._jit()
        if HAS_AIODNS and self._aiodns:
            try:
                r = await self._aiodns.query(host, "AAAA")
                return [x.host for x in r]
            except Exception: return []
        if self._async_res:
            try:
                ans = await self._async_res.resolve(host, "AAAA", raise_on_no_answer=False)
                return [str(r) for r in ans if r.rdtype == dns.rdatatype.AAAA]
            except Exception: return []
        return []

    async def resolve_ns(self, domain: str) -> list[str]:
        await self._jit()
        if not HAS_DNSPYTHON: return []
        if self._async_res:
            try:
                ans = await self._async_res.resolve(domain, "NS")
                return [str(r).rstrip(".") for r in ans]
            except Exception: return []
        loop = asyncio.get_running_loop()
        try:
            ans = await loop.run_in_executor(
                None, lambda: self._sync_res.resolve(domain, "NS"))
            return [str(r).rstrip(".") for r in ans]
        except Exception: return []

    async def resolve_mx(self, domain: str) -> list[str]:
        await self._jit()
        if not HAS_DNSPYTHON: return []
        if self._async_res:
            try:
                ans = await self._async_res.resolve(domain, "MX")
                return [str(r.exchange).rstrip(".") for r in ans]
            except Exception: return []
        loop = asyncio.get_running_loop()
        try:
            ans = await loop.run_in_executor(
                None, lambda: self._sync_res.resolve(domain, "MX"))
            return [str(r.exchange).rstrip(".") for r in ans]
        except Exception: return []

    def resolve_a_sync(self, host: str) -> list[str]:
        if not HAS_DNSPYTHON:
            try:
                info = socket.getaddrinfo(host, None, socket.AF_INET)
                return list({i[4][0] for i in info})
            except Exception: return []
        try: return [str(r) for r in self._sync_res.resolve(host, "A")]
        except Exception: return []

    def wildcard_ips(self, domain: str) -> list[str]:
        probe = "".join(random.choices(string.ascii_lowercase, k=16)) + "." + domain
        return self.resolve_a_sync(probe)

# ═════════════════════════════════════════════════════════════════════════════
# NS / MX DELEGATION TAKEOVER
# ═════════════════════════════════════════════════════════════════════════════

class NSChecker:
    """
    Checks NS and MX records for delegation takeover vulnerabilities.

    Reserved / non-registerable TLDs are explicitly excluded to prevent
    false positives. Common examples:
      .invalid  — RFC 2606 reserved; used by Microsoft Exchange Online
                  for internal MX routing (e.g. ms72504339.msv1.invalid)
      .local    — mDNS / Bonjour LAN addressing (RFC 6762)
      .test     — RFC 2606 reserved for testing
      .example  — RFC 2606 reserved for documentation
      .internal — common private infrastructure naming convention
      .localhost — RFC 6761 reserved
      .corp     — commonly used for private AD domains
      .home     — commonly used for private networks
      .lan      — commonly used for private networks
    None of these can be registered at a public registrar.
    """

    # RFC 2606 / RFC 6761 reserved TLDs + common private namespace suffixes.
    # Hostnames ending in any of these are excluded from takeover checks.
    RESERVED_TLDS = frozenset({
        "invalid", "local", "test", "example", "localhost",
        "internal", "corp", "home", "lan", "intranet", "private",
        "localdomain", "domain", "workgroup", "belkin", "router",
    })

    def __init__(self, dns_prober: DNSProber):
        self.dns = dns_prober

    @staticmethod
    def _root(h: str) -> str:
        parts = h.rstrip(".").split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else h

    def _is_registerable(self, hostname: str) -> bool:
        """
        Return False if the hostname uses a reserved / non-public TLD.
        Prevents false positives on internal naming conventions and
        provider-internal routing domains (e.g. Exchange Online).
        """
        tld = hostname.rstrip(".").rsplit(".", 1)[-1].lower()
        if tld in self.RESERVED_TLDS:
            log.debug(
                f"[NS-check] Skipping '{hostname}' — "
                f"TLD '.{tld}' is reserved/non-registerable (RFC 2606/6761)"
            )
            return False
        return True

    async def check_ns(self, domain: str) -> list[dict]:
        findings = []
        for ns in await self.dns.resolve_ns(domain):
            if not self._is_registerable(ns):
                continue
            root = self._root(ns)
            if not self._is_registerable(root):
                continue
            _, a = await self.dns.probe_async(root)
            if not a and not (await self.dns.resolve_ns(root)):
                findings.append({
                    "type": "NS_DELEGATION", "record": ns,
                    "root_domain": root, "severity": "CRITICAL",
                    "detail": (
                        f"NS '{ns}' root domain '{root}' does not resolve. "
                        f"Registering '{root}' grants full DNS zone control over {domain}."
                    ),
                })
        return findings

    async def check_mx(self, domain: str) -> list[dict]:
        findings = []
        for mx in await self.dns.resolve_mx(domain):
            if not self._is_registerable(mx):
                continue
            root = self._root(mx)
            if not self._is_registerable(root):
                continue
            _, a = await self.dns.probe_async(mx)
            if not a and not (await self.dns.resolve_ns(root)):
                findings.append({
                    "type": "MX_DANGLING", "record": mx,
                    "root_domain": root, "severity": "HIGH",
                    "detail": (
                        f"MX '{mx}' does not resolve. "
                        f"Registering '{root}' may allow mail interception for {domain}."
                    ),
                })
        return findings

# ═════════════════════════════════════════════════════════════════════════════
# IP RANGE TAKEOVER
# ═════════════════════════════════════════════════════════════════════════════

class IPRangeChecker:
    def __init__(self, timeout: float = 15.0):
        self.timeout = timeout
        self._ranges: dict[str, list[ipaddress.IPv4Network]] = {}
        self._loaded = False

    async def load_ranges(self):
        if not HAS_HTTPX: return
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as c:
            for provider, url in CLOUD_IP_SOURCES.items():
                try:
                    resp = await c.get(url)
                    if resp.status_code != 200: continue
                    data = resp.json()
                    nets: list[ipaddress.IPv4Network] = []
                    if provider == "AWS":
                        for p in data.get("prefixes", []):
                            try: nets.append(ipaddress.IPv4Network(p["ip_prefix"]))
                            except Exception: pass
                    elif provider == "GCP":
                        for p in data.get("prefixes", []):
                            try: nets.append(ipaddress.IPv4Network(p.get("ipv4Prefix","")))
                            except Exception: pass
                    self._ranges[provider] = nets
                    log.info(f"[IP-check] Loaded {len(nets):,} {provider} CIDRs")
                except Exception as exc:
                    log.warning(f"[IP-check] {provider} failed: {exc}")
        self._loaded = True

    def check(self, a_records: list[str], status: int | None, body: str) -> dict:
        if not self._loaded: return {}
        for ip in a_records:
            try: addr = ipaddress.IPv4Address(ip)
            except Exception: continue
            for provider, nets in self._ranges.items():
                if any(addr in net for net in nets):
                    if status in (None, 404, 403, 500, 503):
                        return {
                            "ip": ip, "provider": provider, "http_status": status,
                            "detail": (
                                f"IP {ip} is in {provider} range but response "
                                f"suggests unclaimed resource (status={status})."
                            ),
                        }
        return {}

# ═════════════════════════════════════════════════════════════════════════════
# PASSIVE DNS ENRICHMENT
# ═════════════════════════════════════════════════════════════════════════════

class PassiveDNSEnricher:
    """
    Passive DNS enrichment from 9 sources, queried concurrently.

    Free sources (no API key):
      1. Wayback CDX      — Internet Archive URL index
      2. HackerTarget     — hostsearch API (~10 req/day free)
      3. AlienVault OTX   — passive DNS records
      4. Anubis-DB        — subdomain index
      5. RapidDNS         — subdomain search
      6. BufferOver       — DNS history (tls.bufferover.run)
      7. crt.sh names     — certificate name query (separate from CT log)
      8. DNSRepo          — passive DNS archive

    API-key sources:
      9.  VirusTotal      — free key at virustotal.com
      10. SecurityTrails  — paid

    Sources are queried concurrently so the total wait time equals the
    slowest source, not the sum of all sources. Each source failure is
    reported individually so you can see exactly what's working.

    Note: many of these sources will return 0 results for low-footprint
    targets (small/new domains with minimal internet presence). That is
    correct behaviour — the sources are working, there simply isn't any
    historical passive DNS data to return.
    """

    # ── Source URLs ───────────────────────────────────────────────────────────
    SOURCES = {
        "Wayback CDX":    "https://web.archive.org/cdx/search/cdx?url=*.{d}&output=json&fl=original&collapse=urlkey&limit=50000",
        "HackerTarget":   "https://api.hacktarget.com/hostsearch/?q={d}",
        "AlienVault OTX": "https://otx.alienvault.com/api/v1/indicators/domain/{d}/passive_dns",
        "Anubis-DB":      "https://jonlu.ca/anubis/subdomains/{d}",
        "RapidDNS":       "https://rapiddns.io/subdomain/{d}?full=1#result",
        "BufferOver":     "https://tls.bufferover.run/dns?q=.{d}",
        "crt.sh names":   "https://crt.sh/?q=%.{d}&output=json",
        "DNSRepo":        "https://dnsrepo.noc.org/?domain={d}",
    }

    VIRUSTOTAL = "https://www.virustotal.com/vtapi/v2/domain/report"
    SECTRAILS  = "https://api.securitytrails.com/v1/domain/{d}/subdomains"

    def __init__(self, timeout: float = 30.0,
                 vt_key: str | None = None, st_key: str | None = None):
        self.timeout = timeout
        self.vt_key  = vt_key
        self.st_key  = st_key

    def _add(self, found: set[str], candidate: str, dl: str) -> None:
        """Normalise and add a hostname if it belongs to the target domain."""
        h = candidate.strip().lower().lstrip("*.")
        if h and (h == dl or h.endswith(f".{dl}")):
            found.add(h)

    async def _get(self, url: str, source: str,
                   **kwargs) -> "httpx.Response | None":
        """
        Shared fetch with per-source error logging.
        Uses its own client so sources run truly concurrently via asyncio.gather.
        Retries once on ConnectError (common transient DNS failure on mobile).
        """
        ua = {"User-Agent": "subtakeover-scanner/1.0"}
        for attempt in range(2):
            try:
                async with httpx.AsyncClient(
                    timeout=self.timeout, follow_redirects=True, headers=ua
                ) as c:
                    resp = await c.get(url, **kwargs)
                    if resp.status_code == 200:
                        return resp
                    if resp.status_code == 429:
                        log.warning(f"[Passive] {source}: rate-limited (HTTP 429) — skipping")
                        return None
                    if resp.status_code == 404:
                        # 404 is valid for some sources (domain not in their DB)
                        log.debug(f"[Passive] {source}: 404 — domain not in index")
                        return None
                    log.warning(
                        f"[Passive] {source}: HTTP {resp.status_code}"
                    )
                    return None
            except httpx.TimeoutException:
                log.warning(f"[Passive] {source}: timed out after {self.timeout}s")
                return None
            except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                if attempt == 0:
                    log.debug(f"[Passive] {source}: ConnectError on attempt 1, retrying...")
                    await asyncio.sleep(1.0)
                    continue
                log.warning(
                    f"[Passive] {source}: ConnectError after retry — "
                    f"check network connectivity ({exc})"
                )
                return None
            except Exception as exc:
                log.warning(f"[Passive] {source}: {type(exc).__name__}: {exc}")
                return None
        return None

    # ── Per-source parsers ────────────────────────────────────────────────────

    async def _wayback(self, domain: str, dl: str) -> tuple[str, set[str]]:
        found: set[str] = set()
        url  = self.SOURCES["Wayback CDX"].format(d=domain)
        resp = await self._get(url, "Wayback CDX")
        if resp:
            try:
                rows = resp.json()
                for row in (rows[1:] if rows else []):
                    try:
                        self._add(found, urlparse(row[0]).hostname or "", dl)
                    except Exception:
                        pass
            except Exception as exc:
                log.warning(f"[Passive] Wayback CDX: parse error: {exc}")
        return "Wayback CDX", found

    async def _hackertarget(self, domain: str, dl: str) -> tuple[str, set[str]]:
        found: set[str] = set()
        url  = self.SOURCES["HackerTarget"].format(d=domain)
        resp = await self._get(url, "HackerTarget")
        if resp:
            text = resp.text.strip()
            if any(e in text.lower() for e in ("error", "api count", "invalid")):
                log.warning(f"[Passive] HackerTarget: API limit / error: {text[:80]}")
            else:
                for line in text.splitlines():
                    parts = line.split(",")
                    if parts:
                        self._add(found, parts[0], dl)
        return "HackerTarget", found

    async def _otx(self, domain: str, dl: str) -> tuple[str, set[str]]:
        found: set[str] = set()
        url  = self.SOURCES["AlienVault OTX"].format(d=domain)
        resp = await self._get(url, "AlienVault OTX", timeout=40.0)
        if resp:
            try:
                for record in resp.json().get("passive_dns", []):
                    self._add(found, record.get("hostname", ""), dl)
            except Exception as exc:
                log.warning(f"[Passive] AlienVault OTX: parse error: {exc}")
        return "AlienVault OTX", found

    async def _anubis(self, domain: str, dl: str) -> tuple[str, set[str]]:
        found: set[str] = set()
        url  = self.SOURCES["Anubis-DB"].format(d=domain)
        resp = await self._get(url, "Anubis-DB")
        if resp:
            try:
                for sub in resp.json():
                    if isinstance(sub, str):
                        self._add(found, sub, dl)
            except Exception as exc:
                log.warning(f"[Passive] Anubis-DB: parse error: {exc}")
        return "Anubis-DB", found

    async def _rapiddns(self, domain: str, dl: str) -> tuple[str, set[str]]:
        """
        RapidDNS returns HTML. Parse anchor text matching the domain.
        Pattern: href="/subdomain/sub.domain.com" or text containing the domain.
        """
        found: set[str] = set()
        url  = self.SOURCES["RapidDNS"].format(d=domain)
        resp = await self._get(url, "RapidDNS")
        if resp:
            # Regex-based HTML parse (avoids bs4 dependency for a simple pattern)
            for m in re.finditer(
                rf'([a-zA-Z0-9._-]+\.{re.escape(domain)})',
                resp.text, re.IGNORECASE
            ):
                self._add(found, m.group(1), dl)
        return "RapidDNS", found

    async def _bufferover(self, domain: str, dl: str) -> tuple[str, set[str]]:
        """
        BufferOver tls endpoint returns JSON: {"FDNS_A": ["ip,sub.domain.com", ...]}
        """
        found: set[str] = set()
        url  = self.SOURCES["BufferOver"].format(d=domain)
        resp = await self._get(url, "BufferOver")
        if resp:
            try:
                data = resp.json()
                for entry in data.get("FDNS_A", []) + data.get("RDNS", []):
                    # Format: "1.2.3.4,sub.domain.com" or just "sub.domain.com"
                    parts = entry.split(",")
                    candidate = parts[-1] if len(parts) > 1 else parts[0]
                    self._add(found, candidate, dl)
            except Exception as exc:
                log.warning(f"[Passive] BufferOver: parse error: {exc}")
        return "BufferOver", found

    async def _crtsh_names(self, domain: str, dl: str) -> tuple[str, set[str]]:
        """
        Query crt.sh for certificate names — complementary to CT log mode.
        Uses the name_value field which sometimes includes SANs not in the
        common name, different from the CT log issuer-centric query.
        """
        found: set[str] = set()
        url  = self.SOURCES["crt.sh names"].format(d=domain)
        resp = await self._get(url, "crt.sh names")
        if resp:
            try:
                for entry in resp.json():
                    for name in entry.get("name_value", "").splitlines():
                        self._add(found, name.strip(), dl)
            except Exception as exc:
                log.warning(f"[Passive] crt.sh names: parse error: {exc}")
        return "crt.sh names", found

    async def _dnsrepo(self, domain: str, dl: str) -> tuple[str, set[str]]:
        """
        DNSRepo returns HTML with subdomain table. Extract FQDNs via regex.
        """
        found: set[str] = set()
        url  = self.SOURCES["DNSRepo"].format(d=domain)
        resp = await self._get(url, "DNSRepo")
        if resp:
            for m in re.finditer(
                rf'([a-zA-Z0-9._-]+\.{re.escape(domain)})',
                resp.text, re.IGNORECASE
            ):
                self._add(found, m.group(1), dl)
        return "DNSRepo", found

    async def _virustotal(self, domain: str, dl: str) -> tuple[str, set[str]]:
        found: set[str] = set()
        if not self.vt_key:
            return "VirusTotal", found
        resp = await self._get(
            self.VIRUSTOTAL, "VirusTotal",
            params={"apikey": self.vt_key, "domain": domain},
        )
        if resp:
            try:
                for s in resp.json().get("subdomains", []):
                    self._add(found, s, dl)
            except Exception as exc:
                log.warning(f"[Passive] VirusTotal: parse error: {exc}")
        return "VirusTotal", found

    async def _sectrails(self, domain: str, dl: str) -> tuple[str, set[str]]:
        found: set[str] = set()
        if not self.st_key:
            return "SecurityTrails", found
        resp = await self._get(
            self.SECTRAILS.format(d=domain), "SecurityTrails",
            headers={"APIKEY": self.st_key},
        )
        if resp:
            try:
                for s in resp.json().get("subdomains", []):
                    found.add(f"{s}.{dl}".lower())
            except Exception as exc:
                log.warning(f"[Passive] SecurityTrails: parse error: {exc}")
        return "SecurityTrails", found

    # ── Main entry point ──────────────────────────────────────────────────────

    async def query_all(self, domain: str) -> set[str]:
        """
        Run all sources concurrently. Total time = slowest source, not sum.
        Prints a per-source result table so the user can see exactly what
        each source contributed.
        """
        if not HAS_HTTPX:
            log.warning("[Passive] httpx not installed — passive DNS disabled.")
            return set()

        dl    = domain.lower()
        n_src = len(self.SOURCES) + (1 if self.vt_key else 0) + (1 if self.st_key else 0)
        log.info(f"[Passive] Querying {n_src} sources...")

        # Sources are grouped by sensitivity to rate-limiting:
        #   Group A — robust / rarely rate-limited: fire immediately
        #   Group B — rate-limit sensitive (OTX, Wayback, HackerTarget):
        #             stagger with a small delay so back-to-back scans
        #             don't all hammer the same endpoints simultaneously.
        #
        # Within each group we still use asyncio.gather for concurrency.
        # Total time = max(slowest_A, delay + slowest_B) — still much
        # faster than sequential.

        async def _delayed(coro, delay: float):
            await asyncio.sleep(delay)
            return await coro

        group_a = [                                 # fire immediately
            self._anubis(domain, dl),
            self._rapiddns(domain, dl),
            self._bufferover(domain, dl),
            self._crtsh_names(domain, dl),
            self._dnsrepo(domain, dl),
        ]
        group_b = [                                 # 1-3s stagger
            _delayed(self._wayback(domain, dl),      1.0),
            _delayed(self._otx(domain, dl),          2.0),
            _delayed(self._hackertarget(domain, dl), 3.0),
        ]
        if self.vt_key:
            group_a.append(self._virustotal(domain, dl))
        if self.st_key:
            group_a.append(self._sectrails(domain, dl))

        results = await asyncio.gather(
            *group_a, *group_b, return_exceptions=True
        )

        all_found: set[str] = set()
        for result in results:
            if isinstance(result, Exception):
                log.warning(f"[Passive] Unexpected source error: {result}")
                continue
            source_name, source_found = result
            count  = len(source_found)
            status = f"+{count}" if count > 0 else "0 (not indexed / no history)"
            log.info(f"[Passive]   {source_name:<22} {status}")
            all_found.update(source_found)

        log.info(f"[Passive] Total unique subdomains from all sources: {len(all_found)}")
        return all_found


# ═════════════════════════════════════════════════════════════════════════════
# PERMUTATION ENGINE
# ═════════════════════════════════════════════════════════════════════════════

class PermutationEngine:
    @staticmethod
    def permute(known: list[str], domain: str) -> list[str]:
        cands: set[str] = set()
        dl = domain.lower()
        for sub in known:
            prefix = sub.replace(f".{dl}", "").lstrip(".")
            if not prefix or prefix == dl: continue
            for env in PERM_ENVS:
                if env in prefix:
                    for other in PERM_ENVS:
                        if other != env:
                            cands.add(f"{prefix.replace(env, other)}.{dl}")
            for suf in PERM_SUFFIXES: cands.add(f"{prefix}{suf}.{dl}")
            for pre in PERM_PREFIXES: cands.add(f"{pre}{prefix}.{dl}")
            base = re.sub(r"\d+$", "", prefix)
            if base != prefix:
                for n in range(1, 5): cands.add(f"{base}{n}.{dl}")
        known_set = {s.lower() for s in known}
        return sorted(c for c in cands if c not in known_set and c.endswith(f".{dl}"))

# ═════════════════════════════════════════════════════════════════════════════
# CT LOG QUERIER
# ═════════════════════════════════════════════════════════════════════════════

class CTLogQuerier:
    CRT_SH      = "https://crt.sh/?q=%.{d}&output=json"
    CERTSPOTTER = "https://api.certspotter.com/v1/issuances?domain={d}&include_subdomains=true&expand=dns_names"

    def __init__(self, timeout: float = 20.0):
        self.timeout = timeout

    async def query(self, domain: str) -> list[str]:
        if not HAS_HTTPX: return []
        found: set[str] = set()
        dl = domain.lower()
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as c:
            try:
                resp = await c.get(self.CRT_SH.format(d=domain),
                                   headers={"User-Agent": "subtakeover/1.0"})
                if resp.status_code == 200:
                    for e in resp.json():
                        for name in e.get("name_value","").splitlines():
                            name = name.strip().lower().lstrip("*.")
                            if name.endswith(f".{dl}") or name == dl: found.add(name)
                    log.info(f"[CT] crt.sh: {len(found)} unique names")
                    return sorted(found)
            except Exception as exc:
                log.warning(f"[CT] crt.sh failed: {exc}")
            try:
                resp = await c.get(self.CERTSPOTTER.format(d=domain),
                                   headers={"User-Agent": "subtakeover/1.0"})
                if resp.status_code == 200:
                    for entry in resp.json():
                        for name in entry.get("dns_names", []):
                            name = name.strip().lower().lstrip("*.")
                            if name.endswith(f".{dl}"): found.add(name)
                    log.info(f"[CT] certspotter: {len(found)} unique names")
            except Exception as exc:
                log.warning(f"[CT] certspotter failed: {exc}")
        return sorted(found)


# ═════════════════════════════════════════════════════════════════════════════
# HTTP FINGERPRINTER
# ═════════════════════════════════════════════════════════════════════════════

class HTTPFingerprinter:
    HEADERS = {
        "User-Agent": "Mozilla/5.0 (compatible; SubTakeoverScanner/1.0)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    SNIPPET = 4096

    def __init__(self, timeout: float = 10.0):
        self.timeout  = timeout
        self._cluster: dict[str, int] = {}

    async def probe(self, host: str) -> tuple[int | None, str, str]:
        if not HAS_HTTPX: return None, "", ""
        for scheme in ("https", "http"):
            try:
                async with httpx.AsyncClient(
                    timeout=self.timeout, follow_redirects=True,
                    verify=False, headers=self.HEADERS,
                ) as c:
                    resp = await c.get(f"{scheme}://{host}")
                    body = resp.text[:self.SNIPPET]
                    bh   = hashlib.md5(resp.content[:8192]).hexdigest()
                    self._cluster[bh] = self._cluster.get(bh, 0) + 1
                    return resp.status_code, body, bh
            except httpx.TimeoutException: return None, "", ""
            except Exception: continue
        return None, "", ""

    def is_duplicate(self, bh: str, threshold: int = 5) -> bool:
        return self._cluster.get(bh, 0) >= threshold

    def match(self, body: str, status: int | None, provider: dict) -> list[str]:
        return [fp for fp in provider.get("fingerprints", [])
                if fp.lower() in body.lower()]

# ═════════════════════════════════════════════════════════════════════════════
# TLS ANALYZER
# ═════════════════════════════════════════════════════════════════════════════

class TLSAnalyzer:
    def analyze(self, host: str, port: int = 443) -> dict:
        result: dict = {}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with ctx.wrap_socket(
                socket.create_connection((host, port), timeout=5),
                server_hostname=host,
            ) as sock:
                raw = sock.getpeercert(binary_form=True)
            if not HAS_CRYPTOGRAPHY or not raw:
                return result
            cert = x509.load_der_x509_certificate(raw, default_backend())
            cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            result["cn"] = cn_attrs[0].value if cn_attrs else ""
            exp = getattr(cert, "not_valid_after_utc", None)
            if exp is None:
                exp = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
            result["expiry"]        = exp.isoformat()
            now                     = datetime.datetime.now(datetime.timezone.utc)
            result["days_remaining"]= (exp - now).days
            result["is_expired"]    = result["days_remaining"] < 0
            try:
                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                result["sans"] = [str(n) for n in san.value]
            except Exception:
                result["sans"] = []
            all_names = [result["cn"]] + result.get("sans", [])
            result["cn_mismatch"] = not any(
                host.lower().endswith(n.lstrip("*.").lower())
                for n in all_names if n)
        except Exception as exc:
            result["error"] = str(exc)
        return result

# ═════════════════════════════════════════════════════════════════════════════
# ASSET CORRELATOR
# ═════════════════════════════════════════════════════════════════════════════

class AssetCorrelator:
    PATTERNS = [
        re.compile(r'https?://([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})', re.IGNORECASE),
        re.compile(r'bucket["\s:=]+["\']([a-z0-9.-]+)["\']', re.IGNORECASE),
    ]

    def extract(self, body: str, domain: str) -> list[str]:
        found: set[str] = set()
        dl   = domain.lower()
        text = body
        if HAS_BS4:
            try: text = str(BeautifulSoup(body, "html.parser"))
            except Exception: pass
        for pat in self.PATTERNS:
            for m in pat.finditer(text):
                c = m.group(1).lower().rstrip("/.,;'\"")
                if c.endswith(f".{dl}") and c != dl: found.add(c)
        return sorted(found)

# ═════════════════════════════════════════════════════════════════════════════
# WHOIS / RDAP
# ═════════════════════════════════════════════════════════════════════════════

class WHOISChecker:
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    async def check_expiry(self, domain: str) -> dict:
        if not HAS_HTTPX: return {}
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as c:
                resp = await c.get(f"https://rdap.org/domain/{domain}")
                if resp.status_code != 200: return {}
                data   = resp.json()
                expiry = next(
                    (ev.get("eventDate","") for ev in data.get("events",[])
                     if ev.get("eventAction") == "expiration"), None)
                if not expiry: return {}
                dt   = datetime.datetime.fromisoformat(
                    expiry.replace("Z","+00:00")).replace(tzinfo=datetime.timezone.utc)
                days = (dt - datetime.datetime.now(datetime.timezone.utc)).days
                return {"expiry": expiry, "days_remaining": days,
                        "is_expired": days < 0, "is_expiring_soon": 0 <= days <= 30}
        except Exception as e:
            log.debug(f"[RDAP] {domain}: {e}")
            return {}

# ═════════════════════════════════════════════════════════════════════════════
# DEEP PROBE ENGINE
# ═════════════════════════════════════════════════════════════════════════════

class DeepProbeEngine:
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    async def _get(self, url: str, **kwargs):
        if not HAS_HTTPX: return None
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=True) as c:
                return await c.get(url, **kwargs)
        except Exception: return None

    async def probe_github(self, cname: str) -> dict:
        m = re.match(r"^([^.]+)\.github\.io", cname)
        if not m: return {"exists": None, "detail": "Cannot parse user.", "api_used": "GitHub API v3"}
        user = m.group(1)
        resp = await self._get(f"https://api.github.com/users/{user}")
        if resp is None: return {"exists": None, "detail": "API unreachable.", "api_used": "GitHub API v3"}
        if resp.status_code == 404:
            return {"exists": False, "detail": f"User '{user}' does not exist — takeover viable.", "api_used": "GitHub API v3"}
        return {"exists": True, "detail": f"User '{user}' exists. Verify repo '{user}.github.io'.", "api_used": "GitHub API v3"}

    async def probe_s3(self, cname: str) -> dict:
        m = re.match(r"^([^.]+)\.s3", cname)
        if not m: return {"exists": None, "detail": "Cannot extract bucket.", "api_used": "AWS S3 REST"}
        bucket = m.group(1)
        resp   = await self._get(f"https://s3.amazonaws.com/{bucket}")
        if resp is None: return {"exists": None, "detail": "API unreachable.", "api_used": "AWS S3 REST"}
        if resp.status_code == 404 and "NoSuchBucket" in resp.text:
            return {"exists": False, "detail": f"Bucket '{bucket}' does not exist — takeover viable.", "api_used": "AWS S3 REST"}
        if resp.status_code == 403:
            return {"exists": True, "detail": f"Bucket '{bucket}' exists.", "api_used": "AWS S3 REST"}
        return {"exists": None, "detail": f"S3 → {resp.status_code}", "api_used": "AWS S3 REST"}

    async def probe_azure(self, cname: str) -> dict:
        m = re.match(r"^([^.]+)\.blob\.core\.windows\.net", cname)
        if not m: return {"exists": None, "detail": "Not Azure Blob.", "api_used": "Azure Blob REST"}
        acct = m.group(1)
        resp = await self._get(f"https://{acct}.blob.core.windows.net/?comp=list")
        if resp is None: return {"exists": None, "detail": "API unreachable.", "api_used": "Azure Blob REST"}
        if resp.status_code == 404:
            return {"exists": False, "detail": f"Account '{acct}' not found.", "api_used": "Azure Blob REST"}
        return {"exists": True, "detail": f"Account '{acct}' exists.", "api_used": "Azure Blob REST"}

    async def dispatch(self, provider: str, cname: str) -> dict:
        n = provider.lower()
        if "github" in n: return await self.probe_github(cname)
        if "s3" in n:     return await self.probe_s3(cname)
        if "azure" in n and "blob" in cname: return await self.probe_azure(cname)
        return {"exists": None, "detail": f"No deep probe for '{provider}'.", "api_used": "N/A"}

# ═════════════════════════════════════════════════════════════════════════════
# FINGERPRINT LOADER
# ═════════════════════════════════════════════════════════════════════════════

def load_fingerprints(path: str | None = None) -> dict:
    if path:
        if not HAS_YAML:
            log.error("PyYAML required for custom fingerprints."); sys.exit(1)
        with open(path) as fh:
            data = yaml.safe_load(fh)
        log.info(f"Loaded {len(data['providers'])} providers from {path}")
        return data
    if HAS_YAML:
        data = yaml.safe_load(BUILTIN_FP)
    else:
        log.warning("PyYAML not installed — using minimal fingerprint set.")
        data = {"providers": [], "trusted_cdns": []}
    log.info(f"Loaded {len(data['providers'])} built-in provider fingerprints.")
    return data


# ═════════════════════════════════════════════════════════════════════════════
# CORE SCANNER
# ═════════════════════════════════════════════════════════════════════════════

class SubTakeoverScanner:
    def __init__(
        self, target_domain: str, fingerprints: dict, *,
        wildcard_check: bool = True, use_ct: bool = False, deep_mode: bool = False,
        concurrency: int = 50, dns_concurrency: int = 300,
        http_timeout: float = 10.0, dns_timeout: float = 1.5,
        nameservers: list[str] | None = None, jitter: float = 0.0,
        ns_check: bool = False, ip_check: bool = False, tls_check: bool = False,
        asset_check: bool = False, whois_check: bool = False, cluster: bool = False,
        use_passive: bool = False, vt_key: str | None = None,
        st_key: str | None = None, permute: bool = False,
        permute_limit: int = 500,
    ):
        self.domain          = target_domain
        self.fp_db           = fingerprints
        self.wildcard_check  = wildcard_check
        self.use_ct          = use_ct
        self.deep_mode       = deep_mode
        self.concurrency     = concurrency
        self.dns_concurrency = dns_concurrency
        self.ns_check        = ns_check
        self.ip_check        = ip_check
        self.tls_check       = tls_check
        self.asset_check     = asset_check
        self.whois_check     = whois_check
        self.cluster         = cluster
        self.use_passive     = use_passive
        self.permute         = permute
        self.permute_limit   = permute_limit

        self.dns     = DNSProber(dns_timeout, nameservers, jitter)
        self.http    = HTTPFingerprinter(http_timeout)
        self.ct      = CTLogQuerier()
        self.deep    = DeepProbeEngine(http_timeout)
        self.ns_chk  = NSChecker(self.dns)
        self.ip_chk  = IPRangeChecker()
        self.tls_chk = TLSAnalyzer()
        self.assets  = AssetCorrelator()
        self.whois   = WHOISChecker()
        self.passive = PassiveDNSEnricher(vt_key=vt_key, st_key=st_key)
        self.perm    = PermutationEngine()

        self._providers    = self.fp_db.get("providers", [])
        self._trusted_cdns = self.fp_db.get("trusted_cdns", [])
        self._compiled     = [
            (p, [re.compile(pat, re.IGNORECASE) for pat in p.get("cname", [])])
            for p in self._providers
        ]

    def detect_wildcard(self) -> list[str]:
        ips = self.dns.wildcard_ips(self.domain)
        if ips: log.warning(f"[WILDCARD] *.{self.domain} → {ips}")
        return ips

    def match_provider(self, chain: list[str]) -> dict | None:
        for cname in chain:
            for provider, patterns in self._compiled:
                for pat in patterns:
                    if pat.search(cname): return provider
        return None

    def is_trusted_cdn(self, chain: list[str]) -> bool:
        return any(c.rstrip(".").endswith(cdn)
                   for c in chain for cdn in self._trusted_cdns)

    def assign_verdict(self, r: SubdomainResult, provider: dict | None):
        if r.is_wildcard_match or r.is_trusted_cdn:
            r.verdict = "SAFE"; r.confidence = 5; return
        if provider is None:
            r.verdict = "SAFE"; r.confidence = 10; return
        conf = 40
        if not r.a_records:          conf += 20
        if r.fingerprint_matched:    conf += 30
        if r.http_status in (provider.get("status_codes") or []): conf += 10
        r.confidence = min(conf, 100); r.provider_match = provider["name"]
        if conf >= 70 and r.fingerprint_matched: r.verdict = "VULNERABLE"
        elif conf >= 40: r.verdict = "POTENTIAL"
        else: r.verdict = "SAFE"

    # ── Phase 1: DNS ──────────────────────────────────────────────────────────

    async def dns_phase(self, subdomain: str, wildcard_ips: list[str]) -> SubdomainResult:
        r = SubdomainResult(subdomain=subdomain)
        r.cname_chain, r.a_records = await self.dns.probe_async(subdomain)
        r.is_resolvable = bool(r.a_records)

        if not r.is_resolvable and not r.cname_chain:
            r.verdict = "SAFE"; r.confidence = 0
            r.notes.append("NXDOMAIN: no A records and no CNAME chain.")
            return r
        if wildcard_ips and r.a_records and set(r.a_records).issubset(set(wildcard_ips)):
            r.is_wildcard_match = True
            r.notes.append("Suppressed: wildcard DNS match.")
            self.assign_verdict(r, None); return r
        if self.is_trusted_cdn(r.cname_chain):
            r.is_trusted_cdn = True
            r.notes.append("Trusted CDN CNAME — not a takeover vector.")
            self.assign_verdict(r, None); return r

        provider = self.match_provider(r.cname_chain)
        if provider:
            r.provider_match = provider["name"]
            r.verdict        = "_NEEDS_HTTP"
        else:
            self.assign_verdict(r, None)
        return r

    # ── Phase 2: HTTP ─────────────────────────────────────────────────────────

    async def http_phase(self, r: SubdomainResult) -> SubdomainResult:
        provider = next((p for p in self._providers if p["name"] == r.provider_match), None)
        if provider is None: r.verdict = "SAFE"; return r

        status, body, bh = await self.http.probe(r.subdomain)
        r.http_status = status; r.http_body_snippet = body; r.body_hash = bh

        if self.cluster and self.http.is_duplicate(bh):
            r.verdict = "SAFE"
            r.notes.append("Suppressed: clustered duplicate response.")
            return r

        r.fingerprint_matched = self.http.match(body, status, provider)
        self.assign_verdict(r, provider)

        if self.ip_check and r.a_records:
            ip_f = self.ip_chk.check(r.a_records, status, body)
            if ip_f: r.ip_takeover = ip_f; r.notes.append(f"[IP] {ip_f['detail']}")

        if self.tls_check and r.verdict in ("POTENTIAL","VULNERABLE"):
            r.tls_info = self.tls_chk.analyze(r.subdomain)
            if r.tls_info.get("is_expired"):
                r.notes.append(f"[TLS] Cert expired {r.tls_info.get('days_remaining')} days ago.")
                r.confidence = min(r.confidence + 10, 100)
            if r.tls_info.get("cn_mismatch"):
                r.notes.append("[TLS] CN mismatch — provider serving default cert.")

        if self.asset_check and body:
            refs = self.assets.extract(body, self.domain)
            if refs: r.asset_refs = refs; r.notes.append(f"[Assets] {len(refs)} subdomain refs found.")

        if self.deep_mode and r.verdict in ("POTENTIAL","VULNERABLE"):
            fc = r.cname_chain[-1] if r.cname_chain else r.subdomain
            r.deep_probe_result = await self.deep.dispatch(provider["name"], fc)

        ref = CVE_MAP.get(provider["name"])
        if ref and r.verdict in ("POTENTIAL","VULNERABLE"):
            r.notes.append(f"[Ref] {ref}")

        return r

    # ── Main scan ─────────────────────────────────────────────────────────────

    async def scan(
        self, subdomains: list[str],
        db: "DatabaseManager | None"     = None,
        checkpoint_hash: str | None      = None,
        completed_set: "set[str] | None" = None,
    ) -> ScanReport:
        report = ScanReport(
            target_domain=self.domain,
            scan_time=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )
        all_subs = list(subdomains)

        # CT
        if self.use_ct:
            ct = await self.ct.query(self.domain)
            report.ct_subdomains_found = len(ct); report.ct_names = sorted(ct)
            prev = len(all_subs); all_subs = sorted(set(all_subs) | set(ct))
            if ct: log.info(f"[CT] {len(ct)} names → merged to {len(all_subs)} total")

        # Passive DNS
        if self.use_passive:
            pdn = await self.passive.query_all(self.domain)
            report.passive_dns_found = len(pdn)
            prev     = len(all_subs)
            all_subs = sorted(set(all_subs) | pdn)
            added    = len(all_subs) - prev
            log.info(
                f"[Passive] Total unique from all sources: {len(pdn)}  "
                f"New (not in wordlist): {added}  "
                f"Merged total: {len(all_subs):,}"
            )

        # NOTE: --permute runs as Phase 3 (after DNS), seeding only from
        # subdomains that actually resolved. Seeding from the full wordlist
        # (103k+ entries × 20 mutations = 2M+ strings) causes OOM on mobile.

        # Resume
        if completed_set:
            before = len(all_subs)
            all_subs = [s for s in all_subs if s not in completed_set]
            log.info(f"[Resume] Skipping {before-len(all_subs)} → {len(all_subs)} remaining")

        report.total_subdomains  = len(all_subs)
        wildcard_ips: list[str] = []
        if self.wildcard_check:
            wildcard_ips = self.detect_wildcard()
        report.wildcard_base_ips = wildcard_ips

        if self.ip_check:
            await self.ip_chk.load_ranges()

        if self.ns_check:
            log.info("[NS-check] Checking NS/MX delegation...")
            ns_f = await self.ns_chk.check_ns(self.domain)
            mx_f = await self.ns_chk.check_mx(self.domain)
            report.ns_findings = ns_f + mx_f
            for f in report.ns_findings:
                log.warning(f"[{f['severity']}] {f['type']}: {f['record']} — {f['detail'][:80]}")

        if self.whois_check:
            log.info("[WHOIS] Checking domain expiry...")
            exp = await self.whois.check_expiry(self.domain)
            if exp:
                report.stats["domain_expiry"] = exp
                if exp.get("is_expired"):
                    log.warning(f"[WHOIS] {self.domain} EXPIRED {abs(exp['days_remaining'])} days ago!")
                elif exp.get("is_expiring_soon"):
                    log.warning(f"[WHOIS] {self.domain} expires in {exp['days_remaining']} days!")

        dns_sem  = asyncio.Semaphore(self.dns_concurrency)
        http_sem = asyncio.Semaphore(self.concurrency)
        done_set: set[str] = set(completed_set or [])
        CKPT      = 1000
        # Chunk size limits peak coroutine-object memory on mobile.
        # 103k coroutines × ~1KB each = ~100MB before any run without chunking.
        # Processing in 5k chunks keeps peak overhead to ~5MB per chunk.
        CHUNK     = 5000

        async def bdns(s: str) -> SubdomainResult:
            async with dns_sem: return await self.dns_phase(s, wildcard_ips)

        async def bhttp(r: SubdomainResult) -> SubdomainResult:
            async with http_sem: return await self.http_phase(r)

        t0 = time.perf_counter()
        dns_engine = ("aiodns" if HAS_AIODNS else
                      "asyncresolver" if HAS_ASYNC_DNS else "thread-pool")
        log.info(f"[Phase 1] DNS — {len(all_subs):,} subdomains "
                 f"@ concurrency {self.dns_concurrency} ({dns_engine})")

        # Phase 1 — chunked to avoid creating all coroutines at once (mobile RAM)
        phase1: list[SubdomainResult] = []
        chunks = [all_subs[i:i+CHUNK] for i in range(0, len(all_subs), CHUNK)]

        if HAS_RICH:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]Phase 1 DNS[/]"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TextColumn("[dim]{task.fields[rate]}/s[/]"),
                console=console,
            ) as prog:
                task = prog.add_task("DNS", total=len(all_subs), rate="—")
                p1t0 = time.perf_counter(); dc = 0
                for chunk in chunks:
                    for coro in asyncio.as_completed([bdns(s) for s in chunk]):
                        r = await coro; phase1.append(r); dc += 1
                        done_set.add(r.subdomain)
                        if db and checkpoint_hash and dc % CKPT == 0:
                            db.save_checkpoint(self.domain, checkpoint_hash, done_set)
                        el   = time.perf_counter() - p1t0
                        rate = int(dc / el) if el > 0 else 0
                        prog.update(task, advance=1, rate=str(rate))
        else:
            for chunk in chunks:
                results = await asyncio.gather(*[bdns(s) for s in chunk])
                phase1.extend(results)
                done_set.update(r.subdomain for r in results)

        # ── Phase 3: Permutation on resolved names only ─────────────────────
        # Seeds are subdomains that actually returned A records in Phase 1.
        # This is correct semantically (mutate real names, not wordlist noise)
        # and critical for mobile RAM: 4 resolved names × 20 mutations = 80
        # extra candidates, not 103k × 20 = 2M+ which OOM-kills Termux.
        if self.permute:
            resolved_names = [r.subdomain for r in phase1 if r.is_resolvable][:self.permute_limit]
            if resolved_names:
                muts = self.perm.permute(resolved_names, self.domain)
                # Exclude any we already scanned
                new_muts = [m for m in muts if m not in done_set]
                report.permutations_added = len(new_muts)
                if new_muts:
                    log.info(
                        f"[Phase 3 Permute] {len(resolved_names)} resolved names "
                        f"→ {len(new_muts)} new mutations to scan"
                    )
                    p3_sem = asyncio.Semaphore(self.dns_concurrency)
                    async def bp3(s: str) -> SubdomainResult:
                        async with p3_sem: return await self.dns_phase(s, wildcard_ips)

                    if HAS_RICH:
                        with Progress(
                            SpinnerColumn(),
                            TextColumn("[bold purple]Phase 3 Permute[/]"),
                            BarColumn(),
                            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                            console=console,
                        ) as prog:
                            task = prog.add_task("Permute", total=len(new_muts))
                            p3_chunks = [new_muts[i:i+CHUNK] for i in range(0, len(new_muts), CHUNK)]
                            for chunk in p3_chunks:
                                for coro in asyncio.as_completed([bp3(s) for s in chunk]):
                                    r = await coro
                                    phase1.append(r)
                                    prog.update(task, advance=1)
                    else:
                        for chunk in [new_muts[i:i+CHUNK] for i in range(0, len(new_muts), CHUNK)]:
                            phase1.extend(await asyncio.gather(*[bp3(s) for s in chunk]))
                else:
                    log.info("[Phase 3 Permute] No new mutation candidates.")
            else:
                log.info("[Phase 3 Permute] No resolved subdomains to seed from — skipped.")

        # Phase 2
        http_cands = [r for r in phase1 if r.verdict == "_NEEDS_HTTP"]
        safe_res   = [r for r in phase1 if r.verdict != "_NEEDS_HTTP"]
        log.info(f"[Phase 2] HTTP — {len(http_cands)} candidates @ concurrency {self.concurrency}")

        final: list[SubdomainResult] = safe_res[:]
        if http_cands:
            lv = lp = 0
            if HAS_RICH:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[bold yellow]Phase 2 HTTP[/]"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TextColumn("[bold red]VULN:{task.fields[v]}[/] [bold yellow]POT:{task.fields[p]}[/]"),
                    console=console,
                ) as prog:
                    task = prog.add_task("HTTP", total=len(http_cands), v=0, p=0)
                    for coro in asyncio.as_completed([bhttp(r) for r in http_cands]):
                        r = await coro; final.append(r)
                        if r.verdict == "VULNERABLE": lv += 1
                        elif r.verdict == "POTENTIAL": lp += 1
                        prog.update(task, advance=1, v=lv, p=lp)
            else:
                final.extend(await asyncio.gather(*[bhttp(r) for r in http_cands]))
        else:
            log.info("[Phase 2] No HTTP candidates — skipped.")

        report.elapsed_seconds = round(time.perf_counter() - t0, 2)
        report.results = sorted(final, key=lambda r: r.verdict != "VULNERABLE")

        # Inject NS_TAKEOVER results
        for f in report.ns_findings:
            if f["severity"] == "CRITICAL":
                ns_r = SubdomainResult(subdomain=self.domain)
                ns_r.verdict = "NS_TAKEOVER"; ns_r.confidence = 95
                ns_r.ns_takeover = [f]; ns_r.notes.append(f["detail"])
                report.results.insert(0, ns_r); break

        n_resolved  = sum(1 for r in final if r.is_resolvable)
        n_nxdomain  = sum(1 for r in final if not r.is_resolvable and not r.cname_chain)
        n_provider  = sum(1 for r in final if r.provider_match)
        n_cname_any = sum(1 for r in final if r.cname_chain)
        n_http      = sum(1 for r in final if r.http_status is not None)

        # ── Resolved subdomains intel ─────────────────────────────────────
        # Collected regardless of verdict — actionable recon even when no
        # takeover candidates are found. Sorted by subdomain for easy reading.
        report.resolved_subdomains = sorted(
            [
                {
                    "subdomain":    r.subdomain,
                    "a_records":    r.a_records,
                    "aaaa_records": r.aaaa_records,
                    "cname_chain":  r.cname_chain,
                    "is_cdn":       r.is_trusted_cdn,
                    "provider":     r.provider_match,
                }
                for r in final if r.is_resolvable
            ],
            key=lambda x: x["subdomain"],
        )

        # ── Post-scan advisory hints ──────────────────────────────────────
        hints: list[str] = []
        no_findings = not report.all_findings()

        if no_findings and n_resolved > 0:
            if n_provider == 0 and not self.ip_check:
                hints.append(
                    f"All {n_resolved} live subdomains resolve via direct A records "
                    f"(no provider CNAME detected). Run with --ip-check to test for "
                    f"cloud IP-range takeovers (AWS/GCP) which bypass CNAME matching."
                )
            if (self.deep_mode or self.tls_check) and n_provider == 0:
                hints.append(
                    "--deep and --tls only activate on CNAME-matched subdomains. "
                    "They were skipped this scan because Provider match = 0."
                )
            if n_resolved > 10 and not self.asset_check:
                hints.append(
                    f"Found {n_resolved} live hosts. Add --assets to scrape their "
                    f"JS/HTML for hardcoded subdomain references and bucket names."
                )
            if not self.whois_check:
                hints.append(
                    "Run with --whois to check domain registration expiry via RDAP."
                )

        if n_cname_any > 0 and n_provider == 0:
            hints.append(
                f"{n_cname_any} subdomains have CNAME records but none matched the "
                f"built-in provider list. Use --fingerprints to supply a custom YAML "
                f"if you believe a provider is missing."
            )

        report.stats = {
            "resolved":            n_resolved,
            "nxdomain":            n_nxdomain,
            "provider_match":      n_provider,
            "cname_any":           n_cname_any,
            "http_probed":         n_http,
            "wildcard_suppressed": sum(1 for r in final if r.is_wildcard_match),
            "cdn_suppressed":      sum(1 for r in final if r.is_trusted_cdn),
            "ip_findings":         sum(1 for r in final if r.ip_takeover),
            "asset_refs_found":    sum(1 for r in final if r.asset_refs),
            "dns_concurrency":     self.dns_concurrency,
            "http_concurrency":    self.concurrency,
            "dns_engine":          dns_engine,
            "hints":               hints,
        }
        if db and checkpoint_hash:
            db.clear_checkpoint(self.domain, checkpoint_hash)
        return report


# ═════════════════════════════════════════════════════════════════════════════
# REPORTING
# ═════════════════════════════════════════════════════════════════════════════

VERDICT_COLORS = {
    "VULNERABLE": "bold red", "POTENTIAL": "bold yellow",
    "NS_TAKEOVER": "bold magenta", "SAFE": "dim green",
}


def print_report(report: ScanReport):
    vuln  = report.vulnerable()
    pot   = report.potential()
    ns_t  = report.ns_takeovers()
    stats = report.stats

    if HAS_RICH:
        console.print()
        stats_line = ""
        if stats:
            stats_line = (
                f"\n[white]Resolved:[/] {stats.get('resolved',0)}  "
                f"[dim]NXDOMAIN:[/] {stats.get('nxdomain',0)}  "
                f"[cyan]Provider match:[/] {stats.get('provider_match',0)}  "
                f"[dim]HTTP probed:[/] {stats.get('http_probed',0)}"
                f"\n[dim]DNS engine:[/] {stats.get('dns_engine','?')}  "
                f"[dim]DNS concurrency:[/] {stats.get('dns_concurrency','?')}  "
                f"[dim]HTTP concurrency:[/] {stats.get('http_concurrency','?')}"
            )
            if stats.get("ip_findings"):
                stats_line += f"\n[orange3]IP-range findings:[/] {stats['ip_findings']}"
            if stats.get("domain_expiry"):
                exp = stats["domain_expiry"]
                col = "red" if exp.get("is_expired") else "yellow"
                stats_line += (f"\n[{col}]Domain expiry:[/] {exp.get('expiry','')} "
                               f"({exp.get('days_remaining','?')} days)")

        ct_line = ""
        if report.ct_names:
            ct_line = ("\n[white]CT names:[/] "
                       + ", ".join(f"[cyan]{n}[/]" for n in report.ct_names[:8])
                       + (f" +{len(report.ct_names)-8} more" if len(report.ct_names) > 8 else ""))

        enrich = ""
        if report.passive_dns_found or report.permutations_added:
            enrich = (f"\n[dim]Passive DNS:[/] +{report.passive_dns_found}  "
                      f"[dim]Permutations:[/] +{report.permutations_added}")

        console.print(Panel.fit(
            f"[white]Target:[/] [cyan]{report.target_domain}[/]\n"
            f"[white]Scan time:[/] {report.scan_time}\n"
            f"[white]Elapsed:[/] {report.elapsed_seconds}s\n"
            f"[white]Scanned:[/] {report.total_subdomains:,} subdomains  "
            f"[white]CT:[/] {report.ct_subdomains_found} names"
            f"{ct_line}{enrich}"
            f"\n[white]Wildcard IPs:[/] {report.wildcard_base_ips or 'None detected'}"
            f"{stats_line}\n"
            f"[bold red]VULNERABLE:[/] {len(vuln)}    "
            f"[bold yellow]POTENTIAL:[/] {len(pot)}    "
            f"[bold magenta]NS_TAKEOVER:[/] {len(ns_t)}",
            title="[bold]SubTakeover Scan Report[/]",
            border_style="blue",
        ))

        if report.ns_findings:
            console.print("\n[bold magenta]── NS / MX Delegation Findings ──[/]")
            for f in report.ns_findings:
                col = "red" if f["severity"] == "CRITICAL" else "yellow"
                console.print(f"  [{col}][{f['severity']}][/] {f['type']}: "
                               f"[cyan]{f['record']}[/] → {f['detail']}")

        if vuln or pot or ns_t:
            tbl = Table(show_header=True, header_style="bold blue", border_style="dim")
            tbl.add_column("Subdomain", style="cyan", no_wrap=True)
            tbl.add_column("Verdict", justify="center")
            tbl.add_column("Provider")
            tbl.add_column("Conf", justify="right")
            tbl.add_column("HTTP", justify="right")
            tbl.add_column("Fingerprint")
            tbl.add_column("CNAME Chain", style="dim")
            for r in (vuln + pot + ns_t):
                col = VERDICT_COLORS.get(r.verdict, "white")
                tbl.add_row(
                    r.subdomain, f"[{col}]{r.verdict}[/]",
                    r.provider_match or "—", str(r.confidence),
                    str(r.http_status or "—"),
                    "; ".join(r.fingerprint_matched[:2]) or "—",
                    " → ".join(r.cname_chain[:3]) or "—",
                )
            console.print(tbl)
            for r in (vuln + pot):
                if r.deep_probe_result:
                    console.print(f"  [bold]Deep probe [{r.subdomain}]:[/] "
                                  f"{r.deep_probe_result.get('detail','')} "
                                  f"({r.deep_probe_result.get('api_used','')})")
                if r.tls_info.get("is_expired"):
                    console.print(f"  [red]TLS:[/] Cert expired {r.tls_info.get('days_remaining')} days ago")
                if r.asset_refs:
                    console.print(f"  [cyan]Assets:[/] "
                                  + ", ".join(r.asset_refs[:5])
                                  + ("..." if len(r.asset_refs) > 5 else ""))
        if not vuln and not pot and not ns_t:
            console.print("[bold green]✓ No takeover candidates found.[/]")

        # ── Resolved subdomains intel table ──────────────────────────────
        resolved = report.resolved_subdomains
        if resolved:
            console.print(
                f"\n[bold cyan]── Resolved Subdomains"
                f" ({len(resolved)} live hosts) ──[/]"
            )
            rtbl = Table(
                show_header=True, header_style="bold cyan",
                border_style="dim", show_lines=False,
            )
            rtbl.add_column("Subdomain",   style="cyan",  no_wrap=True)
            rtbl.add_column("A Records",   style="dim")
            rtbl.add_column("CNAME Chain", style="dim")
            rtbl.add_column("Type",        style="dim",   justify="right")

            for rec in resolved[:60]:   # cap terminal at 60 rows
                if rec["is_cdn"]:
                    kind = "[dim]CDN[/]"
                elif rec["provider"]:
                    kind = f"[yellow]{rec['provider']}[/]"
                elif rec["cname_chain"]:
                    kind = "[dim]CNAME[/]"
                else:
                    kind = "[dim]direct A[/]"

                rtbl.add_row(
                    rec["subdomain"],
                    ", ".join(rec["a_records"][:2])
                        + (" ..." if len(rec["a_records"]) > 2 else ""),
                    " → ".join(rec["cname_chain"][:2])
                        + (" ..." if len(rec["cname_chain"]) > 2 else ""),
                    kind,
                )

            console.print(rtbl)
            if len(resolved) > 60:
                console.print(
                    f"  [dim]... {len(resolved)-60} more hosts in JSON "
                    f"(resolved_subdomains[])[/]"
                )

        # ── Next-step hints ───────────────────────────────────────────────
        hints = report.stats.get("hints", [])
        if hints:
            console.print("\n[bold yellow]── Suggested Next Steps ──[/]")
            for h in hints:
                console.print(f"  [yellow]→[/] {h}")

    else:
        print(f"\n=== SubTakeover Report: {report.target_domain} ===")
        print(f"Scanned: {report.total_subdomains} | VULNERABLE: {len(vuln)} | "
              f"POTENTIAL: {len(pot)} | NS_TAKEOVER: {len(ns_t)} | "
              f"Elapsed: {report.elapsed_seconds}s")
        for r in report.all_findings():
            print(f"\n[{r.verdict}] {r.subdomain}")
            print(f"  Provider: {r.provider_match}  Confidence: {r.confidence}%")
            print(f"  HTTP: {r.http_status}  CNAME: {' -> '.join(r.cname_chain)}")
            for note in r.notes: print(f"  {note}")

        if report.resolved_subdomains:
            print(f"\n── Resolved Subdomains ({len(report.resolved_subdomains)} hosts) ──")
            for rec in report.resolved_subdomains[:60]:
                kind = "CDN" if rec["is_cdn"] else (rec["provider"] or "direct A")
                print(f"  {rec['subdomain']:<45} {', '.join(rec['a_records'][:2]):<18} {kind}")
            if len(report.resolved_subdomains) > 60:
                print(f"  ... {len(report.resolved_subdomains)-60} more in JSON report")

        hints = report.stats.get("hints", [])
        if hints:
            print("\n── Suggested Next Steps ──")
            for h in hints:
                print(f"  → {h}")
    print()


def save_report(report: ScanReport, path: str):
    data = {
        "target_domain":      report.target_domain,
        "scan_time":          report.scan_time,
        "elapsed_seconds":    report.elapsed_seconds,
        "total_subdomains":   report.total_subdomains,
        "ct_subdomains_found":report.ct_subdomains_found,
        "passive_dns_found":  report.passive_dns_found,
        "permutations_added": report.permutations_added,
        "ct_names":           report.ct_names,
        "wildcard_base_ips":  report.wildcard_base_ips,
        "ns_findings":        report.ns_findings,
        "stats":              report.stats,
        "summary": {
            "vulnerable":   len(report.vulnerable()),
            "potential":    len(report.potential()),
            "ns_takeovers": len(report.ns_takeovers()),
            "safe":         sum(1 for r in report.results if r.verdict == "SAFE"),
        },
        "findings": [asdict(r) for r in report.all_findings()],
        "resolved_subdomains": report.resolved_subdomains,
        "hints": report.stats.get("hints", []),
    }
    with open(path, "w") as fh: json.dump(data, fh, indent=2)
    n_resolved = len(report.resolved_subdomains)
    log.info(f"JSON report saved → {path}")
    if n_resolved:
        log.info(
            f"  resolved_subdomains[]: {n_resolved} live hosts with IPs and CNAME chains"
        )


# ═════════════════════════════════════════════════════════════════════════════
# EXPORTERS
# ═════════════════════════════════════════════════════════════════════════════

class NucleiExporter:
    TMPL = """\
id: subdomain-takeover-{safe_id}
info:
  name: "Subdomain Takeover - {subdomain}"
  author: subtakeover-scanner
  severity: high
  description: >
    {subdomain} CNAMEs to {provider}. Fingerprint: {fingerprint}
  reference:
    - {ref}
  tags: subdomain-takeover,dns,{provider_tag}
http:
  - method: GET
    path:
      - "http://{{{{Hostname}}}}"
      - "https://{{{{Hostname}}}}"
    matchers-condition: and
    matchers:
      - type: word
        words:
{fp_lines}
      - type: status
        status: [{status_code}]
"""

    def export(self, report: ScanReport, out_dir: str) -> int:
        findings = report.vulnerable() + report.potential()
        if not findings: log.info("[Nuclei] No findings to export."); return 0
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        count = 0
        for r in findings:
            if not r.provider_match: continue
            safe_id  = re.sub(r"[^a-z0-9-]", "-", r.subdomain.lower())
            fp_lines = "\n".join(
                f'          - "{fp}"' for fp in (r.fingerprint_matched or ["error"])
            )
            ref = CVE_MAP.get(r.provider_match, "https://owasp.org/www-project-web-security-testing-guide/")
            content = self.TMPL.format(
                safe_id=safe_id, subdomain=r.subdomain,
                provider=r.provider_match,
                provider_tag=r.provider_match.lower().replace(" ","-").replace("/","-"),
                fingerprint="; ".join(r.fingerprint_matched or []),
                fp_lines=fp_lines, status_code=404, ref=ref,
            )
            (Path(out_dir) / f"{safe_id}.yaml").write_text(content)
            count += 1
        log.info(f"[Nuclei] Exported {count} templates to {out_dir}/")
        return count


class BurpExporter:
    SEV = {"VULNERABLE": "High", "POTENTIAL": "Medium", "NS_TAKEOVER": "High"}

    def export(self, report: ScanReport, path: str):
        root = ET.Element("issues", burpVersion="2.0", exportTime=report.scan_time)
        for r in report.all_findings():
            issue = ET.SubElement(root, "issue")
            ET.SubElement(issue, "serialNumber").text = str(abs(hash(r.subdomain)))
            ET.SubElement(issue, "type").text         = "134217728"
            ET.SubElement(issue, "name").text         = (
                f"Subdomain Takeover ({r.provider_match or 'NS Delegation'})"
            )
            ET.SubElement(issue, "host", ip=", ".join(r.a_records or [""])).text = (
                f"https://{r.subdomain}"
            )
            ET.SubElement(issue, "path").text       = "/"
            ET.SubElement(issue, "severity").text   = self.SEV.get(r.verdict, "Medium")
            ET.SubElement(issue, "confidence").text = "Certain" if r.confidence >= 70 else "Tentative"
            ET.SubElement(issue, "issueDetail").text = (
                f"Provider: {r.provider_match}<br>"
                f"CNAME: {' → '.join(r.cname_chain)}<br>"
                f"Fingerprint: {'; '.join(r.fingerprint_matched)}<br>"
                f"Confidence: {r.confidence}%<br>"
                + "<br>".join(r.notes)
            )
            ET.SubElement(issue, "remediationDetail").text = (
                "Remove the dangling DNS record or reclaim the resource at the provider."
            )
        tree = ET.ElementTree(root)
        ET.indent(tree, space="  ")
        with open(path, "wb") as fh: tree.write(fh, encoding="utf-8", xml_declaration=True)
        log.info(f"[Burp] XML exported → {path}")


class HTMLReporter:
    CSS = """
:root{--bg:#0d1117;--sf:#161b22;--bd:#30363d;--tx:#c9d1d9;--mt:#8b949e;
      --rd:#f85149;--yw:#d29922;--gn:#3fb950;--pu:#bc8cff;--bl:#58a6ff;--cy:#39c5cf;}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--tx);font-family:'Consolas','Monaco',monospace;font-size:14px;}
.wrap{max-width:1200px;margin:0 auto;padding:24px;}
h1{color:var(--bl);font-size:1.6em;margin-bottom:4px;}
.sub{color:var(--mt);margin-bottom:24px;font-size:.85em;}
.panel{background:var(--sf);border:1px solid var(--bd);border-radius:8px;padding:20px;margin-bottom:20px;}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px;margin-top:12px;}
.stat{background:var(--bg);border:1px solid var(--bd);border-radius:6px;padding:12px;text-align:center;}
.sv{font-size:1.8em;font-weight:bold;}.sl{color:var(--mt);font-size:.75em;margin-top:4px;}
.red{color:var(--rd);}.yw{color:var(--yw);}.gn{color:var(--gn);}.pu{color:var(--pu);}.mt{color:var(--mt);}
table{width:100%;border-collapse:collapse;}
th{background:var(--bg);color:var(--mt);text-align:left;padding:10px 12px;
   border-bottom:1px solid var(--bd);font-size:.8em;text-transform:uppercase;letter-spacing:.05em;}
td{padding:10px 12px;border-bottom:1px solid var(--bd);vertical-align:top;font-size:.9em;}
tr:hover td{background:rgba(88,166,255,.04);}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.75em;font-weight:bold;}
.bv{background:rgba(248,81,73,.2);color:var(--rd);border:1px solid var(--rd);}
.bp{background:rgba(210,153,34,.2);color:var(--yw);border:1px solid var(--yw);}
.bn{background:rgba(188,140,255,.2);color:var(--pu);border:1px solid var(--pu);}
.cn{color:var(--cy);font-size:.8em;}.nt{color:var(--mt);font-size:.8em;margin-top:4px;}
.sec{color:var(--bl);font-size:1em;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid var(--bd);}
.nsf{background:rgba(248,81,73,.05);border:1px solid var(--rd);border-radius:6px;padding:12px;margin-bottom:10px;}
.empty{text-align:center;color:var(--mt);padding:40px;}
.foot{text-align:center;color:var(--mt);font-size:.75em;margin-top:32px;padding-top:16px;border-top:1px solid var(--bd);}
"""

    def _badge(self, v: str) -> str:
        cls = {"VULNERABLE":"bv","POTENTIAL":"bp","NS_TAKEOVER":"bn"}.get(v,"")
        return f'<span class="badge {cls}">{v}</span>'

    def export(self, report: ScanReport, path: str):
        findings = report.all_findings()
        s = report.stats

        ns_html = ""
        if report.ns_findings:
            parts = ['<div class="panel"><div class="sec">NS / MX Delegation Findings</div>']
            for f in report.ns_findings:
                parts.append(
                    f'<div class="nsf">'
                    f'<span class="badge bv">{f["severity"]}</span> '
                    f'<strong>{f["type"]}</strong>: {f["record"]}<br>'
                    f'<span class="mt">{f["detail"]}</span></div>'
                )
            parts.append("</div>"); ns_html = "\n".join(parts)

        if findings:
            rows = []
            for r in findings:
                cn_str = " → ".join(r.cname_chain[:4]) or "—"
                nt_str = "<br>".join(r.notes[:3])
                rows.append(
                    f"<tr><td>{r.subdomain}</td><td>{self._badge(r.verdict)}</td>"
                    f"<td>{r.provider_match or '—'}</td><td>{r.confidence}%</td>"
                    f"<td>{r.http_status or '—'}</td>"
                    f"<td><span class='cn'>{cn_str}</span>"
                    f"{'<div class=nt>'+nt_str+'</div>' if nt_str else ''}</td></tr>"
                )
            findings_html = (
                '<div class="panel"><div class="sec">Findings</div>'
                '<table><thead><tr>'
                '<th>Subdomain</th><th>Verdict</th><th>Provider</th>'
                '<th>Conf</th><th>HTTP</th><th>CNAME / Notes</th>'
                '</tr></thead><tbody>' + "\n".join(rows) + '</tbody></table></div>'
            )
        else:
            findings_html = '<div class="panel"><div class="empty">✓ No takeover candidates found.</div></div>'

        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>SubTakeover — {report.target_domain}</title>
<style>{self.CSS}</style></head>
<body><div class="wrap">
<h1>SubTakeover Report</h1>
<p class="sub">{report.target_domain} &nbsp;·&nbsp; {report.scan_time} &nbsp;·&nbsp; {report.elapsed_seconds}s</p>
<div class="panel"><div class="sec">Summary</div><div class="grid">
<div class="stat"><div class="sv red">{len(report.vulnerable())}</div><div class="sl">VULNERABLE</div></div>
<div class="stat"><div class="sv yw">{len(report.potential())}</div><div class="sl">POTENTIAL</div></div>
<div class="stat"><div class="sv pu">{len(report.ns_takeovers())}</div><div class="sl">NS TAKEOVER</div></div>
<div class="stat"><div class="sv">{report.total_subdomains:,}</div><div class="sl">SCANNED</div></div>
<div class="stat"><div class="sv gn">{s.get('resolved',0)}</div><div class="sl">RESOLVED</div></div>
<div class="stat"><div class="sv mt">{s.get('nxdomain',0)}</div><div class="sl">NXDOMAIN</div></div>
<div class="stat"><div class="sv">{report.ct_subdomains_found}</div><div class="sl">CT NAMES</div></div>
<div class="stat"><div class="sv mt">{report.passive_dns_found}</div><div class="sl">PASSIVE DNS</div></div>
</div></div>
{ns_html}
{findings_html}
<div class="foot">Generated by SubTakeover Scanner &nbsp;·&nbsp; Authorized security testing only</div>
</div></body></html>"""
        with open(path, "w", encoding="utf-8") as fh: fh.write(html)
        log.info(f"[HTML] Report saved → {path}")


class WebhookNotifier:
    def __init__(self, url: str, timeout: float = 10.0):
        self.url = url; self.timeout = timeout

    def _is_discord(self) -> bool:
        return "discord.com/api/webhooks" in self.url

    def _slack_payload(self, report: ScanReport, findings: list[SubdomainResult]) -> dict:
        blocks = [
            {"type":"header","text":{"type":"plain_text",
             "text":f"SubTakeover Alert: {report.target_domain}"}},
            {"type":"section","fields":[
                {"type":"mrkdwn","text":f"*VULNERABLE:* {len(report.vulnerable())}"},
                {"type":"mrkdwn","text":f"*POTENTIAL:* {len(report.potential())}"},
                {"type":"mrkdwn","text":f"*NS Takeover:* {len(report.ns_takeovers())}"},
                {"type":"mrkdwn","text":f"*Scanned:* {report.total_subdomains:,}"},
            ]},
        ]
        for r in findings[:5]:
            blocks.append({"type":"section","text":{"type":"mrkdwn","text":(
                f"*[{r.verdict}]* `{r.subdomain}`\n"
                f"Provider: {r.provider_match}  Conf: {r.confidence}%\n"
                f"CNAME: `{' -> '.join(r.cname_chain)}`"
            )}})
        if len(findings) > 5:
            blocks.append({"type":"section","text":{"type":"mrkdwn",
                "text":f"_... and {len(findings)-5} more findings_"}})
        return {"blocks": blocks}

    def _discord_payload(self, report: ScanReport, findings: list[SubdomainResult]) -> dict:
        lines = [
            f"**SubTakeover Alert: {report.target_domain}**",
            f"VULNERABLE: **{len(report.vulnerable())}** | "
            f"POTENTIAL: **{len(report.potential())}** | "
            f"Scanned: {report.total_subdomains:,}", "",
        ]
        for r in findings[:10]:
            lines.append(f"`[{r.verdict}]` **{r.subdomain}** → {r.provider_match} ({r.confidence}%)")
        return {"content": "\n".join(lines)}

    async def send(self, report: ScanReport,
                   new_findings: list[SubdomainResult] | None = None) -> bool:
        if not HAS_HTTPX: return False
        findings = new_findings or report.all_findings()
        if not findings: return True
        payload = (self._discord_payload(report, findings)
                   if self._is_discord() else self._slack_payload(report, findings))
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as c:
                resp = await c.post(self.url, json=payload,
                                    headers={"Content-Type": "application/json"})
                if resp.status_code in (200, 204):
                    log.info(f"[Webhook] Alert sent ({resp.status_code})"); return True
                log.warning(f"[Webhook] Status {resp.status_code}")
        except Exception as exc:
            log.warning(f"[Webhook] Failed: {exc}")
        return False


# ═════════════════════════════════════════════════════════════════════════════
# INPUT HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def load_subdomains(path: str) -> list[str]:
    lines = []
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                lines.append(line.lower())
    log.info(f"Loaded {len(lines):,} subdomains from {path}")
    return lines


def builtin_wordlist(domain: str) -> list[str]:
    prefixes = [
        "www","mail","smtp","pop","imap","ftp","ssh","vpn","dev","staging",
        "test","api","cdn","static","assets","media","img","images","video",
        "blog","shop","store","admin","dashboard","portal","login","auth",
        "beta","preview","demo","sandbox","qa","uat","prod","legacy","old",
        "new","secure","help","support","docs","documentation","wiki","status",
        "monitor","analytics","tracking","data","reports","metrics","app",
        "apps","mobile","m","wap","git","gitlab","github","bitbucket","ci",
        "jenkins","jira","confluence","slack","chat","crm","erp","s3","files",
        "upload","download","assets2","ns1","ns2","ns3","mx","mx1","mx2",
    ]
    return [f"{p}.{domain}" for p in prefixes]

# ═════════════════════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="SubTakeover — Advanced Subdomain Takeover Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python subtakeover.py -d example.com
  python subtakeover.py -d example.com --ct --passive --permute --ns-check
  python subtakeover.py -d example.com --subdomains 1m.txt --resume
  python subtakeover.py -d example.com --monitor --interval 3600 --webhook URL
  python subtakeover.py -d example.com --ct --passive --permute --ns-check \\
      --ip-check --tls --assets --whois --deep \\
      --output scan --html report.html --burp findings.xml --nuclei templates/

LEGAL NOTICE: Authorized penetration testing and bug bounty research ONLY.
""")

    # Target
    p.add_argument("-d","--domain", required=True, help="Target root domain")
    p.add_argument("--subdomains", metavar="FILE", help="Subdomain wordlist file")
    p.add_argument("--scope", metavar="FILE",
                   help="Scope file (*.target.com, !out.target.com)")

    # Recon
    p.add_argument("--ct", action="store_true",
                   help="Certificate Transparency enrichment (crt.sh)")
    p.add_argument("--passive", action="store_true",
                   help="Passive DNS (Wayback CDX + HackerTarget)")
    p.add_argument("--vt-key", metavar="KEY", help="VirusTotal API key")
    p.add_argument("--st-key", metavar="KEY", help="SecurityTrails API key")
    p.add_argument("--permute", action="store_true",
                   help="Generate subdomain permutations from resolved names (runs as Phase 3)")
    p.add_argument("--permute-limit", type=int, default=500, metavar="N",
                   help="Max resolved names to seed permutations from (default: 500). "
                        "Prevents OOM on mobile when many subdomains resolve.")

    # Detection
    p.add_argument("--wildcard-check", action="store_true", default=True)
    p.add_argument("--no-wildcard-check", action="store_false", dest="wildcard_check")
    p.add_argument("--ns-check", action="store_true",
                   help="NS/MX delegation takeover detection")
    p.add_argument("--ip-check", action="store_true",
                   help="Cloud IP-range takeover detection (AWS, GCP)")
    p.add_argument("--deep", action="store_true",
                   help="Deep API probes (GitHub, S3, Azure)")
    p.add_argument("--tls", action="store_true",
                   help="TLS certificate analysis on findings")
    p.add_argument("--assets", action="store_true",
                   help="JS/HTML asset correlation")
    p.add_argument("--whois", action="store_true",
                   help="Domain expiry check via RDAP")
    p.add_argument("--cluster", action="store_true",
                   help="Suppress clustered duplicate HTTP responses (reduces FP)")
    p.add_argument("--fingerprints", metavar="YAML",
                   help="Custom provider fingerprints YAML")

    # Performance
    p.add_argument("--concurrency", type=int, default=50, metavar="N",
                   help="HTTP phase concurrency (default: 50)")
    p.add_argument("--dns-concurrency", type=int, default=300, metavar="N",
                   help="DNS phase concurrency (default: 300)")
    p.add_argument("--timeout", type=float, default=10.0, metavar="SEC",
                   help="HTTP timeout (default: 10s)")
    p.add_argument("--dns-timeout", type=float, default=1.5, metavar="SEC",
                   help="DNS timeout (default: 1.5s)")
    p.add_argument("--nameservers", metavar="IP,...",
                   help="Custom resolvers (comma-separated)")
    p.add_argument("--jitter", type=float, default=0.0, metavar="SEC",
                   help="Max random sleep before DNS query (default: 0)")

    # Persistence
    p.add_argument("--db", metavar="PATH", default="subtakeover.db")
    p.add_argument("--resume", action="store_true",
                   help="Resume interrupted scan from checkpoint")
    p.add_argument("--history", action="store_true",
                   help="Show scan history for this domain and exit")

    # Output
    p.add_argument("--output", metavar="BASE",
                   help="Save JSON report (e.g. --output scan → scan.json)")
    p.add_argument("--html", metavar="FILE",
                   help="Export self-contained HTML report")
    p.add_argument("--burp", metavar="FILE",
                   help="Export Burp Suite XML")
    p.add_argument("--nuclei", metavar="DIR",
                   help="Export Nuclei YAML templates to directory")
    p.add_argument("--webhook", metavar="URL",
                   help="Slack/Discord webhook for finding alerts")

    # Monitor
    p.add_argument("--monitor", action="store_true",
                   help="Continuous monitoring — re-scan on interval")
    p.add_argument("--interval", type=int, default=3600, metavar="SEC",
                   help="Monitor re-scan interval in seconds (default: 3600)")

    # Logging
    p.add_argument("-v","--verbose", action="store_true",
                   help="Verbose tool-level logging")
    p.add_argument("--trace", action="store_true",
                   help="Full httpx transport debug (very noisy)")

    return p.parse_args()

# ═════════════════════════════════════════════════════════════════════════════
# SCAN RUNNER
# ═════════════════════════════════════════════════════════════════════════════

async def run_scan(
    args: argparse.Namespace,
    scanner: SubTakeoverScanner,
    subdomains: list[str],
    db: DatabaseManager,
    list_hash: str,
    previous: set[str],
    webhook: "WebhookNotifier | None",
) -> ScanReport:
    completed: set[str] = set()
    if args.resume:
        completed = db.load_checkpoint(args.domain, list_hash)
        if completed:
            log.info(f"[Resume] Checkpoint found — {len(completed):,} already done")

    report = await scanner.scan(
        subdomains, db=db, checkpoint_hash=list_hash,
        completed_set=completed if args.resume else None,
    )
    report.scan_id = db.save_scan(report)

    print_report(report)

    if args.output:
        out_path = args.output
        if not out_path.endswith(".json"):
            out_path += ".json"
        save_report(report, out_path)
    if args.html:       HTMLReporter().export(report, args.html)
    if args.burp:       BurpExporter().export(report, args.burp)
    if args.nuclei:     NucleiExporter().export(report, args.nuclei)

    if webhook:
        new = [r for r in report.all_findings() if r.subdomain not in previous]
        if new:
            log.info(f"[Webhook] {len(new)} new findings — sending alert")
            await webhook.send(report, new)
        else:
            log.info("[Webhook] No new findings since last scan.")

    return report

# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════

async def main():
    args = parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)
    if args.trace:
        logging.getLogger().setLevel(logging.DEBUG)
        for _t in ("httpx","httpcore","httpcore.connection","httpcore.http11"):
            logging.getLogger(_t).setLevel(logging.DEBUG)

    # Dependency hints
    missing = []
    if not HAS_DNSPYTHON: missing.append("dnspython")
    if not HAS_HTTPX:     missing.append("httpx")
    if missing:
        log.warning("Missing: " + "  ".join(f"pip install {m}" for m in missing))
    if not HAS_AIODNS:
        log.info("Tip: pip install aiodns  — fastest DNS (c-ares)")
    if not HAS_CRYPTOGRAPHY:
        log.info("Tip: pip install cryptography  — enables TLS cert analysis")
    if not HAS_BS4:
        log.info("Tip: pip install beautifulsoup4  — improves asset correlation")

    print("""
╔══════════════════════════════════════════════════════════════════╗
║       SubTakeover — Advanced Subdomain Takeover Scanner          ║
║  For authorized penetration testing and bug bounty research only ║
║  Ensure you have WRITTEN permission before scanning any target   ║
╚══════════════════════════════════════════════════════════════════╝
""")

    db      = DatabaseManager(args.db)
    fp_db   = load_fingerprints(args.fingerprints)
    scope   = ScopeFilter(args.scope)

    if args.history:
        history = db.get_scan_history(args.domain)
        if not history:
            print(f"No scan history for {args.domain}")
        else:
            print(f"\nScan history for {args.domain}:")
            for row in history:
                print(f"  [{row['id']}] {row['scan_time']}  "
                      f"elapsed={row['elapsed']}s  total={row['total']}  "
                      f"VULN={row['vulnerable']}  POT={row['potential']}")
        return

    raw_subs = load_subdomains(args.subdomains) if args.subdomains else builtin_wordlist(args.domain)
    if not args.subdomains:
        log.info(f"Using built-in wordlist ({len(raw_subs)} entries).")

    subdomains = InputNormalizer.normalize(raw_subs, args.domain, scope)
    list_hash  = InputNormalizer.list_hash(subdomains)
    log.info(
        f"[Normalize] {len(raw_subs):,} raw entries -> "
        f"{len(subdomains):,} unique FQDNs for {args.domain} "
        f"(bare prefixes expanded, duplicates removed)"
    )

    nameservers = (
        [ns.strip() for ns in args.nameservers.split(",")]
        if args.nameservers else None
    )

    scanner = SubTakeoverScanner(
        target_domain   = args.domain,
        fingerprints    = fp_db,
        wildcard_check  = args.wildcard_check,
        use_ct          = args.ct,
        deep_mode       = args.deep,
        concurrency     = args.concurrency,
        dns_concurrency = args.dns_concurrency,
        http_timeout    = args.timeout,
        dns_timeout     = args.dns_timeout,
        nameservers     = nameservers,
        jitter          = args.jitter,
        ns_check        = args.ns_check,
        ip_check        = args.ip_check,
        tls_check       = args.tls,
        asset_check     = args.assets,
        whois_check     = args.whois,
        cluster         = args.cluster,
        use_passive     = args.passive,
        vt_key          = args.vt_key,
        st_key          = args.st_key,
        permute         = args.permute,
        permute_limit   = args.permute_limit,
    )

    webhook = WebhookNotifier(args.webhook) if args.webhook else None

    if args.monitor:
        log.info(f"[Monitor] Scanning every {args.interval}s. Ctrl+C to stop.")
        n = 0
        while True:
            n += 1
            log.info(f"[Monitor] Scan #{n}...")
            previous = db.get_previous_findings(args.domain)
            try:
                await run_scan(args, scanner, subdomains, db, list_hash, previous, webhook)
            except Exception as exc:
                log.error(f"[Monitor] Scan #{n} failed: {exc}")
            log.info(f"[Monitor] Next scan in {args.interval}s.")
            await asyncio.sleep(args.interval)
    else:
        previous = db.get_previous_findings(args.domain)
        await run_scan(args, scanner, subdomains, db, list_hash, previous, webhook)


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted."); sys.exit(0)
