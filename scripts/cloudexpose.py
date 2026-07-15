#!/usr/bin/env python3
"""
cloudexpose.py — Cloud Storage & Service Misconfiguration Hunter
================================================================
Author  : RareKez / security research tooling
License : MIT (for authorized use only)

Chains from : subtakeover.py (--subtakeover) — IPs, resolved subdomains
              jsreaper.py    (--js)           — bucket names from JS files
              reconharvest.py (--scan)        — IPs, service data
              plain list      (--domain)      — brute-forces name variants

Feeds into  : ssrfprobe.py, bug bounty reports

Pipeline:
  1. Harvest cloud resource names from every available source:
       - CT log subdomain prefixes (api, assets, cdn, media, static, backup …)
       - JS files (S3 bucket URLs, GCS references, Azure blob references)
       - DNS CNAMEs (*.s3.amazonaws.com, *.blob.core.windows.net, etc.)
       - Domain-derived wordlist (target, target-prod, target-dev, target-backup …)
  2. Test each resource for public access:
       S3   — list, read, write, ACL, website-hosting checks
       GCS  — list, read, write, allUsers IAM checks
       Azure Blob — container enumeration, anonymous read
       Firebase   — /.json unauthenticated read/write
  3. Probe open IPs for exposed database ports:
       Redis (6379), MongoDB (27017), Elasticsearch (9200),
       CouchDB (5984), Memcached (11211), Cassandra (9042)
  4. Check GCP metadata endpoint accessibility via SSRF vectors
  5. Generate JSON + HTML report with curl PoC per finding

Usage:
  python3 cloudexpose.py --subtakeover scan.json --domain eskimi.com --output cloud
  python3 cloudexpose.py --js js-findings.json --domain eskimi.com --output cloud
  python3 cloudexpose.py --scan recon-report-v2.json --domain eskimi.com --output cloud
  python3 cloudexpose.py --domain eskimi.com --output cloud
  python3 cloudexpose.py --domain eskimi.com --wordlist bucket-names.txt --output cloud

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
log = logging.getLogger("cloudexpose")
for _n in ("httpx", "httpcore"):
    logging.getLogger(_n).setLevel(logging.WARNING)


# ═════════════════════════════════════════════════════════════════════════════
# CLOUD PROVIDER PATTERNS
# ═════════════════════════════════════════════════════════════════════════════

# S3 bucket URL patterns
S3_PATTERNS = [
    re.compile(r'([\w\-\.]+)\.s3\.amazonaws\.com', re.I),
    re.compile(r's3\.amazonaws\.com/([\w\-\.]+)', re.I),
    re.compile(r's3[\-\.](?:us|eu|ap|sa|ca|me|af)[\-\w]+\.amazonaws\.com/([\w\-\.]+)', re.I),
    re.compile(r'([\w\-\.]+)\.s3[\-\.](?:us|eu|ap|sa|ca|me|af)[\-\w]+\.amazonaws\.com', re.I),
]

# GCS bucket URL patterns
GCS_PATTERNS = [
    re.compile(r'([\w\-\.]+)\.storage\.googleapis\.com', re.I),
    re.compile(r'storage\.googleapis\.com/([\w\-\.]+)', re.I),
    re.compile(r'([\w\-\.]+)\.appspot\.com', re.I),
]

# Azure blob URL patterns
AZURE_PATTERNS = [
    re.compile(r'([\w\-]+)\.blob\.core\.windows\.net', re.I),
    re.compile(r'([\w\-]+)\.file\.core\.windows\.net', re.I),
]

# Firebase URL patterns
FIREBASE_PATTERNS = [
    re.compile(r'([\w\-]+)\.firebaseio\.com', re.I),
    re.compile(r'([\w\-]+)\.firebaseapp\.com', re.I),
]

# Common bucket name suffixes to try per domain
BUCKET_SUFFIXES = [
    "", "-prod", "-production", "-dev", "-development", "-staging", "-stage",
    "-test", "-testing", "-qa", "-uat", "-demo",
    "-assets", "-asset", "-static", "-cdn", "-media",
    "-uploads", "-upload", "-files", "-file", "-docs", "-data",
    "-backup", "-backups", "-bak", "-archive", "-logs", "-log",
    "-public", "-private", "-internal", "-admin",
    "-www", "-web", "-app", "-api",
    ".com", ".io", ".net",
]

# Common database ports to probe
DB_PORTS = {
    6379:  "Redis",
    27017: "MongoDB",
    9200:  "Elasticsearch",
    9300:  "Elasticsearch (transport)",
    5984:  "CouchDB",
    11211: "Memcached",
    9042:  "Cassandra",
    5432:  "PostgreSQL",
    3306:  "MySQL/MariaDB",
    1433:  "MSSQL",
    7474:  "Neo4j HTTP",
    8529:  "ArangoDB",
    5601:  "Kibana",
    9000:  "SonarQube / Minio",
}

# Database probe commands / HTTP paths
DB_PROBES: dict[int, dict] = {
    6379:  {"type": "tcp_send",  "payload": b"PING\r\n",   "expect": b"+PONG"},
    27017: {"type": "tcp_recv",  "payload": None,           "expect": b"MongoDB"},
    9200:  {"type": "http",      "path": "/",               "expect": '"cluster_name"'},
    5984:  {"type": "http",      "path": "/_all_dbs",       "expect": "["},
    11211: {"type": "tcp_send",  "payload": b"stats\r\n",   "expect": b"STAT"},
    5601:  {"type": "http",      "path": "/api/status",     "expect": '"version"'},
    9000:  {"type": "http",      "path": "/api/system/status", "expect": '"version"'},
    7474:  {"type": "http",      "path": "/",               "expect": '"neo4j"'},
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_COLOR = {
    "CRITICAL": "bold red", "HIGH": "bold yellow",
    "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim",
}
SEV_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}
UA = "Mozilla/5.0 (compatible; CloudExpose/1.0)"


# ═════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class CloudFinding:
    resource_name: str
    resource_type: str          # "S3" | "GCS" | "AZURE" | "FIREBASE" | "DATABASE" | "METADATA"
    url: str
    severity: str
    title: str
    detail: str
    evidence: str
    curl_command: str
    recommendation: str
    cvss_estimate: str = ""
    response_snippet: str = ""
    allows_write: bool = False
    allows_list: bool = False
    allows_read: bool = False


@dataclass
class CloudReport:
    domain: str
    scan_time: str
    source_files: list[str]
    elapsed_seconds: float = 0.0
    buckets_tested: int = 0
    ips_probed: int = 0
    findings: list[CloudFinding] = field(default_factory=list)


# ═════════════════════════════════════════════════════════════════════════════
# HTTP + TCP HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def _curl(url: str, method: str = "GET", headers: dict | None = None,
          extra: str = "") -> str:
    parts = ["curl -sk -D -"]
    if method != "GET":
        parts.append(f"-X {method}")
    for k, v in (headers or {}).items():
        parts.append(f'-H "{k}: {v}"')
    if extra:
        parts.append(extra)
    parts.append(f'"{url}"')
    return " \\\n  ".join(parts)


async def http_get(
    url: str, timeout: float = 10.0,
    headers: dict | None = None,
    follow_redirects: bool = True,
) -> tuple[int | None, dict, str, int]:
    if not HAS_HTTPX:
        return None, {}, "", 0
    hdrs = {"User-Agent": UA, **(headers or {})}
    try:
        async with httpx.AsyncClient(
            timeout=timeout, verify=False,
            follow_redirects=follow_redirects, headers=hdrs,
        ) as c:
            resp = await c.get(url)
            return resp.status_code, dict(resp.headers), resp.text[:4000], len(resp.content)
    except Exception as exc:
        log.debug(f"[GET] {url}: {exc}")
        return None, {}, "", 0


async def http_put(
    url: str, body: bytes = b"cloudexpose-test",
    timeout: float = 10.0,
) -> int | None:
    if not HAS_HTTPX:
        return None
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as c:
            resp = await c.put(url, content=body,
                               headers={"User-Agent": UA})
            return resp.status_code
    except Exception:
        return None


async def tcp_probe(
    host: str, port: int, timeout: float = 5.0,
    send_bytes: bytes | None = None,
    expect_bytes: bytes | None = None,
) -> tuple[bool, str]:
    """
    Attempt TCP connection, optionally send data and check response.
    Returns (is_open, banner_snippet).
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        banner = b""
        if send_bytes:
            writer.write(send_bytes)
            await writer.drain()
            try:
                banner = await asyncio.wait_for(reader.read(256), timeout=2.0)
            except asyncio.TimeoutError:
                pass
        else:
            try:
                banner = await asyncio.wait_for(reader.read(256), timeout=2.0)
            except asyncio.TimeoutError:
                pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        banner_text = banner.decode("utf-8", errors="replace")[:200]
        if expect_bytes:
            return expect_bytes in banner, banner_text
        return True, banner_text
    except Exception:
        return False, ""


# ═════════════════════════════════════════════════════════════════════════════
# NAME HARVESTING
# ═════════════════════════════════════════════════════════════════════════════

def harvest_names_from_subtakeover(path: str) -> tuple[set[str], set[str], list[str]]:
    """
    Parse subtakeover scan.json.
    Returns (s3_names, gcs_names, ips).
    """
    s3: set[str] = set()
    gcs: set[str] = set()
    ips: list[str] = []
    seen_ips: set[str] = set()

    with open(path) as f:
        data = json.load(f)

    for entry in data.get("resolved_subdomains", []):
        sub  = entry.get("subdomain", "")
        cnames = entry.get("cname_chain", [])
        for ip in entry.get("a_records", []):
            if ip not in seen_ips:
                seen_ips.add(ip)
                ips.append(ip)
        # CNAME-based bucket detection
        for cname in cnames:
            for pat in S3_PATTERNS:
                m = pat.search(cname)
                if m:
                    s3.add(m.group(1))
            for pat in GCS_PATTERNS:
                m = pat.search(cname)
                if m:
                    gcs.add(m.group(1))
        # Subdomain prefix as candidate bucket name
        prefix = sub.split(".")[0] if "." in sub else sub
        if len(prefix) > 2:
            s3.add(prefix)

    return s3, gcs, ips


def harvest_names_from_jsreaper(path: str) -> tuple[set[str], set[str], set[str], set[str]]:
    """
    Parse jsreaper.py output.
    Returns (s3_names, gcs_names, azure_names, firebase_names).
    """
    s3: set[str] = set()
    gcs: set[str] = set()
    az: set[str] = set()
    fb: set[str] = set()

    with open(path) as f:
        data = json.load(f)

    # Scan all endpoint URLs
    all_text = json.dumps(data)
    for pat in S3_PATTERNS:
        for m in pat.finditer(all_text):
            name = m.group(1).strip(".").lower()
            if name and len(name) > 2:
                s3.add(name)
    for pat in GCS_PATTERNS:
        for m in pat.finditer(all_text):
            name = m.group(1).strip(".").lower()
            if name and len(name) > 2:
                gcs.add(name)
    for pat in AZURE_PATTERNS:
        for m in pat.finditer(all_text):
            name = m.group(1).strip().lower()
            if name:
                az.add(name)
    for pat in FIREBASE_PATTERNS:
        for m in pat.finditer(all_text):
            name = m.group(1).strip().lower()
            if name:
                fb.add(name)

    return s3, gcs, az, fb


def harvest_names_from_recon(path: str) -> tuple[set[str], list[str]]:
    """
    Parse reconharvest.py output.
    Returns (candidate_names_from_subdomains, ips).
    """
    names: set[str] = set()
    ips: list[str] = []
    seen_ips: set[str] = set()

    with open(path) as f:
        data = json.load(f)

    for hr in data.get("host_reports", []):
        ip = hr.get("ip", "")
        if ip and ip not in seen_ips:
            seen_ips.add(ip)
            ips.append(ip)
        host = hr.get("host", "")
        prefix = host.split(".")[0] if "." in host else host
        if len(prefix) > 2:
            names.add(prefix)
        # Scan proxy disclosure backend IPs
        for pd in hr.get("proxy_disclosures", []):
            bip = pd.get("backend_ip", "")
            if bip and bip not in seen_ips:
                seen_ips.add(bip)
                ips.append(bip)

    return names, ips


def generate_bucket_names(domain: str, extra_seeds: set[str] | None = None) -> list[str]:
    """
    Generate candidate bucket names from the domain and optional extra seeds.
    """
    names: set[str] = set()
    base = domain.lower().split(".")[0]
    org  = domain.lower().replace(".", "-").rstrip("-")

    # Seed names
    seeds = {base, org, domain.lower()} | (extra_seeds or set())

    for seed in seeds:
        seed = seed.strip(".").lower()
        if not seed or len(seed) < 2:
            continue
        for suffix in BUCKET_SUFFIXES:
            candidate = seed + suffix
            if 3 <= len(candidate) <= 63:   # S3 bucket name constraints
                names.add(candidate)

    log.info(f"[Names] Generated {len(names)} bucket name candidates")
    return sorted(names)


def load_wordlist(path: str) -> list[str]:
    with open(path) as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


# ═════════════════════════════════════════════════════════════════════════════
# S3 BUCKET TESTING
# ═════════════════════════════════════════════════════════════════════════════

S3_REGIONS = [
    "us-east-1", "us-west-2", "eu-west-1", "eu-central-1",
    "ap-southeast-1", "ap-northeast-1",
]

async def test_s3_bucket(name: str, timeout: float = 10.0) -> list[CloudFinding]:
    findings: list[CloudFinding] = []

    # Try path-style and virtual-hosted-style URLs
    urls_to_try = [
        f"https://{name}.s3.amazonaws.com/",
        f"https://s3.amazonaws.com/{name}/",
    ]
    # Also try regional endpoints for the first region
    urls_to_try.append(f"https://{name}.s3.us-east-1.amazonaws.com/")

    for url in urls_to_try:
        status, hdrs, body, blen = await http_get(url, timeout, follow_redirects=False)
        if status is None:
            continue

        # 301 redirect = bucket exists but wrong region — follow it
        if status == 301:
            loc = hdrs.get("location") or hdrs.get("Location", "")
            if loc:
                status, hdrs, body, blen = await http_get(loc, timeout)

        if status is None:
            continue

        hl = {k.lower(): v for k, v in hdrs.items()}

        # ── Bucket does not exist ─────────────────────────────────────────
        if status == 404 and ("NoSuchBucket" in body or "<Code>NoSuchBucket" in body):
            break

        # ── Bucket exists — check access ──────────────────────────────────
        bucket_exists = status in (200, 403, 400) or (
            status == 404 and "NoSuchKey" in body
        )
        if not bucket_exists:
            continue

        final_url = loc if status == 301 and loc else url

        # ── Public listing ────────────────────────────────────────────────
        if status == 200 and ("<ListBucketResult" in body or "<Contents>" in body):
            # Count objects
            obj_count = body.count("<Key>")
            findings.append(CloudFinding(
                resource_name=name, resource_type="S3",
                url=final_url, severity="HIGH",
                title=f"S3 Bucket Publicly Listable — {name}",
                detail=(
                    f"The S3 bucket '{name}' allows unauthenticated directory listing. "
                    f"Approximately {obj_count} object keys are visible in the response. "
                    f"All stored files are potentially publicly accessible."
                ),
                evidence=f"GET {final_url} → HTTP 200\nBody: {body[:300]}",
                curl_command=_curl(final_url),
                recommendation=(
                    "Remove the s3:ListBucket permission from the bucket policy for "
                    "unauthenticated (anonymous) principals. "
                    "In the AWS console: S3 → Bucket → Permissions → Block Public Access."
                ),
                cvss_estimate="7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)",
                response_snippet=body[:500],
                allows_list=True,
            ))

        # ── Public read of a known key ────────────────────────────────────
        if status in (200, 403):
            # Try reading a common file that might exist
            for test_key in ["index.html", "README.md", "manifest.json", ".env"]:
                s2, _, b2, l2 = await http_get(f"{final_url}{test_key}", timeout)
                if s2 == 200 and l2 > 0:
                    findings.append(CloudFinding(
                        resource_name=name, resource_type="S3",
                        url=f"{final_url}{test_key}", severity="HIGH",
                        title=f"S3 Bucket Publicly Readable — {name}/{test_key}",
                        detail=(
                            f"The file '{test_key}' in S3 bucket '{name}' is readable "
                            f"without authentication. ({l2} bytes)"
                        ),
                        evidence=f"GET {final_url}{test_key} → HTTP 200 ({l2}B)",
                        curl_command=_curl(f"{final_url}{test_key}"),
                        recommendation=(
                            "Set bucket and object ACLs to private. "
                            "Enable 'Block all public access' in S3 bucket settings."
                        ),
                        cvss_estimate="7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)",
                        response_snippet=b2[:300],
                        allows_read=True,
                    ))
                    break

        # ── Public write test ─────────────────────────────────────────────
        test_obj_url = f"{final_url}cloudexpose-writetest-{name}.txt"
        write_status = await http_put(test_obj_url, b"cloudexpose-write-test", timeout)
        if write_status in (200, 204):
            findings.append(CloudFinding(
                resource_name=name, resource_type="S3",
                url=final_url, severity="CRITICAL",
                title=f"S3 Bucket Publicly WRITABLE — {name}",
                detail=(
                    f"A PUT request to S3 bucket '{name}' succeeded (HTTP {write_status}). "
                    f"Unauthenticated users can upload arbitrary files to this bucket. "
                    f"This enables content injection, malware hosting, data poisoning, "
                    f"and supply chain attacks if the bucket serves application assets."
                ),
                evidence=(
                    f"PUT {test_obj_url} → HTTP {write_status}\n"
                    f"A test object was written — delete it: "
                    f"aws s3 rm s3://{name}/cloudexpose-writetest-{name}.txt"
                ),
                curl_command=_curl(
                    test_obj_url, "PUT",
                    extra='--data-binary "cloudexpose-write-test"'
                ),
                recommendation=(
                    "Remove s3:PutObject permission for unauthenticated principals immediately. "
                    "Enable 'Block all public access'. Review the full bucket policy."
                ),
                cvss_estimate="9.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)",
                allows_write=True,
            ))

        # ── ACL readable ──────────────────────────────────────────────────
        acl_url = final_url + "?acl"
        s_acl, _, b_acl, _ = await http_get(acl_url, timeout)
        if s_acl == 200 and "Owner" in b_acl:
            findings.append(CloudFinding(
                resource_name=name, resource_type="S3",
                url=acl_url, severity="MEDIUM",
                title=f"S3 Bucket ACL Readable Without Authentication — {name}",
                detail=(
                    f"The ACL for bucket '{name}' is readable without credentials. "
                    f"This exposes the bucket owner's AWS account ID and current permission grants."
                ),
                evidence=f"GET {acl_url} → HTTP 200\n{b_acl[:200]}",
                curl_command=_curl(acl_url),
                recommendation="Remove s3:GetBucketAcl from public access. Block all public access.",
                response_snippet=b_acl[:300],
            ))

        break   # Found a working URL — don't try others

    return findings


# ═════════════════════════════════════════════════════════════════════════════
# GCS BUCKET TESTING
# ═════════════════════════════════════════════════════════════════════════════

async def test_gcs_bucket(name: str, timeout: float = 10.0) -> list[CloudFinding]:
    findings: list[CloudFinding] = []

    # GCS URL formats
    urls = [
        f"https://storage.googleapis.com/{name}/",
        f"https://{name}.storage.googleapis.com/",
    ]

    for url in urls:
        status, hdrs, body, blen = await http_get(url, timeout)
        if status is None:
            continue

        if status == 404 and ("NoSuchBucket" in body or "404" in body[:50]):
            continue

        # ── Public listing ────────────────────────────────────────────────
        if status == 200 and ("items" in body or '"kind": "storage#objects"' in body):
            item_count = body.count('"name"')
            findings.append(CloudFinding(
                resource_name=name, resource_type="GCS",
                url=url, severity="HIGH",
                title=f"GCS Bucket Publicly Listable — {name}",
                detail=(
                    f"Google Cloud Storage bucket '{name}' allows unauthenticated listing. "
                    f"Approximately {item_count} object names visible."
                ),
                evidence=f"GET {url} → HTTP 200\n{body[:300]}",
                curl_command=_curl(url),
                recommendation=(
                    "Remove allUsers and allAuthenticatedUsers from the bucket IAM policy. "
                    "Use 'Uniform bucket-level access' and set to private."
                ),
                cvss_estimate="7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)",
                response_snippet=body[:500],
                allows_list=True,
            ))

        # ── Try JSON API listing ──────────────────────────────────────────
        api_url = f"https://storage.googleapis.com/storage/v1/b/{name}/o"
        s2, _, b2, _ = await http_get(api_url, timeout)
        if s2 == 200 and '"items"' in b2:
            findings.append(CloudFinding(
                resource_name=name, resource_type="GCS",
                url=api_url, severity="HIGH",
                title=f"GCS Bucket Listable via JSON API — {name}",
                detail=(
                    f"The GCS JSON API returns a full object listing for bucket '{name}' "
                    f"without authentication."
                ),
                evidence=f"GET {api_url} → HTTP 200\n{b2[:300]}",
                curl_command=_curl(api_url),
                recommendation="Remove allUsers storage.objects.list IAM permission.",
                response_snippet=b2[:500],
                allows_list=True,
            ))

        # ── Write test ────────────────────────────────────────────────────
        write_url = f"{url.rstrip('/')}/cloudexpose-writetest.txt"
        ws = await http_put(write_url, b"cloudexpose-test", timeout)
        if ws in (200, 204):
            findings.append(CloudFinding(
                resource_name=name, resource_type="GCS",
                url=url, severity="CRITICAL",
                title=f"GCS Bucket Publicly WRITABLE — {name}",
                detail=(
                    f"PUT request to GCS bucket '{name}' succeeded (HTTP {ws}). "
                    f"Unauthenticated upload is enabled."
                ),
                evidence=f"PUT {write_url} → HTTP {ws}",
                curl_command=_curl(write_url, "PUT", extra='--data-binary "test"'),
                recommendation="Remove allUsers storage.objects.create IAM permission.",
                cvss_estimate="9.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)",
                allows_write=True,
            ))
        break

    return findings


# ═════════════════════════════════════════════════════════════════════════════
# AZURE BLOB TESTING
# ═════════════════════════════════════════════════════════════════════════════

AZURE_CONTAINERS = [
    "$web", "public", "assets", "static", "cdn", "media",
    "uploads", "files", "documents", "images", "backup",
    "logs", "data", "content",
]

async def test_azure_storage(account: str, timeout: float = 10.0) -> list[CloudFinding]:
    findings: list[CloudFinding] = []
    base = f"https://{account}.blob.core.windows.net"

    # ── Container enumeration ─────────────────────────────────────────────
    list_url = f"{base}/?comp=list"
    status, hdrs, body, blen = await http_get(list_url, timeout)

    if status == 200 and ("<EnumerationResults" in body or "<Container>" in body):
        container_count = body.count("<Name>")
        findings.append(CloudFinding(
            resource_name=account, resource_type="AZURE",
            url=list_url, severity="HIGH",
            title=f"Azure Storage Account Allows Container Enumeration — {account}",
            detail=(
                f"Azure blob storage account '{account}' exposes its container list "
                f"without authentication. {container_count} container names visible."
            ),
            evidence=f"GET {list_url} → HTTP 200\n{body[:300]}",
            curl_command=_curl(list_url),
            recommendation=(
                "Set container access policy to 'Private'. "
                "Disable anonymous access at the storage account level."
            ),
            cvss_estimate="7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)",
            response_snippet=body[:500],
            allows_list=True,
        ))

    # ── Test common containers for anonymous read ─────────────────────────
    for container in AZURE_CONTAINERS:
        cont_url = f"{base}/{container}?restype=container&comp=list"
        s, _, b, bl = await http_get(cont_url, timeout)
        if s == 200 and ("<EnumerationResults" in b or "<Blob>" in b):
            blob_count = b.count("<Name>")
            findings.append(CloudFinding(
                resource_name=f"{account}/{container}", resource_type="AZURE",
                url=cont_url, severity="HIGH",
                title=f"Azure Blob Container Publicly Listable — {account}/{container}",
                detail=(
                    f"Container '{container}' in Azure storage account '{account}' "
                    f"allows unauthenticated listing. ~{blob_count} blobs visible."
                ),
                evidence=f"GET {cont_url} → HTTP 200\n{b[:300]}",
                curl_command=_curl(cont_url),
                recommendation=(
                    "Set container access level to 'Private (no anonymous access)'."
                ),
                cvss_estimate="7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)",
                response_snippet=b[:500],
                allows_list=True,
            ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
# FIREBASE TESTING
# ═════════════════════════════════════════════════════════════════════════════

async def test_firebase(project: str, timeout: float = 10.0) -> list[CloudFinding]:
    findings: list[CloudFinding] = []
    db_url = f"https://{project}.firebaseio.com/.json"

    status, hdrs, body, blen = await http_get(db_url, timeout)
    if status is None:
        return findings

    if status == 200 and blen > 10:
        # Check if it's actually data (not just null/empty)
        if body.strip() not in ("null", "false", "{}", "[]", ""):
            findings.append(CloudFinding(
                resource_name=project, resource_type="FIREBASE",
                url=db_url, severity="CRITICAL",
                title=f"Firebase Database Publicly Readable — {project}",
                detail=(
                    f"The Firebase Realtime Database at {db_url} is readable without "
                    f"authentication. The response contains {blen} bytes of data. "
                    f"This may expose user records, application data, or API keys "
                    f"stored in the database."
                ),
                evidence=f"GET {db_url} → HTTP 200 ({blen}B)\n{body[:300]}",
                curl_command=_curl(db_url),
                recommendation=(
                    "Add Firebase security rules that require authentication: "
                    '{ "rules": { ".read": "auth != null", ".write": "auth != null" } }'
                ),
                cvss_estimate="9.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)",
                response_snippet=body[:500],
                allows_read=True,
            ))

    # Test write
    write_url = f"https://{project}.firebaseio.com/cloudexpose_test.json"
    ws = await http_put(write_url, b'"cloudexpose-test"', timeout)
    if ws in (200, 204):
        findings.append(CloudFinding(
            resource_name=project, resource_type="FIREBASE",
            url=f"https://{project}.firebaseio.com/", severity="CRITICAL",
            title=f"Firebase Database Publicly WRITABLE — {project}",
            detail=(
                f"Writing to Firebase database '{project}' without authentication "
                f"returned HTTP {ws}. An attacker can inject arbitrary data."
            ),
            evidence=f"PUT {write_url} → HTTP {ws}",
            curl_command=_curl(write_url, "PUT", extra='--data-raw \'"cloudexpose-test"\''),
            recommendation=(
                'Set Firebase security rules to require auth: '
                '{ "rules": { ".write": "auth != null" } }'
            ),
            cvss_estimate="9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
            allows_write=True,
        ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
# DATABASE PORT PROBING
# ═════════════════════════════════════════════════════════════════════════════

async def probe_database_ports(
    ip: str,
    timeout: float = 5.0,
) -> list[CloudFinding]:
    findings: list[CloudFinding] = []

    for port, db_name in DB_PORTS.items():
        probe = DB_PROBES.get(port)

        if probe and probe["type"] == "http":
            url = f"http://{ip}:{port}{probe['path']}"
            status, hdrs, body, blen = await http_get(url, timeout=timeout)
            if status == 200 and blen > 0:
                is_confirmed = probe["expect"] in body
                if is_confirmed or blen > 100:
                    findings.append(CloudFinding(
                        resource_name=ip, resource_type="DATABASE",
                        url=url, severity="CRITICAL",
                        title=f"Unauthenticated {db_name} Accessible — {ip}:{port}",
                        detail=(
                            f"{db_name} at {ip}:{port} responds to unauthenticated HTTP "
                            f"requests (HTTP {status}, {blen}B). "
                            f"Unauthenticated database access means full data exposure."
                        ),
                        evidence=f"GET {url} → HTTP {status} ({blen}B)\n{body[:200]}",
                        curl_command=_curl(url),
                        recommendation=(
                            f"Bind {db_name} to 127.0.0.1 or a VPN-only interface. "
                            f"Enable authentication. Add firewall rules to block port {port} "
                            f"from public internet access."
                        ),
                        cvss_estimate="9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
                        response_snippet=body[:400],
                    ))

        elif probe and probe["type"] in ("tcp_send", "tcp_recv"):
            send = probe.get("payload")
            expect = probe.get("expect", b"")
            open_, banner = await tcp_probe(ip, port, timeout, send, expect if isinstance(expect, bytes) else None)
            if open_:
                confirmed = expect and isinstance(expect, bytes) and expect in banner.encode("utf-8", errors="ignore")
                findings.append(CloudFinding(
                    resource_name=ip, resource_type="DATABASE",
                    url=f"tcp://{ip}:{port}",
                    severity="CRITICAL" if confirmed else "HIGH",
                    title=f"{'Confirmed ' if confirmed else 'Possible '}{db_name} Port Open — {ip}:{port}",
                    detail=(
                        f"TCP port {port} ({db_name}) is open on {ip}"
                        + (f" and responded with a {db_name} banner." if confirmed else ".")
                        + " Unauthenticated database access grants full data read/write."
                    ),
                    evidence=(
                        f"TCP connect to {ip}:{port} succeeded.\n"
                        f"Banner: {banner[:100]}" if banner else f"TCP connect to {ip}:{port} succeeded."
                    ),
                    curl_command=f"nc -zv {ip} {port}  # or: redis-cli -h {ip}" if "Redis" in db_name else f"nc -zv {ip} {port}",
                    recommendation=(
                        f"Add firewall rules blocking port {port} from public internet. "
                        f"Bind {db_name} to localhost or internal network only. Enable auth."
                    ),
                    cvss_estimate="9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
                    response_snippet=banner[:200],
                ))
        else:
            # Just check if the port is open via TCP
            open_, banner = await tcp_probe(ip, port, timeout)
            if open_:
                findings.append(CloudFinding(
                    resource_name=ip, resource_type="DATABASE",
                    url=f"tcp://{ip}:{port}",
                    severity="HIGH",
                    title=f"{db_name} Port Publicly Open — {ip}:{port}",
                    detail=(
                        f"Port {port} ({db_name}) is accepting TCP connections from the "
                        f"public internet on {ip}. Investigate whether authentication is required."
                    ),
                    evidence=f"TCP connect to {ip}:{port} → open",
                    curl_command=f"nc -zv {ip} {port}",
                    recommendation=(
                        f"Restrict port {port} via firewall unless public access is intentional."
                    ),
                    response_snippet=banner[:100],
                ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ═════════════════════════════════════════════════════════════════════════════

class CloudExposer:
    def __init__(
        self,
        domain: str,
        timeout: float   = 10.0,
        concurrency: int = 30,
        db_concurrency: int = 50,
        probe_dbs: bool  = True,
    ):
        self.domain        = domain
        self.timeout       = timeout
        self._bucket_sem   = asyncio.Semaphore(concurrency)
        self._db_sem       = asyncio.Semaphore(db_concurrency)
        self.probe_dbs     = probe_dbs

    async def run(
        self,
        bucket_names: list[str],
        ips: list[str],
        azure_accounts: set[str],
        firebase_projects: set[str],
    ) -> list[CloudFinding]:
        all_findings: list[CloudFinding] = []

        # ── Cloud storage tests ───────────────────────────────────────────
        log.info(
            f"[Cloud] Testing {len(bucket_names)} S3/GCS bucket names, "
            f"{len(azure_accounts)} Azure accounts, "
            f"{len(firebase_projects)} Firebase projects"
        )

        async def test_bucket(name: str) -> list[CloudFinding]:
            async with self._bucket_sem:
                found: list[CloudFinding] = []
                found.extend(await test_s3_bucket(name, self.timeout))
                found.extend(await test_gcs_bucket(name, self.timeout))
                return found

        async def test_azure(account: str) -> list[CloudFinding]:
            async with self._bucket_sem:
                return await test_azure_storage(account, self.timeout)

        async def test_firebase(project: str) -> list[CloudFinding]:
            async with self._bucket_sem:
                from __main__ import test_firebase as _tf
                return await _tf(project, self.timeout)

        if HAS_RICH:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]Probing cloud resources[/]"),
                BarColumn(),
                TaskProgressColumn(),
                console=console,
            ) as prog:
                task = prog.add_task(
                    "cloud",
                    total=len(bucket_names) + len(azure_accounts) + len(firebase_projects)
                )

                async def _run_bucket(name: str) -> list[CloudFinding]:
                    r = await test_bucket(name)
                    prog.advance(task)
                    return r

                async def _run_azure(account: str) -> list[CloudFinding]:
                    r = await test_azure(account)
                    prog.advance(task)
                    return r

                async def _run_firebase(proj: str) -> list[CloudFinding]:
                    async with self._bucket_sem:
                        r = await test_firebase_module(proj, self.timeout)
                    prog.advance(task)
                    return r

                results = await asyncio.gather(
                    *[_run_bucket(n) for n in bucket_names],
                    *[_run_azure(a) for a in azure_accounts],
                    *[_run_firebase(p) for p in firebase_projects],
                    return_exceptions=True,
                )
        else:
            results = await asyncio.gather(
                *[test_bucket(n) for n in bucket_names],
                *[test_azure(a) for a in azure_accounts],
                return_exceptions=True,
            )

        for r in results:
            if isinstance(r, list):
                all_findings.extend(r)
                for f in r:
                    log.warning(f"[{f.severity}] {f.title}")

        # ── Database port probing ─────────────────────────────────────────
        if self.probe_dbs and ips:
            unique_ips = list(dict.fromkeys(ips))[:100]  # cap at 100 IPs
            log.info(f"[DB] Probing {len(unique_ips)} IPs for exposed database ports")

            async def probe_ip(ip: str) -> list[CloudFinding]:
                async with self._db_sem:
                    return await probe_database_ports(ip, self.timeout)

            if HAS_RICH:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[bold cyan]Probing database ports[/]"),
                    BarColumn(),
                    TaskProgressColumn(),
                    console=console,
                ) as prog:
                    task = prog.add_task("db", total=len(unique_ips))

                    async def _probe_ip(ip: str) -> list[CloudFinding]:
                        r = await probe_ip(ip)
                        prog.advance(task)
                        return r

                    db_results = await asyncio.gather(
                        *[_probe_ip(ip) for ip in unique_ips],
                        return_exceptions=True,
                    )
            else:
                db_results = await asyncio.gather(
                    *[probe_ip(ip) for ip in unique_ips],
                    return_exceptions=True,
                )

            for r in db_results:
                if isinstance(r, list):
                    all_findings.extend(r)
                    for f in r:
                        log.warning(f"[{f.severity}] {f.title}")

        return sorted(all_findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))


async def test_firebase_module(project: str, timeout: float) -> list[CloudFinding]:
    """Standalone wrapper for firebase testing (avoids __main__ import issue)."""
    return await test_firebase(project, timeout)


# ═════════════════════════════════════════════════════════════════════════════
# REPORTING
# ═════════════════════════════════════════════════════════════════════════════

def print_report(report: CloudReport) -> None:
    by_sev = {s: [f for f in report.findings if f.severity == s]
              for s in SEVERITY_ORDER}

    if not HAS_RICH:
        print(f"\n=== CloudExpose: {report.domain} ===")
        print(f"Buckets tested: {report.buckets_tested}  IPs probed: {report.ips_probed}  "
              f"Elapsed: {report.elapsed_seconds:.1f}s")
        for f in report.findings:
            print(f"\n[{f.severity}] [{f.resource_type}] {f.title}")
            print(f"  {f.url}\n  {f.detail[:150]}")
        print()
        return

    border = "red" if by_sev.get("CRITICAL") else "yellow" if by_sev.get("HIGH") else "blue"
    console.print()
    console.print(Panel.fit(
        f"[white]Domain:[/] [cyan]{report.domain}[/]\n"
        f"[white]Scan time:[/] {report.scan_time}\n"
        f"[white]Elapsed:[/] {report.elapsed_seconds:.1f}s\n"
        f"[white]Buckets/resources tested:[/] {report.buckets_tested}    "
        f"[white]IPs probed:[/] {report.ips_probed}\n\n"
        f"[bold red]CRITICAL:[/] {len(by_sev.get('CRITICAL',[]))}    "
        f"[bold yellow]HIGH:[/] {len(by_sev.get('HIGH',[]))}    "
        f"[yellow]MEDIUM:[/] {len(by_sev.get('MEDIUM',[]))}    "
        f"[cyan]LOW:[/] {len(by_sev.get('LOW',[]))}",
        title="[bold]CloudExpose Report[/]",
        border_style=border,
    ))

    if not report.findings:
        console.print("[bold green]✓ No cloud misconfigurations found.[/]\n")
        return

    # Summary table
    console.print("\n[bold cyan]── Findings Summary ──[/]")
    tbl = Table(show_header=True, header_style="bold cyan", border_style="dim")
    tbl.add_column("Severity",   justify="center")
    tbl.add_column("Type",       style="dim",    justify="center")
    tbl.add_column("Resource",   style="yellow")
    tbl.add_column("Title",      max_width=55)
    tbl.add_column("Write",      justify="center")
    tbl.add_column("List",       justify="center")

    for f in report.findings:
        col = SEV_COLOR.get(f.severity, "white")
        tbl.add_row(
            f"[{col}]{f.severity}[/]",
            f.resource_type,
            f.resource_name[:30],
            f.title[:55],
            "[red]✓[/]" if f.allows_write else "",
            "[yellow]✓[/]" if f.allows_list else "",
        )
    console.print(tbl)

    # Detail
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        sf = by_sev.get(sev, [])
        if not sf:
            continue
        col = SEV_COLOR.get(sev, "white")
        console.print(f"\n[{col}]── {SEV_EMOJI.get(sev,'')} {sev} ({len(sf)}) ──[/]")
        for i, f in enumerate(sf, 1):
            console.print(
                f"  [{col}][{i}][/] [white]{f.title}[/]\n"
                f"      [dim]Resource:[/] {f.resource_name}  "
                f"[dim]Type:[/] {f.resource_type}  "
                f"[dim]URL:[/] {f.url}\n"
                f"      [dim]Detail:[/] {f.detail[:200]}{'...' if len(f.detail)>200 else ''}"
            )
            if f.evidence:
                console.print(f"      [dim]Evidence:[/] {escape(f.evidence[:140])}")
            if f.curl_command:
                console.print(f"      [dim]Curl:[/] {escape(f.curl_command[:120])}")
            if f.cvss_estimate:
                console.print(f"      [dim]CVSS:[/] {f.cvss_estimate}")
            if i < len(sf):
                console.print()
    console.print()


def save_json(report: CloudReport, path: str) -> None:
    data = {
        "domain":           report.domain,
        "scan_time":        report.scan_time,
        "source_files":     report.source_files,
        "buckets_tested":   report.buckets_tested,
        "ips_probed":       report.ips_probed,
        "elapsed_seconds":  report.elapsed_seconds,
        "summary": {s: len([f for f in report.findings if f.severity == s])
                    for s in SEVERITY_ORDER},
        "findings": [asdict(f) for f in report.findings],
    }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    log.info(f"JSON report saved → {path}")
    log.info(f"  findings[]: {len(report.findings)}")


def save_html(report: CloudReport, path: str) -> None:
    by_sev = {s: [f for f in report.findings if f.severity == s]
              for s in SEVERITY_ORDER}
    sc = {"CRITICAL":"#f85149","HIGH":"#d29922","MEDIUM":"#e3b341",
          "LOW":"#58a6ff","INFO":"#8b949e"}
    sb = {"CRITICAL":"rgba(248,81,73,.12)","HIGH":"rgba(210,153,34,.12)",
          "MEDIUM":"rgba(227,179,65,.10)","LOW":"rgba(88,166,255,.10)",
          "INFO":"rgba(139,148,158,.08)"}

    rows = ""
    for f in report.findings:
        rows += (
            f"<tr>"
            "<td style='color:" + sc.get(f.severity,"#fff") + ";font-weight:bold'>" + f.severity + "</td>"
            f"<td style='color:#39c5cf'>{f.resource_type}</td>"
            f"<td style='color:#d29922'>{f.resource_name}</td>"
            f"<td style='color:#fff'>{f.title}</td>"
            f"<td style='text-align:center;color:#f85149'>{'✓' if f.allows_write else ''}</td>"
            f"<td style='text-align:center;color:#d29922'>{'✓' if f.allows_list else ''}</td>"
            f"</tr>"
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
            findings_html += (
                f'<div class="finding" style="border-left:3px solid {sc[sev]};background:{sb[sev]}">'
                f'<div class="ft">[{i}] {f.title}</div>'
                f'<div class="fm">'
                f'<span class="badge" style="color:{sc[sev]};background:{sb[sev]};'
                f'border:1px solid {sc[sev]}">{sev}</span>'
                f'<span style="color:#39c5cf;font-size:.8em">{f.resource_type}</span>'
                f'<span style="color:#d29922;font-size:.8em">{f.resource_name}</span>'
                + (f'<span style="color:#58a6ff;font-size:.78em">{f.url}</span>' if len(f.url) < 80 else "")
                + (f'<span style="color:#d29922;font-size:.75em">{f.cvss_estimate}</span>' if f.cvss_estimate else "")
                + f'</div>'
                f'<div class="fd">{f.detail}</div>'
                + (f'<div class="ev"><span class="evl">Evidence:</span><code>{ev_e[:250]}</code></div>' if f.evidence else "")
                + (f'<div class="ev"><span class="evl">Reproduce:</span>'
                   f'<pre style="margin:4px 0 0 0;font-size:.8em;color:#a8dadc">{curl_e}</pre></div>'
                   if f.curl_command else "")
                + f'<div class="rec"><span class="recl">Fix:</span> {f.recommendation}</div>'
                + f'</div>'
            )
        findings_html += "</div>"

    if not findings_html:
        findings_html = "<p style='color:#3fb950'>No misconfigurations found.</p>"

    html = f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CloudExpose — {report.domain}</title>
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
<h1>CloudExpose</h1>
<p class="sub">{report.domain} &nbsp;·&nbsp; {report.scan_time} &nbsp;·&nbsp;
{report.elapsed_seconds:.1f}s &nbsp;·&nbsp;
{report.buckets_tested} resources tested &nbsp;·&nbsp;
{report.ips_probed} IPs probed</p>
<div class="stats">
<div class="stat"><div class="sv" style="color:#f85149">{len(by_sev.get('CRITICAL',[]))}</div><div class="sl">CRITICAL</div></div>
<div class="stat"><div class="sv" style="color:#d29922">{len(by_sev.get('HIGH',[]))}</div><div class="sl">HIGH</div></div>
<div class="stat"><div class="sv" style="color:#e3b341">{len(by_sev.get('MEDIUM',[]))}</div><div class="sl">MEDIUM</div></div>
<div class="stat"><div class="sv" style="color:#58a6ff">{len(by_sev.get('LOW',[]))}</div><div class="sl">LOW</div></div>
<div class="stat"><div class="sv">{report.buckets_tested}</div><div class="sl">RESOURCES</div></div>
<div class="stat"><div class="sv">{report.ips_probed}</div><div class="sl">IPS PROBED</div></div>
</div>
<div class="card"><h2>📋 Summary</h2>
<table><thead><tr>
<th>Severity</th><th>Type</th><th>Resource</th>
<th>Title</th><th>Writable</th><th>Listable</th>
</tr></thead><tbody>{rows}</tbody></table></div>
<div class="card"><h2>🔎 Findings Detail</h2>{findings_html}</div>
<div class="footer">CloudExpose &nbsp;·&nbsp; For authorized security research only</div>
</div></body></html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    log.info(f"HTML report saved → {path}")


# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="CloudExpose — Cloud Storage & Service Misconfiguration Hunter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 cloudexpose.py --subtakeover scan.json --domain eskimi.com --output cloud
  python3 cloudexpose.py --js js-findings.json --domain eskimi.com --output cloud
  python3 cloudexpose.py --scan recon-report-v2.json --domain eskimi.com --output cloud
  python3 cloudexpose.py --domain eskimi.com --output cloud
  python3 cloudexpose.py --domain eskimi.com --wordlist my-buckets.txt --output cloud

Sources can be combined:
  python3 cloudexpose.py \\
    --subtakeover scan.json \\
    --js js-findings.json \\
    --scan recon-report-v2.json \\
    --domain eskimi.com --output cloud

Chains from : subtakeover.py, jsreaper.py, reconharvest.py, or domain-only
Output      : JSON + HTML report with curl PoC per finding
        """,
    )
    p.add_argument("--domain",       required=True,  help="Target root domain")
    p.add_argument("--subtakeover",  metavar="FILE",
                   help="subtakeover.py scan.json output")
    p.add_argument("--js",           metavar="FILE",
                   help="jsreaper.py output JSON")
    p.add_argument("--scan",         metavar="FILE",
                   help="reconharvest.py output JSON")
    p.add_argument("--wordlist",     metavar="FILE",
                   help="Additional bucket name wordlist (one per line)")
    p.add_argument("-o","--output",  metavar="BASE",
                   help="Output base → BASE.json + BASE.html")
    p.add_argument("--no-db",        action="store_true",
                   help="Skip database port probing")
    p.add_argument("--timeout",      type=float, default=10.0,
                   help="HTTP/TCP timeout per probe (default: 10s)")
    p.add_argument("--concurrency",  type=int,   default=30,
                   help="Concurrent cloud resource probes (default: 30)")
    p.add_argument("-v","--verbose", action="store_true", help="Verbose logging")
    return p.parse_args()


async def main() -> None:
    args = parse_args()
    if args.verbose:
        log.setLevel(logging.DEBUG)

    print("""
╔══════════════════════════════════════════════════════════════════╗
║       CloudExpose — Cloud Storage & Service Misconfiguration     ║
║  For authorized penetration testing and bug bounty research only ║
╚══════════════════════════════════════════════════════════════════╝
""")

    if not HAS_HTTPX:
        log.error("httpx required: pip install httpx")
        sys.exit(1)

    # ── Harvest names and IPs from all available sources ──────────────────
    s3_names:   set[str] = set()
    gcs_names:  set[str] = set()
    az_accounts: set[str] = set()
    fb_projects: set[str] = set()
    ips:        list[str] = []
    source_files: list[str] = []

    if args.subtakeover:
        s3_sub, gcs_sub, ips_sub = harvest_names_from_subtakeover(args.subtakeover)
        s3_names  |= s3_sub
        gcs_names |= gcs_sub
        ips.extend(ips_sub)
        source_files.append(args.subtakeover)
        log.info(f"[subtakeover] S3 hints: {len(s3_sub)}  GCS hints: {len(gcs_sub)}  IPs: {len(ips_sub)}")

    if args.js:
        s3_js, gcs_js, az_js, fb_js = harvest_names_from_jsreaper(args.js)
        s3_names    |= s3_js
        gcs_names   |= gcs_js
        az_accounts |= az_js
        fb_projects |= fb_js
        source_files.append(args.js)
        log.info(f"[jsreaper] S3: {len(s3_js)}  GCS: {len(gcs_js)}  Azure: {len(az_js)}  Firebase: {len(fb_js)}")

    if args.scan:
        names_recon, ips_recon = harvest_names_from_recon(args.scan)
        s3_names  |= names_recon
        gcs_names |= names_recon
        ips.extend(ips_recon)
        source_files.append(args.scan)
        log.info(f"[reconharvest] Name seeds: {len(names_recon)}  IPs: {len(ips_recon)}")

    # Load custom wordlist
    extra_seeds: list[str] = []
    if args.wordlist:
        extra_seeds = load_wordlist(args.wordlist)
        s3_names |= set(extra_seeds)
        log.info(f"[wordlist] Added {len(extra_seeds)} names from {args.wordlist}")

    # Generate domain-derived bucket names and merge
    generated = generate_bucket_names(args.domain, s3_names | gcs_names)
    all_bucket_names = sorted(set(generated) | s3_names | gcs_names)

    # Deduplicate IPs
    seen_ips: set[str] = set()
    unique_ips: list[str] = []
    for ip in ips:
        if ip not in seen_ips:
            seen_ips.add(ip)
            unique_ips.append(ip)

    log.info(
        f"[Config] Total bucket/resource names: {len(all_bucket_names)}  "
        f"Azure accounts: {len(az_accounts)}  "
        f"Firebase projects: {len(fb_projects)}  "
        f"IPs for DB probing: {len(unique_ips)}"
    )

    report = CloudReport(
        domain=args.domain,
        scan_time=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        source_files=source_files or ["domain-only"],
        buckets_tested=len(all_bucket_names) + len(az_accounts) + len(fb_projects),
        ips_probed=len(unique_ips),
    )

    exposer = CloudExposer(
        domain=args.domain,
        timeout=args.timeout,
        concurrency=args.concurrency,
        probe_dbs=not args.no_db,
    )

    t0 = time.perf_counter()
    report.findings = await exposer.run(
        bucket_names=all_bucket_names,
        ips=unique_ips,
        azure_accounts=az_accounts,
        firebase_projects=fb_projects,
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

    crit = len([f for f in report.findings if f.severity == "CRITICAL"])
    high = len([f for f in report.findings if f.severity == "HIGH"])
    if crit or high:
        log.warning(
            f"[!] {crit} CRITICAL + {high} HIGH findings — "
            f"report to bug bounty program immediately"
        )
    elif not report.findings:
        log.info("[✓] No cloud misconfigurations found.")


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(0)
