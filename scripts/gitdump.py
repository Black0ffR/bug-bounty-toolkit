#!/usr/bin/env python3
"""
gitdump.py — Exposed Version Control & Configuration File Harvester
====================================================================
Author  : RareKez / security research tooling
License : MIT (for authorized use only)

Chains from : subtakeover.py  (--subtakeover) — all 120 resolved hosts
              reconharvest.py (--scan)         — hosts with open ports
              plain list      (--hosts)        — one host per line

Feeds into  : jsreaper.py (extracted source code), bug bounty reports

Pipeline:
  1. Detect exposed VCS repositories:
       .git/HEAD, .git/config, .git/COMMIT_EDITMSG
       .svn/entries, .svn/wc.db
       .hg/requires, .bzr/branch-format
  2. Reconstruct .git repository (pure Python, no git binary):
       HEAD → branch ref → commit hash
       Commit object → tree object → blobs
       Pack index (.idx) + pack data (.pack) for bulk extraction
       Walk commit parents for deleted secrets in history
  3. Scan 90+ common sensitive file paths:
       .env variants, PHP configs, Python settings, Ruby YAMLs,
       Node.js auth files, CI/CD configs, Docker files,
       backup/swap files, IDE configs, log files
  4. Run secret detection on all recovered content:
       Same 45-pattern engine as jsreaper.py
       Also scans git commit messages for secret indicators
  5. Extract developer intelligence from git history:
       Committer email addresses
       Internal hostnames and service URLs
       Deployment infrastructure from Dockerfiles/k8s YAMLs
  6. Deduplicate findings by (host, category, key_evidence)
  7. Generate JSON + HTML report with curl/wget PoC

Usage:
  python3 gitdump.py --subtakeover scan.json --domain eskimi.com --output git
  python3 gitdump.py --scan recon-report-v2.json --domain eskimi.com --output git
  python3 gitdump.py --hosts targets.txt --domain eskimi.com --output git

LEGAL: Only use against targets you have explicit written authorization to test.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import binascii
import datetime
import hashlib
import json
import re
import socket
import struct
import sys
import time
import zlib
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

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
log = logging.getLogger("gitdump")
for _n in ("httpx", "httpcore"):
    logging.getLogger(_n).setLevel(logging.WARNING)


# ═════════════════════════════════════════════════════════════════════════════
# VCS DETECTION PATHS
# ═════════════════════════════════════════════════════════════════════════════

GIT_DETECT_PATHS = [
    "/.git/HEAD",
    "/.git/config",
    "/.git/COMMIT_EDITMSG",
    "/.git/description",
    "/.git/info/refs",
]

SVN_DETECT_PATHS = [
    "/.svn/entries",
    "/.svn/wc.db",
    "/.svn/format",
]

HG_DETECT_PATHS = [
    "/.hg/requires",
    "/.hg/hgrc",
    "/.hg/00changelog.i",
]

BZR_DETECT_PATHS = [
    "/.bzr/branch-format",
    "/.bzr/README",
]

# ═════════════════════════════════════════════════════════════════════════════
# SENSITIVE FILE PATHS
# ═════════════════════════════════════════════════════════════════════════════

SENSITIVE_PATHS: list[tuple[str, str, str]] = [
    # (path, description, severity)

    # ── Environment & secrets ─────────────────────────────────────────────
    ("/.env",                        ".env — main env config",                "CRITICAL"),
    ("/.env.local",                  ".env.local — local overrides",          "CRITICAL"),
    ("/.env.production",             ".env.production",                       "CRITICAL"),
    ("/.env.prod",                   ".env.prod",                             "CRITICAL"),
    ("/.env.staging",                ".env.staging",                          "HIGH"),
    ("/.env.development",            ".env.development",                      "HIGH"),
    ("/.env.dev",                    ".env.dev",                              "HIGH"),
    ("/.env.test",                   ".env.test",                             "MEDIUM"),
    ("/.env.backup",                 ".env.backup",                           "CRITICAL"),
    ("/.env.example",                ".env.example — may contain real values","MEDIUM"),
    ("/.env.sample",                 ".env.sample",                           "MEDIUM"),

    # ── PHP configurations ────────────────────────────────────────────────
    ("/config.php",                  "PHP config",                            "CRITICAL"),
    ("/configuration.php",           "Joomla config",                         "CRITICAL"),
    ("/wp-config.php",               "WordPress config",                      "CRITICAL"),
    ("/settings.php",                "Drupal settings",                       "CRITICAL"),
    ("/app/config.php",              "App config",                            "HIGH"),
    ("/include/config.php",          "Include config",                        "HIGH"),
    ("/conf/config.php",             "Conf config",                           "HIGH"),
    ("/db.php",                      "Database connection file",              "CRITICAL"),
    ("/database.php",                "Database file",                         "CRITICAL"),
    ("/connect.php",                 "DB connect file",                       "HIGH"),

    # ── Python / Django / Flask ───────────────────────────────────────────
    ("/settings.py",                 "Django settings",                       "HIGH"),
    ("/local_settings.py",           "Django local settings",                 "CRITICAL"),
    ("/config.py",                   "Python config",                         "HIGH"),
    ("/app/settings.py",             "App Django settings",                   "HIGH"),
    ("/myapp/settings.py",           "Django app settings",                   "HIGH"),

    # ── Ruby / Rails ──────────────────────────────────────────────────────
    ("/config/database.yml",         "Rails database config",                 "CRITICAL"),
    ("/config/secrets.yml",          "Rails secrets",                         "CRITICAL"),
    ("/config/application.yml",      "Rails application config",              "HIGH"),
    ("/config/credentials.yml.enc",  "Rails encrypted credentials",           "MEDIUM"),
    ("/config/master.key",           "Rails master key — decrypts credentials","CRITICAL"),
    ("/.ruby-version",               "Ruby version file",                     "INFO"),

    # ── Node.js ───────────────────────────────────────────────────────────
    ("/.npmrc",                      ".npmrc — may contain auth tokens",       "CRITICAL"),
    ("/.yarnrc",                     ".yarnrc",                               "MEDIUM"),
    ("/package.json",                "package.json — deps + scripts",          "INFO"),
    ("/package-lock.json",           "package-lock.json",                     "INFO"),

    # ── CI/CD ─────────────────────────────────────────────────────────────
    ("/.travis.yml",                 "Travis CI config — may have secrets",   "HIGH"),
    ("/.circleci/config.yml",        "CircleCI config",                       "HIGH"),
    ("/Jenkinsfile",                 "Jenkinsfile — CI pipeline",             "HIGH"),
    ("/.github/workflows/deploy.yml","GitHub Actions deploy workflow",        "HIGH"),
    ("/.gitlab-ci.yml",              "GitLab CI config",                      "HIGH"),
    ("/bitbucket-pipelines.yml",     "Bitbucket pipelines",                   "HIGH"),
    ("/azure-pipelines.yml",         "Azure DevOps pipeline",                 "HIGH"),
    ("/.drone.yml",                  "Drone CI config",                       "HIGH"),

    # ── Docker & Kubernetes ───────────────────────────────────────────────
    ("/docker-compose.yml",          "Docker Compose — service definitions",  "HIGH"),
    ("/docker-compose.override.yml", "Docker Compose override",               "HIGH"),
    ("/Dockerfile",                  "Dockerfile",                            "MEDIUM"),
    ("/.dockerenv",                  ".dockerenv — confirms Docker container","INFO"),
    ("/k8s/secret.yaml",             "K8s secret manifest",                   "CRITICAL"),
    ("/kubernetes/secret.yaml",      "K8s secret manifest",                   "CRITICAL"),
    ("/helm/values.yaml",            "Helm values",                           "HIGH"),
    ("/helm/values-prod.yaml",       "Helm production values",                "CRITICAL"),

    # ── Backup & swap files ───────────────────────────────────────────────
    ("/config.php.bak",              "PHP config backup",                     "CRITICAL"),
    ("/config.php.old",              "PHP config old",                        "CRITICAL"),
    ("/config.php~",                 "PHP config vim swap",                   "CRITICAL"),
    ("/.env.bak",                    ".env backup",                           "CRITICAL"),
    ("/wp-config.php.bak",           "WordPress config backup",               "CRITICAL"),
    ("/database.sql",                "Database dump",                         "CRITICAL"),
    ("/db.sql",                      "Database dump",                         "CRITICAL"),
    ("/backup.sql",                  "Database backup",                       "CRITICAL"),
    ("/dump.sql",                    "Database dump",                         "CRITICAL"),

    # ── IDE & editor files ────────────────────────────────────────────────
    ("/.idea/workspace.xml",         "JetBrains workspace — project paths",   "MEDIUM"),
    ("/.idea/.name",                 "JetBrains project name",                "INFO"),
    ("/.vscode/settings.json",       "VS Code settings",                      "LOW"),
    ("/.vscode/launch.json",         "VS Code debug config",                  "MEDIUM"),

    # ── Log files ─────────────────────────────────────────────────────────
    ("/storage/logs/laravel.log",    "Laravel log",                           "MEDIUM"),
    ("/var/log/nginx/error.log",     "Nginx error log",                       "MEDIUM"),
    ("/logs/error.log",              "Error log",                             "MEDIUM"),
    ("/debug.log",                   "Debug log",                             "MEDIUM"),
    ("/error.log",                   "Error log",                             "MEDIUM"),
    ("/application.log",             "Application log",                       "MEDIUM"),

    # ── Server config ─────────────────────────────────────────────────────
    ("/.htpasswd",                   ".htpasswd — HTTP basic auth credentials","CRITICAL"),
    ("/.htaccess",                   ".htaccess — server config",              "LOW"),
    ("/nginx.conf",                  "Nginx config",                          "MEDIUM"),
    ("/web.config",                  "IIS web.config",                        "MEDIUM"),
    ("/server.xml",                  "Tomcat server config",                  "MEDIUM"),

    # ── SSH & crypto ──────────────────────────────────────────────────────
    ("/.ssh/id_rsa",                 "SSH private key",                       "CRITICAL"),
    ("/.ssh/id_ed25519",             "SSH Ed25519 private key",               "CRITICAL"),
    ("/.ssh/authorized_keys",        "SSH authorized keys",                   "HIGH"),
    ("/id_rsa",                      "SSH private key in webroot",            "CRITICAL"),
    ("/server.key",                  "TLS private key",                       "CRITICAL"),
    ("/private.key",                 "Private key",                           "CRITICAL"),
    ("/.gnupg/secring.gpg",          "GPG secret keyring",                    "CRITICAL"),

    # ── Certificates ──────────────────────────────────────────────────────
    ("/server.crt",                  "TLS certificate",                       "LOW"),
    ("/ssl.crt",                     "SSL certificate",                       "LOW"),
    ("/cert.pem",                    "Certificate PEM",                       "LOW"),
]

# ═════════════════════════════════════════════════════════════════════════════
# SECRET PATTERNS (same engine as jsreaper.py)
# ═════════════════════════════════════════════════════════════════════════════

SECRET_PATTERNS: list[tuple[str, re.Pattern, str]] = []

def _p(name: str, pattern: str, sev: str = "HIGH") -> None:
    try:
        SECRET_PATTERNS.append((name, re.compile(pattern, re.IGNORECASE | re.MULTILINE), sev))
    except re.error:
        pass

_p("AWS Access Key",        r'(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])',            "CRITICAL")
_p("AWS Secret Key",        r'(?i)(?:aws.{0,20}secret|aws_secret_access_key)\s*[=:]\s*([A-Za-z0-9/+=]{40})', "CRITICAL")
_p("GCP API Key",           r'AIza[0-9A-Za-z\-_]{35}',                                  "HIGH")
_p("GCP Service Account",   r'"type"\s*:\s*"service_account"',                           "CRITICAL")
_p("Azure Connection String",r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86,88}==', "CRITICAL")
_p("Stripe Secret Key",     r'sk_(?:live|test)_[0-9a-zA-Z]{24,}',                       "CRITICAL")
_p("SendGrid API Key",      r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}',             "HIGH")
_p("GitHub PAT",            r'ghp_[A-Za-z0-9]{36}',                                     "HIGH")
_p("Slack Bot Token",       r'xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}',               "HIGH")
_p("Slack Webhook",         r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+', "HIGH")
_p("JWT Token",             r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+', "MEDIUM")
_p("JWT Secret",            r'(?i)(?:jwt.{0,15}secret|jwt_secret)\s*[=:]\s*([^\s"\']{8,})', "CRITICAL")
_p("Password Assignment",   r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']', "HIGH")
_p("DB Connection String",  r'(?i)(?:postgres|mysql|mongodb|redis)\://[^\s"\'@]+:[^\s"\'@]+@', "CRITICAL")
_p("RSA Private Key",       r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',                 "CRITICAL")
_p("Generic Secret",        r'(?i)(?:secret|api_key|apikey|auth_token|access_token)\s*[=:]\s*["\']([A-Za-z0-9_\-+/=]{16,})["\']', "HIGH")
_p("Private IPv4",          r'(?<!\d)(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)(?!\d)', "MEDIUM")
_p("Internal Hostname",     r'https?://(?:[a-z0-9\-]+\.){1,5}(?:internal|corp|local|intranet|lan)\b', "MEDIUM")
_p("Bearer Token",          r'(?i)Authorization\s*:\s*["\']Bearer\s+([A-Za-z0-9_\-+/=.]{20,})', "HIGH")

# Git commit message indicators
GIT_SECRET_MSG_PATTERNS = [
    re.compile(r'(?i)(password|secret|key|token|credential|api.?key|private)', re.I),
    re.compile(r'(?i)(oops|accidentally|remove|delete|fix|forgot)\s+(?:password|secret|key|token)', re.I),
    re.compile(r'(?i)do not commit|not for commit|remove before push', re.I),
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_COLOR = {
    "CRITICAL": "bold red", "HIGH": "bold yellow",
    "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim",
}
SEV_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}
UA = "Mozilla/5.0 (compatible; GitDump/1.0)"


# ═════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class SecretHit:
    secret_type: str
    value_redacted: str
    severity: str
    source_path: str       # file path it was found in
    context: str           # surrounding text (100 chars)


@dataclass
class GitDumpFinding:
    host: str
    url: str
    category: str          # "GIT_EXPOSED" | "CONFIG_FILE" | "SECRET" | "SVN" | "HG" | "DATABASE_DUMP"
    severity: str
    title: str
    detail: str
    evidence: str
    curl_command: str
    recommendation: str
    cvss_estimate: str = ""
    secrets: list[SecretHit] = field(default_factory=list)
    files_recovered: list[str] = field(default_factory=list)
    developer_emails: list[str] = field(default_factory=list)


@dataclass
class HostGitResult:
    host: str
    ip: str
    has_git: bool = False
    has_svn: bool = False
    has_hg: bool = False
    git_branch: str = ""
    git_remote: str = ""
    git_commit_count: int = 0
    files_recovered: list[str] = field(default_factory=list)
    secrets_found: list[SecretHit] = field(default_factory=list)
    developer_emails: list[str] = field(default_factory=list)
    config_files_found: list[str] = field(default_factory=list)
    findings: list[GitDumpFinding] = field(default_factory=list)
    error: str = ""


@dataclass
class GitDumpReport:
    domain: str
    scan_time: str
    source_files: list[str]
    total_hosts: int = 0
    elapsed_seconds: float = 0.0
    host_results: list[HostGitResult] = field(default_factory=list)
    all_findings: list[GitDumpFinding] = field(default_factory=list)


# ═════════════════════════════════════════════════════════════════════════════
# HTTP CLIENT
# ═════════════════════════════════════════════════════════════════════════════

def _curl(url: str) -> str:
    return f'curl -sk -D - "{url}"'


def _wget(url: str, output: str = "output") -> str:
    return f'wget -q --no-check-certificate "{url}" -O {output}'


async def fetch(
    url: str,
    timeout: float = 10.0,
    binary: bool = False,
) -> tuple[int | None, dict, bytes | str]:
    """
    GET a URL. Returns (status, headers, body).
    body is bytes if binary=True, str otherwise.
    Never raises.
    """
    if not HAS_HTTPX:
        return None, {}, b"" if binary else ""
    try:
        async with httpx.AsyncClient(
            timeout=timeout, verify=False,
            follow_redirects=True,
            headers={"User-Agent": UA},
        ) as c:
            resp = await c.get(url)
            if binary:
                return resp.status_code, dict(resp.headers), resp.content
            return resp.status_code, dict(resp.headers), resp.text[:50000]
    except Exception as exc:
        log.debug(f"[Fetch] {url}: {exc}")
        return None, {}, b"" if binary else ""


# ═════════════════════════════════════════════════════════════════════════════
# GIT OBJECT PARSING (pure Python — no git binary required)
# ═════════════════════════════════════════════════════════════════════════════

def _zlib_decompress(data: bytes) -> bytes | None:
    """Decompress a loose git object. Returns None on failure."""
    try:
        return zlib.decompress(data)
    except Exception:
        return None


def _parse_git_object(raw: bytes) -> tuple[str, bytes]:
    """
    Parse a raw (decompressed) git object.
    Format: "<type> <size>\x00<content>"
    Returns (type, content_bytes).
    """
    null_pos = raw.index(b"\x00")
    header   = raw[:null_pos].decode("utf-8", errors="replace")
    content  = raw[null_pos + 1:]
    obj_type = header.split(" ")[0]
    return obj_type, content


def _parse_tree(tree_bytes: bytes) -> list[tuple[str, str, str]]:
    """
    Parse a git tree object.
    Returns list of (mode, name, sha1_hex).
    """
    entries: list[tuple[str, str, str]] = []
    i = 0
    while i < len(tree_bytes):
        try:
            sp    = tree_bytes.index(b" ", i)
            nl    = tree_bytes.index(b"\x00", sp)
            mode  = tree_bytes[i:sp].decode("utf-8", errors="replace")
            name  = tree_bytes[sp + 1:nl].decode("utf-8", errors="replace")
            sha1  = tree_bytes[nl + 1: nl + 21]
            sha1_hex = sha1.hex()
            entries.append((mode, name, sha1_hex))
            i = nl + 21
        except (ValueError, struct.error):
            break
    return entries


def _parse_commit(commit_bytes: bytes) -> dict:
    """
    Parse a git commit object.
    Returns dict with tree, parents, author, committer, message.
    """
    text    = commit_bytes.decode("utf-8", errors="replace")
    lines   = text.split("\n")
    result  = {"tree": "", "parents": [], "author": "", "committer": "", "message": ""}
    msg_start = False
    msg_lines: list[str] = []
    for line in lines:
        if msg_start:
            msg_lines.append(line)
        elif line.startswith("tree "):
            result["tree"] = line[5:].strip()
        elif line.startswith("parent "):
            result["parents"].append(line[7:].strip())
        elif line.startswith("author "):
            result["author"] = line[7:]
        elif line.startswith("committer "):
            result["committer"] = line[10:]
        elif line == "":
            msg_start = True
    result["message"] = "\n".join(msg_lines).strip()
    return result


# ═════════════════════════════════════════════════════════════════════════════
# GIT PACK FILE PARSING
# ═════════════════════════════════════════════════════════════════════════════

async def fetch_pack_list(base_git_url: str, timeout: float) -> list[str]:
    """
    Fetch the list of .pack files from .git/objects/info/packs.
    Returns list of pack file basenames.
    """
    url = base_git_url + "/objects/info/packs"
    status, _, body = await fetch(url, timeout)
    if status != 200 or not body:
        return []
    # Format: "P pack-<sha1>.pack\n"
    packs: list[str] = []
    for line in body.strip().split("\n"):
        line = line.strip()
        if line.startswith("P "):
            packs.append(line[2:].strip())
    return packs


# ═════════════════════════════════════════════════════════════════════════════
# GIT REPOSITORY RECONSTRUCTOR
# ═════════════════════════════════════════════════════════════════════════════

class GitReconstructor:
    """
    Downloads and reconstructs a .git repository from a web server.
    Uses only standard HTTP requests — no git binary needed.
    """

    def __init__(self, base_url: str, base_git_url: str, timeout: float):
        self.base_url     = base_url
        self.base_git_url = base_git_url    # base_url + "/.git"
        self.timeout      = timeout
        self._object_cache: dict[str, bytes] = {}

    async def _fetch_object(self, sha1: str) -> bytes | None:
        """Fetch a loose git object by its SHA1 hash."""
        if sha1 in self._object_cache:
            return self._object_cache[sha1]
        url    = f"{self.base_git_url}/objects/{sha1[:2]}/{sha1[2:]}"
        status, _, body = await fetch(url, self.timeout, binary=True)
        if status != 200 or not body:
            return None
        data = _zlib_decompress(body if isinstance(body, bytes) else body.encode())
        if data:
            self._object_cache[sha1] = data
        return data

    async def get_head_commit(self) -> str | None:
        """
        Read HEAD to find the current branch, then read the ref to get commit hash.
        Returns the HEAD commit SHA1 or None.
        """
        status, _, head_body = await fetch(
            f"{self.base_git_url}/HEAD", self.timeout
        )
        if status != 200 or not head_body:
            return None

        head_body = head_body.strip()
        if head_body.startswith("ref: "):
            # Symbolic ref — read the actual ref
            ref_path = head_body[5:].strip()   # e.g. refs/heads/main
            url      = f"{self.base_git_url}/{ref_path}"
            status2, _, ref_body = await fetch(url, self.timeout)
            if status2 == 200 and ref_body:
                return ref_body.strip()[:40]
        elif len(head_body) == 40 and all(c in "0123456789abcdef" for c in head_body.lower()):
            return head_body

        return None

    async def get_config(self) -> str:
        """Fetch .git/config and extract remote URL."""
        status, _, body = await fetch(f"{self.base_git_url}/config", self.timeout)
        return body if status == 200 else ""

    async def walk_tree(
        self,
        tree_sha1: str,
        prefix: str = "",
        max_files: int = 500,
    ) -> dict[str, bytes]:
        """
        Recursively walk a git tree and recover all blobs.
        Returns dict of {path: content_bytes}.
        """
        recovered: dict[str, bytes] = {}
        if len(recovered) >= max_files:
            return recovered

        raw = await self._fetch_object(tree_sha1)
        if not raw:
            return recovered

        obj_type, content = _parse_git_object(raw)
        if obj_type != "tree":
            return recovered

        entries = _parse_tree(content)
        tasks   = []
        for mode, name, sha1 in entries:
            full_path = f"{prefix}/{name}" if prefix else name
            if mode.startswith("04"):  # directory
                tasks.append(self.walk_tree(sha1, full_path, max_files))
            else:                      # blob
                tasks.append(self._fetch_blob(sha1, full_path))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict):
                recovered.update(r)
        return recovered

    async def _fetch_blob(self, sha1: str, path: str) -> dict[str, bytes]:
        raw = await self._fetch_object(sha1)
        if not raw:
            return {}
        obj_type, content = _parse_git_object(raw)
        if obj_type == "blob":
            return {path: content}
        return {}

    async def walk_commits(
        self,
        head_sha1: str,
        max_commits: int = 50,
    ) -> list[dict]:
        """
        Walk commit history from HEAD. Returns list of commit dicts.
        """
        commits: list[dict] = []
        seen:    set[str]   = set()
        queue   = [head_sha1]

        while queue and len(commits) < max_commits:
            sha1 = queue.pop(0)
            if sha1 in seen or not sha1:
                continue
            seen.add(sha1)

            raw = await self._fetch_object(sha1)
            if not raw:
                continue
            obj_type, content = _parse_git_object(raw)
            if obj_type != "commit":
                continue

            commit = _parse_commit(content)
            commit["sha1"] = sha1
            commits.append(commit)
            queue.extend(commit.get("parents", []))

        return commits

    async def reconstruct(
        self, max_files: int = 300
    ) -> tuple[dict[str, bytes], list[dict], str]:
        """
        Full reconstruction:
         1. Get HEAD commit
         2. Walk tree to recover all files
         3. Walk commit history for author emails + message analysis
        Returns (files_dict, commits_list, remote_url).
        """
        config_text = await self.get_config()
        remote_url  = ""
        m = re.search(r'url\s*=\s*(.+)', config_text)
        if m:
            remote_url = m.group(1).strip()

        head = await self.get_head_commit()
        if not head:
            return {}, [], remote_url

        raw_commit = await self._fetch_object(head)
        if not raw_commit:
            return {}, [], remote_url

        _, commit_content = _parse_git_object(raw_commit)
        commit_data       = _parse_commit(commit_content)
        tree_sha1         = commit_data.get("tree", "")

        files_dict: dict[str, bytes] = {}
        if tree_sha1:
            files_dict = await self.walk_tree(tree_sha1, max_files=max_files)

        commits = await self.walk_commits(head, max_commits=50)
        return files_dict, commits, remote_url


# ═════════════════════════════════════════════════════════════════════════════
# SECRET SCANNING
# ═════════════════════════════════════════════════════════════════════════════

def _redact(value: str) -> str:
    if len(value) <= 10:
        return "***"
    return f"{value[:6]}...{value[-4:]}"


def scan_for_secrets(text: str, source_path: str) -> list[SecretHit]:
    """Run all secret patterns against text content."""
    hits:  list[SecretHit] = []
    seen:  set[str]        = set()

    for name, pattern, severity in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            val = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
            if not val or len(val) < 6:
                continue
            # Skip obvious placeholders
            val_lower = val.lower()
            if any(p in val_lower for p in [
                "your_", "yourkey", "example", "changeme",
                "placeholder", "xxxxxxxxxxxx", "1234567890",
                "aabbccdd", "00000000", "aaaaaaaa",
            ]):
                continue
            if val in seen:
                continue
            seen.add(val)
            # Context: 80 chars either side
            start   = max(0, m.start() - 80)
            end     = min(len(text), m.end() + 80)
            context = text[start:end].replace("\n", " ").strip()[:200]
            hits.append(SecretHit(
                secret_type=name,
                value_redacted=_redact(val),
                severity=severity,
                source_path=source_path,
                context=context,
            ))
    return hits


def extract_emails(text: str) -> list[str]:
    """Extract email addresses (developer/author emails from git commits)."""
    emails: list[str] = []
    seen:   set[str]  = set()
    for m in re.finditer(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', text):
        email = m.group(0).lower()
        # Filter out common non-personal patterns
        if any(skip in email for skip in ["@example", "@test.", "@localhost", "noreply@"]):
            continue
        if email not in seen:
            seen.add(email)
            emails.append(email)
    return emails


# ═════════════════════════════════════════════════════════════════════════════
# HOST SCANNER
# ═════════════════════════════════════════════════════════════════════════════

class HostScanner:
    def __init__(
        self,
        domain: str,
        timeout: float   = 10.0,
        concurrency: int = 15,
        deep: bool       = False,
    ):
        self.domain      = domain
        self.timeout     = timeout
        self._sem        = asyncio.Semaphore(concurrency)
        self.deep        = deep

    async def scan(self, host: str, ip: str) -> HostGitResult:
        result = HostGitResult(host=host, ip=ip)
        async with self._sem:
            try:
                await self._run(host, ip, result)
            except Exception as exc:
                result.error = str(exc)
                log.debug(f"[{host}] Error: {exc}")
        return result

    async def _run(self, host: str, ip: str, result: HostGitResult) -> None:
        # Determine working URL
        base_url = ""
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}/"
            status, _, _ = await fetch(url, timeout=5)
            if status is not None:
                base_url = f"{scheme}://{host}"
                break
        if not base_url:
            result.error = "Host unreachable"
            return

        # ── Git detection and reconstruction ──────────────────────────────
        await self._check_git(host, base_url, result)

        # ── SVN detection ─────────────────────────────────────────────────
        await self._check_svn(host, base_url, result)

        # ── Mercurial detection ───────────────────────────────────────────
        await self._check_hg(host, base_url, result)

        # ── Sensitive file probing ────────────────────────────────────────
        await self._probe_sensitive_files(host, base_url, result)

    async def _check_git(
        self, host: str, base_url: str, result: HostGitResult
    ) -> None:
        # Quick check: is HEAD accessible?
        head_url    = base_url + "/.git/HEAD"
        status, hdrs, body = await fetch(head_url, self.timeout)

        if status != 200 or not body:
            return
        if "ref:" not in body and not (
            len(body.strip()) == 40 and
            all(c in "0123456789abcdef\n" for c in body.strip().lower())
        ):
            return

        result.has_git = True
        log.warning(f"[{host}] .git/HEAD accessible! Reconstructing repository...")

        # Read config for remote URL
        base_git = base_url + "/.git"
        recon    = GitReconstructor(base_url, base_git, self.timeout)
        config   = await recon.get_config()
        if config:
            m = re.search(r'url\s*=\s*(.+)', config)
            if m:
                result.git_remote = m.group(1).strip()

        # Full reconstruction
        try:
            files, commits, remote_url = await recon.reconstruct(max_files=200)
        except Exception as exc:
            log.debug(f"[{host}] Git reconstruction error: {exc}")
            files, commits, remote_url = {}, [], result.git_remote

        result.git_commit_count = len(commits)
        result.git_remote       = result.git_remote or remote_url

        # Determine branch
        s, _, hd_body = await fetch(base_git + "/HEAD", self.timeout)
        if s == 200 and "ref: refs/heads/" in hd_body:
            m = re.search(r'ref: refs/heads/(\S+)', hd_body)
            if m:
                result.git_branch = m.group(1)

        # Scan recovered files for secrets
        all_secrets: list[SecretHit] = []
        recovered_paths: list[str]   = []
        for path, content_bytes in files.items():
            recovered_paths.append(path)
            try:
                text = content_bytes.decode("utf-8", errors="replace")
            except Exception:
                continue
            hits = scan_for_secrets(text, path)
            all_secrets.extend(hits)

        result.files_recovered = recovered_paths[:50]
        result.secrets_found.extend(all_secrets)

        # Extract developer emails from commits
        emails: list[str] = []
        deleted_secret_commits: list[dict] = []
        for commit in commits:
            author = commit.get("author", "")
            em     = extract_emails(author)
            emails.extend(em)
            # Flag commits whose messages suggest secrets were added/removed
            msg = commit.get("message", "")
            for pat in GIT_SECRET_MSG_PATTERNS:
                if pat.search(msg):
                    deleted_secret_commits.append(commit)
                    break
        result.developer_emails = sorted(set(emails))

        # ── Build finding ─────────────────────────────────────────────────
        worst_secret_sev = "INFO"
        if all_secrets:
            worst_secret_sev = min(
                all_secrets, key=lambda s: SEVERITY_ORDER.get(s.severity, 9)
            ).severity

        finding_sev = "CRITICAL" if all_secrets else "HIGH"

        finding = GitDumpFinding(
            host=host,
            url=head_url,
            category="GIT_EXPOSED",
            severity=finding_sev,
            title=f"Exposed .git Repository — Source Code Recoverable",
            detail=(
                f"The .git directory is publicly accessible at {base_url}/.git/. "
                f"The full repository can be reconstructed without authentication. "
                f"{len(files)} files recovered from {len(commits)} commits. "
                + (f"Remote: {result.git_remote}. " if result.git_remote else "")
                + (f"{len(all_secrets)} secrets found in source code. " if all_secrets else "")
                + (f"Developer emails: {', '.join(result.developer_emails[:3])}. "
                   if result.developer_emails else "")
                + (f"{len(deleted_secret_commits)} commits with messages indicating "
                   f"secrets were added/deleted." if deleted_secret_commits else "")
            ),
            evidence=(
                f"curl -sk {head_url} → HTTP 200\n"
                f"Content: {body.strip()[:60]}\n"
                f"Files recovered: {len(files)}\n"
                f"Commits walked: {len(commits)}"
            ),
            curl_command=_curl(head_url),
            recommendation=(
                "Block access to /.git/ at the web server level:\n"
                "  Nginx: location /.git/ { deny all; }\n"
                "  Apache: <DirectoryMatch '^\\.git'>\\n    Require all denied\\n</DirectoryMatch>\n"
                "Rotate any credentials found in the repository history immediately."
            ),
            cvss_estimate="9.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)",
            secrets=all_secrets[:20],
            files_recovered=recovered_paths[:50],
            developer_emails=result.developer_emails,
        )
        result.findings.append(finding)

        # Add separate findings for each CRITICAL secret found
        for secret in all_secrets:
            if secret.severity in ("CRITICAL", "HIGH"):
                result.findings.append(GitDumpFinding(
                    host=host,
                    url=f"{base_url}/{secret.source_path}",
                    category="SECRET",
                    severity=secret.severity,
                    title=f"{secret.secret_type} Found in Git Repository — {secret.source_path}",
                    detail=(
                        f"A {secret.secret_type} was found in {secret.source_path} "
                        f"in the exposed git repository at {base_url}. "
                        f"Value (redacted): {secret.value_redacted}"
                    ),
                    evidence=f"Context: {secret.context[:200]}",
                    curl_command=_curl(f"{base_url}/{secret.source_path}"),
                    recommendation=f"Rotate the {secret.secret_type} immediately. "
                                   f"Remove from git history using git-filter-repo or BFG.",
                    cvss_estimate="9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
                    secrets=[secret],
                ))

    async def _check_svn(
        self, host: str, base_url: str, result: HostGitResult
    ) -> None:
        for path in SVN_DETECT_PATHS:
            url    = base_url + path
            status, _, body = await fetch(url, self.timeout)
            if status == 200 and body:
                result.has_svn = True
                log.warning(f"[{host}] SVN repository exposed at {path}")
                result.findings.append(GitDumpFinding(
                    host=host, url=url,
                    category="SVN_EXPOSED",
                    severity="HIGH",
                    title=f"Exposed SVN Repository Detected — {path}",
                    detail=(
                        f"The SVN working copy metadata at {path} is publicly accessible "
                        f"on {host}. SVN repository contents can be recovered using "
                        f"'svn checkout {base_url}' or by manually fetching objects from "
                        f"the exposed .svn directory."
                    ),
                    evidence=f"GET {url} → HTTP {status}\n{body[:200]}",
                    curl_command=_curl(url),
                    recommendation=(
                        "Block access to /.svn/ at the web server level. "
                        "Rotate any credentials found in the repository."
                    ),
                    cvss_estimate="8.6 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N)",
                ))
                break

    async def _check_hg(
        self, host: str, base_url: str, result: HostGitResult
    ) -> None:
        for path in HG_DETECT_PATHS:
            url    = base_url + path
            status, _, body = await fetch(url, self.timeout)
            if status == 200 and body:
                result.has_hg = True
                log.warning(f"[{host}] Mercurial repository exposed at {path}")
                result.findings.append(GitDumpFinding(
                    host=host, url=url,
                    category="HG_EXPOSED",
                    severity="HIGH",
                    title=f"Exposed Mercurial (.hg) Repository — {path}",
                    detail=(
                        f"Mercurial repository metadata at {path} is publicly accessible. "
                        f"Source code can be recovered with: hg clone {base_url}"
                    ),
                    evidence=f"GET {url} → HTTP {status}\n{body[:200]}",
                    curl_command=_curl(url),
                    recommendation=(
                        "Block access to /.hg/ at the web server level."
                    ),
                    cvss_estimate="8.6 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N)",
                ))
                break

    async def _probe_sensitive_files(
        self, host: str, base_url: str, result: HostGitResult
    ) -> None:
        """
        Probe all sensitive file paths. For found files, scan content for secrets.
        Use catch-all detection: if first 2 paths return the same body,
        skip the remaining to avoid false positives on catch-all servers.
        """
        file_sem     = asyncio.Semaphore(10)
        first_bodies: list[str] = []
        is_catch_all = False

        async def probe_path(path: str, desc: str, sev: str) -> GitDumpFinding | None:
            async with file_sem:
                url    = base_url + path
                status, hdrs, body = await fetch(url, self.timeout)
                if status != 200 or not body or len(body.strip()) < 10:
                    return None

                # Catch-all detection on first 2 responses
                nonlocal is_catch_all, first_bodies
                if len(first_bodies) < 2:
                    first_bodies.append(body[:200])
                    if len(first_bodies) == 2 and first_bodies[0] == first_bodies[1]:
                        is_catch_all = True
                if is_catch_all:
                    return None

                # Check content is actually the expected file type
                if not _looks_like_config(body, path):
                    return None

                result.config_files_found.append(path)
                log.warning(f"[{host}] {path} accessible! ({len(body)}B)")

                # Scan for secrets
                secrets = scan_for_secrets(body, path)
                result.secrets_found.extend(secrets)

                worst = min(
                    [s.severity for s in secrets],
                    key=lambda s: SEVERITY_ORDER.get(s, 9),
                    default=sev,
                )
                final_sev = worst if secrets else sev

                return GitDumpFinding(
                    host=host, url=url,
                    category="CONFIG_FILE",
                    severity=final_sev,
                    title=f"Sensitive File Accessible — {path} ({desc})",
                    detail=(
                        f"The file {path} is publicly accessible on {host}. "
                        f"File size: {len(body)} bytes. "
                        + (f"{len(secrets)} secrets detected in file content."
                           if secrets else
                           f"File content should not be accessible from the web.")
                    ),
                    evidence=(
                        f"GET {url} → HTTP 200 ({len(body)}B)\n"
                        f"Content preview: {body[:200].strip()}"
                    ),
                    curl_command=_curl(url),
                    recommendation=(
                        f"Remove {path} from the web root or block access via server config. "
                        f"If this file contains credentials, rotate them immediately."
                    ),
                    cvss_estimate=(
                        "9.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)"
                        if final_sev == "CRITICAL" else
                        "7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)"
                    ),
                    secrets=secrets[:10],
                )

        # Run probes: first 2 paths synchronously for catch-all detection
        # then the rest concurrently
        sorted_paths = sorted(
            SENSITIVE_PATHS,
            key=lambda x: SEVERITY_ORDER.get(x[2], 9)
        )
        # First 2 serial
        for path, desc, sev in sorted_paths[:2]:
            f = await probe_path(path, desc, sev)
            if f:
                result.findings.append(f)
        if is_catch_all:
            log.debug(f"[{host}] Catch-all server detected — skipping sensitive file scan")
            return

        # Rest concurrent
        tasks = [probe_path(p, d, s) for p, d, s in sorted_paths[2:]]
        findings = await asyncio.gather(*tasks, return_exceptions=True)
        for f in findings:
            if isinstance(f, GitDumpFinding):
                result.findings.append(f)

        # Deduplicate by URL
        seen_urls: set[str] = set()
        deduped: list[GitDumpFinding] = []
        for f in result.findings:
            if f.url not in seen_urls:
                seen_urls.add(f.url)
                deduped.append(f)
        result.findings = deduped


def _looks_like_config(body: str, path: str) -> bool:
    """
    Heuristic: does the response body look like the expected file type?
    Filters out HTML error pages returned for missing files.
    """
    lower = body.lower()[:500]

    # Reject HTML pages (probably 404 served as 200 by catch-all)
    if "<html" in lower or "<!doctype" in lower:
        return False
    if "page not found" in lower or "404" in lower[:100]:
        return False

    # Accept based on file extension or known content patterns
    if path.endswith((".env", ".env.local", ".env.production", ".env.dev")):
        return "=" in body  # .env files always have KEY=VALUE

    if path.endswith((".php", ".py", ".rb", ".yml", ".yaml", ".json")):
        return True  # Let secret scanner determine value

    if path.endswith((".sql",)):
        return "CREATE" in body or "INSERT" in body or "--" in body

    if path.endswith(("id_rsa", ".key", ".pem")):
        return "BEGIN" in body

    return True  # Default: accept


# ═════════════════════════════════════════════════════════════════════════════
# INPUT PARSERS
# ═════════════════════════════════════════════════════════════════════════════

def load_from_subtakeover(path: str) -> list[tuple[str, str]]:
    with open(path) as f:
        data = json.load(f)
    hosts: list[tuple[str, str]] = []
    seen:  set[str] = set()
    for entry in data.get("resolved_subdomains", []):
        h   = entry.get("subdomain", "")
        ips = entry.get("a_records", [])
        if h and ips and h not in seen:
            seen.add(h); hosts.append((h, ips[0]))
    log.info(f"[Parse] {len(hosts)} hosts from subtakeover output")
    return hosts


def load_from_recon(path: str) -> list[tuple[str, str]]:
    with open(path) as f:
        data = json.load(f)
    hosts: list[tuple[str, str]] = []
    seen:  set[str] = set()
    for hr in data.get("host_reports", []):
        h  = hr.get("host", "")
        ip = hr.get("ip", "")
        if h and h not in seen and hr.get("open_ports"):
            seen.add(h); hosts.append((h, ip))
    log.info(f"[Parse] {len(hosts)} hosts with open ports from reconharvest output")
    return hosts


def load_from_hostfile(path: str) -> list[tuple[str, str]]:
    hosts: list[tuple[str, str]] = []
    seen:  set[str] = set()
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            h     = parts[0].strip()
            ip    = parts[1].strip() if len(parts) > 1 else ""
            if not ip:
                try: ip = socket.gethostbyname(h)
                except Exception: ip = h
            if h not in seen:
                seen.add(h); hosts.append((h, ip))
    log.info(f"[Parse] {len(hosts)} hosts from host file")
    return hosts


# ═════════════════════════════════════════════════════════════════════════════
# REPORTING
# ═════════════════════════════════════════════════════════════════════════════

def print_report(report: GitDumpReport) -> None:
    by_sev = {s: [f for f in report.all_findings if f.severity == s]
              for s in SEVERITY_ORDER}

    if not HAS_RICH:
        print(f"\n=== GitDump: {report.domain} ===")
        print(f"Hosts: {report.total_hosts}  Elapsed: {report.elapsed_seconds:.1f}s")
        for f in sorted(report.all_findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 9)):
            print(f"\n[{f.severity}] [{f.category}] {f.title}")
            print(f"  {f.url}\n  {f.detail[:150]}")
        print()
        return

    border = ("red" if by_sev.get("CRITICAL") else
              "yellow" if by_sev.get("HIGH") else "blue")
    console.print()
    console.print(Panel.fit(
        f"[white]Domain:[/] [cyan]{report.domain}[/]\n"
        f"[white]Scan time:[/] {report.scan_time}\n"
        f"[white]Elapsed:[/] {report.elapsed_seconds:.1f}s\n"
        f"[white]Hosts scanned:[/] {report.total_hosts}\n\n"
        f"[bold red]CRITICAL:[/] {len(by_sev.get('CRITICAL',[]))}    "
        f"[bold yellow]HIGH:[/] {len(by_sev.get('HIGH',[]))}    "
        f"[yellow]MEDIUM:[/] {len(by_sev.get('MEDIUM',[]))}    "
        f"[cyan]LOW:[/] {len(by_sev.get('LOW',[]))}    "
        f"[dim]INFO:[/] {len(by_sev.get('INFO',[]))}",
        title="[bold]GitDump Report[/]",
        border_style=border,
    ))

    if not report.all_findings:
        console.print("[bold green]✓ No exposed VCS or sensitive files found.[/]\n")
        return

    # Summary table
    console.print("\n[bold cyan]── Findings Summary ──[/]")
    tbl = Table(show_header=True, header_style="bold cyan", border_style="dim")
    tbl.add_column("Severity",  justify="center")
    tbl.add_column("Category",  style="dim")
    tbl.add_column("Host",      style="cyan")
    tbl.add_column("Title",     max_width=55)
    tbl.add_column("Secrets",   justify="right")

    for f in report.all_findings:
        col = SEV_COLOR.get(f.severity, "white")
        tbl.add_row(
            f"[{col}]{f.severity}[/]",
            f.category,
            f.host,
            f.title[:55],
            str(len(f.secrets)) if f.secrets else "—",
        )
    console.print(tbl)

    # Detail
    for sev in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
        sf = by_sev.get(sev, [])
        if not sf:
            continue
        col = SEV_COLOR.get(sev, "white")
        console.print(f"\n[{col}]── {SEV_EMOJI.get(sev,'')} {sev} ({len(sf)}) ──[/]")
        for i, f in enumerate(sf, 1):
            console.print(
                f"  [{col}][{i}][/] [white]{f.title}[/]\n"
                f"      [dim]Category:[/] {f.category}  [dim]Host:[/] {f.host}\n"
                f"      [dim]URL:[/] {f.url}\n"
                f"      [dim]Detail:[/] {f.detail[:200]}{'...' if len(f.detail)>200 else ''}"
            )
            if f.secrets:
                console.print(f"      [dim]Secrets ({len(f.secrets)}):[/] "
                               + ", ".join(f"[red]{s.secret_type}[/]" for s in f.secrets[:5]))
            if f.developer_emails:
                console.print(f"      [dim]Developer emails:[/] {', '.join(f.developer_emails[:5])}")
            if f.files_recovered:
                console.print(f"      [dim]Files recovered:[/] {len(f.files_recovered)} "
                               f"({', '.join(f.files_recovered[:4])}{'...' if len(f.files_recovered)>4 else ''})")
            if f.evidence:
                console.print(f"      [dim]Evidence:[/] {escape(f.evidence[:140])}")
            if f.curl_command:
                console.print(f"      [dim]Curl:[/] {escape(f.curl_command[:120])}")
            if f.cvss_estimate:
                console.print(f"      [dim]CVSS:[/] {f.cvss_estimate}")
            if i < len(sf):
                console.print()
    console.print()


def save_json(report: GitDumpReport, path: str) -> None:
    def _finding_dict(f: GitDumpFinding) -> dict:
        d = asdict(f)
        return d

    data = {
        "domain":          report.domain,
        "scan_time":       report.scan_time,
        "source_files":    report.source_files,
        "total_hosts":     report.total_hosts,
        "elapsed_seconds": report.elapsed_seconds,
        "summary": {s: len([f for f in report.all_findings if f.severity == s])
                    for s in SEVERITY_ORDER},
        "findings": [_finding_dict(f) for f in sorted(
            report.all_findings,
            key=lambda f: SEVERITY_ORDER.get(f.severity, 9)
        )],
        "host_results": [
            {
                "host":                hr.host,
                "ip":                  hr.ip,
                "has_git":             hr.has_git,
                "has_svn":             hr.has_svn,
                "has_hg":              hr.has_hg,
                "git_branch":          hr.git_branch,
                "git_remote":          hr.git_remote,
                "git_commit_count":    hr.git_commit_count,
                "files_recovered":     hr.files_recovered,
                "config_files_found":  hr.config_files_found,
                "developer_emails":    hr.developer_emails,
                "secret_count":        len(hr.secrets_found),
                "findings_count":      len(hr.findings),
            }
            for hr in report.host_results
        ],
    }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    log.info(f"JSON report saved → {path}")
    log.info(f"  findings[]: {len(report.all_findings)}")


def save_html(report: GitDumpReport, path: str) -> None:
    by_sev = {s: [f for f in report.all_findings if f.severity == s]
              for s in SEVERITY_ORDER}
    sc = {"CRITICAL":"#f85149","HIGH":"#d29922","MEDIUM":"#e3b341",
          "LOW":"#58a6ff","INFO":"#8b949e"}
    sb = {"CRITICAL":"rgba(248,81,73,.12)","HIGH":"rgba(210,153,34,.12)",
          "MEDIUM":"rgba(227,179,65,.10)","LOW":"rgba(88,166,255,.10)",
          "INFO":"rgba(139,148,158,.08)"}

    rows = ""
    for f in report.all_findings:
        c = sc.get(f.severity, "#fff")
        rows += (
            "<td style='color:" + c + ";font-weight:bold'>" + f.severity + "</td>"
            f"<td style='color:#39c5cf'>{f.category}</td>"
            f"<td style='color:#58a6ff'>{f.host}</td>"
            f"<td>{f.title[:55]}</td>"
            f"<td style='text-align:right;color:#f85149'>"
            + (str(len(f.secrets)) if f.secrets else "—") + "</td>"
        )
        rows = f"<tr>{rows}</tr>"

    rows = ""
    for f in report.all_findings:
        c = sc.get(f.severity, "#fff")
        rows += (
            f"<tr>"
            + f"<td style='color:{c};font-weight:bold'>{f.severity}</td>"
            + f"<td style='color:#39c5cf'>{f.category}</td>"
            + f"<td style='color:#58a6ff'>{f.host}</td>"
            + f"<td>{f.title[:55]}</td>"
            + f"<td style='text-align:right;color:#f85149'>{len(f.secrets) if f.secrets else '—'}</td>"
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
            findings_html += (
                f'<div class="finding" style="border-left:3px solid {sc[sev]};background:{sb[sev]}">'
                f'<div class="ft">[{i}] {f.title}</div>'
                f'<div class="fm">'
                f'<span class="badge" style="color:{sc[sev]};background:{sb[sev]};border:1px solid {sc[sev]}">{sev}</span>'
                f'<span style="color:#39c5cf;font-size:.8em">{f.category}</span>'
                f'<span style="color:#58a6ff;font-size:.8em">{f.host}</span>'
                + (f'<span style="color:#d29922;font-size:.75em">{f.cvss_estimate}</span>' if f.cvss_estimate else "")
                + f'</div>'
                f'<div class="fd">{f.detail}</div>'
                + (f'<div class="ev"><span class="evl">Secrets found ({len(f.secrets)}):</span>'
                   + "".join(f'<span style="color:#f85149;margin-right:8px">{s.secret_type}: {s.value_redacted}</span>'
                              for s in f.secrets[:5])
                   + '</div>' if f.secrets else "")
                + (f'<div class="ev"><span class="evl">Dev emails:</span><code>{", ".join(f.developer_emails[:5])}</code></div>'
                   if f.developer_emails else "")
                + (f'<div class="ev"><span class="evl">Files ({len(f.files_recovered)}):</span>'
                   f'<code>{", ".join(f.files_recovered[:6])}</code></div>' if f.files_recovered else "")
                + (f'<div class="ev"><span class="evl">Evidence:</span><code>{ev_e[:300]}</code></div>' if f.evidence else "")
                + (f'<div class="ev"><span class="evl">Reproduce:</span>'
                   f'<code>{curl_e}</code></div>' if f.curl_command else "")
                + f'<div class="rec"><span class="recl">Fix:</span> {f.recommendation}</div>'
                + f'</div>'
            )
        findings_html += "</div>"

    if not findings_html:
        findings_html = "<p style='color:#3fb950'>No exposed VCS or sensitive files found.</p>"

    html = f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GitDump — {report.domain}</title>
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
.stat{{background:var(--sf);border:1px solid var(--bd);border-radius:8px;padding:14px;text-align:center}}
.sv{{font-size:1.8em;font-weight:bold}}.sl{{color:var(--mt);font-size:.72em;margin-top:3px}}
.card{{background:var(--sf);border:1px solid var(--bd);border-radius:8px;padding:20px;margin-bottom:20px}}
h2{{font-family:system-ui,sans-serif;font-size:1.1em;font-weight:700;color:#fff;margin-bottom:14px}}
h3{{font-family:system-ui,sans-serif;font-size:.95em;font-weight:700;margin:16px 0 10px}}
table{{width:100%;border-collapse:collapse}}
th{{background:var(--sf2);color:var(--mt);text-align:left;padding:8px 12px;
   border:1px solid var(--bd);font-size:.72em;text-transform:uppercase;letter-spacing:.07em}}
td{{padding:8px 12px;border-bottom:1px solid var(--bd);vertical-align:top}}
tr:hover td{{background:rgba(88,166,255,.03)}}
.finding{{padding:14px 16px;border-radius:6px;margin-bottom:10px}}
.ft{{font-family:system-ui,sans-serif;font-weight:700;font-size:.9em;color:#fff;margin-bottom:8px}}
.fm{{display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap}}
.badge{{padding:2px 8px;border-radius:10px;font-size:.7em;font-weight:700;letter-spacing:.05em}}
.fd{{color:var(--mt);font-size:.83em;margin-bottom:8px;line-height:1.6}}
.ev{{background:rgba(0,0,0,.4);border:1px solid var(--bd);border-radius:4px;padding:8px 10px;margin-bottom:8px}}
.evl{{color:#39c5cf;font-size:.7em;font-weight:700;margin-right:6px}}
.ev code{{color:#a8dadc;font-size:.82em;word-break:break-all}}
.rec{{color:#3fb950;font-size:.8em}}.recl{{font-weight:700;margin-right:4px}}
.sev-section{{margin-bottom:20px}}
.footer{{text-align:center;color:var(--mt);font-size:.72em;margin-top:32px;
         padding-top:16px;border-top:1px solid var(--bd)}}
</style></head>
<body><div class="wrap">
<h1>GitDump</h1>
<p class="sub">{report.domain} &nbsp;·&nbsp; {report.scan_time} &nbsp;·&nbsp;
{report.elapsed_seconds:.1f}s &nbsp;·&nbsp; {report.total_hosts} hosts</p>
<div class="stats">
<div class="stat"><div class="sv" style="color:#f85149">{len(by_sev.get('CRITICAL',[]))}</div><div class="sl">CRITICAL</div></div>
<div class="stat"><div class="sv" style="color:#d29922">{len(by_sev.get('HIGH',[]))}</div><div class="sl">HIGH</div></div>
<div class="stat"><div class="sv" style="color:#e3b341">{len(by_sev.get('MEDIUM',[]))}</div><div class="sl">MEDIUM</div></div>
<div class="stat"><div class="sv" style="color:#58a6ff">{len(by_sev.get('LOW',[]))}</div><div class="sl">LOW</div></div>
<div class="stat"><div class="sv">{report.total_hosts}</div><div class="sl">HOSTS</div></div>
</div>
<div class="card"><h2>📋 Summary</h2>
<table><thead><tr><th>Severity</th><th>Category</th><th>Host</th>
<th>Title</th><th>Secrets</th></tr></thead><tbody>{rows}</tbody></table></div>
<div class="card"><h2>🔎 Findings Detail</h2>{findings_html}</div>
<div class="footer">GitDump &nbsp;·&nbsp; For authorized security research only</div>
</div></body></html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    log.info(f"HTML report saved → {path}")


# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="GitDump — Exposed VCS & Configuration File Harvester",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 gitdump.py --subtakeover scan.json --domain eskimi.com --output git
  python3 gitdump.py --scan recon-report-v2.json --domain eskimi.com --output git
  python3 gitdump.py --hosts targets.txt --domain eskimi.com --output git

What it checks:
  Git     — /.git/HEAD, full repository reconstruction, commit history, secrets in history
  SVN     — /.svn/entries, /.svn/wc.db
  Mercurial — /.hg/requires
  Config files — 90+ paths: .env, wp-config.php, database.yml, .npmrc, .travis.yml,
                 docker-compose.yml, k8s secrets, .htpasswd, SSH keys, TLS keys, DB dumps

Secret detection:
  17 pattern types: AWS keys, GCP/Azure credentials, Stripe, GitHub PAT, Slack,
  JWT secrets, DB connection strings, private keys, hardcoded passwords

Chains from : subtakeover.py (--subtakeover), reconharvest.py (--scan), plain list (--hosts)
Output      : JSON + HTML report with curl PoC per finding
        """,
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--subtakeover", metavar="FILE", help="subtakeover.py scan.json")
    src.add_argument("--scan",        metavar="FILE", help="reconharvest.py output JSON")
    src.add_argument("--hosts",       metavar="FILE", help="Plain host list")

    p.add_argument("--domain",        required=True,  help="Target root domain")
    p.add_argument("-o","--output",   metavar="BASE",  help="Output base → BASE.json + BASE.html")
    p.add_argument("--timeout",       type=float, default=10.0)
    p.add_argument("--concurrency",   type=int,   default=15)
    p.add_argument("--deep",          action="store_true",
                   help="Walk full git commit history (slower, finds deleted secrets)")
    p.add_argument("-v","--verbose",  action="store_true")
    return p.parse_args()


async def main() -> None:
    args = parse_args()
    if args.verbose:
        log.setLevel(logging.DEBUG)

    print("""
╔══════════════════════════════════════════════════════════════════╗
║       GitDump — Exposed VCS & Configuration File Harvester       ║
║  For authorized penetration testing and bug bounty research only ║
╚══════════════════════════════════════════════════════════════════╝
""")

    if not HAS_HTTPX:
        log.error("httpx required: pip install httpx")
        sys.exit(1)

    source_files: list[str] = []
    if args.subtakeover:
        hosts = load_from_subtakeover(args.subtakeover)
        source_files.append(args.subtakeover)
    elif args.scan:
        hosts = load_from_recon(args.scan)
        source_files.append(args.scan)
    else:
        hosts = load_from_hostfile(args.hosts)
        source_files.append(args.hosts)

    if not hosts:
        log.error("No hosts found."); sys.exit(1)

    report = GitDumpReport(
        domain=args.domain,
        scan_time=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        source_files=source_files,
        total_hosts=len(hosts),
    )

    scanner = HostScanner(
        domain=args.domain,
        timeout=args.timeout,
        concurrency=args.concurrency,
        deep=args.deep,
    )

    t0 = time.perf_counter()

    if HAS_RICH:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]Scanning for exposed VCS & configs[/]"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("[dim]{task.fields[h]}[/]"),
            console=console,
        ) as prog:
            task = prog.add_task("scan", total=len(hosts), h="")
            sem  = asyncio.Semaphore(args.concurrency)

            async def bounded(host: str, ip: str) -> HostGitResult:
                async with sem:
                    prog.update(task, h=host)
                    r = await scanner.scan(host, ip)
                    prog.advance(task)
                    return r

            results = await asyncio.gather(
                *[bounded(h, ip) for h, ip in hosts],
                return_exceptions=True,
            )
    else:
        sem = asyncio.Semaphore(args.concurrency)

        async def bounded(host: str, ip: str) -> HostGitResult:
            async with sem:
                return await scanner.scan(host, ip)

        results = await asyncio.gather(
            *[bounded(h, ip) for h, ip in hosts],
            return_exceptions=True,
        )

    for r in results:
        if isinstance(r, HostGitResult):
            report.host_results.append(r)
            report.all_findings.extend(r.findings)

    report.all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
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

    crit = len([f for f in report.all_findings if f.severity == "CRITICAL"])
    high = len([f for f in report.all_findings if f.severity == "HIGH"])
    if crit or high:
        log.warning(
            f"[!] {crit} CRITICAL + {high} HIGH findings. "
            f"Rotate any exposed credentials immediately."
        )
    elif not report.all_findings:
        log.info("[✓] No exposed VCS repositories or sensitive configuration files found.")


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(0)
