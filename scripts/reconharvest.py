#!/usr/bin/env python3
"""
reconharvest.py — Post-SubTakeover Recon Automation (v2)
=========================================================
Author  : RareKez / security research tooling

Optimisations vs v1:
  Speed
    - TCP pre-check (2s) before HTTP — eliminates full timeout wait on closed ports
    - All 120 hosts processed concurrently (asyncio.gather), not in semaphore batches
    - TLS checked once per unique IP, not once per hostname (120 → 68 for eskimi.com)
    - Catch-all server detection — skip remaining path probes if first 2 responses match
    - Persistent httpx.AsyncClient per host — one TLS handshake, not one per request
    - Concurrency raised from 15 → 60 for port probing, 30 → 80 for TCP checks

  Detection (all missed in v1)
    - SonarQube        port 9000, body pattern
    - HashiCorp Vault  port 8200, JSON /v1/sys/health
    - n8n workflow     port 5678, body pattern
    - NetBird VPN      body pattern
    - Metabase BI      port 3000, body pattern
    - Nexus Repository port 8081, body pattern
    - Kafka UI         port 8080, body pattern
    - PMM (Percona)    port 443/80, body pattern
    - ModX /evo/ CMS admin panel (port 8443 redirect)

  New finding types
    - TLS CN mismatch (wrong cert on host)
    - Cloudflare 1014 origin error (origin misconfiguration)
    - Kubernetes ingress exposed with backend NotFound
    - Shared-hosting "website does not exist" page (potential takeover)
    - Catch-all server detection (path probe noise filter)
    - Finding deduplication by (ip, category) — no repeated cert findings per IP
    - Backend IPs auto-added to scan targets via proxy error harvest
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import json
import re
import socket
import ssl
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
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

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

import logging
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger("reconharvest")
for _n in ("httpx", "httpcore", "httpcore.connection"):
    logging.getLogger(_n).setLevel(logging.WARNING)


# ════════════════════════════════════════════════════════════════════════════
# SERVICE DATABASE
# ════════════════════════════════════════════════════════════════════════════

SERVICES: dict[str, dict] = {
    "Jenkins": {
        "ports":    [8080, 80, 443, 8443],
        "detect":   ["X-Jenkins", "j_spring_security_check", "hudson", "Jenkins"],
        "ver_hdr":  "X-Jenkins",
        "paths": [
            "/api/json?pretty=true", "/login", "/script",
            "/credentials/", "/manage", "/asynchPeople/",
            "/securityRealm/createAccount", "/computer/",
        ],
        "creds":    [("admin","admin"),("admin","password"),("admin","jenkins"),("jenkins","jenkins")],
        "login_path":   "/j_spring_security_check",
        "login_fields": "j_username={u}&j_password={p}&from=&Submit=Sign+in",
        "auth_fail":    "/loginError",
        "severity": "CRITICAL",
        "note":     "CI/CD pipeline — script console = unauthenticated RCE if accessible",
    },
    "Grafana": {
        "ports":    [3000, 80, 443, 8080],
        "detect":   ["grafana", "Grafana", "x-grafana"],
        "ver_hdr":  "X-Grafana-Version",
        "paths":    ["/api/health", "/api/org", "/api/users", "/api/datasources", "/login"],
        "creds":    [("admin","admin"),("admin","grafana"),("admin","password")],
        "login_json_path": "/api/login",
        "login_json":      '{"user":"{u}","password":"{p}"}',
        "auth_success_val": "Logged in",
        "severity": "HIGH",
        "note":     "Monitoring dashboard — default admin:admin is extremely common",
    },
    "Apache Airflow": {
        "ports":    [8080, 80, 443, 8793],
        "detect":   ["Airflow", "airflow", "Apache-Airflow"],
        "ver_hdr":  "X-Airflow-Version",
        "paths":    ["/api/v1/health", "/api/v1/dags", "/health", "/login"],
        "creds":    [("admin","admin"),("airflow","airflow")],
        "severity": "CRITICAL",
        "note":     "Data pipeline DAG execution = code execution in production",
    },
    "ArgoCD": {
        "ports":    [443, 80, 8080, 8443],
        "detect":   ["Argo CD", "argocd", "argo-cd"],
        "paths":    ["/api/v1/session","/api/v1/applications","/api/v1/clusters"],
        "creds":    [("admin","admin")],
        "login_json_path": "/api/v1/session",
        "login_json":      '{"username":"{u}","password":"{p}"}',
        "severity": "CRITICAL",
        "note":     "Kubernetes CD — cluster access, secrets, deployment control",
    },
    "HashiCorp Consul": {
        "ports":    [8500, 8501, 80, 443],
        "detect":   ["consul", "Consul", "X-Consul"],
        "paths":    ["/v1/catalog/services","/v1/agent/members","/v1/kv/?keys","/ui/"],
        "creds":    [],
        "severity": "CRITICAL",
        "note":     "Service mesh — internal topology, KV secrets, service deregistration",
    },
    "HashiCorp Vault": {
        "ports":    [8200, 443, 80, 8080],
        "detect":   ["vault-initialized", "X-Vault-Request", "Vault", '"initialized"'],
        "paths":    ["/v1/sys/health","/v1/sys/seal-status","/ui/"],
        "creds":    [("root","root"),("admin","admin")],
        "severity": "CRITICAL",
        "note":     "Secrets management — unsealed Vault = all secrets accessible",
    },
    "Kibana / ELK": {
        "ports":    [5601, 80, 443, 9200],
        "detect":   ["Kibana", "kibana", "elastic", "kbn-version"],
        "ver_hdr":  "kbn-version",
        "paths":    ["/api/status","/api/spaces/space","/_cat/indices?v","/app/kibana"],
        "creds":    [("elastic","elastic"),("elastic","changeme"),("kibana","kibana")],
        "severity": "HIGH",
        "note":     "Log data — PII, credentials, internal API keys often in logs",
    },
    "Jaeger": {
        "ports":    [16686, 80, 443, 14268],
        "detect":   ["jaeger", "Jaeger", "uber-trace-id"],
        "paths":    ["/api/services","/api/traces","/"],
        "creds":    [],
        "severity": "MEDIUM",
        "note":     "Distributed tracing — internal service communication patterns",
    },
    "Graphite": {
        "ports":    [80, 443, 2003, 8080, 8125],
        "detect":   ["Graphite","graphite","whisper","carbon"],
        "paths":    ["/metrics/find?query=*","/render?target=*","/"],
        "creds":    [("admin","admin"),("graphite","graphite")],
        "severity": "MEDIUM",
        "note":     "Metrics — infrastructure performance data and topology",
    },
    "Icinga": {
        "ports":    [80, 443, 5665, 8080],
        "detect":   ["Icinga","icinga","Icinga2","icingaweb"],
        "paths":    ["/icingaweb2/","/icinga2/","/"],
        "creds":    [("icingaadmin","icinga"),("admin","admin"),("root","icinga")],
        "severity": "MEDIUM",
        "note":     "Network monitoring — full internal host inventory",
    },
    "SonarQube": {
        "ports":    [9000, 80, 443, 8080],
        "detect":   ["SonarQube","sonarqube","SonarSource"],
        "paths":    ["/api/system/status","/api/projects/search","/"],
        "creds":    [("admin","admin"),("admin","sonar"),("admin","password")],
        "severity": "HIGH",
        "note":     "Code quality — source code, vulnerabilities, credentials in scan output",
    },
    "Flower (Celery)": {
        "ports":    [5555, 80, 443, 8080],
        "detect":   ["Flower","flower","Celery"],
        "paths":    ["/","/api/workers","/api/tasks"],
        "creds":    [],
        "severity": "HIGH",
        "note":     "Celery task monitor — task execution visibility and trigger",
    },
    "n8n Workflow": {
        "ports":    [5678, 80, 443, 8080],
        "detect":   ["n8n","n8n.io","workflow-automation"],
        "paths":    ["/rest/login","/rest/workflows","/"],
        "creds":    [("admin","admin"),("n8n","n8n"),("owner","owner")],
        "severity": "HIGH",
        "note":     "Workflow automation — can execute arbitrary code via nodes",
    },
    "Metabase": {
        "ports":    [3000, 80, 443, 8080],
        "detect":   ["Metabase","metabase"],
        "paths":    ["/api/health","/api/session","/"],
        "creds":    [("admin@metabase.local","metabase1234!")],
        "login_json_path": "/api/session",
        "login_json":      '{"username":"{u}","password":"{p}"}',
        "auth_success_val": "id",
        "severity": "HIGH",
        "note":     "BI tool — database connections and query results may contain PII",
    },
    "Nexus Repository": {
        "ports":    [8081, 80, 443, 8443],
        "detect":   ["Nexus Repository","nexus","NexusRepository","Sonatype"],
        "paths":    ["/service/rest/v1/status","/","/service/rest/v1/repositories"],
        "creds":    [("admin","admin123"),("admin","admin")],
        "severity": "HIGH",
        "note":     "Artifact repo — source packages, internal libraries, credentials in repos",
    },
    "NetBird VPN": {
        "ports":    [80, 443, 33073],
        "detect":   ["netbird","NetBird","wiretrustee"],
        "paths":    ["/api/peers","/api/groups","/"],
        "creds":    [],
        "severity": "MEDIUM",
        "note":     "VPN management — peer list reveals all internal network nodes",
    },
    "Plesk": {
        "ports":    [8443, 80, 443, 8880],
        "detect":   ["plesk","Plesk","PleskControlPanel"],
        "paths":    ["/login_up.php","/enterprise/control/agent.php","/"],
        "creds":    [("admin","admin"),("admin","password")],
        "severity": "HIGH",
        "note":     "Hosting control panel — full server management if authenticated",
    },
    "Generic HTTP": {
        "ports":    [80, 443, 8080, 8443, 3000, 5000, 8000, 9000],
        "detect":   [],
        "paths":    ["/","/admin","/login","/api","/health","/status"],
        "creds":    [],
        "severity": "INFO",
        "note":     "Unknown service — investigate manually",
    },
}

ALL_PORTS: list[int] = sorted({
    p for svc in SERVICES.values() for p in svc["ports"]
})

# Patterns for special response types
PROXY_ERR_RE     = re.compile(r"dial tcp[46]?\s+[\d.]+:\d+->([\d.]+):(\d+):\s+(.+)")
K8S_404_PAT      = re.compile(r"backend NotFound|service rules for the path non-existent|routenotfound", re.I)
HOSTING_DOWN_PAT = re.compile(r"does not exist on this server|neegzistuoja|website.*not.*exist|web-site.*not.*found", re.I)
CF_1014_PAT      = re.compile(r"error code: 1014|1014\s*(?:Cross-Origin|Redirect Error)", re.I)
EVO_REDIRECT_PAT = re.compile(r"/evo/", re.I)
MODX_PAT         = re.compile(r"modx|MODx|MODX Revolution", re.I)

SEVERITY_ORDER   = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_COLOR        = {"CRITICAL":"bold red","HIGH":"bold yellow","MEDIUM":"yellow","LOW":"cyan","INFO":"dim"}
SEV_EMOJI        = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵","INFO":"⚪"}


# ════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class PortResult:
    host: str; ip: str; port: int; scheme: str
    http_status: int | None        = None
    headers: dict                  = field(default_factory=dict)
    body: str                      = ""
    service_detected: str | None   = None
    service_version: str | None    = None
    redirect_location: str | None  = None
    is_open: bool                  = False

@dataclass
class TLSInfo:
    host: str; ip: str
    cn: str                        = ""
    sans: list[str]                = field(default_factory=list)
    issuer: str                    = ""
    expiry: str                    = ""
    days_remaining: int            = 9999
    is_expired: bool               = False
    is_expiring_soon: bool         = False
    cn_mismatch: bool              = False
    error: str | None              = None

@dataclass
class CredResult:
    host: str; service: str; username: str; password: str
    success: bool                  = False
    http_status: int | None        = None
    notes: str                     = ""

@dataclass
class Finding:
    host: str; ip: str; severity: str; category: str
    title: str; detail: str; evidence: str; recommendation: str
    port: int | None               = None
    service: str | None            = None
    cvss_estimate: str             = ""
    dedup_key: str                 = ""   # ip:category — for deduplication

@dataclass
class HostReport:
    host: str; ip: str
    open_ports: list[PortResult]   = field(default_factory=list)
    tls_info: TLSInfo | None       = None
    service: str | None            = None
    service_version: str | None    = None
    probe_results: list[dict]      = field(default_factory=list)
    cred_results: list[CredResult] = field(default_factory=list)
    proxy_disclosures: list[dict]  = field(default_factory=list)
    is_catch_all: bool             = False
    findings: list[Finding]        = field(default_factory=list)

@dataclass
class ReconReport:
    domain: str; scan_time: str
    source_file: str | None        = None
    total_hosts: int               = 0
    elapsed_seconds: float         = 0.0
    extra_hosts_from_proxy: int    = 0
    host_reports: list[HostReport] = field(default_factory=list)
    all_findings: list[Finding]    = field(default_factory=list)


# ════════════════════════════════════════════════════════════════════════════
# NETWORKING PRIMITIVES
# ════════════════════════════════════════════════════════════════════════════

UA = "Mozilla/5.0 (compatible; ReconHarvest/2.0)"

# Module-level User-Agent override (C18) — set via --user-agent.
_USER_AGENT = UA


def set_user_agent(value: str) -> None:
    global _USER_AGENT
    _USER_AGENT = value or UA


def user_agent() -> str:
    return _USER_AGENT

async def tcp_check(ip: str, port: int, timeout: float = 2.0) -> bool:
    """Fast TCP connect check. Returns True if port is open."""
    try:
        _, w = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def http_get(
    url: str,
    timeout: float = 8.0,
    headers: dict | None = None,
    client: "httpx.AsyncClient | None" = None,
) -> tuple[int | None, dict, str, str | None]:
    """GET → (status, headers, body[:3000], redirect_location). Never raises."""
    if not HAS_HTTPX:
        return None, {}, "", None
    hdrs = {"User-Agent": user_agent(), **(headers or {})}
    try:
        if client:
            resp = await client.get(url, headers=hdrs)
        else:
            async with httpx.AsyncClient(
                timeout=timeout, verify=False, follow_redirects=False, headers=hdrs
            ) as c:
                resp = await c.get(url)
        return resp.status_code, dict(resp.headers), resp.text[:3000], resp.headers.get("location")
    except Exception:
        return None, {}, "", None


async def http_post(
    url: str,
    data: str | None = None,
    json_body: dict | None = None,
    timeout: float = 8.0,
    client: "httpx.AsyncClient | None" = None,
) -> tuple[int | None, dict, str, str | None]:
    hdrs = {
        "User-Agent": user_agent(),
        "Content-Type": "application/json" if json_body else "application/x-www-form-urlencoded",
    }
    try:
        if client:
            resp = await (client.post(url, json=json_body, headers=hdrs)
                          if json_body else client.post(url, content=data or "", headers=hdrs))
        else:
            async with httpx.AsyncClient(
                timeout=timeout, verify=False, follow_redirects=False
            ) as c:
                resp = await (c.post(url, json=json_body, headers=hdrs)
                              if json_body else c.post(url, content=data or "", headers=hdrs))
        return resp.status_code, dict(resp.headers), resp.text[:3000], resp.headers.get("location")
    except Exception:
        return None, {}, "", None


# ════════════════════════════════════════════════════════════════════════════
# TLS ANALYSIS  (per unique IP, not per hostname)
# ════════════════════════════════════════════════════════════════════════════

def analyse_tls(host: str, ip: str, port: int = 443) -> TLSInfo:
    info = TLSInfo(host=host, ip=ip)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(
            socket.create_connection((ip, port), timeout=6),
            server_hostname=host,
        ) as sock:
            raw = sock.getpeercert(binary_form=True)
        if not raw:
            info.error = "No certificate returned"
            return info
        if HAS_CRYPTO:
            cert = x509.load_der_x509_certificate(raw, default_backend())
            cn_a = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            info.cn = cn_a[0].value if cn_a else ""
            try:
                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                info.sans = [str(n) for n in san.value]
            except Exception:
                info.sans = []
            iss_a = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            info.issuer = iss_a[0].value if iss_a else str(cert.issuer)
            exp = getattr(cert, "not_valid_after_utc", None)
            if exp is None:
                exp = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
            info.expiry = exp.isoformat()
            now = datetime.datetime.now(datetime.timezone.utc)
            info.days_remaining    = (exp - now).days
            info.is_expired        = info.days_remaining < 0
            info.is_expiring_soon  = 0 <= info.days_remaining <= 30
            # CN mismatch check
            host_root = host.split(".", 1)[1] if "." in host else host
            cn_root   = info.cn.lstrip("*.").split(".", 1)[-1] if info.cn else ""
            all_names = [info.cn] + info.sans
            info.cn_mismatch = not any(
                host.lower().endswith(n.lstrip("*.").lower())
                for n in all_names if n
            )
    except Exception as exc:
        info.error = str(exc)
    return info


# ════════════════════════════════════════════════════════════════════════════
# SERVICE DETECTION
# ════════════════════════════════════════════════════════════════════════════

def detect_service(headers: dict, body: str) -> tuple[str | None, str | None]:
    h_lower  = {k.lower(): v for k, v in headers.items()}
    bl       = body.lower()
    for name, svc in SERVICES.items():
        if name == "Generic HTTP":
            continue
        for pat in svc.get("detect", []):
            if pat.lower() in bl:
                ver = h_lower.get(svc.get("ver_hdr", "").lower(), "")
                return name, ver or None
            for v in headers.values():
                if pat.lower() in str(v).lower():
                    ver = h_lower.get(svc.get("ver_hdr", "").lower(), "")
                    return name, ver or None
    return None, None


def detect_special(body: str, headers: dict, redirect: str | None) -> list[str]:
    """Return list of special condition tags."""
    tags = []
    if PROXY_ERR_RE.search(body):    tags.append("proxy_error")
    if K8S_404_PAT.search(body):     tags.append("k8s_404")
    if HOSTING_DOWN_PAT.search(body):tags.append("hosting_down")
    if CF_1014_PAT.search(body):     tags.append("cf_1014")
    if redirect and EVO_REDIRECT_PAT.search(redirect): tags.append("modx_evo")
    if MODX_PAT.search(body):        tags.append("modx_body")
    return tags


# ════════════════════════════════════════════════════════════════════════════
# CREDENTIAL TESTING
# ════════════════════════════════════════════════════════════════════════════

async def test_creds(
    base_url: str, host: str, svc_name: str, svc_def: dict,
    client: "httpx.AsyncClient",
) -> list[CredResult]:
    results = []
    for user, pwd in svc_def.get("creds", []):
        cr = CredResult(host=base_url, service=svc_name, username=user, password=pwd)
        try:
            if "login_json" in svc_def and "login_json_path" in svc_def:
                import json as _j
                payload = _j.loads(
                    svc_def["login_json"].replace("{u}", user).replace("{p}", pwd)
                )
                status, hdrs, body, loc = await http_post(
                    f"{base_url}{svc_def['login_json_path']}",
                    json_body=payload, client=client,
                )
                cr.http_status = status
                sv = svc_def.get("auth_success_val", "")
                if sv and sv.lower() in body.lower():
                    cr.success = True; cr.notes = f"JSON auth matched '{sv}'"
                elif status in (200, 201):
                    cr.success = True; cr.notes = "JSON auth HTTP 200"
            elif "login_fields" in svc_def:
                data = (svc_def["login_fields"]
                        .replace("{u}", user).replace("{p}", pwd))
                status, hdrs, body, loc = await http_post(
                    f"{base_url}{svc_def['login_path']}",
                    data=data, client=client,
                )
                cr.http_status = status
                fail_pat = svc_def.get("auth_fail", "/loginError")
                if loc:
                    if fail_pat and fail_pat in loc:
                        cr.success = False
                    elif loc.rstrip("/") in ("", "/"):
                        cr.success = True; cr.notes = f"Redirect to {loc}"
        except Exception as exc:
            cr.notes = str(exc)
        results.append(cr)
        if cr.success:
            break
    return results


# ════════════════════════════════════════════════════════════════════════════
# HOST PROBER
# ════════════════════════════════════════════════════════════════════════════

class HostProber:
    def __init__(
        self,
        domain: str,
        timeout: float    = 8.0,
        tcp_timeout: float= 2.0,
        test_creds: bool  = True,
        port_concurrency: int = 60,
        tcp_concurrency:  int = 80,
    ):
        self.domain          = domain
        self.timeout         = timeout
        self.tcp_timeout     = tcp_timeout
        self.test_creds_flag = test_creds
        self._port_sem       = asyncio.Semaphore(port_concurrency)
        self._tcp_sem        = asyncio.Semaphore(tcp_concurrency)
        # Shared TLS cache: ip → TLSInfo  (check each IP once)
        self._tls_cache: dict[str, TLSInfo] = {}
        self._tls_lock = asyncio.Lock()
        # Finding dedup: (ip, category) → True
        self._dedup: set[str] = set()

    async def _get_tls(self, host: str, ip: str, port: int = 443) -> TLSInfo | None:
        cache_key = f"{ip}:{port}"
        async with self._tls_lock:
            if cache_key in self._tls_cache:
                return self._tls_cache[cache_key]
        # Run outside the lock so concurrent calls for the same IP don't deadlock
        tls = await asyncio.get_event_loop().run_in_executor(
            None, lambda: analyse_tls(host, ip, port)
        )
        async with self._tls_lock:
            self._tls_cache[cache_key] = tls
        return tls

    async def _probe_port(self, host: str, ip: str, port: int) -> PortResult | None:
        # TCP pre-check — eliminates full HTTP timeout on closed ports
        async with self._tcp_sem:
            is_open = await tcp_check(ip, port, self.tcp_timeout)
        if not is_open:
            return None

        # Port is open — determine scheme and run HTTP probe
        schemes = ["https","http"] if port in (443, 8443, 4443, 8501) else ["http","https"]
        async with self._port_sem:
            for scheme in schemes:
                url = f"{scheme}://{host}:{port}/"
                status, hdrs, body, loc = await http_get(url, self.timeout)
                if status is not None:
                    svc, ver = detect_service(hdrs, body)
                    return PortResult(
                        host=host, ip=ip, port=port, scheme=scheme,
                        http_status=status, headers=hdrs, body=body[:500],
                        service_detected=svc, service_version=ver,
                        redirect_location=loc, is_open=True,
                    )
        return None

    async def analyse_host(self, host: str, ip: str) -> HostReport:
        report = HostReport(host=host, ip=ip)

        # ── 1. Concurrent port scan across all service ports ──────────────
        port_results = await asyncio.gather(
            *[self._probe_port(host, ip, p) for p in ALL_PORTS],
            return_exceptions=True,
        )
        report.open_ports = [
            r for r in port_results
            if isinstance(r, PortResult) and r.is_open
        ]
        if not report.open_ports:
            return report

        # Collect proxy disclosures from port responses
        for pr in report.open_ports:
            m = PROXY_ERR_RE.search(pr.body)
            if m:
                entry = {"port": pr.port, "backend_ip": m.group(1),
                         "backend_port": int(m.group(2)), "error": m.group(3).strip()}
                if entry not in report.proxy_disclosures:
                    report.proxy_disclosures.append(entry)

        # ── 2. Identify best port + service ──────────────────────────────
        best = next(
            (p for p in report.open_ports
             if p.service_detected and p.service_detected != "Generic HTTP"),
            report.open_ports[0]
        )
        report.service         = best.service_detected or "Generic HTTP"
        report.service_version = best.service_version
        svc_def                = SERVICES.get(report.service, SERVICES["Generic HTTP"])
        base_url               = f"{best.scheme}://{host}:{best.port}"

        # ── 3. TLS — use cache, check only once per unique IP:port ────────
        https_port = next(
            (p.port for p in report.open_ports if p.scheme == "https"), None
        )
        if https_port:
            report.tls_info = await self._get_tls(host, ip, https_port)
        if not report.tls_info:
            # Try standard 443 even if not in open_ports
            open_ok = await tcp_check(ip, 443, self.tcp_timeout)
            if open_ok:
                report.tls_info = await self._get_tls(host, ip, 443)

        # ── 4. Catch-all detection ────────────────────────────────────────
        # Probe first 2 paths. If they return the same body, server is catch-all.
        paths = svc_def.get("paths", ["/", "/login"])
        first_bodies: list[str] = []

        async with httpx.AsyncClient(
            timeout=self.timeout, verify=False, follow_redirects=False,
            headers={"User-Agent": user_agent()},
        ) as client:
            for path in paths[:2]:
                s, h, b, loc = await http_get(f"{base_url}{path}", client=client)
                first_bodies.append(b[:200])
                report.probe_results.append({
                    "path": path, "http_status": s,
                    "body_snippet": b[:300], "headers": {
                        k: v for k, v in h.items()
                        if k.lower() in ("server","x-jenkins","x-powered-by",
                                         "via","content-type","x-vault-request",
                                         "kbn-version","x-grafana-version")
                    },
                    "redirect_location": loc,
                    "special_tags": detect_special(b, h, loc),
                    "is_accessible": s == 200 and "login" not in b[:200].lower(),
                })

            is_catch_all = (
                len(first_bodies) == 2
                and first_bodies[0]
                and first_bodies[0] == first_bodies[1]
            )
            report.is_catch_all = is_catch_all

            # Probe remaining paths only if NOT a catch-all
            if not is_catch_all:
                for path in paths[2:]:
                    s, h, b, loc = await http_get(f"{base_url}{path}", client=client)
                    report.probe_results.append({
                        "path": path, "http_status": s,
                        "body_snippet": b[:300], "headers": {
                            k: v for k, v in h.items()
                            if k.lower() in ("server","x-jenkins","x-powered-by",
                                             "via","content-type","x-vault-request")
                        },
                        "redirect_location": loc,
                        "special_tags": detect_special(b, h, loc),
                        "is_accessible": s == 200 and "login" not in b[:200].lower(),
                    })

            # ── 5. Credential testing ─────────────────────────────────────
            if self.test_creds_flag and svc_def.get("creds"):
                report.cred_results = await test_creds(
                    base_url, host, report.service, svc_def, client
                )

        # ── 6. Generate findings ──────────────────────────────────────────
        report.findings = self._gen_findings(report, svc_def)
        return report

    def _dedup_finding(self, ip: str, category: str) -> bool:
        """Returns True if finding has NOT been seen for this ip+category yet."""
        key = f"{ip}:{category}"
        if key in self._dedup:
            return False
        self._dedup.add(key)
        return True

    def _gen_findings(self, report: HostReport, svc_def: dict) -> list[Finding]:
        findings: list[Finding] = []
        svc  = report.service or "Unknown"
        host = report.host
        ip   = report.ip

        # ── TLS expiry ────────────────────────────────────────────────────
        if report.tls_info and not report.tls_info.error:
            t = report.tls_info
            if t.is_expired and self._dedup_finding(ip, "TLS_EXPIRED"):
                findings.append(Finding(
                    host=host, ip=ip, severity="HIGH",
                    category="TLS Certificate Expired",
                    title=f"TLS Certificate Expired (CN={t.cn})",
                    detail=f"Cert expired {abs(t.days_remaining)} days ago on {t.expiry}. Issuer: {t.issuer}.",
                    evidence=f"echo | openssl s_client -connect {ip}:443 -servername {host} 2>/dev/null | openssl x509 -noout -dates",
                    recommendation="Renew TLS certificate immediately.",
                    service=svc, cvss_estimate="5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L)",
                ))
            elif t.is_expiring_soon and self._dedup_finding(ip, "TLS_EXPIRING"):
                findings.append(Finding(
                    host=host, ip=ip, severity="MEDIUM",
                    category="TLS Certificate Expiring Soon",
                    title=f"TLS Certificate Expires in {t.days_remaining} Days (CN={t.cn})",
                    detail=f"Certificate expires {t.expiry}. Issuer: {t.issuer}. All *.{self.domain} HTTPS services will fail.",
                    evidence=f"notAfter={t.expiry}  days_remaining={t.days_remaining}",
                    recommendation=f"Renew TLS certificate before {t.expiry}.",
                    service=svc, cvss_estimate="5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L)",
                ))
            # CN mismatch — always per-host (different host = different mismatch context)
            if t.cn_mismatch and t.cn and self._dedup_finding(ip, f"TLS_MISMATCH_{t.cn}"):
                findings.append(Finding(
                    host=host, ip=ip, severity="MEDIUM",
                    category="TLS CN Mismatch",
                    title=f"TLS Certificate CN Mismatch: Expected *.{self.domain}, Got {t.cn}",
                    detail=(
                        f"The certificate served at {host} ({ip}) has CN={t.cn} "
                        f"(Issuer: {t.issuer}). This does not match the queried hostname. "
                        f"Suggests the server is serving a default/wrong certificate, "
                        f"which may indicate misconfiguration, a different tenant's cert, "
                        f"or a dangling DNS record pointing to a foreign server."
                    ),
                    evidence=f"echo | openssl s_client -connect {ip}:443 -servername {host} 2>/dev/null | openssl x509 -noout -subject -issuer",
                    recommendation="Verify the TLS certificate matches the intended service. Check DNS records.",
                    service=svc,
                ))

        # ── Proxy IP disclosure ───────────────────────────────────────────
        if report.proxy_disclosures and self._dedup_finding(ip, "PROXY_DISCLOSURE"):
            ips_str = ", ".join(
                f"{d['backend_ip']}:{d['backend_port']}" for d in report.proxy_disclosures
            )
            findings.append(Finding(
                host=host, ip=ip, severity="MEDIUM",
                category="Internal IP Disclosure",
                title="Internal Infrastructure IPs Leaked via Reverse Proxy Error",
                detail=(
                    f"The reverse proxy returns Go net/dial error messages exposing "
                    f"internal backend IPs: {ips_str}. Unauthenticated external users "
                    f"can enumerate the production network topology."
                ),
                evidence=f"curl http://{host}/ → 'dial tcp ... -> {report.proxy_disclosures[0]['backend_ip']}:{report.proxy_disclosures[0]['backend_port']}: {report.proxy_disclosures[0]['error']}'",
                recommendation="Return generic 502/503 pages from the proxy. In nginx: proxy_intercept_errors on; error_page 502 /50x.html;",
                service=svc, cvss_estimate="5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)",
            ))

        # ── Default credentials ───────────────────────────────────────────
        for cr in report.cred_results:
            if cr.success:
                findings.append(Finding(
                    host=host, ip=ip, severity="CRITICAL",
                    category="Default Credentials",
                    title=f"Default Credentials Valid: {svc} ({cr.username}:{cr.password})",
                    detail=(
                        f"The default credentials {cr.username}:{cr.password} "
                        f"authenticated successfully against {svc} at {host}."
                    ),
                    evidence=f"POST {cr.host}/login with user={cr.username} → HTTP {cr.http_status} → {cr.notes}",
                    recommendation=f"Change default {svc} credentials immediately. Restrict to VPN/internal only.",
                    service=svc, cvss_estimate="9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
                ))

        # ── Special response conditions ───────────────────────────────────
        all_tags: set[str] = set()
        for pr in report.probe_results:
            all_tags.update(pr.get("special_tags", []))

        if "k8s_404" in all_tags and self._dedup_finding(ip, "K8S_INGRESS"):
            findings.append(Finding(
                host=host, ip=ip, severity="MEDIUM",
                category="Kubernetes Ingress Exposed",
                title=f"Kubernetes Ingress Accessible — Backend Not Found",
                detail=(
                    f"The Kubernetes ingress at {host} ({ip}) is publicly accessible "
                    f"and returns Kubernetes-specific 404 messages: 'backend NotFound, "
                    f"service rules for the path non-existent'. The ingress controller "
                    f"is reachable but no backend service is configured for this hostname."
                ),
                evidence=f"curl https://{host}/ → 'response 404 (backend NotFound), service rules for the path non-existent'",
                recommendation="Remove the DNS record or configure a default backend. Restrict Kubernetes ingress to internal network.",
                service=svc,
            ))

        if "hosting_down" in all_tags:
            findings.append(Finding(
                host=host, ip=ip, severity="HIGH",
                category="Shared Hosting Subdomain Takeover Candidate",
                title=f"Shared Hosting Server Reports 'Website Does Not Exist'",
                detail=(
                    f"{host} ({ip}) resolves to a shared hosting server that serves "
                    f"a 'website does not exist' page, indicating the DNS record points "
                    f"to a hosting account that is no longer active. An attacker may be "
                    f"able to register a new account on this hosting provider and claim "
                    f"the subdomain. The server identifies as: "
                    f"{report.open_ports[0].headers.get('server','unknown') if report.open_ports else 'unknown'}."
                ),
                evidence=f"curl http://{host}/ → 'website does not exist on this server'",
                recommendation="Remove the DNS A record for this subdomain, or create an active site on the hosting account.",
                service=svc, cvss_estimate="8.1 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N)",
            ))

        if "cf_1014" in all_tags and self._dedup_finding(ip, "CF_1014"):
            findings.append(Finding(
                host=host, ip=ip, severity="LOW",
                category="Cloudflare Origin Error",
                title=f"Cloudflare 1014 Cross-Origin Redirect Error",
                detail=(
                    f"{host} is behind Cloudflare but the origin is returning a "
                    f"cross-origin redirect that Cloudflare is blocking (error 1014). "
                    f"This indicates a misconfigured origin redirect."
                ),
                evidence=f"curl https://{host}/ → 'error code: 1014'",
                recommendation="Check origin server redirect configuration and ensure it does not redirect to a cross-origin URL.",
                service=svc,
            ))

        if ("modx_evo" in all_tags or "modx_body" in all_tags) and self._dedup_finding(ip, "MODX_ADMIN"):
            findings.append(Finding(
                host=host, ip=ip, severity="HIGH",
                category="CMS Admin Panel Exposed",
                title=f"ModX Revolution CMS Admin Panel Accessible on Port 8443",
                detail=(
                    f"{host}:8443 redirects to /evo/ — the ModX Revolution CMS "
                    f"Evolution admin panel. CMS admin panels exposed on non-standard "
                    f"ports are often overlooked in security reviews."
                ),
                evidence=f"curl -sk -D - https://{host}:8443/ | grep location  → Location: /evo/",
                recommendation="Restrict CMS admin panel access to internal network/VPN. Enable 2FA on the admin account.",
                service=svc, cvss_estimate="7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)",
            ))

        # ── Sensitive paths accessible without auth ───────────────────────
        sensitive_keywords = [
            "/script", "/api/v1/dags", "/v1/catalog", "/api/workers",
            "/_cat/indices", "/api/users", "/credentials", "/manage",
            "/v1/kv", "/api/datasources", "/v1/sys/health", "/api/system/status",
            "/api/projects/search", "/service/rest/v1/repositories",
        ]
        for pr in report.probe_results:
            if (pr.get("is_accessible")
                    and pr.get("http_status") == 200
                    and any(kw in pr["path"] for kw in sensitive_keywords)):
                findings.append(Finding(
                    host=host, ip=ip,
                    severity=svc_def.get("severity", "MEDIUM"),
                    category="Unauthenticated Endpoint Access",
                    title=f"{svc}: Sensitive Endpoint Accessible Without Auth — {pr['path']}",
                    detail=(
                        f"The endpoint {pr['path']} on {svc} at {host} returns HTTP 200 "
                        f"without requiring authentication."
                    ),
                    evidence=f"curl -sk http://{host}{pr['path']} → HTTP {pr['http_status']}",
                    recommendation=f"Enable authentication on all {svc} endpoints. Restrict to VPN/internal network.",
                    service=svc,
                ))

        # ── Version/key header disclosure ─────────────────────────────────
        sensitive_hdrs = {
            k: v for p in report.open_ports
            for k, v in p.headers.items()
            if k.lower() in ("x-jenkins", "x-instance-identity", "x-vault-request",
                              "x-powered-by", "x-grafana-version", "kbn-version")
        }
        if sensitive_hdrs and self._dedup_finding(ip, "HEADER_DISCLOSURE"):
            findings.append(Finding(
                host=host, ip=ip, severity="LOW",
                category="Version Disclosure",
                title=f"{svc} Sensitive Headers Exposed to Unauthenticated Users",
                detail=f"Headers: {sensitive_hdrs}",
                evidence="\n".join(f"{k}: {v}" for k, v in sensitive_hdrs.items()),
                recommendation="Remove sensitive headers via proxy_hide_header / Header unset in nginx/Apache.",
                port=report.open_ports[0].port if report.open_ports else None,
                service=svc,
            ))

        # ── Service publicly accessible (informational) ───────────────────
        if (report.open_ports and svc not in ("Generic HTTP",)
                and svc_def.get("severity") in ("CRITICAL","HIGH","MEDIUM")
                and self._dedup_finding(ip, f"EXPOSED_{svc}")):
            findings.append(Finding(
                host=host, ip=ip, severity="INFO",
                category="Attack Surface",
                title=f"{svc} Publicly DNS-Resolvable and Port-Accessible Without VPN",
                detail=(
                    f"{svc} at {host} ({ip}) is reachable from the public internet "
                    f"on port(s) {[p.port for p in report.open_ports]}. "
                    f"{svc_def.get('note','')}"
                ),
                evidence=f"nmap -Pn -p {','.join(str(p.port) for p in report.open_ports)} {ip}",
                recommendation=f"Bind {svc} to an internal network interface or place behind a VPN gateway.",
                service=svc,
            ))

        return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))


# ════════════════════════════════════════════════════════════════════════════
# INPUT PARSERS
# ════════════════════════════════════════════════════════════════════════════

def load_from_scan_json(path: str) -> list[tuple[str, str]]:
    with open(path) as f:
        data = json.load(f)
    hosts: list[tuple[str,str]] = []
    seen:  set[str]             = set()

    # Primary: resolved_subdomains[]
    for entry in data.get("resolved_subdomains", []):
        sub = entry.get("subdomain","")
        ips = entry.get("a_records",[])
        if sub and ips and sub not in seen:
            seen.add(sub); hosts.append((sub, ips[0]))

    # Fallback: findings[]
    for f in data.get("findings",[]):
        sub = f.get("subdomain","")
        ips = f.get("a_records",[])
        if sub and ips and sub not in seen:
            seen.add(sub); hosts.append((sub, ips[0]))

    # Harvest backend IPs from proxy disclosures across all host_reports
    extra_hosts: list[tuple[str,str]] = []
    known_ips = {ip for _,ip in hosts}
    for hr in data.get("host_reports",[]):
        for pd in hr.get("proxy_disclosures",[]):
            bip  = pd.get("backend_ip","")
            bport= pd.get("backend_port", 80)
            if bip and bip not in known_ips:
                # Use IP as hostname (we don't have a subdomain for these)
                label = f"{bip}:proxy-disclosed"
                if label not in seen:
                    seen.add(label); extra_hosts.append((bip, bip))
                    known_ips.add(bip)
        # Also harvest from probe body text
        for pr in hr.get("probe_results",[]):
            m = PROXY_ERR_RE.search(pr.get("body_snippet",""))
            if m:
                bip = m.group(1)
                if bip and bip not in known_ips:
                    label = f"{bip}:proxy-disclosed"
                    if label not in seen:
                        seen.add(label); extra_hosts.append((bip, bip))
                        known_ips.add(bip)

    log.info(f"[Parse] {len(hosts)} hosts from resolved_subdomains")
    if extra_hosts:
        log.info(f"[Parse] +{len(extra_hosts)} backend IPs harvested from proxy error disclosures")
    return hosts + extra_hosts


def load_from_hostfile(path: str, domain: str) -> list[tuple[str, str]]:
    hosts: list[tuple[str,str]] = []
    seen:  set[str]             = set()
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "," in line:
                parts = line.split(","); sub, ip = parts[0].strip(), parts[1].strip()
            else:
                parts = line.split(); sub, ip = parts[0], (parts[1] if len(parts)>1 else "")
            sub = sub.lower()
            if not ip:
                try:
                    ip = socket.gethostbyname(sub)
                except Exception:
                    ip = sub
            if sub not in seen:
                seen.add(sub); hosts.append((sub, ip))
    log.info(f"[Parse] Loaded {len(hosts)} hosts from {path}")
    return hosts


# ════════════════════════════════════════════════════════════════════════════
# REPORTING
# ════════════════════════════════════════════════════════════════════════════

def print_report(report: ReconReport) -> None:
    all_f = sorted(report.all_findings, key=lambda f: SEVERITY_ORDER.get(f.severity,9))
    by_sev = {s: [f for f in all_f if f.severity==s] for s in SEVERITY_ORDER}

    if not HAS_RICH:
        print(f"\n=== ReconHarvest v2: {report.domain} ===")
        print(f"Hosts: {report.total_hosts}  Elapsed: {report.elapsed_seconds:.1f}s")
        for f in all_f:
            print(f"\n[{f.severity}] {f.title}")
            print(f"  {f.host} ({f.ip}) — {f.detail[:150]}")
        print(); return

    console.print()
    border = "red" if by_sev.get("CRITICAL") else ("yellow" if by_sev.get("HIGH") else "blue")
    console.print(Panel.fit(
        f"[white]Domain:[/] [cyan]{report.domain}[/]\n"
        f"[white]Scan time:[/] {report.scan_time}\n"
        f"[white]Elapsed:[/] {report.elapsed_seconds:.1f}s\n"
        f"[white]Hosts analysed:[/] {report.total_hosts}"
        + (f"  [dim](+{report.extra_hosts_from_proxy} from proxy disclosures)[/]"
           if report.extra_hosts_from_proxy else "") + "\n\n"
        f"[bold red]CRITICAL:[/] {len(by_sev.get('CRITICAL',[]))}    "
        f"[bold yellow]HIGH:[/] {len(by_sev.get('HIGH',[]))}    "
        f"[yellow]MEDIUM:[/] {len(by_sev.get('MEDIUM',[]))}    "
        f"[cyan]LOW:[/] {len(by_sev.get('LOW',[]))}    "
        f"[dim]INFO:[/] {len(by_sev.get('INFO',[]))}",
        title="[bold]ReconHarvest v2[/]", border_style=border,
    ))

    # ── Host summary ──────────────────────────────────────────────────────
    console.print("\n[bold cyan]── Host Summary ──[/]")
    htbl = Table(show_header=True, header_style="bold cyan", border_style="dim")
    htbl.add_column("Host",      style="cyan", no_wrap=True)
    htbl.add_column("IP",        style="dim")
    htbl.add_column("Service")
    htbl.add_column("Ports",     style="dim")
    htbl.add_column("Findings",  justify="center")
    htbl.add_column("TLS",       justify="right")
    htbl.add_column("Catch-All", justify="center", style="dim")

    for hr in sorted(report.host_reports, key=lambda h: (
        -max((SEVERITY_ORDER.get(f.severity, 9) * -1) for f in h.findings) if h.findings else 99
    )):
        if not hr.open_ports: continue
        ports_str = ", ".join(str(p.port) for p in hr.open_ports)
        f_counts  = {}
        for f in hr.findings:
            f_counts[f.severity] = f_counts.get(f.severity, 0) + 1
        f_str = " ".join(
            f"[{SEV_COLOR.get(s,'white')}]{s[0]}:{n}[/]"
            for s, n in sorted(f_counts.items(), key=lambda x: SEVERITY_ORDER.get(x[0],9))
        ) or "[dim]none[/]"
        tls_str = ""
        if hr.tls_info and not hr.tls_info.error:
            d = hr.tls_info.days_remaining
            if d < 0:   tls_str = f"[red]EXPIRED[/]"
            elif d<=30: tls_str = f"[yellow]⚠ {d}d[/]"
            else:       tls_str = f"[dim]{d}d[/]"
            if hr.tls_info.cn_mismatch:
                tls_str += " [red]MISMATCH[/]"
        svc_str = hr.service or "—"
        if hr.service_version:
            svc_str += f" [dim]{hr.service_version}[/]"
        htbl.add_row(
            hr.host, hr.ip, svc_str, ports_str,
            f_str, tls_str,
            "[yellow]✓[/]" if hr.is_catch_all else "",
        )
    console.print(htbl)

    # ── Findings detail ───────────────────────────────────────────────────
    for sev in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
        sf = by_sev.get(sev, [])
        if not sf: continue
        col = SEV_COLOR.get(sev,"white")
        console.print(f"\n[{col}]── {SEV_EMOJI.get(sev,'')} {sev} ({len(sf)}) ──[/]")
        for i, f in enumerate(sf, 1):
            console.print(
                f"  [{col}][{i}][/] [white]{f.title}[/]\n"
                f"      [dim]Host:[/] {f.host} ({f.ip})"
                + (f"  [dim]Service:[/] {f.service}" if f.service else "") + "\n"
                f"      [dim]Detail:[/] {f.detail[:220]}{'...' if len(f.detail)>220 else ''}"
            )
            if f.evidence:
                console.print(f"      [dim]Evidence:[/] {escape(f.evidence[:160])}")
            if f.cvss_estimate:
                console.print(f"      [dim]CVSS:[/] {f.cvss_estimate}")
            if i < len(sf): console.print()

    console.print()


def save_json(report: ReconReport, path: str) -> None:
    data = {
        "domain":          report.domain,
        "scan_time":       report.scan_time,
        "source_file":     report.source_file,
        "total_hosts":     report.total_hosts,
        "elapsed_seconds": report.elapsed_seconds,
        "extra_hosts_from_proxy": report.extra_hosts_from_proxy,
        "summary": {s: len([f for f in report.all_findings if f.severity==s])
                    for s in SEVERITY_ORDER},
        "findings": [asdict(f) for f in sorted(
            report.all_findings, key=lambda f: SEVERITY_ORDER.get(f.severity,9)
        )],
        "host_reports": [{
            "host":              hr.host,
            "ip":                hr.ip,
            "service":           hr.service,
            "service_version":   hr.service_version,
            "is_catch_all":      hr.is_catch_all,
            "open_ports":        [asdict(p) for p in hr.open_ports],
            "tls_info":          asdict(hr.tls_info) if hr.tls_info else None,
            "probe_results":     hr.probe_results,
            "cred_results":      [asdict(c) for c in hr.cred_results],
            "proxy_disclosures": hr.proxy_disclosures,
            "findings":          [asdict(f) for f in hr.findings],
        } for hr in report.host_reports],
    }
    with open(path,"w") as fh: json.dump(data, fh, indent=2)
    log.info(f"JSON report saved → {path}")


def save_html(report: ReconReport, path: str) -> None:
    all_f   = sorted(report.all_findings, key=lambda f: SEVERITY_ORDER.get(f.severity,9))
    by_sev  = {s: [f for f in all_f if f.severity==s] for s in SEVERITY_ORDER}
    sc = {"CRITICAL":"#f85149","HIGH":"#d29922","MEDIUM":"#e3b341","LOW":"#58a6ff","INFO":"#8b949e"}
    sb = {"CRITICAL":"rgba(248,81,73,.12)","HIGH":"rgba(210,153,34,.12)",
          "MEDIUM":"rgba(227,179,65,.10)","LOW":"rgba(88,166,255,.10)","INFO":"rgba(139,148,158,.08)"}

    findings_html = ""
    for sev in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
        sf = by_sev.get(sev,[])
        if not sf: continue
        findings_html += f'<div class="sev-section"><h3 style="color:{sc[sev]}">{SEV_EMOJI.get(sev,"")} {sev} ({len(sf)})</h3>'
        for i,f in enumerate(sf,1):
            findings_html += (
                f'<div class="finding" style="border-left:3px solid {sc[sev]};background:{sb[sev]}">'
                f'<div class="ft">[{i}] {f.title}</div>'
                f'<div class="fm"><span class="badge" style="background:{sb[sev]};color:{sc[sev]};border:1px solid {sc[sev]}">{f.severity}</span>'
                f'<span class="fhost">{f.host} ({f.ip})</span>'
                + (f'<span class="fsvc">{f.service}</span>' if f.service else "")
                + (f'<span class="fcvss">{f.cvss_estimate}</span>' if f.cvss_estimate else "")
                + f'</div><div class="fd">{f.detail}</div>'
                + (f'<div class="ev"><span class="evl">Evidence:</span><code>{f.evidence[:300]}</code></div>' if f.evidence else "")
                + f'<div class="rec"><span class="recl">Rec:</span> {f.recommendation}</div></div>'
            )
        findings_html += "</div>"

    host_rows = ""
    for hr in sorted(report.host_reports,
                     key=lambda h: min((SEVERITY_ORDER.get(f.severity,9) for f in h.findings), default=99)):
        if not hr.open_ports: continue
        fc = {}
        for f in hr.findings: fc[f.severity] = fc.get(f.severity,0)+1
        fb = " ".join(
            f'<span style="color:{sc.get(s,"#fff")};background:{sb.get(s,"")};border:1px solid {sc.get(s,"#444")};'
            f'padding:1px 6px;border-radius:10px;font-size:.72em">{s[0]}:{n}</span>'
            for s,n in sorted(fc.items(), key=lambda x: SEVERITY_ORDER.get(x[0],9))
        ) or '<span style="color:#3fb950">clean</span>'
        tls_badge = ""
        if hr.tls_info and not hr.tls_info.error:
            d = hr.tls_info.days_remaining
            col = "#f85149" if d<0 else ("#d29922" if d<=30 else "#8b949e")
            lbl = "EXPIRED" if d<0 else f"⚠ {d}d" if d<=30 else f"{d}d"
            tls_badge = f'<span style="color:{col}">{lbl}</span>'
            if hr.tls_info.cn_mismatch:
                tls_badge += ' <span style="color:#f85149;font-size:.8em">MISMATCH</span>'
        catch_all = "✓" if hr.is_catch_all else ""
        host_rows += (
            f"<tr><td style='color:#58a6ff'>{hr.host}</td>"
            f"<td style='color:#8b949e'>{hr.ip}</td>"
            f"<td>{hr.service or '—'}{f' <small style=color:#8b949e>{hr.service_version}</small>' if hr.service_version else ''}</td>"
            f"<td style='color:#8b949e'>{', '.join(str(p.port) for p in hr.open_ports)}</td>"
            f"<td>{fb}</td><td>{tls_badge}</td>"
            f"<td style='color:#627384'>{catch_all}</td></tr>"
        )

    proxy_rows = "".join(
        f"<tr><td style='color:#58a6ff'>{hr.host}</td>"
        f"<td style='color:#f85149'>{pd['backend_ip']}</td>"
        f"<td>{pd['backend_port']}</td>"
        f"<td style='color:#8b949e'>{pd['error']}</td></tr>"
        for hr in report.host_reports for pd in hr.proxy_disclosures
    )

    html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ReconHarvest v2 — {report.domain}</title>
<style>
:root{{--bg:#080c10;--sf:#0d1117;--sf2:#111820;--bd:#1e2d3d;--tx:#cdd6e0;--mt:#627384;
  --rd:#f85149;--yw:#d29922;--gn:#3fb950;--bl:#58a6ff;--cy:#39c5cf;}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--tx);font-family:'Consolas','Monaco',monospace;font-size:13px;line-height:1.7}}
body::before{{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(0,212,255,.012) 1px,transparent 1px),linear-gradient(90deg,rgba(0,212,255,.012) 1px,transparent 1px);background-size:40px 40px;pointer-events:none}}
.wrap{{max-width:1400px;margin:0 auto;padding:32px 28px 80px;position:relative}}
h1{{font-family:system-ui,sans-serif;font-size:2em;font-weight:800;color:#fff;letter-spacing:-.03em;margin-bottom:6px}}
.sub{{color:var(--mt);font-size:.8em;margin-bottom:32px}}
.stats{{display:grid;grid-template-columns:repeat(auto-fill,minmax(110px,1fr));gap:10px;margin-bottom:28px}}
.stat{{background:var(--sf);border:1px solid var(--bd);border-radius:8px;padding:14px;text-align:center}}
.sv{{font-size:1.8em;font-weight:bold}}.sl{{color:var(--mt);font-size:.72em;margin-top:3px}}
.card{{background:var(--sf);border:1px solid var(--bd);border-radius:8px;padding:20px;margin-bottom:20px}}
h2{{font-family:system-ui,sans-serif;font-size:1.1em;font-weight:700;color:#fff;margin-bottom:14px}}
h3{{font-family:system-ui,sans-serif;font-size:.95em;font-weight:700;margin:16px 0 10px}}
table{{width:100%;border-collapse:collapse}}
th{{background:var(--sf2);color:var(--mt);text-align:left;padding:8px 12px;border:1px solid var(--bd);font-size:.72em;text-transform:uppercase;letter-spacing:.07em}}
td{{padding:8px 12px;border-bottom:1px solid var(--bd);vertical-align:top}}
tr:hover td{{background:rgba(88,166,255,.03)}}
.finding{{padding:14px 16px;border-radius:6px;margin-bottom:10px}}
.ft{{font-family:system-ui,sans-serif;font-weight:700;font-size:.9em;color:#fff;margin-bottom:8px}}
.fm{{display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap}}
.badge{{padding:2px 8px;border-radius:10px;font-size:.7em;font-weight:700;letter-spacing:.05em}}
.fhost{{color:var(--cy);font-size:.8em}}.fsvc{{color:var(--mt);font-size:.78em}}.fcvss{{color:var(--yw);font-size:.78em}}
.fd{{color:var(--mt);font-size:.83em;margin-bottom:8px;line-height:1.6}}
.ev{{background:rgba(0,0,0,.4);border:1px solid var(--bd);border-radius:4px;padding:8px 10px;margin-bottom:8px}}
.evl{{color:var(--cy);font-size:.7em;font-weight:700;margin-right:6px}}
.ev code{{color:#a8dadc;font-size:.82em;word-break:break-all}}
.rec{{color:var(--gn);font-size:.8em}}.recl{{font-weight:700;margin-right:4px}}
.sev-section{{margin-bottom:20px}}
.footer{{text-align:center;color:var(--mt);font-size:.72em;margin-top:32px;padding-top:16px;border-top:1px solid var(--bd)}}
</style></head>
<body><div class="wrap">
<h1>ReconHarvest v2</h1>
<p class="sub">{report.domain} &nbsp;·&nbsp; {report.scan_time} &nbsp;·&nbsp; {report.elapsed_seconds:.1f}s &nbsp;·&nbsp; {report.total_hosts} hosts analysed</p>
<div class="stats">
  <div class="stat"><div class="sv" style="color:#f85149">{len(by_sev.get('CRITICAL',[]))}</div><div class="sl">CRITICAL</div></div>
  <div class="stat"><div class="sv" style="color:#d29922">{len(by_sev.get('HIGH',[]))}</div><div class="sl">HIGH</div></div>
  <div class="stat"><div class="sv" style="color:#e3b341">{len(by_sev.get('MEDIUM',[]))}</div><div class="sl">MEDIUM</div></div>
  <div class="stat"><div class="sv" style="color:#58a6ff">{len(by_sev.get('LOW',[]))}</div><div class="sl">LOW</div></div>
  <div class="stat"><div class="sv" style="color:#8b949e">{len(by_sev.get('INFO',[]))}</div><div class="sl">INFO</div></div>
  <div class="stat"><div class="sv">{report.total_hosts}</div><div class="sl">HOSTS</div></div>
</div>
<div class="card"><h2>🖥 Host Summary</h2>
<table><thead><tr><th>Host</th><th>IP</th><th>Service</th><th>Open Ports</th><th>Findings</th><th>TLS</th><th>Catch-All</th></tr></thead>
<tbody>{host_rows}</tbody></table></div>
{f'<div class="card"><h2>🔍 Internal IP Disclosures</h2><table><thead><tr><th>Subdomain</th><th>Backend IP</th><th>Port</th><th>Error</th></tr></thead><tbody>{proxy_rows}</tbody></table></div>' if proxy_rows else ''}
<div class="card"><h2>🔎 Findings Detail</h2>{findings_html}</div>
<div class="footer">ReconHarvest v2 &nbsp;·&nbsp; For authorized security testing only</div>
</div></body></html>"""

    with open(path,"w",encoding="utf-8") as fh: fh.write(html)
    log.info(f"HTML report saved → {path}")


# ════════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════════

async def run(args: argparse.Namespace) -> ReconReport:
    report = ReconReport(
        domain=args.domain,
        scan_time=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    )
    if args.scan:
        hosts = load_from_scan_json(args.scan)
        report.source_file = args.scan
    elif args.hosts:
        hosts = load_from_hostfile(args.hosts, args.domain)
        report.source_file = args.hosts
    else:
        log.error("Provide --scan or --hosts"); sys.exit(1)

    if not HAS_HTTPX:
        log.error("httpx required: pip install httpx"); sys.exit(1)

    # Count extra proxy-harvested hosts
    base_count = sum(1 for h,_ in hosts if "proxy-disclosed" not in h)
    report.extra_hosts_from_proxy = len(hosts) - base_count
    report.total_hosts = len(hosts)

    log.info(
        f"[ReconHarvest v2] {len(hosts)} hosts  "
        f"({report.extra_hosts_from_proxy} from proxy disclosures)"
    )
    if not HAS_CRYPTO:
        log.warning("pip install cryptography for full TLS cert details")

    prober = HostProber(
        domain=args.domain,
        timeout=args.timeout,
        tcp_timeout=2.0,
        test_creds=not args.no_creds,
        port_concurrency=args.concurrency,
        tcp_concurrency=min(args.concurrency * 3, 150),
    )

    t0 = time.perf_counter()

    # Process ALL hosts concurrently (no sequential batching)
    if HAS_RICH:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]Probing[/]"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("[dim]{task.fields[h]}[/]"),
            console=console,
        ) as prog:
            task = prog.add_task("probe", total=len(hosts), h="")
            sem  = asyncio.Semaphore(args.concurrency)

            async def bounded(host: str, ip: str) -> HostReport:
                async with sem:
                    prog.update(task, h=host)
                    r = await prober.analyse_host(host, ip)
                    prog.advance(task)
                    return r

            results = await asyncio.gather(
                *[bounded(h, ip) for h, ip in hosts],
                return_exceptions=True,
            )
    else:
        sem = asyncio.Semaphore(args.concurrency)
        async def bounded(host: str, ip: str) -> HostReport:
            async with sem:
                return await prober.analyse_host(host, ip)
        results = await asyncio.gather(
            *[bounded(h, ip) for h, ip in hosts],
            return_exceptions=True,
        )

    for r in results:
        if isinstance(r, HostReport):
            report.host_reports.append(r)
            report.all_findings.extend(r.findings)
        elif isinstance(r, Exception):
            log.warning(f"Host error: {r}")

    report.elapsed_seconds = round(time.perf_counter() - t0, 2)
    return report


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="ReconHarvest v2 — Post-SubTakeover Recon",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 reconharvest.py --scan scan.json --domain eskimi.com --output report
  python3 reconharvest.py --hosts targets.txt --domain eskimi.com --output report
  python3 reconharvest.py --scan scan.json --domain eskimi.com --no-creds -o report
""")
    p.add_argument("--scan",    metavar="FILE", help="subtakeover.py scan.json")
    p.add_argument("--hosts",   metavar="FILE", help="Plain host list (host or host,IP)")
    p.add_argument("--domain",  required=True,  help="Target root domain")
    p.add_argument("-o","--output", metavar="BASE", help="Output base: BASE.json + BASE.html")
    p.add_argument("--timeout", type=float, default=8.0,  help="HTTP timeout (default: 8s)")
    p.add_argument("--concurrency", type=int, default=30, help="Max concurrent host probes (default: 30)")
    p.add_argument("--no-creds", action="store_true",     help="Skip default credential testing")
    p.add_argument("-v","--verbose", action="store_true", help="Verbose logging")
    p.add_argument("--user-agent", metavar="UA",
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
║       ReconHarvest v2 — Post-SubTakeover Recon Automation        ║
║  For authorized penetration testing and bug bounty research only ║
╚══════════════════════════════════════════════════════════════════╝
""")
    report = await run(args)
    print_report(report)
    if args.output:
        out_base = args.output
        if out_base.endswith(".json"):
            out_base = out_base[:-5]
        if out_base.endswith(".html"):
            out_base = out_base[:-5]
        save_json(report, out_base + ".json")
        save_html(report, out_base + ".html")


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted."); sys.exit(0)
