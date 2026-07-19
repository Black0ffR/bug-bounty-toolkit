#!/usr/bin/env python3
"""
scan.py — autonomous end-to-end scan entrypoint (P2)
===================================================

Ties the pipeline together so a single command actually finds vulnerabilities
on a live target without hand-fed seed lists:

    python scripts/scan.py --url https://target.example.com

Steps:
   1. Crawl the target (toolkit/infra/spider.py) to discover endpoints + params.
   2. Run injection-class detectors on every param:
        - SQLi        (toolkit/testers/sqli.py)
        - Command     (toolkit/testers/cmdi.py)
        - LFI/Traversal (toolkit/testers/lfi.py)
        - SSTI        (toolkit/testers/ssti.py)
        - OpenRedirect (toolkit/testers/openredirect.py)
        - CORS        (toolkit/testers/cors.py)
        - CSRF        (toolkit/testers/csrf.py, heuristic)
        - IDOR        (toolkit/testers/idor.py, heuristic)
        - XXE         (toolkit/testers/xxe.py)
        - AccessCtrl  (toolkit/testers/access_control.py, heuristic)
        - SSRF        (toolkit/testers/ssrf.py)
        - NoSQLi      (toolkit/testers/nosqli.py)
        - GraphQL     (toolkit/testers/graphql.py)
        - Deserialization (toolkit/testers/deserialization.py, heuristic)
   3. Run context-aware XSS verification (toolkit/verify/xss_context.py) on
      query-injected params.
   4. Aggregate normalized findings and emit JSON + (optional) reports.

Authorized penetration testing / bug bounty research only.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

# Make the repo root importable when run as a standalone script.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from toolkit.infra import spider, scope_guard, logfmt, finding as _finding
    from toolkit.testers import (sqli, cmdi, lfi, ssti, openredirect, cors, csrf,
                                idor, xxe, access_control, ssrf, nosqli,
                                graphql, deserialization)
    from toolkit.verify import xss_context
    _HAVE_TOOLKIT = True
    _HAVE_FINDING = True
except Exception as exc:  # pragma: no cover
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    logging.error("toolkit import failed: %s", exc)
    raise

log = logging.getLogger("scan")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="scan.py",
                                 description="Autonomous crawl + vuln scan")
    p.add_argument("--url", "-u", required=True, help="Start URL")
    p.add_argument("--depth", type=int, default=2, help="Crawl depth (default 2)")
    p.add_argument("--max-urls", type=int, default=200, help="Max URLs to crawl")
    p.add_argument("--concurrency", type=int, default=10)
    p.add_argument("--timeout", type=float, default=12.0)
    p.add_argument("--no-xss", action="store_true", help="Skip XSS verification")
    # Stealth mode
    p.add_argument("--stealth", action="store_true",
                   help="Enable low-and-slow stealth pacing (rate/jitter/UA rotation/robots)")
    p.add_argument("--rate", type=float, default=1.0,
                   help="Max requests/sec in stealth mode (default 1.0)")
    p.add_argument("--jitter", type=float, default=0.5,
                   help="Random delay multiplier 0..1 in stealth mode (default 0.5)")
    p.add_argument("--respect-robots", dest="respect_robots", action="store_true",
                   default=True)
    p.add_argument("--no-respect-robots", dest="respect_robots", action="store_false")
    p.add_argument("--random-agent", dest="random_agent", action="store_true", default=True)
    p.add_argument("--no-random-agent", dest="random_agent", action="store_false")
    p.add_argument("--proxy", default=None, help="Single upstream proxy URL")
    p.add_argument("--proxy-list", default=None,
                   help="Comma-separated proxy URLs for rotation")
    p.add_argument("--output", "-o", default="scan-findings.json")
    p.add_argument("--recon", default=None,
                   help="Load a recon.json and feed its seeds into the scan")
    p.add_argument("--chain-recon", action="store_true",
                   help="Run recon first, then scan the discovered surface")
    p.add_argument("--recon-only", action="store_true",
                   help="Skip the heavy detectors; emit only recon-derived "
                        "findings (JS secrets, missing headers) for a fast demo")
    p.add_argument("--report", choices=("sarif", "csv", "hackerone", "bugcrowd"),
                   help="Also render a report in this format")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--log-format", choices=("text", "json"), default="text")
    return p.parse_args()


def _build_policy(args: argparse.Namespace):
    from toolkit.infra.stealth import StealthPolicy
    if args.stealth:
        proxy_list = [p.strip() for p in (args.proxy_list or "").split(",") if p.strip()]
        return StealthPolicy(enabled=True, rate=args.rate, jitter=args.jitter,
                             respect_robots=args.respect_robots,
                             random_agent=args.random_agent,
                             proxy=args.proxy, proxy_list=proxy_list)
    # Non-stealth: no pacing, no robots gating, no UA spoofing.
    return StealthPolicy(enabled=False, rate=1e9, jitter=0.0,
                         respect_robots=False, random_agent=False)


# Secrets found in JS are HIGH when they grant access (keys/tokens/private
# keys) and MEDIUM for lower-impact identifiers.
_SECRET_SEVERITY = {
    "aws_access_key_id": "HIGH",
    "private_key": "HIGH",
    "jwt": "HIGH",
    "github_token": "HIGH",
    "slack_token": "MEDIUM",
    "google_api_key": "MEDIUM",
}


def _secret_findings(secrets: list[dict], target_url: str) -> list[dict]:
    """Convert recon js_secrets ([{type, value}]) into normalized findings."""
    out: list[dict] = []
    host = urlparse(target_url).netloc
    for s in secrets or []:
        stype = s.get("type", "unknown")
        value = s.get("value", "")
        if not value:
            continue
        severity = _SECRET_SEVERITY.get(stype, "MEDIUM")
        title = f"Exposed secret in JavaScript ({stype})"
        detail = (f"A candidate {stype} was extracted from bundled JavaScript "
                  f"on {target_url}. Treat as leaked until proven otherwise.")
        if _HAVE_FINDING:
            nf = _finding.NormalizedFinding(
                source_tool="recon.js", host=host, url=target_url,
                vuln_class_key="EXPOSED_SECRET", severity=severity,
                title=title, detail=detail, evidence=f"{stype}={value}",
                confidence="candidate", cwe="CWE-798",
                owasp="A05:2021",
            )
            d = nf.to_dict()
            d["secret_type"] = stype
        else:
            d = {"source_tool": "recon.js", "host": host, "url": target_url,
                 "vuln_class_key": "EXPOSED_SECRET", "severity": severity,
                 "title": title, "detail": detail, "evidence": f"{stype}={value}",
                 "confidence": "candidate", "secret_type": stype}
        out.append(d)
    return out


_POSTURE_SEVERITY = {
    "missing_hsts": "MEDIUM",
    "missing_csp": "LOW",
    "clickjacking": "LOW",
    "mime_sniffing": "LOW",
    "referrer_leak": "LOW",
}


def _posture_findings(posture: list[dict], target_url: str) -> list[dict]:
    """Convert recon missing-header findings into normalized findings."""
    out: list[dict] = []
    host = urlparse(target_url).netloc
    for p in posture or []:
        issue = p.get("issue", "")
        header = p.get("missing_header", "")
        severity = _POSTURE_SEVERITY.get(issue, "LOW")
        title = f"Missing security header: {header}"
        detail = f"Response is missing the {header} header ({issue})."
        if _HAVE_FINDING:
            nf = _finding.NormalizedFinding(
                source_tool="recon.posture", host=host, url=target_url,
                vuln_class_key="MISSING_SECURITY_HEADER", severity=severity,
                title=title, detail=detail, evidence=header,
                confidence="candidate", cwe="CWE-693", owasp="A05:2021",
            )
            d = nf.to_dict()
            d["issue"] = issue
        else:
            d = {"source_tool": "recon.posture", "host": host, "url": target_url,
                 "vuln_class_key": "MISSING_SECURITY_HEADER", "severity": severity,
                 "title": title, "detail": detail, "evidence": header,
                 "confidence": "candidate", "issue": issue}
        out.append(d)
    return out


def _recon_only_findings(recon: dict, target_url: str) -> list[dict]:
    """Findings derived purely from recon output (no heavy detectors)."""
    findings = _secret_findings(recon.get("js_secrets", []), target_url)
    findings += _posture_findings(recon.get("posture", []), target_url)
    return findings


async def _get_recon(args: argparse.Namespace, client, target_netloc: str) -> dict:
    """Load a recon.json (--recon) or run recon (--chain-recon / --recon-only)."""
    from toolkit.recon import run as recon_run
    if args.recon:
        with open(args.recon, "r", encoding="utf-8") as f:
            return json.load(f)
    log.info("running recon before scan")
    return await recon_run.run_recon(
        args.url, client, depth=args.depth, timeout=args.timeout)


async def _load_recon_seeds(args: argparse.Namespace, client, target_netloc: str):
    """Return (same_origin_urls, subdomain_hosts, js_secrets) from
    --recon / --chain-recon."""
    from toolkit.recon import run as recon_run
    recon = await _get_recon(args, client, target_netloc)
    if not recon:
        return [], [], []
    seeds = recon_run.recon_to_seeds(recon, target_netloc)
    return seeds["same_origin"], seeds["subdomain_hosts"], recon.get("js_secrets", [])


async def _scan(args: argparse.Namespace) -> dict[str, Any]:
    limits = httpx.Limits(max_connections=args.concurrency)
    from toolkit.infra.stealth import StealthClient
    policy = _build_policy(args)
    async with StealthClient(policy, timeout=args.timeout, limits=limits) as client:
        if args.stealth:
            log.info("STEALTH mode: rate=%.2f rps jitter=%.2f robots=%s ua=%s",
                     args.rate, args.jitter, args.respect_robots, args.random_agent)

        target_netloc = urlparse(args.url).netloc

        # --recon-only: skip the heavy detectors, emit recon-derived findings.
        if args.recon_only:
            recon = await _get_recon(args, client, target_netloc)
            findings = _recon_only_findings(recon, args.url)
            log.info("recon-only: %d findings (secrets=%d posture=%d)",
                     len(findings),
                     len(recon.get("js_secrets", []) or []),
                     len(recon.get("posture", []) or []))
            return {
                "target": args.url,
                "mode": "recon-only",
                "endpoints_discovered": len(recon.get("js_endpoints", []) or [])
                                     + len(recon.get("wayback_urls", []) or []),
                "subdomains": recon.get("subdomains", []) or [],
                "total_findings": len(findings),
                "findings": findings,
            }

        same_origin_seeds, subdomain_hosts, js_secrets = await _load_recon_seeds(
            args, client, target_netloc)

        log.info("crawling %s (depth=%d)", args.url, args.depth)
        endpoints = await spider.crawl(
            args.url, client, max_depth=args.depth, max_urls=args.max_urls,
            concurrency=args.concurrency, timeout=args.timeout,
            seeds=same_origin_seeds,
        )
        # Each live subdomain host gets its own bounded crawl.
        for host in subdomain_hosts:
            for scheme in ("https", "http"):
                try:
                    sub_url = f"{scheme}://{host}"
                    sub_eps = await spider.crawl(
                        sub_url, client, max_depth=1, max_urls=args.max_urls,
                        concurrency=args.concurrency, timeout=args.timeout,
                    )
                    endpoints.extend(sub_eps)
                    if sub_eps:
                        break
                except Exception as exc:  # pragma: no cover
                    log.debug("subdomain crawl %s failed: %s", host, exc)

        # de-dup merged endpoints by (url, method)
        merged: dict[tuple[str, str], Any] = {}
        for ep in endpoints:
            key = (ep.url, ep.method)
            if key in merged:
                existing = merged[key]
                merged_params = sorted(set(existing.params) | set(ep.params))
                merged[key] = spider.Endpoint(url=existing.url, method=existing.method,
                                              params=merged_params,
                                              inject_via=existing.inject_via,
                                              source=existing.source)
            else:
                merged[key] = ep
        endpoints = list(merged.values())
        log.info("discovered %d endpoints (%d from recon seeds)",
                 len(endpoints), len(same_origin_seeds))

        # Recon-discovered JS secrets become standalone findings.
        if js_secrets:
            secret_findings = _secret_findings(js_secrets, args.url)
            log.info("JS-secret findings: %d", len(secret_findings))
            findings.extend(secret_findings)
        params_total = sum(len(e.params) for e in endpoints)
        log.info("with %d injectable parameters", params_total)

        findings: list[dict[str, Any]] = []

        # P0 — SQLi
        sqli_res = await sqli.run_sqli(endpoints, client,
                                        timeout=args.timeout,
                                        concurrency=args.concurrency)
        log.info("SQLi findings: %d", len(sqli_res))
        findings.extend(sqli.to_normalized_findings(sqli_res))

        # P1 — injection-class detectors
        for mod, runner in (
            (cmdi, cmdi.run_cmdi),
            (lfi, lfi.run_lfi),
            (ssti, ssti.run_ssti),
            (openredirect, openredirect.run_openredirect),
            (cors, cors.run_cors),
            (idor, idor.run_idor),
            (xxe, xxe.run_xxe),
            (access_control, access_control.run_access_control),
            (ssrf, ssrf.run_ssrf),
            (nosqli, nosqli.run_nosqli),
            (graphql, graphql.run_graphql),
            (deserialization, deserialization.run_deserialization),
        ):
            try:
                res = await runner(endpoints, client, timeout=args.timeout,
                                   concurrency=args.concurrency)
                log.info("%s findings: %d", mod.__name__, len(res))
                findings.extend(mod.to_normalized_findings(res))
            except Exception as exc:  # pragma: no cover
                log.warning("%s failed: %s", mod.__name__, exc)

        # P1 — CSRF heuristic (POST endpoints, no I/O needed)
        csrf_res = await csrf.run_csrf(endpoints, client,
                                       concurrency=args.concurrency)
        log.info("CSRF (possible-missing) candidates: %d", len(csrf_res))
        findings.extend(csrf.to_normalized_findings(csrf_res))

        # XSS (query-injected params only)
        if not args.no_xss:
            points = [{
                "url": e.url, "method": e.method, "param_name": prm,
                "inject_via": e.inject_via,
            } for e in endpoints for prm in e.params if e.inject_via == "query"]
            log.info("XSS injection points: %d", len(points))
            if points:
                guard = scope_guard.get_default()
                xss_res = await xss_context.verify_all(points, guard,
                                                       concurrency=args.concurrency)
                confirmed = sum(1 for x in xss_res if x.breakout_succeeded)
                log.info("XSS findings: %d (confirmed breakout: %d)",
                         len(xss_res), confirmed)
                findings.extend(xss_context.to_normalized_findings(xss_res))

    return {
        "target": args.url,
        "endpoints_discovered": len(endpoints),
        "total_findings": len(findings),
        "findings": findings,
    }


def main() -> int:
    args = parse_args()
    if _HAVE_TOOLKIT:
        logfmt.configure_logging(fmt=args.log_format,
                                 level=logging.DEBUG if args.verbose else logging.INFO)
    elif args.verbose:
        log.setLevel(logging.DEBUG)

    result = asyncio.run(_scan(args))

    out_path = Path(args.output)
    out_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    log.info("wrote %s", out_path)

    if args.report:
        try:
            from toolkit.infra import reporter
            rendered = reporter.render(result["findings"], args.report)
            report_path = out_path.with_suffix(
                ".sarif" if args.report == "sarif" else ".csv"
                if args.report == "csv" else ".md")
            text = json.dumps(rendered, indent=2) if args.report == "sarif" else rendered
            report_path.write_text(text, encoding="utf-8")
            log.info("wrote report %s", report_path)
        except Exception as exc:  # pragma: no cover
            log.warning("report render failed: %s", exc)

    crit = sum(1 for f in result["findings"] if f.get("severity") == "CRITICAL")
    high = sum(1 for f in result["findings"] if f.get("severity") == "HIGH")
    if crit or high:
        log.warning("[!] %d CRITICAL + %d HIGH findings", crit, high)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
