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

import httpx

# Make the repo root importable when run as a standalone script.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from toolkit.infra import spider, scope_guard, logfmt
    from toolkit.testers import (sqli, cmdi, lfi, ssti, openredirect, cors, csrf,
                                idor, xxe, access_control, ssrf, nosqli,
                                graphql, deserialization)
    from toolkit.verify import xss_context
    _HAVE_TOOLKIT = True
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


async def _scan(args: argparse.Namespace) -> dict[str, Any]:
    limits = httpx.Limits(max_connections=args.concurrency)
    from toolkit.infra.stealth import StealthClient
    policy = _build_policy(args)
    async with StealthClient(policy, timeout=args.timeout, limits=limits) as client:
        if args.stealth:
            log.info("STEALTH mode: rate=%.2f rps jitter=%.2f robots=%s ua=%s",
                     args.rate, args.jitter, args.respect_robots, args.random_agent)
        log.info("crawling %s (depth=%d)", args.url, args.depth)
        endpoints = await spider.crawl(
            args.url, client, max_depth=args.depth, max_urls=args.max_urls,
            concurrency=args.concurrency, timeout=args.timeout,
        )
        log.info("discovered %d endpoints", len(endpoints))
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
