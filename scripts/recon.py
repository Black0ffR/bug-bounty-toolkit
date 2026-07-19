#!/usr/bin/env python3
"""recon.py — attack-surface discovery for a target.

Combines passive (crt.sh, Wayback CDX) and active (crawl, JS, header posture)
recon. Supports --stealth for low-and-slow pacing without a full vuln scan.

Usage:
  python scripts/recon.py --url https://example.com --out recon.json
  python scripts/recon.py --url https://example.com --stealth --rate 1.0
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys

sys.path.insert(0, ".")

from toolkit.infra.stealth import StealthClient, StealthPolicy
from toolkit.recon import run as recon_run

log = logging.getLogger("recon")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Bug-bounty recon: attack-surface discovery")
    p.add_argument("--url", required=True, help="Target base URL")
    p.add_argument("--out", "-o", default="recon.json")
    p.add_argument("--depth", type=int, default=1)
    p.add_argument("--wayback-limit", type=int, default=5000)
    p.add_argument("--timeout", type=float, default=12.0)
    p.add_argument("--concurrency", type=int, default=5)
    # stealth
    p.add_argument("--stealth", action="store_true")
    p.add_argument("--rate", type=float, default=1.0)
    p.add_argument("--jitter", type=float, default=0.5)
    p.add_argument("--respect-robots", dest="respect_robots",
                   action="store_true", default=True)
    p.add_argument("--no-respect-robots", dest="respect_robots",
                   action="store_false")
    p.add_argument("--random-agent", dest="random_agent",
                   action="store_true", default=True)
    p.add_argument("--no-random-agent", dest="random_agent",
                   action="store_false")
    p.add_argument("--proxy", default=None)
    p.add_argument("--proxy-list", default=None)
    return p.parse_args()


def _build_policy(args: argparse.Namespace) -> StealthPolicy:
    if args.stealth:
        proxy_list = [x.strip() for x in (args.proxy_list or "").split(",") if x.strip()]
        return StealthPolicy(enabled=True, rate=args.rate, jitter=args.jitter,
                             respect_robots=args.respect_robots,
                             random_agent=args.random_agent,
                             proxy=args.proxy, proxy_list=proxy_list)
    return StealthPolicy(enabled=False, rate=1e9, jitter=0.0,
                         respect_robots=False, random_agent=False)


async def _run(args: argparse.Namespace) -> dict:
    from httpx import Limits
    limits = Limits(max_connections=args.concurrency)
    policy = _build_policy(args)
    async with StealthClient(policy, timeout=args.timeout, limits=limits) as client:
        if args.stealth:
            log.info("STEALTH recon: rate=%.2f jitter=%.2f robots=%s",
                     args.rate, args.jitter, args.respect_robots)
        return await recon_run.run_recon(
            args.url, client, depth=args.depth,
            wayback_limit=args.wayback_limit, timeout=args.timeout)


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(name)s: %(message)s")
    args = parse_args()
    result = asyncio.run(_run(args))
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    tech = result.get("tech") or {}
    log.info("recon complete: subdomains=%d wayback=%d js_endpoints=%d "
             "js_secrets=%d posture=%d tech=%s",
             len(result.get("subdomains", [])),
             len(result.get("wayback_urls", [])),
             len(result.get("js_endpoints", [])),
             len(result.get("js_secrets", [])),
             len(result.get("posture", [])),
             tech or "{}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
