#!/usr/bin/env python3
"""
stealth.py — low-and-slow stealth client (P3)
=============================================
Wraps an httpx client so the whole pipeline (crawler + every detector) stays
under the radar of WAFs / rate-limiters / IDS while still mapping the full
attack surface.

Techniques (informed by WAF-evasion research: jitter, session/UA rotation,
low-and-slow pacing, robots.txt respect):
  * Token-bucket rate limiting (``--rate`` requests/sec).
  * Per-request jitter on the delay (``--jitter`` 0..1).
  * "Think time" pauses between requests to mimic human browsing.
  * Rotating, realistic User-Agents (rotation window).
  * Rotating benign Accept / Accept-Language headers.
  * Optional proxy rotation (``--proxy`` or a proxy list) every N requests.
  * robots.txt respect: disallowed paths are skipped (not requested).

Pure pieces (``StealthPolicy``, ``RobotsCache.parse``) are unit-testable;
only ``StealthClient.request`` performs I/O.
"""
from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

import httpx


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
]

ACCEPTS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "application/json,text/html;q=0.9,*/*;q=0.8",
]
ACCEPT_LANGS = ["en-US,en;q=0.9", "en-GB,en;q=0.9", "en;q=0.9", "fr-FR,fr;q=0.8,en;q=0.6"]


@dataclass
class StealthPolicy:
    enabled: bool = True
    rate: float = 1.0                 # max requests per second (token bucket)
    jitter: float = 0.5               # 0..1 random delay multiplier
    think_min: float = 0.0            # min pause between requests (s)
    think_max: float = 0.0            # max pause between requests (s)
    random_agent: bool = True
    random_headers: bool = True
    respect_robots: bool = True
    rotate_agent_every: int = 10      # rotate UA every N requests
    proxy: Optional[str] = None       # single proxy URL
    proxy_list: list = field(default_factory=list)
    rotate_proxy_every: int = 10
    max_concurrency: int = 3


class RobotsCache:
    """Tiny robots.txt parser + per-host cache. ``fetch`` must be supplied by
    the caller (the StealthClient passes its own GET)."""

    def __init__(self) -> None:
        self._rules: dict[str, list[str]] = {}

    @staticmethod
    def parse(text: str) -> list[str]:
        disallowed: list[str] = []
        active = True  # track the * (default) agent group
        for raw in (text or "").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                continue
            key, _, val = line.partition(":")
            key = key.strip().lower()
            val = val.strip()
            if key == "user-agent":
                active = (val == "*")
            elif key == "disallow" and active and val:
                disallowed.append(val)
        return disallowed

    def learn(self, host: str, text: str) -> None:
        self._rules[host] = self.parse(text)

    def allowed(self, url: str) -> bool:
        p = urlparse(url)
        host = p.netloc
        for rule in self._rules.get(host, []):
            if rule == "/":
                return False
            path = p.path or "/"
            if rule and path.startswith(rule):
                return False
        return True


class _RobotsBlocked(Exception):
    pass


class StealthClient:
    """Async httpx-compatible client that paces + rotates to stay stealthy."""

    def __init__(self, policy: StealthPolicy | None = None, *, timeout: float = 12.0,
                 limits: Optional[httpx.Limits] = None, verify: bool = True,
                 inner: Any = None, client_factory: Any = None) -> None:
        self.policy = policy or StealthPolicy()
        # httpx rejects `proxy` as a per-request kwarg, so we hold one client
        # per distinct proxy (None = direct). Clients are created lazily and
        # entered on first use. `client_factory(proxy=..., **kwargs)` lets
        # tests inject a fake transport.
        self._client_kwargs = dict(
            timeout=timeout,
            limits=limits or httpx.Limits(max_connections=10),
            verify=verify, follow_redirects=True,
        )
        self._factory = client_factory
        self._clients: dict[Optional[str], Any] = {}
        if inner is not None:
            self._clients[None] = inner
        self._tokens = float(self.policy.rate) if self.policy.rate > 0 else 1e9
        self._last = time.monotonic()
        self._lock = asyncio.Lock()
        self._req_count = 0
        self._agent_idx = 0
        self._proxy_log: list[Optional[str]] = []
        self._proxy_idx = 0
        self._robots = RobotsCache()
        self._robots_fetching: set[str] = set()

    # ---- pacing ---------------------------------------------------------
    async def _throttle(self) -> None:
        if not self.policy.enabled or self.policy.rate <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            # token-bucket: ensure at least 1/rate seconds since last send
            min_gap = 1.0 / self.policy.rate
            wait = max(0.0, min_gap - (now - self._last))
            if self.policy.jitter:
                wait *= (1.0 + random.random() * self.policy.jitter)
            if self.policy.think_max > self.policy.think_min:
                wait += random.uniform(self.policy.think_min, self.policy.think_max)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = time.monotonic()

    # ---- header / proxy rotation ---------------------------------------
    def _next_agent(self) -> str:
        if not self.policy.random_agent:
            return USER_AGENTS[0]
        self._agent_idx = (self._agent_idx + 1) % len(USER_AGENTS)
        return USER_AGENTS[self._agent_idx]

    def _next_proxy(self) -> Optional[str]:
        pools = []
        if self.policy.proxy:
            pools.append(self.policy.proxy)
        pools.extend(self.policy.proxy_list)
        if not pools:
            return None
        self._proxy_idx = (self._proxy_idx + 1) % len(pools)
        return pools[self._proxy_idx]

    def _base_headers(self) -> dict[str, str]:
        h: dict[str, str] = {}
        if self.policy.random_agent:
            h["User-Agent"] = self._next_agent()
        if self.policy.random_headers:
            h["Accept"] = random.choice(ACCEPTS)
            h["Accept-Language"] = random.choice(ACCEPT_LANGS)
        return h

    # ---- per-proxy client pool -----------------------------------------
    async def _get_client(self, proxy: Optional[str]) -> Any:
        if proxy in self._clients:
            return self._clients[proxy]
        async with self._lock:
            if proxy in self._clients:
                return self._clients[proxy]
            if self._factory is not None:
                client = self._factory(proxy=proxy, **self._client_kwargs)
            else:
                client = httpx.AsyncClient(proxy=proxy, **self._client_kwargs)
            await client.__aenter__()
            self._clients[proxy] = client
            return client

    # ---- robots ---------------------------------------------------------
    async def _ensure_robots(self, url: str) -> bool:
        if not self.policy.respect_robots:
            return True
        host = urlparse(url).netloc
        if host in self._robots._rules or host in self._robots_fetching:
            return self._robots.allowed(url)
        self._robots_fetching.add(host)
        robots_url = f"{urlparse(url).scheme}://{host}/robots.txt"
        try:
            client = await self._get_client(None)
            r = await client.get(robots_url, timeout=8.0,
                                 headers={"User-Agent": USER_AGENTS[0]})
            self._robots.learn(host, getattr(r, "text", "") or "")
        except Exception:
            self._robots.learn(host, "")  # no robots -> allow all
        finally:
            self._robots_fetching.discard(host)
        return self._robots.allowed(url)

    # ---- public API (httpx-compatible) ---------------------------------
    async def request(self, method: str, url: str, **kw: Any) -> Any:
        if self.policy.respect_robots:
            allowed = await self._ensure_robots(url)
            if not allowed:
                # skip disallowed path; return a benign non-response
                return _StubResponse(0, "")
        await self._throttle()
        self._req_count += 1
        headers = dict(kw.pop("headers", {}) or {})
        headers.update(self._base_headers())
        proxy = self._next_proxy()
        self._proxy_log.append(proxy)
        client = await self._get_client(proxy)
        return await client.request(method, url, headers=headers, **kw)

    async def get(self, url: str, **kw: Any) -> Any:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw: Any) -> Any:
        return await self.request("POST", url, **kw)

    async def __aenter__(self) -> "StealthClient":
        await self._get_client(None)
        return self

    async def __aexit__(self, *exc: Any) -> None:
        for client in self._clients.values():
            try:
                await client.__aexit__(*exc)
            except Exception:
                pass
        self._clients.clear()


class _StubResponse:
    def __init__(self, status_code: int, text: str):
        self.status_code = status_code
        self.text = text
        self.headers: dict = {}
