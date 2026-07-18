"""Proxy rotation for outbound scanning.
=====================================

Holds a list of proxy URLs (HTTP/SOCKS4/SOCKS5) and hands them out round-robin
so a long scan can spread load / evade per-IP rate limits. Designed to plug
into the shared httpx pool (build_client accepts a ``proxy=`` argument).

Usage
-----
    from toolkit.infra.proxy_rotator import ProxyRotator

    rot = ProxyRotator(["http://10.0.0.1:8080", "socks5://10.0.0.2:1080"])
    next_proxy = rot.next()          # round-robin
    # or as an iterator:
    for proxy in rot.iter(limit=10):
        ...

Author : Bug Bounty Toolkit / Tier 1
License : MIT (for authorized use only)
"""

from __future__ import annotations

import itertools
import logging
from typing import Iterable


log = logging.getLogger("proxy_rotator")


class ProxyRotator:
    """Round-robin proxy source. Thread-safe enough for single-loop asyncio use."""

    def __init__(self, proxies: Iterable[str] | None = None) -> None:
        self._proxies: list[str] = [p for p in (proxies or []) if p]
        self._cycle = itertools.cycle(self._proxies) if self._proxies else iter(())
        self._idx: int = 0

    def add(self, proxy: str) -> None:
        if proxy and proxy not in self._proxies:
            self._proxies.append(proxy)
            self._cycle = itertools.cycle(self._proxies)

    @property
    def count(self) -> int:
        return len(self._proxies)

    def next(self) -> str | None:
        """Return the next proxy in rotation, or None if no proxies configured."""
        if not self._proxies:
            return None
        self._idx = (self._idx + 1) % len(self._proxies)
        return next(self._cycle)

    def iter(self, *, limit: int | None = None):
        """Iterate proxies round-robin. If ``limit`` is None, iterates forever."""
        if not self._proxies:
            return
        if limit is None:
            for p in self._cycle:
                yield p
        else:
            for _ in range(limit):
                yield self.next()  # type: ignore[misc]

    @classmethod
    def from_env(cls, var: str = "BBTK_PROXIES") -> "ProxyRotator":
        import os
        raw = os.environ.get(var, "").strip()
        if not raw:
            return cls([])
        return cls([p.strip() for p in raw.split(",") if p.strip()])

    @classmethod
    def from_file(cls, path: str) -> "ProxyRotator":
        import pathlib
        p = pathlib.Path(path)
        if not p.exists():
            return cls([])
        proxies = [line.strip() for line in p.read_text(encoding="utf-8").splitlines()
                   if line.strip() and not line.startswith("#")]
        return cls(proxies)
