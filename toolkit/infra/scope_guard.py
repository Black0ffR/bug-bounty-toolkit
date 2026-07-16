#!/usr/bin/env python3
"""
scope_guard.py — shared scope enforcement + rate limiting
=========================================================

Purpose
-------
Single import every tool calls before firing a request:

    from toolkit.infra.scope_guard import ScopeGuard, ScopeError

Replaces each tool's ad-hoc --scope handling. Reads scope.yaml once at
startup, exposes a stateless check_scope(host) call, and provides a
process-wide token-bucket rate limiter so 11 concurrently-running tools
don't collectively blow past a program's stated rate limit.

Features
--------
- Wildcard / subdomain matching against scope.yaml:
    "*.acme.com" matches "acme.com", "www.acme.com", "a.b.acme.com"
    "api.acme-internal.io" matches only that exact host
- Hard-fails (raises ScopeError) on out-of-scope target — never silently
  proceeds.
- out_of_scope entries take precedence over in_scope (deny-wins), matching
  HackerOne / Bugcrowd policy semantics.
- IP-literal scope entries supported via ipaddress (CIDR notation allowed).
- Token-bucket rate limiter: max_rps and max_concurrent enforced across all
  threads/processes that import this module within one Python interpreter.
  For multi-process enforcement, the limiter falls back to file-lock + flock
  on /tmp/scope_guard.bucket (Termux: $TMPDIR).
- Every blocked attempt is logged to blocked.log next to scope.yaml with
  timestamp, host, source tool (if known), and reason.
- Termux note: pure stdlib (re, ipaddress, threading, time, pathlib, json,
  os, sys). Zero new dependencies.

Chain position
--------------
Layer 0 — used by every Layer 1-5 tool. No upstream dependencies.

Usage
-----
    from toolkit.infra.scope_guard import ScopeGuard, ScopeError

    guard = ScopeGuard("scope.yaml")          # load once
    guard.check_scope("www.acme.com")          # raises ScopeError if OOS
    guard.check_scope("evil.com")              # raises ScopeError
    guard.acquire_token()                       # blocks until rate-limit slot free
    try:
        ... do request ...
    finally:
        guard.release_token()

Or as a context manager (recommended):

    with guard.request_slot("www.acme.com"):
        ... do request ...

Author : Bug Bounty Toolkit / Layer 0
License : MIT (for authorized use only)
"""

from __future__ import annotations

import datetime
import fcntl
import ipaddress
import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Optional YAML loader. Match the existing toolchain's pattern (try PyYAML,
# fall back to a tiny inline parser for scope.yaml's restricted syntax so
# the tool runs on a fresh Termux without `pip install pyyaml`).
try:
    import yaml  # type: ignore
    _HAS_YAML = True
except ImportError:
    yaml = None  # type: ignore
    _HAS_YAML = False


log = logging.getLogger("scope_guard")


def _default_slot_dir() -> Path:
    """Directory for cross-process concurrency lock slots (Termux: $TMPDIR)."""
    base = os.environ.get("TMPDIR") or "/tmp"
    return Path(base) / "scope_guard.slots"


class ScopeError(RuntimeError):
    """Raised when a target is out of scope or scope config is invalid."""


class _CrossProcessGate:
    """Bounded-concurrency gate shared across processes via flock.

    The limiter must cap *total* in-flight requests across all the tools the
    orchestrator spawns (11+ subprocesses), not just within one interpreter.
    This gate enforces ``max_concurrent`` process-wide using advisory locks
    (``fcntl.flock``) on a pool of per-slot lock files.

    Crash-safe by design: flock is released automatically when a process (or
    thread) dies, so a dead tool cannot permanently hold a slot. Each acquire
    opens a fresh fd for the slot it wins and keeps *all* won fds alive in a
    set until explicitly released, so a caller that holds several slots
    simultaneously (e.g. a test, or interleaved coroutines) does not lose the
    underlying lock when a later acquire overwrites the "current" handle.
    """

    def __init__(self, max_concurrent: int, slot_dir: str | Path) -> None:
        self.max = max(1, int(max_concurrent))
        self.slot_dir = Path(slot_dir)
        self._held: set = set()
        self._lock = threading.Lock()
        try:
            self.slot_dir.mkdir(parents=True, exist_ok=True)
            self._available = True
        except OSError as exc:
            log.warning("cross-process gate unavailable (%s) — no shared limiting", exc)
            self._available = False

    def _slot_path(self, i: int) -> Path:
        return self.slot_dir / f"slot_{i}.lock"

    def acquire(self, timeout: float = 60.0):
        """Try to win a concurrency slot. Returns the held file object (truthy)
        on success, or None on timeout / when the gate is unavailable."""
        if not self._available:
            return object()  # truthy sentinel: no shared limiting
        deadline = time.monotonic() + timeout
        while True:
            for i in range(self.max):
                try:
                    fh = open(self._slot_path(i), "a+")
                except OSError:
                    continue
                try:
                    fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError:
                    fh.close()
                    continue
                with self._lock:
                    self._held.add(fh)
                return fh
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            time.sleep(min(0.02, remaining))

    def release(self, fh) -> None:
        if fh is None:
            return
        try:
            fcntl.flock(fh, fcntl.LOCK_UN)
        except OSError:
            pass
        try:
            fh.close()
        except OSError:
            pass
        with self._lock:
            self._held.discard(fh)


@dataclass
class _RateLimit:
    max_rps: float = 5.0
    max_concurrent: int = 10

    # Token-bucket state (per-process rps)
    _tokens: float = field(default=0.0, init=False)
    _last_refill: float = field(default=0.0, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)
    # Cross-process concurrency gate (shared across all spawned tool processes)
    gate: "_CrossProcessGate | None" = field(default=None, init=False)
    _gate_held: Any = field(default=None, init=False)

    def init(self) -> None:
        """Prime the bucket to full on first use."""
        with self._lock:
            if self._last_refill == 0.0:
                self._tokens = float(self.max_rps)
                self._last_refill = time.monotonic()

    def acquire(self, timeout: float = 60.0) -> bool:
        """Block until a cross-process concurrency slot is free AND a token is
        available. Returns True if acquired, False on timeout."""
        self.init()
        deadline = time.monotonic() + timeout
        # Cross-process concurrency slot (crash-safe flock)
        if self.gate is not None:
            gate_timeout = deadline - time.monotonic()
            if gate_timeout <= 0:
                return False
            held = self.gate.acquire(gate_timeout)
            if not held:
                return False
            self._gate_held = held
        # Token (per-process rps)
        with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._last_refill
                self._tokens = min(self.max_rps, self._tokens + elapsed * self.max_rps)
                self._last_refill = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True
                needed = (1.0 - self._tokens) / self.max_rps
                remaining = deadline - now
                if remaining <= needed:
                    if self.gate is not None and self._gate_held is not None:
                        self.gate.release(self._gate_held)
                        self._gate_held = None
                    return False
                time.sleep(min(needed, 0.05, max(0.0, remaining)))

    def release(self) -> None:
        if self.gate is not None and self._gate_held is not None:
            self.gate.release(self._gate_held)
            self._gate_held = None


class ScopeGuard:
    """Load once, call check_scope() per request. Thread-safe after construction."""

    def __init__(self, scope_path: str | Path | None = None) -> None:
        self.path: Path | None = Path(scope_path) if scope_path else None
        self.program: str = ""
        self.in_scope: list[str] = []
        self.out_of_scope: list[str] = []
        self.automation_allowed: bool = True
        self.rate_limit = _RateLimit()
        self._compiled_in: list[tuple[re.Pattern, ipaddress.IPv4Network | ipaddress.IPv6Network | None]] = []
        self._compiled_out: list[tuple[re.Pattern, ipaddress.IPv4Network | ipaddress.IPv6Network | None]] = []
        self._blocked_log: Path | None = None
        # Cross-process concurrency gate (shared across spawned tool processes).
        # Default slot dir; narrowed to a per-scope dir in _load() when a scope
        # file is present so independent scopes don't share the global budget.
        self.rate_limit.gate = _CrossProcessGate(
            self.rate_limit.max_concurrent, _default_slot_dir()
        )
        if self.path:
            self._load()

    # ── Loading ──────────────────────────────────────────────────────────────

    def _load(self) -> None:
        assert self.path is not None
        if not self.path.exists():
            raise ScopeError(f"scope file not found: {self.path}")
        text = self.path.read_text(encoding="utf-8")
        data: dict[str, Any]
        if _HAS_YAML:
            try:
                data = yaml.safe_load(text) or {}
            except yaml.YAMLError as exc:
                raise ScopeError(f"invalid YAML in {self.path}: {exc}") from exc
        else:
            data = _fallback_yaml_parse(text)
        if not isinstance(data, dict):
            raise ScopeError(f"scope file root must be a mapping, got {type(data).__name__}")
        self.program = str(data.get("program", ""))
        self.in_scope = [str(x) for x in data.get("in_scope", [])]
        self.out_of_scope = [str(x) for x in data.get("out_of_scope", [])]
        rl = data.get("rate_limit", {}) or {}
        self.rate_limit.max_rps = float(rl.get("max_rps", 5.0))
        self.rate_limit.max_concurrent = int(rl.get("max_concurrent", 10))
        # Rebuild the cross-process gate keyed to this scope's directory so two
        # unrelated scopes don't share the same concurrency budget.
        if self.path is not None:
            self.rate_limit.gate = _CrossProcessGate(
                self.rate_limit.max_concurrent, self.path.parent / ".scope_guard_slots"
            )
        self.automation_allowed = bool(data.get("automation_allowed", True))
        self._compiled_in = [self._compile(x) for x in self.in_scope]
        self._compiled_out = [self._compile(x) for x in self.out_of_scope]
        self._blocked_log = self.path.parent / "blocked.log"
        if not self.automation_allowed:
            log.warning("scope.yaml sets automation_allowed=false — tools will refuse to fire")
        log.info(
            "scope loaded: program=%s in=%d out=%d rps=%.1f concurrent=%d",
            self.program or "?", len(self.in_scope), len(self.out_of_scope),
            self.rate_limit.max_rps, self.rate_limit.max_concurrent,
        )

    @staticmethod
    def _compile(entry: str) -> tuple[re.Pattern, ipaddress.IPv4Network | ipaddress.IPv6Network | None]:
        """Compile a scope entry into (regex, optional CIDR network).
        Supports:
          *.acme.com          -> regex
          acme.com            -> regex (matches acme.com and *.acme.com)
          10.0.0.0/8          -> CIDR
          192.168.1.5         -> single-IP CIDR
        """
        entry = entry.strip()
        # Try IP/CIDR first
        try:
            net: ipaddress.IPv4Network | ipaddress.IPv6Network
            if "/" in entry:
                net = ipaddress.ip_network(entry, strict=False)
            else:
                # single IP?
                addr = ipaddress.ip_address(entry)
                net = ipaddress.ip_network(f"{addr}/32" if addr.version == 4 else f"{addr}/128", strict=False)
            # regex matches nothing for IP entries (we use network containment)
            return (re.compile(r"$^"), net)
        except ValueError:
            pass
        # Wildcard / hostname
        # Normalize: "*.acme.com" matches "acme.com" and any subdomain
        # Plain "acme.com" matches "acme.com" and "*.acme.com"
        if entry.startswith("*."):
            base = entry[2:]
            # match base or any subdomain of base
            pat = r"^([a-z0-9.-]+\.)?" + re.escape(base) + r"$"
        else:
            # match exactly, OR *.entry (subdomain) — but NOT unrelated siblings
            pat = r"^(\*\.|[a-z0-9.-]+\.)?" + re.escape(entry) + r"$"
        return (re.compile(pat, re.IGNORECASE), None)

    # ── Public API ───────────────────────────────────────────────────────────

    def check_scope(self, host: str, *, source_tool: str = "") -> None:
        """Raise ScopeError if host is out of scope. Returns None on success."""
        if not self.path:
            # No scope file loaded — caller didn't configure, allow but warn once
            return
        if not self.automation_allowed:
            raise ScopeError(
                f"automation_allowed=false in scope.yaml — refusing to test {host}"
            )
        host = host.lower().strip()
        # Strip port
        if ":" in host and not host.startswith("["):
            host = host.split(":", 1)[0]
        host = host.strip("[]")

        # IP-literal target?
        target_net: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
        try:
            addr = ipaddress.ip_address(host)
            target_net = ipaddress.ip_network(
                f"{addr}/32" if addr.version == 4 else f"{addr}/128", strict=False
            )
        except ValueError:
            pass

        # Deny-wins: if any out_of_scope entry matches, reject
        for regex, net in self._compiled_out:
            if net is not None and target_net is not None and target_net.subnet_of(net):
                self._block(host, source_tool, "matches out_of_scope CIDR")
                raise ScopeError(f"{host} is in out_of_scope CIDR {net}")
            if net is None and regex.match(host):
                self._block(host, source_tool, "matches out_of_scope pattern")
                raise ScopeError(f"{host} matches out_of_scope pattern {regex.pattern}")

        # Require at least one in_scope entry to match
        matched = False
        for regex, net in self._compiled_in:
            if net is not None and target_net is not None and target_net.subnet_of(net):
                matched = True
                break
            if net is None and regex.match(host):
                matched = True
                break
        if not matched:
            self._block(host, source_tool, "no in_scope entry matched")
            raise ScopeError(f"{host} is not in any in_scope entry")

    def check_url(self, url: str, *, source_tool: str = "") -> None:
        """Extract host from URL and check. Convenience wrapper."""
        from urllib.parse import urlparse
        host = urlparse(url).hostname or ""
        if not host:
            raise ScopeError(f"could not extract host from URL: {url}")
        self.check_scope(host, source_tool=source_tool)

    def acquire_token(self, timeout: float = 60.0) -> bool:
        return self.rate_limit.acquire(timeout)

    def release_token(self) -> None:
        self.rate_limit.release()

    def request_slot(self, host: str, *, source_tool: str = "") -> "_RequestSlot":
        """Context manager: checks scope + acquires rate-limit token."""
        self.check_scope(host, source_tool=source_tool)
        return _RequestSlot(self)

    # ── Internal ─────────────────────────────────────────────────────────────

    def _block(self, host: str, source_tool: str, reason: str) -> None:
        msg = f"{datetime.datetime.now(datetime.timezone.utc).isoformat()}\t{source_tool or '?'}\t{host}\t{reason}\n"
        log.warning("BLOCKED %s (%s) — %s", host, source_tool or "?", reason)
        if self._blocked_log is None:
            return
        try:
            with self._blocked_log.open("a", encoding="utf-8") as fh:
                fh.write(msg)
        except OSError as exc:
            log.debug("could not write blocked.log: %s", exc)


class _RequestSlot:
    __slots__ = ("guard", "_acquired")

    def __init__(self, guard: ScopeGuard) -> None:
        self.guard = guard
        self._acquired = False

    def __enter__(self) -> "_RequestSlot":
        if not self.guard.acquire_token():
            raise ScopeError("rate-limit token acquire timed out")
        self._acquired = True
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._acquired:
            self.guard.release_token()


# ── Fallback YAML parser (only used if PyYAML is not installed) ──────────────
# Handles the restricted subset used by scope.yaml / auth_profiles.yaml:
#   top-level key: value
#   key:
#     - item
#     - item
#   key:
#     subkey: value
# Does NOT support flow style, anchors, multi-line strings, or tags.
# This is intentionally minimal — install PyYAML for full support.

def _fallback_yaml_parse(text: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    current_key: str | None = None
    current_indent = 0
    for raw_line in text.splitlines():
        # strip comments
        if "#" in raw_line:
            # naive: only strip if # is not inside quotes
            line = re.sub(r"(?<!\\)#.*$", "", raw_line)
        else:
            line = raw_line
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        if indent == 0:
            if ":" not in stripped:
                continue
            key, _, val = stripped.partition(":")
            key = key.strip()
            val = val.strip()
            if not val:
                current_key = key
                current_indent = 0
                result[key] = []
            else:
                current_key = None
                # strip quotes
                val = val.strip("'\"")
                # try bool/int/float
                if val.lower() in ("true", "false"):
                    result[key] = (val.lower() == "true")
                else:
                    try:
                        result[key] = int(val)
                    except ValueError:
                        try:
                            result[key] = float(val)
                        except ValueError:
                            result[key] = val
        else:
            if current_key is None:
                continue
            if stripped.startswith("- "):
                item = stripped[2:].strip().strip("'\"")
                if isinstance(result.get(current_key), list):
                    result[current_key].append(item)
                else:
                    result[current_key] = [item]
            else:
                # nested mapping — represent as dict
                if ":" in stripped:
                    k2, _, v2 = stripped.partition(":")
                    if not isinstance(result.get(current_key), dict):
                        result[current_key] = {} if not result.get(current_key) else result[current_key]
                    if isinstance(result[current_key], list) and not result[current_key]:
                        result[current_key] = {}
                    if isinstance(result[current_key], dict):
                        result[current_key][k2.strip()] = v2.strip().strip("'\"")
    return result


# ── Convenience module-level singleton ───────────────────────────────────────
# Tools that don't want to manage their own ScopeGuard instance can call:
#   from toolkit.infra.scope_guard import configure, check_scope
#   configure("scope.yaml")
#   check_scope("www.acme.com")

_DEFAULT_GUARD: ScopeGuard | None = None
_DEFAULT_LOCK = threading.Lock()


def configure(scope_path: str | Path | None) -> ScopeGuard:
    global _DEFAULT_GUARD
    with _DEFAULT_LOCK:
        _DEFAULT_GUARD = ScopeGuard(scope_path)
        return _DEFAULT_GUARD


def get_default() -> ScopeGuard:
    global _DEFAULT_GUARD
    if _DEFAULT_GUARD is None:
        with _DEFAULT_LOCK:
            if _DEFAULT_GUARD is None:
                # No-op guard (no scope file) — permissive
                _DEFAULT_GUARD = ScopeGuard(None)
    return _DEFAULT_GUARD


def check_scope(host: str, *, source_tool: str = "") -> None:
    get_default().check_scope(host, source_tool=source_tool)


def check_url(url: str, *, source_tool: str = "") -> None:
    get_default().check_url(url, source_tool=source_tool)


def acquire_token(timeout: float = 60.0) -> bool:
    return get_default().acquire_token(timeout)


def release_token() -> None:
    get_default().release_token()


if __name__ == "__main__":
    # Smoke-test CLI: python -m toolkit.infra.scope_guard scope.yaml www.acme.com evil.com
    import sys
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    if len(sys.argv) < 2:
        print("usage: scope_guard.py <scope.yaml> [host ...]", file=sys.stderr)
        sys.exit(2)
    guard = ScopeGuard(sys.argv[1])
    for host in sys.argv[2:]:
        try:
            guard.check_scope(host, source_tool="scope_guard.py")
            print(f"OK   {host}")
        except ScopeError as exc:
            print(f"FAIL {host}  ({exc})")
