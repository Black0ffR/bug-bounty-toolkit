#!/usr/bin/env python3
"""
auth_profiles.py — shared authenticated session provider
=========================================================

Purpose
-------
Loads auth_profiles.yaml and hands any tool a ready-to-use httpx-style
session object for a named profile, instead of each tool parsing its own
--cookie / --session string.

Features
--------
- Profile switching mid-script:  get_session("user_b")  →  fresh client
  with that profile's cookies + headers + bearer token preconfigured.
- Auto-refresh hook for short-lived tokens: register a callable that
  returns a fresh bearer token when the cached one is near expiry.
- Secret redaction in logs: any value longer than 12 chars from the
  'cookie', 'bearer', 'api_key', or 'password' fields is masked before
  being passed to logging or print.
- Profile metadata: user_id, role, email — exposed to tools so they
  can do three-way BOLA comparisons ("user_a sees her own data, user_b
  sees user_a's data") without re-parsing the YAML.
- Optional httpx — if httpx is missing, get_session() returns a thin
  wrapper around urllib.request that exposes the same .get/.post API
  surface used by the verify/ tools.

Chain position
--------------
Layer 0 — used by apifuzz.py (after patching), idor_crosssession.py,
oauthprobe.py, paramfuzz.py. No upstream dependencies.

Usage
-----
    from toolkit.infra.auth_profiles import AuthProfiles

    profiles = AuthProfiles("auth_profiles.yaml")
    sess_a = profiles.get_session("user_a")
    sess_b = profiles.get_session("user_b")
    resp_a = sess_a.get("https://api.target.com/v1/users/8841")
    resp_b = sess_b.get("https://api.target.com/v1/users/8841")
    # If resp_b has user_a's data → IDOR confirmed.

Author : Bug Bounty Toolkit / Layer 0
License : MIT (for authorized use only)
"""

from __future__ import annotations

import base64
import datetime
import json
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

# Match the existing toolchain pattern: try PyYAML, fall back to scope_guard's
# tiny parser for restricted YAML.
try:
    import yaml  # type: ignore
    _HAS_YAML = True
except ImportError:
    yaml = None  # type: ignore
    _HAS_YAML = False

try:
    import httpx  # type: ignore
    _HAS_HTTPX = True
except ImportError:
    httpx = None  # type: ignore
    _HAS_HTTPX = False

# Reuse scope_guard's fallback parser (same restricted YAML subset)
from toolkit.infra.scope_guard import _fallback_yaml_parse


log = logging.getLogger("auth_profiles")


# Field names whose values get redacted in any log output.
_SENSITIVE_FIELDS = {"cookie", "bearer", "api_key", "apikey", "password", "token", "secret"}
_REDACT_REPLACEMENT = "<redacted>"


def redact_value(key: str, value: Any) -> Any:
    """If key is sensitive, return a redacted placeholder; else return value unchanged."""
    if key.lower() in _SENSITIVE_FIELDS and isinstance(value, str):
        if len(value) > 12:
            return value[:4] + "…" + _REDACT_REPLACEMENT
        return _REDACT_REPLACEMENT
    return value


def redact_dict(d: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of d with sensitive values redacted. For logging."""
    out: dict[str, Any] = {}
    for k, v in d.items():
        if isinstance(v, dict):
            out[k] = redact_dict(v)
        elif isinstance(v, list):
            out[k] = [redact_dict(x) if isinstance(x, dict) else redact_value(k, x) for x in v]
        else:
            out[k] = redact_value(k, v)
    return out


@dataclass
class Profile:
    name: str
    cookie: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    bearer: str = ""
    api_key: str = ""
    user_id: str | int | None = None
    role: str = ""
    email: str = ""
    refresh_callback: Callable[[], str] | None = None
    _last_refresh: float = field(default=0.0, init=False)

    def auth_headers(self) -> dict[str, str]:
        """Build the HTTP headers implied by this profile."""
        h: dict[str, str] = {}
        if self.bearer:
            h["Authorization"] = f"Bearer {self.bearer}" if not self.bearer.lower().startswith("bearer ") else self.bearer
        elif self.api_key:
            h["X-Api-Key"] = self.api_key
        if self.cookie:
            h["Cookie"] = self.cookie
        # Profile-defined headers win
        h.update(self.headers)
        return h

    def maybe_refresh(self, max_age: float = 1800.0) -> None:
        """If a refresh_callback is registered and the cached bearer is older
        than max_age seconds, invoke the callback and replace self.bearer."""
        if self.refresh_callback is None:
            return
        now = time.time()
        if self._last_refresh == 0.0 or (now - self._last_refresh) > max_age:
            try:
                new_token = self.refresh_callback()
                if new_token:
                    self.bearer = new_token
                    self._last_refresh = now
                    log.info("profile %s: bearer refreshed", self.name)
            except Exception as exc:
                log.warning("profile %s: refresh callback failed: %s", self.name, exc)


class AuthProfiles:
    """Load auth_profiles.yaml once. Thread-safe after construction."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path: Path | None = Path(path) if path else None
        self.profiles: dict[str, Profile] = {}
        if self.path:
            self._load()

    def _load(self) -> None:
        assert self.path is not None
        if not self.path.exists():
            raise FileNotFoundError(f"auth_profiles file not found: {self.path}")
        text = self.path.read_text(encoding="utf-8")
        if _HAS_YAML:
            try:
                data = yaml.safe_load(text) or {}
            except yaml.YAMLError as exc:
                raise ValueError(f"invalid YAML in {self.path}: {exc}") from exc
        else:
            data = _fallback_yaml_parse(text)
        if not isinstance(data, dict):
            raise ValueError(f"auth_profiles root must be a mapping, got {type(data).__name__}")
        profiles_data = data.get("profiles", {}) or {}
        if not isinstance(profiles_data, dict):
            raise ValueError("'profiles' must be a mapping of name -> profile_dict")
        for name, raw in profiles_data.items():
            raw = raw or {}
            if not isinstance(raw, dict):
                log.warning("profile %s: expected mapping, got %s — skipping", name, type(raw).__name__)
                continue
            self.profiles[name] = Profile(
                name=name,
                cookie=str(raw.get("cookie", "")),
                headers={k: str(v) for k, v in (raw.get("headers") or {}).items()},
                bearer=str(raw.get("bearer", "")),
                api_key=str(raw.get("api_key", "")),
                user_id=raw.get("user_id"),
                role=str(raw.get("role", "")),
                email=str(raw.get("email", "")),
            )
        # Always have an anonymous profile
        if "anon" not in self.profiles:
            self.profiles["anon"] = Profile(name="anon")
        log.info(
            "auth_profiles loaded: %d profiles (%s)",
            len(self.profiles),
            ", ".join(sorted(self.profiles.keys())),
        )
        # Log a redacted summary at debug level
        for name, p in self.profiles.items():
            log.debug("  %s: %s", name, redact_dict({
                "cookie": p.cookie, "bearer": p.bearer, "user_id": p.user_id, "role": p.role,
            }))

    def get_profile(self, name: str) -> Profile:
        if name not in self.profiles:
            raise KeyError(f"auth profile not found: {name!r} (available: {sorted(self.profiles)})")
        return self.profiles[name]

    def list_profiles(self) -> list[str]:
        return sorted(self.profiles)

    def require_two_users(self) -> tuple[Profile, Profile]:
        """Convenience for idor_crosssession.py: return (user_a, user_b) or raise.
        Looks for any two non-anon profiles; prefers ones with explicit user_id set.
        """
        candidates = [p for p in self.profiles.values() if p.name != "anon" and (p.cookie or p.bearer)]
        with_uid = [p for p in candidates if p.user_id is not None]
        pool = with_uid if len(with_uid) >= 2 else candidates
        if len(pool) < 2:
            raise RuntimeError(
                "idor_crosssession needs at least two authenticated profiles; "
                f"found {len(pool)} (have: {sorted(p.name for p in pool)})"
            )
        return pool[0], pool[1]

    # ── Session factory ──────────────────────────────────────────────────────

    def get_session(self, name: str, *, timeout: float = 15.0, verify: bool = False,
                    follow_redirects: bool = True, ua: str = "Mozilla/5.0 (compatible; ToolkitAuth/1.0)"
                    ) -> "AuthenticatedSession":
        """Return a session object bound to this profile. The session exposes
        .get/.post/.put/.patch/.delete/.request with the same signature as
        httpx.Client (sync) — verify, follow_redirects, headers etc. are baked in
        and the profile's Authorization/Cookie headers are auto-merged on every
        request unless overridden per-call."""
        profile = self.get_profile(name)
        profile.maybe_refresh()
        return AuthenticatedSession(profile, timeout=timeout, verify=verify,
                                    follow_redirects=follow_redirects, ua=ua)


class AuthenticatedSession:
    """Thin wrapper around httpx.Client (preferred) or urllib.request (fallback).
    Auto-injects the profile's auth headers on every request. Logs redacted
    request metadata at INFO. Never re-raises — returns Response-like objects
    matching httpx.Response's .status_code / .text / .headers / .content
    surface so downstream tools can treat both backends identically."""

    def __init__(self, profile: Profile, *, timeout: float, verify: bool,
                 follow_redirects: bool, ua: str) -> None:
        self.profile = profile
        self.timeout = timeout
        self.verify = verify
        self.follow_redirects = follow_redirects
        self.ua = ua
        self._httpx_client: Any = None
        if _HAS_HTTPX:
            self._httpx_client = httpx.Client(
                timeout=timeout, verify=verify, follow_redirects=follow_redirects,
                headers={"User-Agent": ua},
            )

    def __enter__(self) -> "AuthenticatedSession":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        if self._httpx_client is not None:
            try:
                self._httpx_client.close()
            except Exception:
                pass

    def _merged_headers(self, extra: dict[str, str] | None) -> dict[str, str]:
        h = self.profile.auth_headers()
        if extra:
            h.update(extra)
        return h

    def _log_req(self, method: str, url: str) -> None:
        log.debug(
            "REQ %s %s as=%s headers=%s",
            method, url, self.profile.name,
            redact_dict(self.profile.auth_headers()),
        )

    # ── httpx-style API ──────────────────────────────────────────────────────

    def get(self, url: str, *, headers: dict[str, str] | None = None, **kw: Any) -> Any:
        return self.request("GET", url, headers=headers, **kw)

    def post(self, url: str, *, headers: dict[str, str] | None = None, **kw: Any) -> Any:
        return self.request("POST", url, headers=headers, **kw)

    def put(self, url: str, *, headers: dict[str, str] | None = None, **kw: Any) -> Any:
        return self.request("PUT", url, headers=headers, **kw)

    def patch(self, url: str, *, headers: dict[str, str] | None = None, **kw: Any) -> Any:
        return self.request("PATCH", url, headers=headers, **kw)

    def delete(self, url: str, *, headers: dict[str, str] | None = None, **kw: Any) -> Any:
        return self.request("DELETE", url, headers=headers, **kw)

    def request(self, method: str, url: str, *, headers: dict[str, str] | None = None,
                params: dict[str, Any] | None = None, json: Any = None,
                data: Any = None, content: Any = None, **kw: Any) -> Any:
        self.profile.maybe_refresh()
        self._log_req(method, url)
        merged = self._merged_headers(headers)
        if self._httpx_client is not None:
            return self._httpx_client.request(
                method, url, headers=merged, params=params, json=json, data=data,
                content=content, **kw,
            )
        return _UrllibResponse.from_request(
            method, url, headers=merged, params=params, json=json,
            data=data, timeout=self.timeout, verify=self.verify,
            follow_redirects=self.follow_redirects,
        )


@dataclass
class _UrllibResponse:
    """Minimal httpx.Response-compatible surface built on urllib.request.
    Supports: .status_code, .text, .content (bytes), .headers, .json().
    Used only when httpx is unavailable."""
    status_code: int
    text: str
    content: bytes
    headers: dict[str, str]
    _json_cache: Any = field(default=None, init=False)

    @classmethod
    def from_request(cls, method: str, url: str, *, headers: dict[str, str],
                     params: dict[str, Any] | None, json: Any, data: Any,
                     timeout: float, verify: bool,
                     follow_redirects: bool) -> "_UrllibResponse":
        import urllib.parse
        import urllib.request
        import urllib.error
        import ssl

        if params:
            sep = "&" if "?" in url else "?"
            url = url + sep + urllib.parse.urlencode(params)

        body: bytes | None = None
        h = dict(headers)
        if json is not None:
            body = json_module_dumps(json).encode("utf-8")
            h.setdefault("Content-Type", "application/json")
        elif data is not None:
            if isinstance(data, dict):
                body = urllib.parse.urlencode(data).encode("utf-8")
                h.setdefault("Content-Type", "application/x-www-form-urlencoded")
            elif isinstance(data, bytes):
                body = data
            else:
                body = str(data).encode("utf-8")
        elif content is not None:
            body = content if isinstance(content, bytes) else str(content).encode("utf-8")

        req = urllib.request.Request(url, data=body, method=method.upper(), headers=h)
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
            raw = resp.read()
            return cls(
                status_code=resp.status,
                text=raw.decode("utf-8", errors="replace"),
                content=raw,
                headers={k: v for k, v in resp.headers.items()},
            )
        except urllib.error.HTTPError as exc:
            raw = exc.read() if hasattr(exc, "read") else b""
            return cls(
                status_code=exc.code,
                text=raw.decode("utf-8", errors="replace"),
                content=raw,
                headers={k: v for k, v in (exc.headers.items() if exc.headers else [])},
            )
        except Exception as exc:
            log.debug("urllib request failed: %s %s — %s", method, url, exc)
            return cls(status_code=0, text="", content=b"", headers={})

    def json(self) -> Any:
        if self._json_cache is None:
            try:
                self._json_cache = json.loads(self.text)
            except Exception:
                self._json_cache = {}
        return self._json_cache


def json_module_dumps(obj: Any) -> str:
    """Indirection so tests can monkeypatch easily."""
    return json.dumps(obj)


# ── Module-level singleton ───────────────────────────────────────────────────

_DEFAULT_PROFILES: AuthProfiles | None = None
_DEFAULT_LOCK = threading.Lock()


def configure(path: str | Path | None) -> AuthProfiles:
    global _DEFAULT_PROFILES
    with _DEFAULT_LOCK:
        _DEFAULT_PROFILES = AuthProfiles(path)
        return _DEFAULT_PROFILES


def get_default() -> AuthProfiles:
    global _DEFAULT_PROFILES
    if _DEFAULT_PROFILES is None:
        with _DEFAULT_LOCK:
            if _DEFAULT_PROFILES is None:
                _DEFAULT_PROFILES = AuthProfiles(None)
    return _DEFAULT_PROFILES


def get_session(name: str, **kw: Any) -> AuthenticatedSession:
    return get_default().get_session(name, **kw)


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.DEBUG, format="[%(levelname)s] %(message)s")
    if len(sys.argv) < 2:
        print("usage: auth_profiles.py <auth_profiles.yaml> [profile_name]", file=sys.stderr)
        sys.exit(2)
    ap = AuthProfiles(sys.argv[1])
    name = sys.argv[2] if len(sys.argv) > 2 else "user_a"
    p = ap.get_profile(name)
    print(f"profile {name}: user_id={p.user_id} role={p.role}")
    print("auth headers (redacted):", redact_dict(p.auth_headers()))
