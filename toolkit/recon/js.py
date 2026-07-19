#!/usr/bin/env python3
"""JavaScript analysis: discover endpoints, collect script srcs, flag secrets.

Designed to surface attack surface that the HTML crawler cannot see — API
paths and tokens embedded in bundled JS.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

JS_URL_RE = re.compile(r"https?://[^\s\"'<>{}()]+")
JS_REL_ENDPOINT_RE = re.compile(r"""['"](/[A-Za-z0-9_.\-/*?=&%]+)['"]""")

SCRIPT_SRC_RE = re.compile(
    r"""<script[^>]+src=["']([^"']+)["']""", re.IGNORECASE)

SECRET_PATTERNS = [
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("slack_token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]+")),
    ("github_token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
]


def extract_urls(js_text: str) -> list[str]:
    return JS_URL_RE.findall(js_text or "")


def extract_endpoints(js_text: str) -> list[str]:
    out = []
    for m in JS_REL_ENDPOINT_RE.findall(js_text or ""):
        m = m.strip()
        if m and len(m) > 1:
            out.append(m)
    return sorted(set(out))


def extract_secrets(js_text: str) -> list[dict]:
    out: list[dict] = []
    for name, pat in SECRET_PATTERNS:
        for m in pat.findall(js_text or ""):
            out.append({"type": name, "value": m})
    return out


async def collect_js(html: str, base_url: str, client,
                     timeout: float = 12.0) -> list[str]:
    """Return absolute URLs of <script src=...> tags found in HTML."""
    base = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}"
    out: list[str] = []
    for src in SCRIPT_SRC_RE.findall(html or ""):
        if src.startswith("//"):
            src = f"{urlparse(base_url).scheme}:{src}"
        if src.startswith("/") or not src.startswith("http"):
            src = urljoin(base + "/", src)
        out.append(src)
    return out
