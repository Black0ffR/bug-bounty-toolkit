#!/usr/bin/env python3
"""
inject.py — URL injection helper (shared by GET-parameter testers)
===============================================================
When a discovered endpoint already carries a query string (the crawler keeps
the query), injecting a payload must *replace* that parameter's value rather
than append a second copy — otherwise many servers read the original (first)
value and the injection is silently dropped.
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


def build_injection_url(url: str, param: str, value: str) -> str:
    """Return ``url`` with ``param`` set to ``value`` (replacing any existing
    occurrence, preserving all other query params)."""
    p = urlparse(url)
    q = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True)
         if k != param]
    q.append((param, value))
    return urlunparse((p.scheme, p.netloc, p.path or "/", p.params,
                       urlencode(q), ""))
