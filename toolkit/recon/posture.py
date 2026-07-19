#!/usr/bin/env python3
"""Security-posture analysis from response headers.

Mirrors the security-posture-analyzer recon skill: flags missing
hardening headers that widen the attack surface.
"""
from __future__ import annotations

_REQUIRED_HEADERS = [
    ("Content-Security-Policy", "missing_csp", "low"),
    ("Strict-Transport-Security", "missing_hsts", "medium"),
    ("X-Frame-Options", "clickjacking", "low"),
    ("X-Content-Type-Options", "mime_sniffing", "low"),
    ("Referrer-Policy", "referrer_leak", "low"),
]


def analyze_headers(headers: dict) -> list[dict]:
    h = {k.lower(): v for k, v in (headers or {}).items()}
    findings: list[dict] = []
    for header, issue, sev in _REQUIRED_HEADERS:
        if header.lower() not in h:
            findings.append({
                "missing_header": header,
                "issue": issue,
                "severity": sev,
            })
    return findings
