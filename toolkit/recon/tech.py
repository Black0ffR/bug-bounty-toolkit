#!/usr/bin/env python3
"""Lightweight tech-stack fingerprinting from response signals."""
from __future__ import annotations

_SERVER_HINTS = {
    "nginx": "nginx",
    "apache": "apache",
    "cloudflare": "cloudflare",
    "amazonS3": "aws-s3",
    "github.io": "github-pages",
    "awselb": "aws-elb",
}

_X_HEADER_FRAMEWORK = {
    "x-drupal": "Drupal",
    "x-lambda": "AWS Lambda",
    "x-vercel": "Vercel",
    "x-netlify": "Netlify",
    "x-powered-by": None,  # handled separately (value)
    "x-aspnet-version": "ASP.NET",
}

_COOKIE_FRAMEWORK = {
    "PHPSESSID": "PHP",
    "JSESSIONID": "Java",
    "ASP.NET_SessionId": "ASP.NET",
    "wordpress_": "WordPress",
    "django": "Django",
    "laravel_session": "Laravel",
}


def fingerprint(headers: dict, body: str = "") -> dict:
    tech: dict[str, str] = {}
    h = {k.lower(): v for k, v in (headers or {}).items()}

    server = h.get("server")
    if server:
        tech["server"] = server
        low = server.lower()
        for needle, name in _SERVER_HINTS.items():
            if needle in low:
                tech["infra"] = name
                break

    powered = h.get("x-powered-by")
    if powered:
        tech["language"] = powered.strip()

    for key, name in _X_HEADER_FRAMEWORK.items():
        if key in h and name:
            tech["framework"] = name

    cookie = h.get("set-cookie", "") or ""
    for needle, name in _COOKIE_FRAMEWORK.items():
        if needle.lower() in cookie.lower():
            tech.setdefault("language", name)
            if needle in ("wordpress_", "django", "laravel_session"):
                tech["framework"] = name
            break

    low_body = (body or "").lower()
    if "wp-content" in low_body or "wp-includes" in low_body:
        tech.setdefault("framework", "WordPress")
    if "drupal" in low_body:
        tech.setdefault("framework", "Drupal")

    return tech
