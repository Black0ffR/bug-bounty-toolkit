#!/usr/bin/env python3
"""
secret_verify.py — verify liveness of secrets harvested from JS / git dumps
============================================================================

Tier 2 verification tool.

Purpose
-------
JS tools (js-extractor_3.py, jsreaper.py, recon_pipeline_v4.py) all emit
secret candidates — but a regex match is not a vuln. The key could be:
  - dead / rotated
  - an example placeholder (AKIAEXAMPLE, ghp_testtest...)
  - a public test key documented in API docs
  - a live key with real account access

This tool does ONE thing per finding: a single read-only API call against
the provider to confirm the key's identity. Never destructive — by design.

Per-provider liveness checks (all read-only, all non-mutating):
  - AWS access key:           sts:GetCallerIdentity
  - GitHub PAT / fine-grained: GET /user
  - Slack bot/user token:     auth.test
  - Stripe secret key:        GET /v1/balance (read-only)
  - Google API key:           GET https://maps.googleapis.com/maps/api/geocode/json
                              (free endpoint, just confirms key validity)
  - Generic JWT:              signature + expiry check only (can't verify against
                              issuer without knowing the secret, so we only
                              flag expired JWTs as dead and unsigned / alg=none
                              JWTs as suspicious)

Findings with live keys get confidence: confirmed + verified_by.
Findings with dead/placeholder keys get disposition: rejected.

Safety
------
This tool MUST NEVER be extended to *use* a live key beyond identity
confirmation. Every check is explicitly read-only. The provider checks
are documented inline so future maintainers can audit them.

Chain position
--------------
Layer 4 — Input: any of the three JS tools' output (normalizes their
          different key names for credential_matches / secrets / SecretFinding).
          Output: updated findings JSON with confidence + verified_by.
          Persisted: pipeline_state.db.

Usage
-----
    python -m toolkit.verify.secret_verify \\
        --input js-findings.json \\
        --output secret-verified.json \\
        --scope scope.yaml

Author : Bug Bounty Toolkit / Tier 2
License : MIT (for authorized use only)
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import datetime
import hashlib
import hmac
import json
import logging
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from toolkit.infra.finding import NormalizedFinding, compute_finding_id, normalize_finding_dict
from toolkit.infra.pipeline_state import PipelineState
from toolkit.infra import scope_guard


log = logging.getLogger("secret_verify")

# Provider detection regexes. The jsreaper.py + js-extractor_3.py patterns
# cover the same keys; we re-detect here so this tool is independent of the
# upstream tool's classification.
# Order matters: more-specific patterns (with prefixes) must come before
# generic catch-alls (aws_secret_access_key matches any 40-char base64;
# github_legacy_token matches any 40-char hex). We iterate in insertion order.
_PROVIDER_PATTERNS: dict[str, re.Pattern] = {
    # Prefixed / highly-specific patterns first
    "aws_access_key_id":      re.compile(r"AKIA[0-9A-Z]{16}"),
    "github_pat":             re.compile(r"gh[pousr]_[A-Za-z0-9]{36,255}"),
    "gitlab_pat":             re.compile(r"glpat-[A-Za-z0-9_\-]{20}"),
    "slack_bot_token":        re.compile(r"xoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+"),
    "slack_user_token":       re.compile(r"xox[pas]-[A-Za-z0-9-]+"),
    "stripe_secret_key":      re.compile(r"sk_live_[A-Za-z0-9]{24,}"),
    "stripe_publishable_key": re.compile(r"pk_live_[A-Za-z0-9]{24,}"),
    "google_api_key":         re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    "twilio_api_key":         re.compile(r"SK[0-9a-fA-F]{32}"),
    "jwt":                    re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"),
    # Generic catch-alls LAST — only match if nothing more specific does
    "aws_secret_access_key":  re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])"),
    "github_legacy_token":    re.compile(r"(?<![a-f0-9])[a-f0-9]{40}(?![a-f0-9])"),
}

# Known placeholder/example values — these are documented in provider docs and
# should never be reported as live keys.
_PLACEHOLDERS = {
    "AKIAEXAMPLE", "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "ghp_testtesttesttesttesttesttesttesttesttest",
    "xoxb-test-test-test",
    "sk_live_test12345",
    "sk_test_...",
    "AIzaSyExample1234567890",
}


@dataclass
class SecretCheck:
    raw_value: str
    provider: str
    is_live: bool
    identity: str        # caller identity / username / account id from the API
    detail: str
    redacted_value: str


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "***"
    return value[:4] + "…" + value[-4:]


def _looks_like_placeholder(value: str) -> bool:
    v = value.strip()
    if v in _PLACEHOLDERS:
        return True
    low = v.lower()
    if any(p in low for p in ("example", "testtest", "placeholder", "your_key", "yourkey",
                              "xxxxxx", "1234567890", "0000000000")):
        return True
    return False


def _detect_provider(value: str) -> str | None:
    """Return the provider name (key of _PROVIDER_PATTERNS) that matches value, or None."""
    for name, pat in _PROVIDER_PATTERNS.items():
        if pat.search(value):
            return name
    return None


def extract_secrets_from_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize the three different shapes that upstream tools emit:
    - js-extractor_3.py: each path has credential_matches: dict[pattern_name, count]
                         plus js_sources_metadata[src][credential_matches]
    - jsreaper.py:       top-level "secrets": [SecretFinding dicts]
                         with secret_type, value (redacted), raw_line
    - recon_pipeline_v4: top-level "secrets": [Secret dataclass asdict]
                         with type_, label, severity, value, source, context

    Returns a unified list of {raw_value, source_tool, host, js_url, context, original_finding}.
    """
    out: list[dict[str, Any]] = []
    for raw in findings:
        # jsreaper-style secret finding
        if "secret_type" in raw and ("value" in raw or "raw_line" in raw):
            value = raw.get("value", "") or raw.get("raw_line", "")
            # If value is already redacted by jsreaper, we need the raw_line context
            # to extract. Try to find a credential pattern in raw_line.
            if "…" in value or "<redacted>" in value:
                # Pull from raw_line
                ctx = raw.get("raw_line", "")
                m = None
                for pat in _PROVIDER_PATTERNS.values():
                    m = pat.search(ctx)
                    if m:
                        value = m.group(0)
                        break
                if not m:
                    continue
            out.append({
                "raw_value": value,
                "source_tool": raw.get("source_tool", "jsreaper.py"),
                "host": raw.get("host", ""),
                "js_url": raw.get("js_url", ""),
                "context": raw.get("raw_line", "")[:200],
                "original_finding": raw,
            })
            continue

        # recon_pipeline_v4.py-style Secret dataclass
        if "type_" in raw and "value" in raw:
            out.append({
                "raw_value": raw.get("value", ""),
                "source_tool": raw.get("source_tool", "recon_pipeline_v4.py"),
                "host": "",
                "js_url": raw.get("js_file", raw.get("source", "")),
                "context": raw.get("context", "")[:200],
                "original_finding": raw,
            })
            continue

        # js-extractor_3.py-style: this tool emits credential_matches as counts;
        # the actual raw values need to be re-extracted from the JS source.
        # We don't have the JS source here, so skip — but log it so the user
        # knows to feed in jsreaper.py output instead.
        if "credential_matches" in raw and isinstance(raw["credential_matches"], dict):
            log.debug("js-extractor_3 path entry found — needs jsreaper.py output for raw values; skipping")
            continue

    return out


# ── Provider-specific checks (all read-only, all non-mutating) ──────────────

async def check_aws(access_key: str, secret_key: str | None = None) -> SecretCheck:
    """AWS: sts:GetCallerIdentity. SigV4 signed GET request to
    https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15
    Returns the ARN of the caller — confirms key is live + which account.
    NOTE: requires both access_key AND secret_key. AWS access keys alone
    are not usable without the secret."""
    redacted = _redact(access_key)
    if not secret_key:
        return SecretCheck(
            raw_value=access_key, provider="aws_access_key_id",
            is_live=False, identity="",
            detail="AWS access key ID without secret — cannot verify (SigV4 needs both). "
                   "Look for the secret near this key in the same JS/source file.",
            redacted_value=redacted,
        )
    # SigV4 implementation (stdlib only — no boto3 dependency)
    try:
        service = "sts"
        region = "us-east-1"
        endpoint = "https://sts.amazonaws.com/"
        amz_date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        date_stamp = amz_date[:8]
        canonical_query = "Action=GetCallerIdentity&Version=2011-06-15"
        canonical_headers = f"host:sts.amazonaws.com\nx-amz-date:{amz_date}\n"
        signed_headers = "host;x-amz-date"
        payload_hash = hashlib.sha256(b"").hexdigest()
        canonical_request = (
            f"GET\n/\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        )
        credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
        string_to_sign = (
            f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n" +
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
        )

        def _hmac(key: bytes, msg: str) -> bytes:
            return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

        k_date = _hmac(("AWS4" + secret_key).encode("utf-8"), date_stamp)
        k_region = _hmac(k_date, region)
        k_service = _hmac(k_region, service)
        k_signing = _hmac(k_service, "aws4_request")
        signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
        auth_header = (
            f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        headers = {
            "Authorization": auth_header,
            "x-amz-date": amz_date,
            "Host": "sts.amazonaws.com",
        }
        import httpx
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            r = await client.get(endpoint + "?" + canonical_query, headers=headers)
        if r.status_code == 200:
            data = r.text
            # Extract Arn / UserId / Account
            arn = ""
            account = ""
            m = re.search(r"<Arn>([^<]+)</Arn>", data)
            if m:
                arn = m.group(1)
            m = re.search(r"<Account>([^<]+)</Account>", data)
            if m:
                account = m.group(1)
            return SecretCheck(
                raw_value=access_key, provider="aws_access_key_id",
                is_live=True, identity=arn or account or "?",
                detail=f" sts:GetCallerIdentity → 200. ARN: {arn}",
                redacted_value=redacted,
            )
        elif r.status_code == 403:
            return SecretCheck(
                raw_value=access_key, provider="aws_access_key_id",
                is_live=False, identity="",
                detail=f"sts:GetCallerIdentity → 403 (key invalid, rotated, or lacks sts:GetCallerIdentity permission).",
                redacted_value=redacted,
            )
        else:
            return SecretCheck(
                raw_value=access_key, provider="aws_access_key_id",
                is_live=False, identity="",
                detail=f"sts:GetCallerIdentity → HTTP {r.status_code}: {r.text[:200]}",
                redacted_value=redacted,
            )
    except Exception as exc:
        return SecretCheck(
            raw_value=access_key, provider="aws_access_key_id",
            is_live=False, identity="",
            detail=f"check failed: {exc}",
            redacted_value=redacted,
        )


async def check_github(token: str) -> SecretCheck:
    """GitHub: GET /user. Returns the authenticated user's login."""
    redacted = _redact(token)
    try:
        import httpx
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            r = await client.get(
                "https://api.github.com/user",
                headers={"Authorization": f"Bearer {token}",
                         "Accept": "application/vnd.github+json",
                         "User-Agent": "secret-verify/1.0"},
            )
        if r.status_code == 200:
            data = r.json()
            login = data.get("login", "?")
            return SecretCheck(
                raw_value=token, provider="github_pat",
                is_live=True, identity=login,
                detail=f"GET /user → 200. Login: {login}",
                redacted_value=redacted,
            )
        elif r.status_code == 401:
            return SecretCheck(
                raw_value=token, provider="github_pat",
                is_live=False, identity="",
                detail="GET /user → 401 (token invalid or revoked).",
                redacted_value=redacted,
            )
        else:
            return SecretCheck(
                raw_value=token, provider="github_pat",
                is_live=False, identity="",
                detail=f"GET /user → HTTP {r.status_code}: {r.text[:200]}",
                redacted_value=redacted,
            )
    except Exception as exc:
        return SecretCheck(
            raw_value=token, provider="github_pat",
            is_live=False, identity="",
            detail=f"check failed: {exc}",
            redacted_value=redacted,
        )


async def check_slack(token: str) -> SecretCheck:
    """Slack: auth.test. Returns the bot/user identity."""
    redacted = _redact(token)
    try:
        import httpx
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            r = await client.post(
                "https://slack.com/api/auth.test",
                headers={"Authorization": f"Bearer {token}",
                         "Content-Type": "application/x-www-form-urlencoded"},
                data="",
            )
        if r.status_code == 200:
            data = r.json()
            if data.get("ok"):
                user = data.get("user", "?")
                team = data.get("team", "?")
                return SecretCheck(
                    raw_value=token, provider="slack_bot_token",
                    is_live=True, identity=f"{user}@{team}",
                    detail=f"auth.test → ok. user={user} team={team}",
                    redacted_value=redacted,
                )
            else:
                return SecretCheck(
                    raw_value=token, provider="slack_bot_token",
                    is_live=False, identity="",
                    detail=f"auth.test → ok=false: {data.get('error', '?')}",
                    redacted_value=redacted,
                )
        else:
            return SecretCheck(
                raw_value=token, provider="slack_bot_token",
                is_live=False, identity="",
                detail=f"auth.test → HTTP {r.status_code}",
                redacted_value=redacted,
            )
    except Exception as exc:
        return SecretCheck(
            raw_value=token, provider="slack_bot_token",
            is_live=False, identity="",
            detail=f"check failed: {exc}",
            redacted_value=redacted,
        )


async def check_stripe(key: str) -> SecretCheck:
    """Stripe: GET /v1/balance (read-only). Returns the available balance.
    Note: this only works for secret keys (sk_live_...); publishable keys
    (pk_live_...) can't access /v1/balance — they're treated as 'cannot verify'."""
    redacted = _redact(key)
    if key.startswith("pk_"):
        return SecretCheck(
            raw_value=key, provider="stripe_publishable_key",
            is_live=False, identity="",
            detail="publishable key — cannot verify via /v1/balance (only secret keys can).",
            redacted_value=redacted,
        )
    try:
        import httpx
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            r = await client.get(
                "https://api.stripe.com/v1/balance",
                auth=(key, ""),
            )
        if r.status_code == 200:
            data = r.json()
            avail = data.get("available", [])
            bal = avail[0].get("amount", "?") if avail else "?"
            return SecretCheck(
                raw_value=key, provider="stripe_secret_key",
                is_live=True, identity=f"balance={bal}",
                detail=f"GET /v1/balance → 200. Available: {bal}",
                redacted_value=redacted,
            )
        elif r.status_code == 401:
            return SecretCheck(
                raw_value=key, provider="stripe_secret_key",
                is_live=False, identity="",
                detail="GET /v1/balance → 401 (key revoked or test key on live endpoint).",
                redacted_value=redacted,
            )
        else:
            return SecretCheck(
                raw_value=key, provider="stripe_secret_key",
                is_live=False, identity="",
                detail=f"GET /v1/balance → HTTP {r.status_code}",
                redacted_value=redacted,
            )
    except Exception as exc:
        return SecretCheck(
            raw_value=key, provider="stripe_secret_key",
            is_live=False, identity="",
            detail=f"check failed: {exc}",
            redacted_value=redacted,
        )


async def check_google_api_key(key: str) -> SecretCheck:
    """Google API key: GET https://maps.googleapis.com/maps/api/geocode/json?address=Mountain+View&key=<KEY>
    Free endpoint; just confirms the key is valid. Returns the status."""
    redacted = _redact(key)
    try:
        import httpx
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            r = await client.get(
                "https://maps.googleapis.com/maps/api/geocode/json",
                params={"address": "Mountain View, CA", "key": key},
            )
        if r.status_code == 200:
            data = r.json()
            status = data.get("status", "?")
            if status == "OK":
                return SecretCheck(
                    raw_value=key, provider="google_api_key",
                    is_live=True, identity=status,
                    detail=f"geocode → status=OK (key valid, geocoding enabled).",
                    redacted_value=redacted,
                )
            elif status == "REQUEST_DENIED":
                return SecretCheck(
                    raw_value=key, provider="google_api_key",
                    is_live=False, identity=status,
                    detail=f"geocode → status=REQUEST_DENIED: {data.get('error_message', '?')}",
                    redacted_value=redacted,
                )
            else:
                # Other statuses (OVER_QUERY_LIMIT, INVALID_REQUEST) — key exists but may be rate-limited
                return SecretCheck(
                    raw_value=key, provider="google_api_key",
                    is_live=True, identity=status,
                    detail=f"geocode → status={status}: {data.get('error_message', '')[:200]}",
                    redacted_value=redacted,
                )
        else:
            return SecretCheck(
                raw_value=key, provider="google_api_key",
                is_live=False, identity="",
                detail=f"geocode → HTTP {r.status_code}",
                redacted_value=redacted,
            )
    except Exception as exc:
        return SecretCheck(
            raw_value=key, provider="google_api_key",
            is_live=False, identity="",
            detail=f"check failed: {exc}",
            redacted_value=redacted,
        )


def check_jwt(token: str) -> SecretCheck:
    """JWT: signature + expiry check only. We CAN'T verify a JWT against its
    issuer without knowing the secret, so we only:
      - decode header + payload
      - flag expired JWTs (exp < now)
      - flag alg=none / unsigned JWTs as suspicious
      - flag JWTs with no exp as suspicious
    """
    redacted = _redact(token)
    parts = token.split(".")
    if len(parts) != 3:
        return SecretCheck(raw_value=token, provider="jwt", is_live=False, identity="",
                           detail="not a 3-part JWT", redacted_value=redacted)
    try:
        def _b64dec(s: str) -> bytes:
            s += "=" * (4 - len(s) % 4)
            return base64.urlsafe_b64decode(s)
        header = json.loads(_b64dec(parts[0]))
        payload = json.loads(_b64dec(parts[1]))
    except Exception as exc:
        return SecretCheck(raw_value=token, provider="jwt", is_live=False, identity="",
                           detail=f"decode failed: {exc}", redacted_value=redacted)
    alg = header.get("alg", "?")
    iss = payload.get("iss", "?")
    exp = payload.get("exp")
    iat = payload.get("iat")
    now = int(time.time())
    if alg.lower() == "none" or parts[2] == "":
        return SecretCheck(
            raw_value=token, provider="jwt", is_live=True, identity=f"iss={iss}",
            detail=f"SUSPICIOUS: alg=none / unsigned JWT. iss={iss} alg={alg}. "
                   "Treat as a finding even without verification — unsigned JWTs are exploitable.",
            redacted_value=redacted,
        )
    if exp is None:
        return SecretCheck(
            raw_value=token, provider="jwt", is_live=True, identity=f"iss={iss}",
            detail=f"SUSPICIOUS: no exp claim. iss={iss} alg={alg}. "
                   "JWT never expires — likely a vuln if accepted by the server.",
            redacted_value=redacted,
        )
    if now > int(exp):
        return SecretCheck(
            raw_value=token, provider="jwt", is_live=False, identity=f"iss={iss}",
            detail=f"expired JWT (exp={exp}, now={now}). Likely dead.",
            redacted_value=redacted,
        )
    return SecretCheck(
        raw_value=token, provider="jwt", is_live=True, identity=f"iss={iss}",
        detail=f"valid-looking JWT (not expired, signed with alg={alg}). iss={iss}. "
               "Cannot verify signature without issuer secret — treat as 'candidate live' "
               "and check expiry + alg only.",
        redacted_value=redacted,
    )


# ── Dispatch ─────────────────────────────────────────────────────────────────

async def verify_secret(value: str, *, provider_hint: str = "") -> SecretCheck:
    """Dispatch to the right provider check based on the value's pattern.
    provider_hint overrides auto-detection."""
    if _looks_like_placeholder(value):
        return SecretCheck(
            raw_value=value, provider=provider_hint or "placeholder",
            is_live=False, identity="",
            detail="placeholder/example value (AKIAEXAMPLE, ghp_test..., etc.) — not a real key.",
            redacted_value=_redact(value),
        )
    provider = provider_hint or _detect_provider(value)
    if provider is None:
        return SecretCheck(
            raw_value=value, provider="unknown",
            is_live=False, identity="",
            detail="no provider pattern matched — skipping.",
            redacted_value=_redact(value),
        )
    if provider == "aws_access_key_id":
        # AWS needs both access_key_id and secret — we have only the ID
        return await check_aws(value, secret_key=None)
    if provider == "github_pat" or provider == "github_legacy_token":
        return await check_github(value)
    if provider.startswith("slack"):
        return await check_slack(value)
    if provider.startswith("stripe"):
        return await check_stripe(value)
    if provider == "google_api_key":
        return await check_google_api_key(value)
    if provider == "jwt":
        return check_jwt(value)
    # AWS secret access key alone — can't verify
    if provider == "aws_secret_access_key":
        return SecretCheck(
            raw_value=value, provider=provider,
            is_live=False, identity="",
            detail="AWS secret access key without the access key ID — cannot SigV4-sign.",
            redacted_value=_redact(value),
        )
    # Other providers (gitlab, twilio) — TODO; for now, treat as candidate
    return SecretCheck(
        raw_value=value, provider=provider,
        is_live=False, identity="",
        detail=f"no read-only check implemented for {provider} yet — flagging as candidate.",
        redacted_value=_redact(value),
    )


async def verify_all(secrets: list[dict[str, Any]], guard: scope_guard.ScopeGuard | None,
                     *, concurrency: int = 4) -> list[tuple[dict[str, Any], SecretCheck]]:
    """Verify a batch of secrets. Returns list of (input_secret, check_result)."""
    sem = asyncio.Semaphore(concurrency)

    async def _one(s: dict[str, Any]) -> tuple[dict[str, Any], SecretCheck]:
        async with sem:
            check = await verify_secret(s["raw_value"])
            return (s, check)

    return await asyncio.gather(*[_one(s) for s in secrets])


def build_verified_findings(secrets: list[dict[str, Any]],
                            results: list[tuple[dict[str, Any], SecretCheck]]) -> list[dict[str, Any]]:
    """Convert verification results into NormalizedFinding dicts."""
    out: list[dict[str, Any]] = []
    for secret, check in results:
        source_tool = secret.get("source_tool", "secret_verify.py")
        host = secret.get("host", "")
        js_url = secret.get("js_url", "")
        # Build a stable finding id
        evidence = f"{check.provider}:{check.redacted_value}:{check.identity}"
        fid = compute_finding_id(source_tool, host or js_url, "EXPOSED_SECRET", evidence)
        severity = "HIGH" if check.is_live else "MEDIUM"
        if check.is_live and check.provider == "jwt" and "SUSPICIOUS" in check.detail:
            severity = "HIGH"
        if not check.is_live and "placeholder" in check.detail.lower():
            severity = "INFO"
        confidence = "confirmed" if check.is_live else "probable"
        disposition = "new" if check.is_live else "rejected"
        title = f"Exposed {check.provider} ({'LIVE' if check.is_live else 'dead/placeholder'})"
        detail = (f"Provider: {check.provider}\n"
                  f"Identity: {check.identity or '(unknown)'}\n"
                  f"Source: {js_url or host}\n"
                  f"Context: {secret.get('context', '')}\n"
                  f"Detail: {check.detail}")
        out.append({
            "id": fid,
            "source_tool": "secret_verify.py",
            "host": host,
            "url": js_url,
            "vuln_class_key": "EXPOSED_SECRET",
            "severity": severity,
            "title": title,
            "detail": detail,
            "evidence": evidence,
            "remediation": ("Rotate the key immediately and remove from source. "
                            "Audit CloudTrail / audit logs for prior use." if check.is_live else
                            "Remove from source even if dead — reduces noise and prevents confusion."),
            "raw": {"redacted_value": check.redacted_value, "provider": check.provider,
                    "original_source_tool": source_tool,
                    "identity": check.identity},
            "confidence": confidence,
            "disposition": disposition,
            "verified_by": "secret_verify.py" if check.is_live else None,
        })
    return out


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="secret_verify.py",
        description="Verify liveness of secrets harvested from JS / git dumps. Read-only.",
    )
    ap.add_argument("--input", "-i", required=True, help="jsreaper.py / recon_pipeline_v4.py JSON")
    ap.add_argument("--output", "-o", default="secret-verified.json", help="output JSON (default: secret-verified.json)")
    ap.add_argument("--db", default="pipeline_state.db", help="pipeline_state.db path")
    ap.add_argument("--scope", help="scope.yaml path (required if any provider endpoints are out-of-scope, though most are not)")
    ap.add_argument("--concurrency", type=int, default=4, help="concurrent provider checks (default: 4)")
    ap.add_argument("--dry-run", action="store_true", help="extract + detect providers, no live checks")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )

    in_path = Path(args.input)
    if not in_path.exists():
        log.error("input file not found: %s", in_path)
        return 2
    data = json.loads(in_path.read_text(encoding="utf-8"))
    findings: list[dict[str, Any]]
    if isinstance(data, list):
        findings = data
    elif isinstance(data, dict):
        # Look in 'secrets', 'all_secrets', or 'findings'
        findings = data.get("secrets") or data.get("all_secrets") or data.get("findings") or []
        # If js-extractor_3.py shape with paths[].credential_matches, those don't
        # have raw values — log a warning.
        if "paths" in data and not findings:
            log.warning("input looks like js-extractor_3.py output (has 'paths' but no 'secrets'). "
                        "secret_verify needs raw secret values — feed jsreaper.py output instead.")
    else:
        log.error("input root must be a list or object with 'secrets'")
        return 2

    log.info("loaded %d raw entries from %s", len(findings), in_path)
    secrets = extract_secrets_from_findings(findings)
    log.info("extracted %d secret candidates", len(secrets))

    if args.dry_run:
        log.info("--dry-run: detecting providers only")
        for s in secrets:
            provider = _detect_provider(s["raw_value"]) or "?"
            placeholder = "PLACEHOLDER" if _looks_like_placeholder(s["raw_value"]) else ""
            print(f"  {provider:25s} {placeholder:12s} {s['raw_value'][:8]}…")
        return 0

    guard = scope_guard.ScopeGuard(args.scope) if args.scope else scope_guard.get_default()
    state = PipelineState(args.db)
    try:
        results = asyncio.run(verify_all(secrets, guard, concurrency=args.concurrency))
        verified = build_verified_findings(secrets, results)
        for f in verified:
            state.upsert_finding(f)
        out_path = Path(args.output)
        out_path.write_text(
            json.dumps({
                "scan_time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                "input": str(in_path),
                "total_candidates": len(secrets),
                "live": sum(1 for _, c in results if c.is_live),
                "dead_or_placeholder": sum(1 for _, c in results if not c.is_live),
                "results": [
                    {
                        "provider": c.provider,
                        "redacted": c.redacted_value,
                        "is_live": c.is_live,
                        "identity": c.identity,
                        "detail": c.detail,
                    }
                    for _, c in results
                ],
                "findings": verified,
            }, indent=2, default=str),
            encoding="utf-8",
        )
        log.info("wrote %s", out_path)
        return 0
    finally:
        state.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(0)
