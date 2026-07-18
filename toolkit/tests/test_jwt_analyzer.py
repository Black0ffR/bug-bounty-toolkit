#!/usr/bin/env python3
"""Tests for toolkit.verify.jwt_analyzer (TDD for B23)."""

import hashlib
import hmac
import json

import pytest

from toolkit.verify import jwt_analyzer as m


def _make_token(alg="HS256", extra_header=None, payload=None):
    import base64
    h = {"alg": alg, "typ": "JWT"}
    if extra_header:
        h.update(extra_header)
    p = payload or {"sub": "user1", "role": "admin"}
    def b64(d):
        return base64.urlsafe_b64encode(d).rstrip(b"=").decode()
    hb = b64(json.dumps(h, separators=(",", ":")).encode())
    pb = b64(json.dumps(p, separators=(",", ":")).encode())
    sig = m._sign_hs256(hb, pb, b"secret") if alg.startswith("HS") else "x"
    return f"{hb}.{pb}.{sig}"


def test_parse_jwt_roundtrip():
    t = _make_token("HS256")
    header, payload, sig = m.parse_jwt(t)
    assert header["alg"] == "HS256"
    assert payload["sub"] == "user1"


def test_parse_jwt_malformed():
    with pytest.raises(ValueError):
        m.parse_jwt("not.a.jwt")


def test_forge_alg_none_decodes():
    t = _make_token()
    _, payload, _ = m.parse_jwt(t)
    forged = m.forge_alg_none(payload)
    fh, fp, fs = m.parse_jwt(forged)
    assert fh["alg"] == "none"
    assert fs == ""
    assert fp["sub"] == "user1"


def test_forge_rs256_as_hs256_verifies_with_pubkey_as_secret():
    # public key bytes used as HMAC secret must re-verify under HS256
    pubkey = b"-----BEGIN PUBLIC KEY-----\nabc123\n-----END PUBLIC KEY-----"
    t = _make_token("RS256")
    _, payload, _ = m.parse_jwt(t)
    forged = m.forge_rs256_as_hs256(payload, pubkey)
    fh, fp, fs = m.parse_jwt(forged)
    assert fh["alg"] == "HS256"
    # signature verifies when server treats pubkey as HMAC secret
    expected = m._sign_hs256(forged.split(".")[0], forged.split(".")[1], pubkey)
    assert fs == expected


def test_forge_header_injection_sets_kid_jku():
    t = _make_token("RS256", extra_header={"kid": "k1", "jku": "https://x/jwks"})
    _, payload, _ = m.parse_jwt(t)
    forged = m.forge_header_injection(payload, kid="k1/../../etc/passwd",
                                      jku="https://evil/jwks", x5u="https://evil/c.pem")
    fh, _, _ = m.parse_jwt(forged)
    assert fh["kid"].endswith("/etc/passwd")
    assert fh["jku"] == "https://evil/jwks"
    assert fh["x5u"] == "https://evil/c.pem"


def test_analyze_token_detects_issues_and_forgeries():
    t = _make_token("RS256", extra_header={"kid": "k1"})
    a = m.analyze_token(t)
    assert any("kid" in i for i in a.issues)
    assert "alg_none" in a.forgeries
    assert "kid_injection" in a.forgeries


def test_analyze_token_rs256_confusion_needs_pubkey():
    t = _make_token("RS256", extra_header={"kid": "k1"})
    a = m.analyze_token(t)  # no pubkey
    assert "rs256_as_hs256" not in a.forgeries
    a2 = m.analyze_token(t, b"pubkeybytes")
    assert "rs256_as_hs256" in a2.forgeries


def test_to_normalized_emits_finding():
    t = _make_token("none")
    a = m.analyze_token(t)
    norms = m.to_normalized([a])
    assert len(norms) == 1
    assert norms[0]["vuln_class_key"].startswith("JWT_ALG=NONE")
    assert norms[0]["severity"] == "HIGH"


def test_collect_tokens_from_json():
    data = {"tokens": [_make_token(), "notajwt"]}
    toks = m._collect_tokens(data)
    assert len(toks) == 1
    data2 = [{"token": _make_token("RS256", extra_header={"kid": "k"})}, {"x": 1}]
    assert len(m._collect_tokens(data2)) == 1
