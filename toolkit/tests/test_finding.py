"""Unit tests for toolkit.infra.finding (NormalizedFinding + normalize_finding_dict)."""
from __future__ import annotations

import pytest

from toolkit.infra.finding import (
    NormalizedFinding,
    compute_finding_id,
    normalize_finding_dict,
)


def test_compute_finding_id_stable():
    a = compute_finding_id("apifuzz.py", "h.com", "BOLA_POSSIBLE", "ev1")
    b = compute_finding_id("apifuzz.py", "h.com", "BOLA_POSSIBLE", "ev1")
    c = compute_finding_id("apifuzz.py", "h.com", "BOLA_POSSIBLE", "ev2")
    assert a == b
    assert a != c
    assert len(a) == 16


def test_normalized_finding_defaults():
    f = NormalizedFinding(source_tool="t", host="h", vuln_class_key="X", severity="HIGH", title="x")
    assert f.confidence == "candidate"
    assert f.disposition == "new"
    assert f.verified_by is None
    assert f.first_seen  # auto-set
    assert f.last_seen


def test_normalized_finding_to_dict_has_all_fields():
    f = NormalizedFinding(source_tool="t", host="h", vuln_class_key="X", severity="HIGH", title="x")
    d = f.to_dict()
    assert "confidence" in d
    assert "disposition" in d
    assert "first_seen" in d
    assert "last_seen" in d
    assert "verified_by" in d
    assert "raw" in d


def test_normalized_finding_from_dict_ignores_unknown_keys():
    f = NormalizedFinding.from_dict({
        "source_tool": "t", "host": "h", "vuln_class_key": "X", "severity": "HIGH",
        "title": "x", "unknown_key": "ignored",
    })
    assert f.host == "h"
    assert not hasattr(f, "unknown_key")


def test_normalize_apifuzz_bola_finding():
    raw = {
        "host": "api.example.com",
        "url": "https://api.example.com/v1/users/8841",
        "method": "GET",
        "test_type": "BOLA",
        "severity": "HIGH",
        "title": "Possible BOLA/IDOR — Predictable ID Access",
        "detail": "...",
        "evidence": "...",
        "curl_command": "curl ...",
    }
    n = normalize_finding_dict(raw, source_tool="apifuzz.py")
    assert n["source_tool"] == "apifuzz.py"
    assert n["vuln_class_key"] == "BOLA_POSSIBLE"  # HIGH severity BOLA → POSSIBLE
    assert n["severity"] == "HIGH"
    assert n["confidence"] == "candidate"
    assert n["id"]
    assert n["raw"]["method"] == "GET"


def test_normalize_apifuzz_bola_critical_becomes_confirmed():
    raw = {
        "host": "h", "url": "u", "method": "GET",
        "test_type": "BOLA", "severity": "CRITICAL",
        "title": "BOLA confirmed", "detail": "d", "evidence": "e", "curl_command": "c",
    }
    n = normalize_finding_dict(raw, source_tool="apifuzz.py")
    assert n["vuln_class_key"] == "BOLA_CONFIRMED"


def test_normalize_paramfuzz_finding():
    raw = {
        "host": "h", "url": "u", "method": "POST",
        "param_name": "user_id", "inject_via": "body_json",
        "test_value": "999", "finding_type": "IDOR_PARAM",
        "severity": "HIGH", "title": "t", "detail": "d", "evidence": "e",
        "curl_command": "c",
    }
    n = normalize_finding_dict(raw, source_tool="paramfuzz.py")
    assert n["vuln_class_key"] == "BOLA_POSSIBLE"
    assert n["raw"]["param_name"] == "user_id"


def test_normalize_ssrfprobe_finding():
    raw = {
        "host": "h", "url": "u", "param": "url",
        "payload_url": "http://169.254.169.254/",
        "payload_category": "metadata",
        "severity": "CRITICAL", "title": "t", "detail": "d", "evidence": "e",
        "curl_command": "c", "is_blind": True, "is_reflective": False,
    }
    n = normalize_finding_dict(raw, source_tool="ssrfprobe.py")
    assert n["vuln_class_key"] == "SSRF_CLOUD_METADATA"
    assert n["confidence"] == "probable"  # blind → probable


def test_normalize_subtakeover_finding():
    raw = {
        "subdomain": "vuln.example.com",
        "verdict": "VULNERABLE",
        "provider_match": "S3",
        "cname_chain": ["vuln.example.com", "s3.amazonaws.com"],
        "fingerprint_matched": ["NoSuchBucket"],
        "http_status": 404,
    }
    n = normalize_finding_dict(raw, source_tool="subtakeover10.py")
    assert n["host"] == "vuln.example.com"
    assert n["vuln_class_key"] == "SUBDOMAIN_TAKEOVER"
    assert n["severity"] == "HIGH"
    assert "S3" in n["title"]


def test_normalize_jsreaper_secret():
    raw = {
        "host": "h", "js_url": "https://h/app.js",
        "secret_type": "AWS Access Key",
        "value": "AKIAEXAMPLE",
        "raw_line": "aws_key = 'AKIAEXAMPLE'",
        "severity": "HIGH",
        "confidence": "HIGH",
        "note": "found in app.js",
    }
    n = normalize_finding_dict(raw, source_tool="jsreaper.py")
    assert "Exposed secret" in n["title"]
    assert n["confidence"] == "probable"  # jsreaper HIGH → probable


def test_normalize_passthrough_normalized_finding():
    """If the input already has vuln_class_key + host, pass through unchanged."""
    raw = {
        "source_tool": "x", "host": "h", "url": "u",
        "vuln_class_key": "BOLA_CONFIRMED", "severity": "CRITICAL",
        "title": "t", "evidence": "e", "confidence": "confirmed",
        "id": "preset_id",
    }
    n = normalize_finding_dict(raw)
    assert n["vuln_class_key"] == "BOLA_CONFIRMED"
    assert n["confidence"] == "confirmed"
    assert n["id"] == "preset_id"


def test_normalize_falls_back_for_unknown_shape():
    raw = {"some_random": "shape", "with": "fields"}
    n = normalize_finding_dict(raw, source_tool="unknown_tool")
    assert n["vuln_class_key"] == "UNKNOWN"
    assert n["confidence"] == "candidate"
    assert n["source_tool"] == "unknown_tool"
