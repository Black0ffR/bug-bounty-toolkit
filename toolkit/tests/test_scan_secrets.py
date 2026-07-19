#!/usr/bin/env python3
"""Tests for recon js_secrets -> standalone scan findings (scan.py)."""
import asyncio
import json
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts import scan


def test_secret_findings_emits_normalized():
    secrets = [
        {"type": "aws_access_key_id", "value": "AKIA1234567890ABCDEF"},
        {"type": "google_api_key", "value": "AIzaXXXXXXXXXXXXXXXXXXXXXXXXXXXX"},
        {"type": "empty", "value": ""},  # skipped
    ]
    out = scan._secret_findings(secrets, "https://example.com")
    assert len(out) == 2  # empty value dropped
    by_type = {f["secret_type"]: f for f in out}
    assert by_type["aws_access_key_id"]["severity"] == "HIGH"
    assert by_type["google_api_key"]["severity"] == "MEDIUM"
    assert by_type["aws_access_key_id"]["vuln_class_key"] == "EXPOSED_SECRET"
    assert "AKIA" in by_type["aws_access_key_id"]["evidence"]
    assert by_type["aws_access_key_id"]["url"] == "https://example.com"


def test_load_recon_seeds_reads_js_secrets(tmp_path):
    # The --recon path reads a recon.json off disk and must surface js_secrets
    # (no network needed -> exercises the file branch of _load_recon_seeds).
    p = tmp_path / "r.json"
    p.write_text(json.dumps({
        "js_secrets": [{"type": "jwt", "value": "eyJ.eyJ.xxx"}],
        "js_endpoints": [], "wayback_urls": [], "live_hosts": [],
    }))
    args = types.SimpleNamespace(recon=str(p), chain_recon=False)
    same_origin, hosts, secrets = asyncio.run(
        scan._load_recon_seeds(args, None, "example.com"))
    assert same_origin == [] and hosts == []
    assert secrets == [{"type": "jwt", "value": "eyJ.eyJ.xxx"}]


def test_recon_only_findings_merges_secrets_and_posture():
    recon = {
        "js_secrets": [{"type": "aws_access_key_id", "value": "AKIA123"}],
        "posture": [{"issue": "missing_hsts", "missing_header": "Strict-Transport-Security"},
                    {"issue": "missing_csp", "missing_header": "Content-Security-Policy"}],
    }
    out = scan._recon_only_findings(recon, "https://example.com")
    classes = {f["vuln_class_key"] for f in out}
    assert "EXPOSED_SECRET" in classes
    assert "MISSING_SECURITY_HEADER" in classes
    hsts = [f for f in out if f.get("issue") == "missing_hsts"][0]
    assert hsts["severity"] == "MEDIUM"  # HSTS is MEDIUM
    csp = [f for f in out if f.get("issue") == "missing_csp"][0]
    assert csp["severity"] == "LOW"


def test_get_recon_loads_file(tmp_path):
    p = tmp_path / "r.json"
    p.write_text(json.dumps({"js_secrets": [{"type": "jwt", "value": "x"}],
                              "posture": []}))
    args = types.SimpleNamespace(recon=str(p), chain_recon=False, recon_only=False)
    recon = asyncio.run(scan._get_recon(args, None, "example.com"))
    assert recon["js_secrets"] == [{"type": "jwt", "value": "x"}]


