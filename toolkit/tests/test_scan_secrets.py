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

