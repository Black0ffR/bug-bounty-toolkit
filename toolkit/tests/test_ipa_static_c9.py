#!/usr/bin/env python3
"""Tests for C9: ipa_static — iOS .ipa static analysis."""

import plistlib
import zipfile

import pytest

from toolkit.testers import ipa_static as m
from toolkit.testers.ipa_static import IpaFinding


def _make_info_plist(url_schemes=("myapp",), get_task_allow=False):
    plist = {
        "CFBundleIdentifier": "com.example.app",
        "CFBundleURLTypes": [
            {"CFBundleURLName": "com.example.app", "CFBundleURLSchemes": list(url_schemes)},
        ],
        "Entitlements": {"get-task-allow": get_task_allow},
    }
    return plistlib.dumps(plist)


def test_extract_url_schemes():
    plist = plistlib.loads(_make_info_plist(url_schemes=("a", "b")))
    assert m.extract_url_schemes(plist) == ["a", "b"]


def test_extract_url_schemes_missing():
    assert m.extract_url_schemes({}) == []


def test_parse_info_plist(tmp_path):
    p = tmp_path / "Info.plist"
    p.write_bytes(_make_info_plist())
    plist = m.parse_info_plist(p)
    assert plist["CFBundleIdentifier"] == "com.example.app"


def test_scan_app_dir_finds_scheme_and_secret(tmp_path):
    app = tmp_path / "MyApp.app"
    app.mkdir()
    (app / "Info.plist").write_bytes(_make_info_plist(url_schemes=("evil",)))
    # A binary-ish file containing a fake AWS key
    (app / "MyApp").write_bytes(b"\x00\x01AKIAABCDEFGHIJKLMNOP\x00some other bytes")
    findings = m.scan_app_dir(app)
    types = {f.finding_type for f in findings}
    assert "url_scheme" in types
    assert "hardcoded_secret" in types
    secrets = [f for f in findings if f.finding_type == "hardcoded_secret"]
    assert any("aws_access_key_id" in f.extra.get("provider", "") for f in secrets)


def test_scan_ipa_file(tmp_path):
    app = tmp_path / "Payload" / "MyApp.app"
    app.mkdir(parents=True)
    (app / "Info.plist").write_bytes(_make_info_plist(url_schemes=("deep",)))
    (app / "MyApp").write_bytes(b"AKIAABCDEFGHIJKLMNOP")
    ipa = tmp_path / "app.ipa"
    with zipfile.ZipFile(ipa, "w") as z:
        z.write(app / "Info.plist", "Payload/MyApp.app/Info.plist")
        z.write(app / "MyApp", "Payload/MyApp.app/MyApp")
    findings = m.scan_ipa_file(ipa)
    types = {f.finding_type for f in findings}
    assert "url_scheme" in types
    assert "hardcoded_secret" in types


def test_to_normalized_shape(tmp_path):
    app = tmp_path / "MyApp.app"
    app.mkdir()
    (app / "Info.plist").write_bytes(_make_info_plist(url_schemes=("x",)))
    findings = m.scan_app_dir(app)
    norm = m.to_normalized(findings, source=str(app))
    assert isinstance(norm, list) and norm
    assert "id" in norm[0] and norm[0]["source_tool"] == "ipa_static.py"
