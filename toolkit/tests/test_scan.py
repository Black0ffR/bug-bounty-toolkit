"""Smoke test for P2 scan entrypoint (scripts/scan.py)."""

import importlib.util
import os
import sys

import pytest


def _load():
    path = os.path.join(os.path.dirname(__file__), "..", "..", "scripts", "scan.py")
    spec = importlib.util.spec_from_file_location("scan_cli", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_parse_args_basic(monkeypatch):
    mod = _load()
    monkeypatch.setattr(sys, "argv", ["scan.py", "--url", "http://t.com"])
    ns = mod.parse_args()
    assert ns.url == "http://t.com"
    assert ns.depth == 2
    assert ns.output == "scan-findings.json"


def test_parse_args_flags(monkeypatch):
    mod = _load()
    monkeypatch.setattr(sys, "argv", ["scan.py", "--url", "http://t.com", "--no-xss",
                                      "--report", "sarif", "--depth", "3",
                                      "--log-format", "json"])
    ns = mod.parse_args()
    assert ns.no_xss is True
    assert ns.report == "sarif"
    assert ns.depth == 3
    assert ns.log_format == "json"
