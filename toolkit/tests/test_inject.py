#!/usr/bin/env python3
"""Tests for toolkit/infra/inject.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from toolkit.infra import inject


def test_replace_existing():
    out = inject.build_injection_url("http://t/x?file=notes.txt", "file", "../../etc/passwd")
    assert out == "http://t/x?file=..%2F..%2Fetc%2Fpasswd"


def test_preserves_other_params():
    out = inject.build_injection_url("http://t/x?a=1&b=2", "b", "9")
    assert "a=1" in out and "b=9" in out


def test_no_existing_query():
    out = inject.build_injection_url("http://t/x", "q", "z")
    assert out == "http://t/x?q=z"
