#!/usr/bin/env python3
"""Tests for C4: triage_memory interactive open/copy/full actions."""

import json

import pytest

from toolkit.infra.finding import NormalizedFinding
from toolkit.verify import triage_memory as m
from toolkit.infra.pipeline_state import PipelineState


def _finding(**over):
    d = {
        "id": "abc123def456", "source_tool": "nuclei-harvest.py",
        "host": "api.target.com", "url": "https://api.target.com/order/1",
        "vuln_class_key": "BOLA_CONFIRMED", "severity": "HIGH",
        "title": "Broken Object Level Auth", "detail": "id param",
        "evidence": "GET /order/1", "confidence": "candidate",
        "disposition": "new", "verified_by": None,
        "curl_command": "curl https://api.target.com/order/1",
    }
    d.update(over)
    return NormalizedFinding.from_dict(d)


def _entry(f=None):
    f = f or _finding()
    return m.TriageEntry(finding=f, is_new=True,
                         previously_submitted=False, previously_rejected=False)


def test_copy_finding_field_id():
    f = _finding()
    calls = []
    val, ok = m.copy_finding_field(f, "id", _clipboard=lambda t: (calls.append(t) or True))
    assert val == f.id
    assert ok is True
    assert calls == [f.id]


def test_copy_finding_field_unknown_returns_empty():
    f = _finding()
    val, ok = m.copy_finding_field(f, "nonsense", _clipboard=lambda t: True)
    assert val == ""
    assert ok is False


def test_copy_finding_field_curl():
    f = _finding()
    val, ok = m.copy_finding_field(f, "curl", _clipboard=lambda t: True)
    assert val == f.curl_command
    assert ok is True


def test_format_finding_full_contains_id():
    f = _finding()
    out = m.format_finding_full(f)
    parsed = json.loads(out)
    assert parsed["id"] == f.id
    assert parsed["severity"] == "HIGH"


def test_interactive_open_calls_opener(tmp_path, monkeypatch, capsys):
    f = _finding()
    e = _entry(f)
    opened = []
    responses = iter(["open", "quit"])
    monkeypatch.setattr("builtins.input", lambda *a, **k: next(responses))
    n = m.interactive_triage([e], PipelineState(":memory:"), top=1,
                              _opener=lambda u: (opened.append(u) or True))
    assert opened == [f.url]
    assert n == 0  # open is an inspect action, not a disposition


def test_interactive_copy_then_review(tmp_path, monkeypatch, capsys):
    f = _finding()
    e = _entry(f)
    copied = []
    responses = iter(["copy url", "review"])
    monkeypatch.setattr("builtins.input", lambda *a, **k: next(responses))
    n = m.interactive_triage([e], PipelineState(":memory:"), top=1,
                              _clipboard=lambda t: (copied.append(t) or True))
    assert copied == [f.url]
    assert n == 1


def test_interactive_full_prints_json(tmp_path, monkeypatch, capsys):
    f = _finding()
    e = _entry(f)
    responses = iter(["full", "quit"])
    monkeypatch.setattr("builtins.input", lambda *a, **k: next(responses))
    n = m.interactive_triage([e], PipelineState(":memory:"), top=1)
    out = capsys.readouterr().out
    assert f.id in out
    assert n == 0
