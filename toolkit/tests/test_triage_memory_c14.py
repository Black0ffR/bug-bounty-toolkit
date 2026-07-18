#!/usr/bin/env python3
"""Tests for C14: triage_memory severity-name + date filters in apply_filters."""

from toolkit.verify.triage_memory import TriageEntry, apply_filters
from toolkit.infra.finding import NormalizedFinding


def _entry(sev, last_seen, host="h.com", vc="XSS"):
    nf = NormalizedFinding(id="x", source_tool="t", host=host,
                            url="https://h.com", vuln_class_key=vc,
                            severity=sev, title="t", detail="d", evidence="e",
                            last_seen=last_seen)
    return TriageEntry(finding=nf, is_new=True, previously_submitted=False,
                       previously_rejected=False)


def test_filter_severity_unchanged():
    entries = [_entry("HIGH", "2026-01-01T00:00:00+00:00"),
               _entry("LOW", "2026-01-01T00:00:00+00:00")]
    out = apply_filters(entries, severity="high")
    assert [e.finding.severity for e in out] == ["HIGH"]


def test_filter_since_excludes_earlier():
    entries = [_entry("HIGH", "2026-01-01T00:00:00+00:00"),
               _entry("HIGH", "2026-06-01T00:00:00+00:00")]
    out = apply_filters(entries, since="2026-03-01T00:00:00+00:00")
    assert len(out) == 1
    assert out[0].finding.last_seen.startswith("2026-06")


def test_filter_until_excludes_later():
    entries = [_entry("HIGH", "2026-01-01T00:00:00+00:00"),
               _entry("HIGH", "2026-06-01T00:00:00+00:00")]
    out = apply_filters(entries, until="2026-03-01T00:00:00+00:00")
    assert len(out) == 1
    assert out[0].finding.last_seen.startswith("2026-01")


def test_filter_since_and_until_window():
    entries = [
        _entry("HIGH", "2026-01-01T00:00:00+00:00"),
        _entry("HIGH", "2026-04-01T00:00:00+00:00"),
        _entry("HIGH", "2026-09-01T00:00:00+00:00"),
    ]
    out = apply_filters(entries, since="2026-03-01T00:00:00+00:00",
                        until="2026-05-01T00:00:00+00:00")
    assert len(out) == 1
    assert out[0].finding.last_seen.startswith("2026-04")


def test_filter_no_args_returns_all():
    entries = [_entry("HIGH", "2026-01-01T00:00:00+00:00"),
               _entry("LOW", "2026-06-01T00:00:00+00:00")]
    assert apply_filters(entries) == entries
