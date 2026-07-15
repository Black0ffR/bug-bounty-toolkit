"""Unit + integration tests for toolkit.verify.triage_memory."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from toolkit.verify.triage_memory import (
    load_final_json,
    build_triage_entries,
    render_queue_md,
    generate_writeup,
    interactive_triage,
    batch_triage,
)
from toolkit.infra.pipeline_state import PipelineState


def test_load_final_json_finds_findings_key(tmp_path, sample_nuclei_harvest_json):
    p = tmp_path / "final.json"
    p.write_text(json.dumps(sample_nuclei_harvest_json), encoding="utf-8")
    findings = load_final_json(p)
    assert len(findings) == 2


def test_load_final_json_accepts_bare_list(tmp_path):
    p = tmp_path / "bare.json"
    p.write_text(json.dumps([{"id": "1"}, {"id": "2"}]), encoding="utf-8")
    findings = load_final_json(p)
    assert len(findings) == 2


def test_load_final_json_accepts_results_key(tmp_path):
    p = tmp_path / "alt.json"
    p.write_text(json.dumps({"results": [{"id": "1"}]}), encoding="utf-8")
    findings = load_final_json(p)
    assert len(findings) == 1


def test_build_triage_entries_sorts_by_severity(temp_db, sample_nuclei_harvest_json):
    entries = build_triage_entries(sample_nuclei_harvest_json["findings"], temp_db)
    # CRITICAL (ssrfprobe) should come before HIGH (apifuzz)
    assert entries[0].finding.severity == "CRITICAL"
    assert entries[1].finding.severity == "HIGH"
    # Both should be marked as new (first time seen)
    assert all(e.is_new for e in entries)


def test_build_triage_entries_filters_submitted(temp_db, sample_nuclei_harvest_json):
    # Pre-mark the apifuzz finding as submitted
    temp_db.upsert_finding({
        "id": "abc123def456", "source_tool": "apifuzz.py", "host": "h",
        "url": "u", "vuln_class_key": "BOLA_POSSIBLE", "severity": "HIGH",
        "title": "x", "disposition": "submitted",
    })
    entries = build_triage_entries(sample_nuclei_harvest_json["findings"], temp_db)
    # Only the SSRF finding should remain
    assert len(entries) == 1
    assert entries[0].finding.severity == "CRITICAL"


def test_build_triage_entries_filters_rejected(temp_db, sample_nuclei_harvest_json):
    temp_db.upsert_finding({
        "id": "abc123def456", "source_tool": "apifuzz.py", "host": "h",
        "url": "u", "vuln_class_key": "BOLA_POSSIBLE", "severity": "HIGH",
        "title": "x", "disposition": "rejected",
    })
    entries = build_triage_entries(sample_nuclei_harvest_json["findings"], temp_db)
    assert len(entries) == 1
    assert entries[0].finding.severity == "CRITICAL"


def test_build_triage_entries_persists_findings(temp_db, sample_nuclei_harvest_json):
    entries = build_triage_entries(sample_nuclei_harvest_json["findings"], temp_db)
    # All findings should now be in the DB
    counts = temp_db.count_findings()
    assert counts.get("new", 0) == 2


def test_render_queue_md_has_checkboxes(temp_db, sample_nuclei_harvest_json):
    entries = build_triage_entries(sample_nuclei_harvest_json["findings"], temp_db)
    md = render_queue_md(entries, top=10)
    assert "# Triage Queue" in md
    assert "CRITICAL" in md
    assert "[ ] review" in md
    assert "[ ] submit" in md


def test_generate_writeup_h1_format():
    from toolkit.infra.finding import NormalizedFinding
    f = NormalizedFinding(
        source_tool="apifuzz.py", host="api.example.com",
        url="https://api.example.com/v1/users/1",
        vuln_class_key="BOLA_CONFIRMED", severity="CRITICAL",
        title="Test IDOR",
        detail="A test finding.", evidence="ev1",
        curl_command="curl -sk https://api.example.com/v1/users/1",
        remediation="Fix it.", cvss_vector="CVSS:3.1/AV:N",
        cwe="CWE-639", owasp="A01:2021",
    )
    md = generate_writeup(f, format="h1")
    assert "# Test IDOR" in md
    assert "CRITICAL" in md
    assert "api.example.com" in md
    assert "## Summary" in md
    assert "## Steps to Reproduce" in md
    assert "## Impact" in md
    assert "## Remediation" in md
    assert "curl -sk" in md


def test_generate_writeup_bc_format():
    from toolkit.infra.finding import NormalizedFinding
    f = NormalizedFinding(
        source_tool="t", host="h", vuln_class_key="X", severity="HIGH",
        title="T", detail="D", evidence="E", curl_command="curl",
        remediation="R",
    )
    txt = generate_writeup(f, format="bc")
    assert "Title: T" in txt
    assert "Severity: HIGH" in txt
    assert "Host: h" in txt


def test_generate_writeup_invalid_format():
    from toolkit.infra.finding import NormalizedFinding
    f = NormalizedFinding(source_tool="t", host="h", vuln_class_key="X",
                          severity="HIGH", title="T")
    with pytest.raises(ValueError):
        generate_writeup(f, format="bogus")


def test_batch_triage_applies_csv(temp_db, tmp_path, sample_nuclei_harvest_json):
    entries = build_triage_entries(sample_nuclei_harvest_json["findings"], temp_db)
    # Build a CSV marking the apifuzz finding as submitted
    csv_path = tmp_path / "dispositions.csv"
    csv_path.write_text(
        "finding_id,disposition,note\n"
        "abc123def456,submitted,confirmed via Burp\n"
        "def789abc012,rejected,false positive\n",
        encoding="utf-8",
    )
    writeup_dir = tmp_path / "reports"
    count = batch_triage(entries, temp_db, csv_path, writeup_dir=writeup_dir)
    assert count == 2
    # Verify the disposition was persisted
    f1 = temp_db.get_finding("abc123def456")
    assert f1["disposition"] == "submitted"
    # Verify the writeup was written
    h1_files = list(writeup_dir.glob("h1_*.md"))
    assert len(h1_files) == 1


def test_interactive_triage_eof_exits_cleanly(temp_db, sample_nuclei_harvest_json, capsys):
    """If stdin is closed (EOF), interactive_triage should exit cleanly."""
    import io, sys
    entries = build_triage_entries(sample_nuclei_harvest_json["findings"], temp_db)
    old_stdin = sys.stdin
    sys.stdin = io.StringIO("")  # immediate EOF
    try:
        count = interactive_triage(entries, temp_db, top=10, writeup_dir=None)
    finally:
        sys.stdin = old_stdin
    # Should not raise; count is whatever was recorded before EOF (0 in this case)
    assert count == 0
