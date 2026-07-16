"""Unit tests for toolkit.infra.pipeline_state."""
from __future__ import annotations

import pytest

from toolkit.infra.pipeline_state import PipelineState


def test_upsert_finding_first_time_returns_true(temp_db):
    is_new = temp_db.upsert_finding({
        "id": "abc", "source_tool": "t", "host": "h", "url": "u",
        "vuln_class_key": "BOLA_POSSIBLE", "severity": "HIGH", "title": "x",
    })
    assert is_new is True


def test_upsert_finding_second_time_returns_false(temp_db):
    temp_db.upsert_finding({
        "id": "abc", "source_tool": "t", "host": "h", "url": "u",
        "vuln_class_key": "BOLA_POSSIBLE", "severity": "HIGH", "title": "x",
    })
    is_new = temp_db.upsert_finding({
        "id": "abc", "source_tool": "t", "host": "h", "url": "u",
        "vuln_class_key": "BOLA_POSSIBLE", "severity": "HIGH", "title": "x",
    })
    assert is_new is False


def test_mark_disposition_filters_from_active(temp_db):
    temp_db.upsert_finding({
        "id": "abc", "source_tool": "t", "host": "h", "url": "u",
        "vuln_class_key": "BOLA_POSSIBLE", "severity": "HIGH", "title": "x",
    })
    temp_db.mark_disposition("abc", "submitted")
    active = temp_db.get_active_findings()
    assert all(f["id"] != "abc" for f in active)


def test_mark_disposition_rejected_excludes(temp_db):
    temp_db.upsert_finding({
        "id": "r1", "source_tool": "t", "host": "h", "url": "u",
        "vuln_class_key": "X", "severity": "MEDIUM", "title": "r",
    })
    temp_db.mark_disposition("r1", "rejected")
    assert all(f["id"] != "r1" for f in temp_db.get_active_findings())


def test_mark_disposition_reviewed_stays_active(temp_db):
    temp_db.upsert_finding({
        "id": "rev1", "source_tool": "t", "host": "h", "url": "u",
        "vuln_class_key": "X", "severity": "MEDIUM", "title": "r",
    })
    temp_db.mark_disposition("rev1", "reviewed")
    active = temp_db.get_active_findings()
    assert any(f["id"] == "rev1" for f in active)


def test_invalid_disposition_rejected(temp_db):
    with pytest.raises(ValueError):
        temp_db.mark_disposition("x", "bogus")


def test_get_active_findings_severity_sorted(temp_db):
    # Insert in mixed severity order
    for i, sev in enumerate(["LOW", "CRITICAL", "MEDIUM", "HIGH"]):
        temp_db.upsert_finding({
            "id": f"f{i}", "source_tool": "t", "host": "h", "url": "u",
            "vuln_class_key": "X", "severity": sev, "title": f"t{i}",
        })
    active = temp_db.get_active_findings()
    assert [f["severity"] for f in active] == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def test_count_findings_by_disposition(temp_db):
    for i, disp in enumerate(["new", "new", "submitted", "rejected", "reviewed"]):
        temp_db.upsert_finding({
            "id": f"c{i}", "source_tool": "t", "host": "h", "url": "u",
            "vuln_class_key": "X", "severity": "LOW", "title": "x",
        })
        if disp != "new":
            temp_db.mark_disposition(f"c{i}", disp)
    counts = temp_db.count_findings()
    assert counts.get("new") == 2
    assert counts.get("submitted") == 1
    assert counts.get("rejected") == 1
    assert counts.get("reviewed") == 1


def test_start_run_and_update(temp_db):
    rid = temp_db.start_run("example.com", scope_yaml="scope.yaml", mode="quick", stages_total=5)
    assert isinstance(rid, int) and rid > 0
    temp_db.update_run(rid, stages_completed=3, stages_failed=0)
    temp_db.update_run(rid, finished=True, summary={"ok": True})
    last = temp_db.get_last_run("example.com")
    assert last is not None
    assert last["stages_completed"] == 3
    assert last["finished_at"] is not None


def test_record_and_diff_assets(temp_db):
    rid = temp_db.start_run("example.com")
    temp_db.record_assets("example.com", scan_run_id=rid,
                          subdomains=["www.example.com", "api.example.com"])
    # Diff with a new subdomain added
    diffs = temp_db.diff_assets("example.com",
                                subdomains=["www.example.com", "new.example.com"])
    assert "subdomain" in diffs
    assert "new.example.com" in diffs["subdomain"].added
    assert "api.example.com" in diffs["subdomain"].removed


def test_record_multiple_asset_kinds(temp_db):
    rid = temp_db.start_run("example.com")
    temp_db.record_assets("example.com", scan_run_id=rid,
                          subdomains=["a.example.com"],
                          js_hashes=["sha256:abc"],
                          params=["user_id"],
                          endpoints=["/api/v1/users"])
    history = temp_db.get_asset_history("example.com", asset_kind="subdomain")
    assert len(history) == 1
    assert history[0]["asset_value"] == "a.example.com"


def test_get_findings_by_host(temp_db):
    temp_db.upsert_finding({
        "id": "h1", "source_tool": "t", "host": "host1.com", "url": "u",
        "vuln_class_key": "X", "severity": "HIGH", "title": "x",
    })
    temp_db.upsert_finding({
        "id": "h2", "source_tool": "t", "host": "host2.com", "url": "u",
        "vuln_class_key": "X", "severity": "HIGH", "title": "x",
    })
    h1 = temp_db.get_findings_by_host("host1.com")
    assert len(h1) == 1
    assert h1[0]["id"] == "h1"


def test_migrate_from_v0_adds_column(tmp_path):
    db = tmp_path / "ps.db"
    # Build a v0 database: base schema + schema_meta pinned at version 0,
    # but WITHOUT the v1 'tags' column.
    import sqlite3 as _sql

    from toolkit.infra import pipeline_state as psmod
    conn = _sql.connect(str(db))
    conn.executescript(psmod.SCHEMA_SQL)
    conn.executescript(psmod.SCHEMA_META_SQL)
    conn.execute("INSERT INTO schema_meta(key, value) VALUES('version', '0')")
    conn.commit()
    conn.close()

    # Reopen → should migrate v0 -> v1 and add the 'tags' column.
    state = psmod.PipelineState(db)
    cols = {r["name"] for r in state._conn.execute(
        "PRAGMA table_info(findings_history)")}
    assert "tags" in cols
    assert state._get_schema_version() == psmod.SCHEMA_VERSION
    state.close()
