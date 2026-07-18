#!/usr/bin/env python3
"""Tests for C1 (FTS5 search) and C2 (sqlite3 backup) in pipeline_state."""

import os
import sqlite3

from toolkit.infra import pipeline_state as m


def _sample(ident, title, detail, host="api.target.com", vc="BOLA"):
    return {
        "id": ident, "source_tool": "apifuzz.py", "host": host,
        "url": f"https://{host}/x", "vuln_class_key": vc, "severity": "HIGH",
        "title": title, "detail": detail, "confidence": "candidate",
        "disposition": "new",
    }


def test_fts_search_finds_by_title(tmp_path):
    db = tmp_path / "pipeline_state.db"
    st = m.PipelineState(db)
    try:
        st.upsert_finding(_sample("a1", "Broken Object Level Auth on /api/order", "id param", "a.com"))
        st.upsert_finding(_sample("a2", "Reflected XSS in search", "q param", "b.com"))
        results = st.search_findings("Broken Object")
        ids = {r["id"] for r in results}
        assert "a1" in ids
        assert "a2" not in ids
    finally:
        st.close()


def test_fts_search_finds_by_detail(tmp_path):
    db = tmp_path / "pipeline_state.db"
    st = m.PipelineState(db)
    try:
        st.upsert_finding(_sample("b1", "Endpoint A", "ssrf via url parameter to metadata", "c.com"))
        res = st.search_findings("metadata")
        assert any(r["id"] == "b1" for r in res)
    finally:
        st.close()


def test_fts_search_finds_by_vuln_class(tmp_path):
    db = tmp_path / "pipeline_state.db"
    st = m.PipelineState(db)
    try:
        st.upsert_finding(_sample("c1", "t", "d", "d.com", vc="SSRF_POSSIBLE"))
        res = st.search_findings("SSRF_POSSIBLE")
        assert any(r["id"] == "c1" for r in res)
    finally:
        st.close()


def test_fts_rebuild_reindexes(tmp_path):
    db = tmp_path / "pipeline_state.db"
    st = m.PipelineState(db)
    try:
        st.upsert_finding(_sample("d1", "orig title", "orig detail", "e.com"))
        # tamper the fts row directly to simulate drift
        with st._lock:
            st._conn.execute("DELETE FROM findings_fts WHERE finding_id = 'd1'")
            st._conn.commit()
        assert st.search_findings("orig") == []
        n = st.rebuild_fts()
        assert n >= 1
        assert any(r["id"] == "d1" for r in st.search_findings("orig"))
    finally:
        st.close()


def test_backup_creates_file_and_prunes(tmp_path):
    db = tmp_path / "pipeline_state.db"
    st = m.PipelineState(db)
    try:
        st.upsert_finding(_sample("e1", "t", "d", "f.com"))
        backup_dir = tmp_path / "backups"
        paths = [st._backup(backup_dir, keep=3) for _ in range(6)]
        # every call produced a distinct, valid backup path
        assert len(set(paths)) == 6
        # pruned to 3 (oldest removed)
        remaining = sorted(backup_dir.glob("pipeline_state_*.db"))
        assert len(remaining) == 3
        assert all(os.path.exists(p) for p in remaining)
        # backup is a valid sqlite db with our finding
        bc = sqlite3.connect(str(remaining[-1]))
        try:
            rows = bc.execute("SELECT id FROM findings_history").fetchall()
            assert any(r[0] == "e1" for r in rows)
        finally:
            bc.close()
    finally:
        st.close()
