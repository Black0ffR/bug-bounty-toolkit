#!/usr/bin/env python3
"""Tests for C29: pipeline_state FTS synonym expansion."""

from toolkit.infra import pipeline_state as m


def test_expand_query_adds_synonyms():
    out = m._expand_fts_query("xss")
    assert "xss" in out
    assert "cross-site scripting" in out
    assert " OR " in out


def test_expand_query_passthrough_unknown():
    assert m._expand_fts_query("zzznotreal") == "zzznotreal"
    # multiword unknown → keep quoted tokens joined by OR
    assert " OR " in m._expand_fts_query("foo bar")


def test_search_xss_matches_cross_site_scripting(tmp_path):
    db = tmp_path / "pipeline_state.db"
    st = m.PipelineState(db)
    try:
        st.upsert_finding({
            "id": "x1", "source_tool": "xss_reflected.py", "host": "h.com",
            "url": "https://h.com/s", "vuln_class_key": "XSS_REFL",
            "severity": "HIGH", "title": "Reflected input",
            "detail": "potential cross-site scripting in the q parameter",
            "confidence": "candidate", "disposition": "new",
        })
        res = st.search_findings("xss")
        assert any(r["id"] == "x1" for r in res)
        # also the reverse direction
        res2 = st.search_findings("cross-site scripting")
        assert any(r["id"] == "x1" for r in res2)
    finally:
        st.close()


def test_search_ssrf_synonym(tmp_path):
    db = tmp_path / "pipeline_state.db"
    st = m.PipelineState(db)
    try:
        st.upsert_finding({
            "id": "s1", "source_tool": "ssrf.py", "host": "h.com",
            "url": "https://h.com/u", "vuln_class_key": "SSRF",
            "severity": "HIGH", "title": "SSRF",
            "detail": "server side request forgery via url param",
            "confidence": "candidate", "disposition": "new",
        })
        res = st.search_findings("ssrf")
        assert any(r["id"] == "s1" for r in res)
    finally:
        st.close()
