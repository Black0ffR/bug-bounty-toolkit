"""Unit tests for toolkit.verify.xss_context — context detection + payloads."""
from __future__ import annotations

from toolkit.verify.xss_context import (
    _detect_contexts,
    _pick_payload,
    _PAYLOADS,
)


def test_single_quoted_attribute_context():
    body = "<input type='PROBE123'>"
    assert _detect_contexts("PROBE123", body) == ["html_attribute_'"]


def test_double_quoted_attribute_context():
    body = '<input type="PROBE123">'
    assert _detect_contexts("PROBE123", body) == ['html_attribute_"']


def test_unquoted_attribute_context():
    body = "<input value=PROBE123>"
    assert _detect_contexts("PROBE123", body) == ["html_attribute_"]


def test_html_body_context():
    body = "<p>PROBE123</p>"
    assert _detect_contexts("PROBE123", body) == ["html_body"]


def test_script_block_context():
    body = "<script>var x='PROBE123';</script>"
    assert _detect_contexts("PROBE123", body) == ["script_block"]


def test_url_context():
    body = '<a href="PROBE123">'
    assert _detect_contexts("PROBE123", body) == ["url"]


def test_per_attribute_payloads_exist():
    for ctx in ('html_attribute_"', "html_attribute_'", "html_attribute_"):
        assert ctx in _PAYLOADS
        assert _pick_payload(ctx, "TK") is not None
        # single-quoted context payloads must break out of single quotes
        if ctx == "html_attribute_'":
            assert "' onmouseover" in _pick_payload(ctx, "TK")
