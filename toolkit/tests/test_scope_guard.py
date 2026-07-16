"""Unit tests for toolkit.infra.scope_guard."""
from __future__ import annotations

import pytest

from toolkit.infra.scope_guard import (
    ScopeGuard,
    ScopeError,
    _fallback_yaml_parse,
    _CrossProcessGate,
    configure,
    get_default,
    check_scope as default_check_scope,
)


def test_wildcard_matches_subdomain(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text(
        "program: acme\n"
        "in_scope:\n"
        "  - '*.acme.com'\n"
        "out_of_scope: []\n"
        "rate_limit:\n"
        "  max_rps: 5\n"
        "  max_concurrent: 10\n"
        "automation_allowed: true\n",
        encoding="utf-8",
    )
    g = ScopeGuard(p)
    g.check_scope("acme.com")
    g.check_scope("www.acme.com")
    g.check_scope("a.b.acme.com")
    with pytest.raises(ScopeError):
        g.check_scope("evil.com")
    with pytest.raises(ScopeError):
        g.check_scope("acme.com.evil.com")


def test_deny_wins(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text(
        "program: acme\n"
        "in_scope:\n"
        "  - '*.acme.com'\n"
        "out_of_scope:\n"
        "  - 'blog.acme.com'\n"
        "rate_limit:\n"
        "  max_rps: 5\n"
        "  max_concurrent: 10\n",
        encoding="utf-8",
    )
    g = ScopeGuard(p)
    g.check_scope("www.acme.com")
    g.check_scope("api.acme.com")
    with pytest.raises(ScopeError):
        g.check_scope("blog.acme.com")


def test_automation_disabled_blocks_all(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text(
        "program: acme\n"
        "in_scope:\n"
        "  - '*.acme.com'\n"
        "automation_allowed: false\n",
        encoding="utf-8",
    )
    g = ScopeGuard(p)
    with pytest.raises(ScopeError, match="automation_allowed"):
        g.check_scope("www.acme.com")


def test_cidr_matching(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text(
        "program: acme\n"
        "in_scope:\n"
        "  - '10.0.0.0/8'\n"
        "out_of_scope: []\n"
        "rate_limit:\n"
        "  max_rps: 5\n"
        "  max_concurrent: 10\n",
        encoding="utf-8",
    )
    g = ScopeGuard(p)
    g.check_scope("10.1.2.3")
    g.check_scope("10.255.255.255")
    with pytest.raises(ScopeError):
        g.check_scope("192.168.1.1")


def test_check_url_extracts_host(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text(
        "program: acme\n"
        "in_scope:\n"
        "  - '*.acme.com'\n"
        "rate_limit:\n"
        "  max_rps: 5\n"
        "  max_concurrent: 10\n",
        encoding="utf-8",
    )
    g = ScopeGuard(p)
    g.check_url("https://www.acme.com/path?x=1")
    with pytest.raises(ScopeError):
        g.check_url("https://evil.com/")


def test_rate_limiting_blocks_after_burst(tmp_path):
    """A token-bucket with max_rps=2 should let ~2 requests through instantly,
    then start throttling."""
    import time
    p = tmp_path / "scope.yaml"
    p.write_text(
        "program: acme\n"
        "in_scope:\n"
        "  - '*.acme.com'\n"
        "rate_limit:\n"
        "  max_rps: 2\n"
        "  max_concurrent: 100\n",
        encoding="utf-8",
    )
    g = ScopeGuard(p)
    # First two should be near-instant
    t0 = time.monotonic()
    assert g.acquire_token(timeout=1.0) is True
    assert g.acquire_token(timeout=1.0) is True
    g.release_token()
    g.release_token()
    # Third should require waiting ~0.5s for one token to refill
    assert g.acquire_token(timeout=2.0) is True
    g.release_token()


def test_fallback_yaml_parser_handles_scope_file():
    text = (
        "program: acme\n"
        "in_scope:\n"
        "  - '*.acme.com'\n"
        "  - 'api.acme-internal.io'\n"
        "out_of_scope:\n"
        "  - 'blog.acme.com'\n"
        "rate_limit:\n"
        "  max_rps: 5\n"
        "  max_concurrent: 10\n"
        "automation_allowed: true\n"
    )
    parsed = _fallback_yaml_parse(text)
    assert parsed["program"] == "acme"
    assert "*.acme.com" in parsed["in_scope"]
    assert "blog.acme.com" in parsed["out_of_scope"]
    assert parsed["automation_allowed"] is True


def test_module_level_singleton_permissive_when_unconfigured():
    # Without configure(), get_default() returns a no-op guard that allows all
    g = get_default()
    g.check_scope("any.host.example")  # should not raise


def test_blocked_log_written(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text(
        "program: acme\n"
        "in_scope:\n"
        "  - '*.acme.com'\n"
        "rate_limit:\n"
        "  max_rps: 5\n"
        "  max_concurrent: 10\n",
        encoding="utf-8",
    )
    g = ScopeGuard(p)
    try:
        g.check_scope("evil.com", source_tool="test")
    except ScopeError:
        pass
    blocked_log = p.parent / "blocked.log"
    assert blocked_log.exists()
    content = blocked_log.read_text()
    assert "evil.com" in content
    assert "test" in content


def test_request_slot_context_manager(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text(
        "program: acme\n"
        "in_scope:\n"
        "  - '*.acme.com'\n"
        "rate_limit:\n"
        "  max_rps: 100\n"
        "  max_concurrent: 10\n",
        encoding="utf-8",
    )
    g = ScopeGuard(p)
    with g.request_slot("www.acme.com", source_tool="test"):
        pass  # would do the request here
    with pytest.raises(ScopeError):
        with g.request_slot("evil.com", source_tool="test"):
            pass


def test_cross_process_gate_limits_concurrency(tmp_path):
    """The gate must refuse a slot once max_concurrent are held, even within a
    single process (which exercises the flock path on a fresh fd per acquire)."""
    import time

    gate = _CrossProcessGate(2, tmp_path / "slots")
    fh1 = gate.acquire(timeout=1.0)
    assert fh1 is not None
    fh2 = gate.acquire(timeout=1.0)
    assert fh2 is not None
    # Third acquire should time out — both slots are held.
    assert gate.acquire(timeout=0.2) is None
    # Releasing one frees a slot.
    gate.release(fh2)
    assert gate.acquire(timeout=1.0) is not None
    gate.release(fh1)
