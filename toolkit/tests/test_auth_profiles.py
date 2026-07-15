"""Unit tests for toolkit.infra.auth_profiles."""
from __future__ import annotations

import pytest

from toolkit.infra.auth_profiles import (
    AuthProfiles,
    Profile,
    AuthenticatedSession,
    redact_value,
    redact_dict,
)


def test_load_two_users(temp_auth_profiles_yaml):
    ap = AuthProfiles(temp_auth_profiles_yaml)
    assert "user_a" in ap.profiles
    assert "user_b" in ap.profiles
    assert "anon" in ap.profiles
    a, b = ap.require_two_users()
    assert a.name == "user_a"
    assert b.name == "user_b"
    assert a.user_id == 1
    assert b.user_id == 2


def test_auth_headers_bearer():
    p = Profile(name="x", bearer="tok123")
    h = p.auth_headers()
    assert h["Authorization"] == "Bearer tok123"


def test_auth_headers_bearer_already_prefixed():
    p = Profile(name="x", bearer="Bearer already")
    h = p.auth_headers()
    assert h["Authorization"] == "Bearer already"


def test_auth_headers_cookie_and_custom():
    p = Profile(
        name="x",
        cookie="session=abc",
        headers={"X-User-Role": "admin", "X-Trace-Id": "123"},
    )
    h = p.auth_headers()
    assert h["Cookie"] == "session=abc"
    assert h["X-User-Role"] == "admin"
    assert h["X-Trace-Id"] == "123"


def test_redact_value_masks_long_secrets():
    assert redact_value("cookie", "session=abc123def456") == "sess…<redacted>"
    # Short values get fully redacted
    assert redact_value("password", "abc") == "<redacted>"
    # Non-sensitive keys pass through
    assert redact_value("host", "example.com") == "example.com"


def test_redact_dict_recursive():
    d = {
        "cookie": "session=verylongtokenvaluehere",
        "host": "example.com",
        "nested": {"bearer": "verylongbearertoken", "ok": "visible"},
    }
    r = redact_dict(d)
    assert "<redacted>" in r["cookie"]
    assert r["host"] == "example.com"
    assert "<redacted>" in r["nested"]["bearer"]
    assert r["nested"]["ok"] == "visible"


def test_get_session_returns_authenticated_session(temp_auth_profiles_yaml):
    ap = AuthProfiles(temp_auth_profiles_yaml)
    sess = ap.get_session("user_a", timeout=5.0)
    assert isinstance(sess, AuthenticatedSession)
    assert sess.profile.name == "user_a"
    headers = sess.profile.auth_headers()
    assert headers["Cookie"] == "session=user-a"


def test_require_two_users_raises_with_only_anon(tmp_path):
    p = tmp_path / "auth_profiles.yaml"
    p.write_text("profiles:\n  anon: {}\n", encoding="utf-8")
    ap = AuthProfiles(p)
    with pytest.raises(RuntimeError, match="at least two authenticated"):
        ap.require_two_users()


def test_profile_with_api_key():
    p = Profile(name="svc", api_key="sk_test_123")
    h = p.auth_headers()
    assert h["X-Api-Key"] == "sk_test_123"


def test_maybe_refresh_no_callback_is_noop():
    p = Profile(name="x", bearer="original")
    p.maybe_refresh()  # should not raise
    assert p.bearer == "original"


def test_maybe_refresh_invokes_callback():
    state = {"calls": 0}
    def cb():
        state["calls"] += 1
        return "fresh_token"
    p = Profile(name="x", bearer="original", refresh_callback=cb)
    p.maybe_refresh(max_age=0.001)  # force refresh on first call
    assert state["calls"] == 1
    assert p.bearer == "fresh_token"
