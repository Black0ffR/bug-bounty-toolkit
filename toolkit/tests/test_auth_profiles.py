"""Unit tests for toolkit.infra.auth_profiles."""
from __future__ import annotations

import datetime

import pytest

from toolkit.infra import auth_profiles as _ap
from toolkit.infra.auth_profiles import (
    AuthProfiles,
    Profile,
    AuthenticatedSession,
    redact_value,
    redact_dict,
)

_HAS_YAML = _ap._HAS_YAML


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


def test_expires_at_triggers_proactive_refresh():
    state = {"calls": 0}
    exp = (datetime.datetime.now(datetime.timezone.utc) +
           datetime.timedelta(seconds=30)).isoformat()
    p = Profile(name="x", bearer="original", expires_at=exp,
                refresh_callback=lambda: state.__setitem__("calls", state["calls"] + 1) or "fresh")
    p.maybe_refresh()  # within 60s of expiry → refresh
    assert state["calls"] == 1
    assert p.bearer == "fresh"


def test_expires_at_far_future_skips_refresh():
    state = {"calls": 0}
    exp = (datetime.datetime.now(datetime.timezone.utc) +
           datetime.timedelta(seconds=3600)).isoformat()
    p = Profile(name="x", bearer="original", expires_at=exp,
                refresh_callback=lambda: state.__setitem__("calls", state["calls"] + 1) or "fresh")
    p.maybe_refresh()  # first call always refreshes (last_refresh unset)
    assert state["calls"] == 1
    # second call soon after: far from expiry AND within max_age → no refresh
    p.maybe_refresh()
    assert state["calls"] == 1
    assert p.bearer == "fresh"


def test_yaml_expires_at_loaded(tmp_path):
    if not _HAS_YAML:
        pytest.skip("PyYAML not installed")
    text = (
        "profiles:\n"
        "  user_a:\n"
        "    cookie: 'session=abc'\n"
        "    expires_at: '2030-01-01T00:00:00+00:00'\n"
    )
    f = tmp_path / "ap.yaml"
    f.write_text(text)
    ap = AuthProfiles(f)
    assert ap.get_profile("user_a").expires_at == "2030-01-01T00:00:00+00:00"


def test_auth_header_names_parsed_and_union(tmp_path):
    if not _HAS_YAML:
        pytest.skip("PyYAML not installed")
    text = (
        "profiles:\n"
        "  user_a:\n"
        "    cookie: 'session=abc'\n"
        "    auth_header_names:\n"
        "      - X-Auth-Token\n"
        "  user_b:\n"
        "    cookie: 'session=def'\n"
        "    auth_header_names:\n"
        "      - X-Api-Token\n"
    )
    f = tmp_path / "ap.yaml"
    f.write_text(text)
    ap = AuthProfiles(f)
    assert ap.get_profile("user_a").auth_header_names == ["X-Auth-Token"]
    assert set(ap.auth_header_names) == {"x-auth-token", "x-api-token"}
