"""Tests for C16: apifuzz.py cookie-shaped --session-a detection."""

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_SCRIPTS = str(_REPO_ROOT / "scripts")
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)

import apifuzz  # noqa: E402


def test_detect_session_shape_jwt():
    assert apifuzz.detect_session_shape("Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig") == "jwt"


def test_detect_session_shape_bare_jwt():
    assert apifuzz.detect_session_shape("eyJhbGciOiJIUzI1NiJ9.payload.sig") == "jwt"


def test_detect_session_shape_basic():
    assert apifuzz.detect_session_shape("Basic dXNlcjpwYXNz") == "basic"


def test_detect_session_shape_cookie_bare():
    assert apifuzz.detect_session_shape("session=abc123") == "cookie"


def test_detect_session_shape_cookie_prefixed():
    assert apifuzz.detect_session_shape("Cookie: session=abc123") == "cookie"


def test_detect_session_shape_raw():
    assert apifuzz.detect_session_shape("opaque-token-xyz") == "raw"


def test_detect_session_shape_none():
    assert apifuzz.detect_session_shape("") == "none"


def test_build_auth_headers_cookie_uses_cookie_header():
    assert apifuzz.build_auth_headers("session=abc123") == {"Cookie": "session=abc123"}


def test_build_auth_headers_cookie_prefixed_strips_prefix():
    assert apifuzz.build_auth_headers("Cookie: session=abc123") == {"Cookie": "session=abc123"}


def test_build_auth_headers_bearer_jwt():
    assert apifuzz.build_auth_headers("Bearer eyJhbGciOiJIUzI1NiJ9.a.b") == {
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.a.b"}


def test_build_auth_headers_raw_becomes_bearer():
    assert apifuzz.build_auth_headers("opaque") == {"Authorization": "Bearer opaque"}


def test_auth_headers_backward_compatible():
    # existing call sites still get Authorization headers
    assert apifuzz._auth_headers("Bearer x") == {"Authorization": "Bearer x"}
    assert apifuzz._auth_headers(None) == {}
