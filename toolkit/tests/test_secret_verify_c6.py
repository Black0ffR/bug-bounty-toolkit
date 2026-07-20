#!/usr/bin/env python3
"""Tests for C6: secret_verify provider registry + entry points."""

import pytest

from toolkit.verify import secret_verify as m
from toolkit.verify.secret_verify import SecretCheck


def test_registry_lists_builtin_providers():
    provs = m.list_providers()
    for expected in ("aws_access_key_id", "github_pat", "google_api_key",
                     "jwt", "slack", "stripe"):
        assert expected in provs


def test_resolve_exact_provider():
    assert m.resolve_provider_handler("aws_access_key_id") is m.PROVIDER_HANDLERS["aws_access_key_id"]


def test_resolve_prefix_provider():
    # slack_bot_token / slack_webhook resolve via the 'slack' prefix handler
    assert m.resolve_provider_handler("slack_bot_token") is m.PROVIDER_PREFIX_HANDLERS["slack"]
    assert m.resolve_provider_handler("stripe_secret_key") is m.PROVIDER_PREFIX_HANDLERS["stripe"]


def test_resolve_unknown_returns_none():
    assert m.resolve_provider_handler("nonexistent_xyz") is None
    assert m.resolve_provider_handler("") is None


def test_register_provider_override_and_new():
    called = {}

    async def fake_handler(value, *, paired_secret=None):
        called["v"] = value
        return SecretCheck(raw_value=value, provider="custom_p", is_live=True,
                           identity="", detail="ok", redacted_value=value[:4])

    m.register_provider("custom_p", fake_handler)
    assert "custom_p" in m.list_providers()
    h = m.resolve_provider_handler("custom_p")
    assert h is fake_handler


def test_verify_secret_uses_registry_for_aws(capsys):
    # A non-placeholder AWS key triggers the registered handler (network may
    # fail, but the registry path must be taken, not the old if/elif chain).
    import asyncio
    # AKIAEXAMPLE1111111111 is NOT a placeholder under the tightened boundary
    # rule (the 'example' substring must be a standalone token), so this goes
    # through the registered AWS handler — which returns early (no network) when
    # the secret is absent. That still proves the registry dispatch path is used.
    res = asyncio.run(m.verify_secret("AKIAEXAMPLE1111111111", provider_hint="aws_access_key_id"))
    assert res.provider == "aws_access_key_id"
    assert "placeholder" not in res.detail.lower()
    assert "cannot verify" in res.detail.lower()


def test_verify_secret_unknown_provider_is_candidate():
    import asyncio
    res = asyncio.run(m.verify_secret("zzz_not_a_real_key_1234567890", provider_hint="gitlab_token"))
    assert res.provider == "gitlab_token"
    assert "candidate" in res.detail.lower()
