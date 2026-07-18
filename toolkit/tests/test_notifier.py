"""Tests for toolkit.infra.notifier (Phase B: B20 pluggable alerting)."""
from __future__ import annotations

import os

from toolkit.infra import notifier


def test_format_discord():
    n = notifier.Notifier("https://hooks/discord", kind="discord")
    p = n.format("Title", "body", severity="HIGH")
    assert p["content"] == "**[HIGH]** Title\nbody"


def test_format_slack():
    n = notifier.Notifier("https://hooks/slack", kind="slack")
    p = n.format("Title", "body")
    assert p["text"].startswith("*[ALERT]* Title")


def test_notify_success_via_send_func():
    calls = []
    def fake(url, payload, headers):
        calls.append((url, payload, headers))
        return True
    n = notifier.Notifier("https://hooks/x", kind="discord", send_func=fake)
    assert n.notify("T", "M", severity="LOW") is True
    assert calls[0][0] == "https://hooks/x"
    assert calls[0][2]["Content-Type"] == "application/json"


def test_notify_failure_returns_false():
    n = notifier.Notifier("https://hooks/x", send_func=lambda u, p, h: False)
    assert n.notify("T", "M") is False


def test_from_env_none_when_unset(monkeypatch):
    monkeypatch.delenv("BBTK_WEBHOOK_URL", raising=False)
    assert notifier.from_env() is None


def test_from_env_builds(monkeypatch):
    monkeypatch.setenv("BBTK_WEBHOOK_URL", "https://hooks/x")
    monkeypatch.setenv("BBTK_WEBHOOK_KIND", "slack")
    n = notifier.from_env()
    assert n is not None
    assert n.kind == "slack"
    assert n.webhook_url == "https://hooks/x"
