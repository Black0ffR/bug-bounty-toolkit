"""Pluggable alert notifier (Discord / Slack / generic webhook).
==============================================================

watch_daemon.py and triage_memory.py can push alerts to a chat channel instead
of (or in addition to) writing them to the DB. The transport is pluggable: by
default it POSTs JSON to a webhook URL via the shared httpx pool; for testing,
pass ``send_func`` to capture/assert the payload without any network I/O.

Usage
-----
    from toolkit.infra.notifier import Notifier, from_env

    n = from_env()                      # reads BBTK_WEBHOOK_URL / BBTK_WEBHOOK_KIND
    if n:
        n.notify("New subdomain", "api.acme.com appeared", severity="HIGH")

Author : Bug Bounty Toolkit / Tier 1
License : MIT (for authorized use only)
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, Callable

from toolkit.infra import http_pool


log = logging.getLogger("notifier")

SendFunc = Callable[[str, dict[str, Any], dict[str, str]], bool]


class Notifier:
    """POSTs alert payloads to a webhook. ``send_func`` is injectable for tests."""

    def __init__(self, webhook_url: str, kind: str = "discord", *,
                 send_func: SendFunc | None = None, timeout: float = 10.0) -> None:
        self.webhook_url = webhook_url
        self.kind = (kind or "discord").lower()
        self._timeout = timeout
        self._send: SendFunc = send_func or self._default_send

    # ── Formatting ──────────────────────────────────────────────────────────

    def format(self, title: str, message: str, *, severity: str | None = None) -> dict[str, Any]:
        tag = severity or "ALERT"
        if self.kind == "discord":
            return {"content": f"**[{tag}]** {title}\n{message}"}
        if self.kind == "slack":
            return {"text": f"*[{tag}]* {title}\n{message}"}
        # generic / telegram (sendMessage uses text)
        return {"text": f"[{tag}] {title}\n{message}"}

    # ── Transport ───────────────────────────────────────────────────────────

    def _default_send(self, url: str, payload: dict[str, Any], headers: dict[str, str]) -> bool:
        async def _go() -> bool:
            client = await http_pool.get_shared_client(timeout=self._timeout)
            resp = await client.post(url, json=payload, headers=headers)
            return 200 <= int(resp.status_code) < 300
        try:
            return asyncio.run(_go())
        except Exception as exc:  # network/timeout — never crash the pipeline
            log.warning("notify to %s failed: %s", url, exc)
            return False

    def notify(self, title: str, message: str, *, severity: str | None = None) -> bool:
        """Send an alert. Returns True if the webhook accepted it."""
        payload = self.format(title, message, severity=severity)
        headers = {"Content-Type": "application/json"}
        return self._send(self.webhook_url, payload, headers)


def from_env(*, send_func: SendFunc | None = None) -> Notifier | None:
    """Build a Notifier from environment variables, or None if unconfigured."""
    url = os.environ.get("BBTK_WEBHOOK_URL", "").strip()
    if not url:
        return None
    kind = os.environ.get("BBTK_WEBHOOK_KIND", "discord").strip()
    return Notifier(url, kind=kind, send_func=send_func)


def from_config(config: dict[str, Any], *, send_func: SendFunc | None = None) -> Notifier | None:
    """Build a Notifier from a config dict with ``webhook_url`` / ``webhook_kind``."""
    url = (config.get("webhook_url") or "").strip()
    if not url:
        return None
    kind = config.get("webhook_kind", "discord")
    return Notifier(url, kind=kind, send_func=send_func)
