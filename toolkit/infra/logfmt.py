#!/usr/bin/env python3
"""
logfmt.py — shared logging configuration for toolkit tools
===========================================================

Provides a ``JsonFormatter`` that emits one JSON object per log line (machine
parseable) and a ``configure_logging`` helper so every tool can switch between
human-readable and JSON logs via ``--log-format`` (C20).

Usage (in a tool's main):
    from toolkit.infra import logfmt
    args = parse_args()
    logfmt.configure_logging(
        format=args.log_format,            # "text" (default) or "json"
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

JSON lines look like:
    {"ts": "2026-07-18T12:00:00Z", "level": "INFO", "logger": "apifuzz", "msg": "..."}

Author : Bug Bounty Toolkit / Layer 0
License : MIT (for authorized use only)
"""

from __future__ import annotations

import datetime
import json
import logging
from typing import Any

_JSON_HANDLER = "toolkit.infra.logfmt.JsonFormatter"


class JsonFormatter(logging.Formatter):
    """Render a log record as a single-line JSON object (C20)."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.datetime.fromtimestamp(
                record.created, datetime.timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(*, fmt: str = "text", level: int = logging.INFO) -> None:
    """Apply a logging format to the root logger.

    ``fmt`` is "text" (default, colored-ish %(levelname)s %(message)s) or
    "json" (one object per line). Idempotent: re-applying just swaps the
    handler formatter, so repeated calls from imported modules are safe.
    """
    root = logging.getLogger()
    root.setLevel(level)

    # Remove any previous handler installed by this helper to avoid duplicates
    for h in list(root.handlers):
        if getattr(h, "_toolkit_logfmt", False):
            root.removeHandler(h)

    handler = logging.StreamHandler()
    handler._toolkit_logfmt = True  # type: ignore[attr-defined]
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    root.addHandler(handler)
