#!/usr/bin/env python3
"""
config.py — per-target YAML configuration loader (C21)
======================================================

Lets any tool accept a ``--config target.yaml`` file that supplies defaults for
its CLI options. Values from the file are applied only when the corresponding
CLI flag was *not* explicitly provided (heuristic: None / False / empty list /
empty string count as "not provided"), so the CLI always wins.

Config file shape is just ``key: value`` pairs matching argparse dest names::

    timeout: 15.0
    concurrency: 8
    user_agent: "Mozilla/5.0 (audit)"
    session_a: "eyJ...Bearer token"

Author : Bug Bounty Toolkit / Layer 0
License : MIT (for authorized use only)
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import yaml


def load_config(path: str | Path) -> dict[str, Any]:
    """Load a per-target YAML config file. Returns {} on empty file."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"config file not found: {path}")
    with p.open() as fh:
        data = yaml.safe_load(fh)
    return data or {}


def _is_unset(value: Any) -> bool:
    """A CLI value counts as 'not provided' when it is unset/empty."""
    if value is None or value is False:
        return True
    if isinstance(value, (list, str, tuple)) and len(value) == 0:
        return True
    return False


def overlay_config(args: argparse.Namespace, path: str | Path) -> argparse.Namespace:
    """Apply YAML defaults onto ``args`` for unset fields. CLI wins."""
    data = load_config(path)
    for key, val in data.items():
        if not hasattr(args, key):
            setattr(args, key, val)
            continue
        if _is_unset(getattr(args, key)):
            setattr(args, key, val)
    return args
