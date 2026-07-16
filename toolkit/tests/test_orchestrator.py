"""Tests for orchestrator.py repo-root wiring (Phase A: A1, A2)."""

from __future__ import annotations

import sys

import pytest

# Importable because conftest.py puts the project root on sys.path.
import orchestrator


def test_subprocess_env_injects_repo_root(monkeypatch):
    """_subprocess_env must prepend the repo root to PYTHONPATH so spawned
    scripts can import sibling packages (toolkit, oob_catcher)."""
    monkeypatch.delenv("PYTHONPATH", raising=False)
    env = orchestrator._subprocess_env()
    paths = env["PYTHONPATH"].split(orchestrator.os.pathsep)
    assert paths[0] == str(orchestrator.REPO_ROOT)
    # toolkit must be importable from that root
    assert (orchestrator.REPO_ROOT / "toolkit").is_dir()


def test_subprocess_env_preserves_existing_pythonpath(monkeypatch):
    monkeypatch.setenv("PYTHONPATH", "/some/existing/path")
    env = orchestrator._subprocess_env()
    assert "/some/existing/path" in env["PYTHONPATH"]
    assert env["PYTHONPATH"].startswith(str(orchestrator.REPO_ROOT))


def test_main_fails_when_scripts_dir_missing(monkeypatch):
    """Without a valid scripts/ directory, main() should fail fast with code 2
    instead of silently spawning broken subprocesses."""
    from pathlib import Path

    missing = Path(orchestrator.REPO_ROOT) / "scripts_DOES_NOT_EXIST"
    monkeypatch.setattr(orchestrator, "SCRIPTS_DIR", missing)
    monkeypatch.setattr(sys, "argv", ["orchestrator.py", "--target", "example.com"])

    # monkeypatch has already swapped the module-level SCRIPTS_DIR used by main()
    rc = orchestrator.main()
    assert rc == 2
