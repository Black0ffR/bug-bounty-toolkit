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


# ── B14/B15/B16: stage selection, --stages/--list-stages/--dry-run, isolation ──

def test_resolve_stages_quick_deep():
    quick = orchestrator.resolve_stages("quick")
    deep = orchestrator.resolve_stages("deep")
    assert [n for n, _ in quick] == [n for n, _ in orchestrator.QUICK_STAGES]
    assert [n for n, _ in deep] == [n for n, _ in orchestrator.DEEP_STAGES]
    assert "subtakeover" in [n for n, _ in deep]


def test_resolve_stages_filter_subset_preserves_order():
    stages = orchestrator.resolve_stages("deep", ["jsreaper", "HEADERAUDIT"])
    names = [n for n, _ in stages]
    assert names == ["jsreaper", "headeraudit"]


def test_resolve_stages_unknown_name_raises():
    import pytest
    with pytest.raises(ValueError):
        orchestrator.resolve_stages("deep", ["nope_stage"])


def test_get_stage_fn_returns_callable():
    fn = orchestrator.get_stage_fn("jsreaper")
    assert callable(fn)
    assert orchestrator.get_stage_fn("does_not_exist") is None


def test_main_list_stages(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["orchestrator.py", "--list-stages"])
    rc = orchestrator.main()
    assert rc == 0
    out = capsys.readouterr().out
    assert "jsreaper" in out
    assert "subtakeover" in out


def test_dry_run_plans_without_execution(monkeypatch, tmp_path):
    """B15: --dry-run must print the planned stages and return 0 without
    running any stage subprocess."""
    calls = []
    def fake_run(*a, **k):
        calls.append(a)
        return (0, "", "")
    monkeypatch.setattr(orchestrator, "_run_subprocess", fake_run)

    from pathlib import Path
    ctx = orchestrator.OrchestratorContext(
        target="example.com", work_dir=tmp_path,
        scope_path=None, auth_profiles_path=None,
        db_path=tmp_path / "pipeline_state.db", mode="quick", dry_run=True,
    )
    rc = orchestrator.run_pipeline(ctx)
    assert rc == 0
    assert calls == []  # no subprocess executed
    assert ctx.stage_results == []


def test_stage_runs_in_isolation(monkeypatch, tmp_path):
    """B16: stage functions are importable and testable in isolation — here we
    stub the subprocess runner and verify _stage_subtakeover reports success
    and invoked exactly one subprocess, with no import-time side effects."""
    calls = []
    def fake_run(cmd, **k):
        calls.append(cmd)
        return (0, "", "")
    monkeypatch.setattr(orchestrator, "_run_subprocess", fake_run)

    ctx = orchestrator.OrchestratorContext(
        target="example.com", work_dir=tmp_path,
        scope_path=None, auth_profiles_path=None,
        db_path=tmp_path / "pipeline_state.db", mode="deep",
    )
    result = orchestrator._stage_subtakeover(ctx)
    assert result.success is True
    assert len(calls) == 1
    assert "subtakeover10.py" in calls[0][1]


def test_dry_run_respects_stages_subset():
    """C13: --dry-run planning must honor an explicit --stages subset, returning
    only the requested stages in the requested order."""
    stages = orchestrator.resolve_stages("quick", ["jsreaper", "headeraudit"])
    names = [n for n, _ in stages]
    assert names == ["jsreaper", "headeraudit"]
    # And the full quick set is larger than the subset (sanity).
    full = orchestrator.resolve_stages("quick", None)
    assert len(full) > len(stages)

