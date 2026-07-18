"""Tests for watch_daemon.py (Phase B: B17 cooldown, B18 max-runs/until)."""
from __future__ import annotations

import datetime
import pathlib

import watch_daemon


def test_parse_until_iso():
    dt = watch_daemon.parse_until("2030-01-01T00:00:00+00:00")
    assert dt.year == 2030
    assert dt.tzinfo is not None


def test_parse_until_hhmm_is_future():
    # Whatever the current time, a parsed HH:MM should be in the future
    dt = watch_daemon.parse_until("03:00")
    assert dt > datetime.datetime.now(datetime.timezone.utc)
    assert dt.hour == 3 and dt.minute == 0


def test_past_stop_max_runs_inclusive():
    # max_runs=2 means cycles 1 and 2 run; cycle 3 stops
    assert watch_daemon._past_stop(1, 2, None) is False
    assert watch_daemon._past_stop(2, 2, None) is False
    assert watch_daemon._past_stop(3, 2, None) is True
    # No limit
    assert watch_daemon._past_stop(50, None, None) is False


def test_past_stop_until():
    past = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)
    future = datetime.datetime(2999, 1, 1, tzinfo=datetime.timezone.utc)
    assert watch_daemon._past_stop(1, None, past) is True
    assert watch_daemon._past_stop(1, None, future) is False


def test_run_watch_respects_max_runs(monkeypatch, temp_scope_yaml, tmp_path):
    """B18: with --max-runs the daemon must stop after N cycles without
    spawning real subprocesses (run_one_cycle is stubbed)."""
    calls = []

    def fake_cycle(target, *a, **k):
        calls.append(target)
        return {"success": True, "duration_s": 0.0, "alerts": 0,
                "alert_kinds": {}, "workdir": str(tmp_path)}

    monkeypatch.setattr(watch_daemon, "run_one_cycle", fake_cycle)

    rc = watch_daemon.run_watch(
        pathlib.Path(temp_scope_yaml),
        None, interval=0, output_dir=tmp_path, db_path=tmp_path / "pipeline_state.db",
        cooldown=0, max_runs=2,
    )
    assert rc == 0
    # temp_scope_yaml lists 2 targets (127.0.0.1, localhost) × 2 cycles = 4 calls
    assert len(calls) == 4


def test_run_watch_cooldown_between_targets(monkeypatch, temp_scope_yaml, tmp_path):
    """B17: cooldown is honored between consecutive target polls — verify by
    stubbing time.sleep and counting per-target sleeps."""
    import pathlib

    sleeps = []
    monkeypatch.setattr(watch_daemon.time, "sleep", lambda s: sleeps.append(s))

    def fake_cycle(target, *a, **k):
        return {"success": True, "duration_s": 0.0, "alerts": 0,
                "alert_kinds": {}, "workdir": str(tmp_path)}

    monkeypatch.setattr(watch_daemon, "run_one_cycle", fake_cycle)

    # Two targets come from scope only if it lists two; craft a scope with 2.
    scope = tmp_path / "scope2.yaml"
    scope.write_text(
        "program: test\nin_scope:\n  - '127.0.0.1'\n  - 'localhost'\nout_of_scope: []\n"
        "rate_limit:\n  max_rps: 100\n  max_concurrent: 20\nautomation_allowed: true\n",
        encoding="utf-8",
    )
    rc = watch_daemon.run_watch(
        pathlib.Path(scope), None, interval=0, output_dir=tmp_path,
        db_path=tmp_path / "pipeline_state.db", cooldown=5, max_runs=1,
    )
    assert rc == 0
    # With 2 targets and cooldown=5, exactly one cooldown window of 5×1s sleeps
    assert sleeps == [1, 1, 1, 1, 1]
