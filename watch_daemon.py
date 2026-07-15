#!/usr/bin/env python3
"""
watch_daemon.py — continuous-monitoring daemon
===============================================

Tier 3 workflow multiplier.

Purpose
-------
subtakeover10.py already has continuous monitoring + a SQLite history DB,
but only for subdomain takeover. This tool widens the same pattern to the
whole pipeline — re-running all stages on a schedule and alerting only on
genuinely new signal:

  - new subdomain seen (subtakeover)
  - new JS file hash (jsreaper)
  - new param discovered (paramfuzz)
  - new endpoint observed (jsreaper)
  - CNAME entering a takeover-eligible state (subtakeover)

Shares pipeline_state.db with triage_memory.py — same DB, two tables:
asset_history (this tool reads/writes) + findings_history (triage reads).

Each watch cycle:
  1. Runs orchestrator.py --quick (or --deep if --full-mode)
  2. Diffs current asset set against pipeline_state.asset_history
  3. For new assets, emits a "watch_alert" finding and bumps triage queue
  4. Sleeps --interval seconds
  5. Loops forever (Ctrl+C-safe)

One command turns "watch" off per target: --stop <target> sets a flag in
pipeline_state.watch_targets table.

Chain position
--------------
Top-level — runs orchestrator.py stages on schedule.

Usage
-----
    # Start watch (foreground)
    python watch_daemon.py --scope scope.yaml --interval 3600

    # Stop watch for a target
    python watch_daemon.py --stop acme.com

    # One-shot diff (run once, don't loop)
    python watch_daemon.py --scope scope.yaml --once

Author : Bug Bounty Toolkit / Tier 3
License : MIT (for authorized use only)
"""

from __future__ import annotations

import argparse
import datetime
import json
import logging
import signal
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from toolkit.infra import scope_guard, auth_profiles
from toolkit.infra.finding import compute_finding_id
from toolkit.infra.pipeline_state import PipelineState


log = logging.getLogger("watch_daemon")

# SQL to add the watch_targets table (run on first start)
_WATCH_TARGETS_SQL = """
CREATE TABLE IF NOT EXISTS watch_targets (
    target           TEXT PRIMARY KEY,
    scope_yaml       TEXT,
    interval_sec     INTEGER DEFAULT 3600,
    started_at       TEXT NOT NULL,
    last_cycle_at    TEXT,
    next_cycle_at    TEXT,
    active           INTEGER DEFAULT 1,
    cycles_completed INTEGER DEFAULT 0,
    cycles_failed    INTEGER DEFAULT 0
);
"""


@dataclass
class WatchAlert:
    target: str
    asset_kind: str       # subdomain | js_hash | param | endpoint | cname_change
    asset_value: str
    severity: str
    title: str
    detail: str


def _ensure_watch_targets_table(state: PipelineState) -> None:
    """Create watch_targets table if missing."""
    with state._lock:
        state._conn.executescript(_WATCH_TARGETS_SQL)
        state._conn.commit()


def _load_scope_targets(scope_path: Path) -> list[str]:
    """Parse scope.yaml and return a list of target root domains (one per
    in_scope wildcard entry). For '*.acme.com' → 'acme.com'."""
    from toolkit.infra.scope_guard import ScopeGuard
    guard = ScopeGuard(scope_path)
    targets: list[str] = []
    for entry in guard.in_scope:
        e = entry.lstrip("*.")
        if e and e not in targets:
            targets.append(e)
    return targets


def _extract_assets_from_workdir(workdir: Path, target: str) -> dict[str, list[str]]:
    """Walk a workdir and extract asset lists per kind for diffing.
    Returns {subdomains: [...], js_hashes: [...], params: [...], endpoints: [...]}."""
    out: dict[str, list[str]] = {
        "subdomain": [],
        "js_hash": [],
        "param": [],
        "endpoint": [],
        "cname_chain": [],
    }
    # subtakeover.json → resolved_subdomains[].subdomain + findings[].subdomain + cname_chain
    st = workdir / "subtakeover.json"
    if st.exists():
        try:
            data = json.loads(st.read_text(encoding="utf-8"))
            for s in data.get("resolved_subdomains", []) or []:
                if isinstance(s, dict) and s.get("subdomain"):
                    out["subdomain"].append(s["subdomain"])
            for f in data.get("findings", []) or []:
                if isinstance(f, dict):
                    if f.get("subdomain"):
                        out["subdomain"].append(f["subdomain"])
                    if f.get("cname_chain"):
                        chain = " -> ".join(f["cname_chain"]) if isinstance(f["cname_chain"], list) else str(f["cname_chain"])
                        out["cname_chain"].append(chain)
        except Exception as exc:
            log.debug("could not parse %s: %s", st, exc)
    # jsreaper.json → host_results[].js_assets[].content_hash + endpoints[].endpoint
    js = workdir / "jsreaper.json"
    if js.exists():
        try:
            data = json.loads(js.read_text(encoding="utf-8"))
            for hr in data.get("host_results", []) or []:
                for asset in hr.get("js_assets", []) or []:
                    if asset.get("content_hash"):
                        out["js_hash"].append(asset["content_hash"])
                for ep in hr.get("endpoints", []) or []:
                    if ep.get("endpoint"):
                        out["endpoint"].append(ep["endpoint"])
            for ep in data.get("all_endpoints", []) or []:
                if isinstance(ep, dict) and ep.get("endpoint"):
                    out["endpoint"].append(ep["endpoint"])
                elif isinstance(ep, str):
                    out["endpoint"].append(ep)
        except Exception as exc:
            log.debug("could not parse %s: %s", js, exc)
    # paramfuzz.json → findings[].param_name
    pf = workdir / "paramfuzz.json"
    if pf.exists():
        try:
            data = json.loads(pf.read_text(encoding="utf-8"))
            for f in data.get("findings", []) or []:
                if f.get("param_name"):
                    out["param"].append(f["param_name"])
        except Exception as exc:
            log.debug("could not parse %s: %s", pf, exc)
    # Dedupe
    for k in out:
        out[k] = list(set(out[k]))
    return out


def _emit_alerts(state: PipelineState, target: str,
                 diffs: dict[str, Any]) -> list[WatchAlert]:
    """For each new asset in diffs, emit a watch_alert finding and persist to
    pipeline_state.findings_history. Returns the list of alerts."""
    alerts: list[WatchAlert] = []
    for kind, diff in diffs.items():
        for added in diff.added:
            sev = "HIGH" if kind == "cname_chain" else "MEDIUM"
            title = f"New {kind} observed: {added[:80]}"
            detail = f"Watch daemon detected a new {kind} for target {target}: {added}"
            alert = WatchAlert(
                target=target, asset_kind=kind, asset_value=added,
                severity=sev, title=title, detail=detail,
            )
            alerts.append(alert)
            # Persist as a finding
            fid = compute_finding_id("watch_daemon.py", target, "WATCH_NEW_" + kind.upper(), added)
            state.upsert_finding({
                "id": fid,
                "source_tool": "watch_daemon.py",
                "host": target,
                "url": "",
                "vuln_class_key": "WATCH_NEW_" + kind.upper(),
                "severity": sev,
                "title": title,
                "detail": detail,
                "evidence": f"{kind}={added}",
                "raw": {"asset_kind": kind, "asset_value": added},
                "confidence": "candidate",
                "disposition": "new",
                "verified_by": None,
            })
    return alerts


def run_one_cycle(target: str, scope_path: Path, auth_profiles_path: Path | None,
                  output_dir: Path, db_path: Path, *,
                  full_mode: bool = False) -> dict[str, Any]:
    """Run one watch cycle: orchestrator + diff + alert. Returns a summary dict."""
    log.info("=== watch cycle starting for %s ===", target)
    # Step 1: run orchestrator
    import subprocess
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    workdir = output_dir / target.replace("/", "_") / f"watch_{timestamp}"
    workdir.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable, str(Path(__file__).resolve().parent / "orchestrator.py"),
        "--target", target,
        "--output-dir", str(output_dir / target.replace("/", "_")),
        "--db", str(db_path),
    ]
    if scope_path:
        cmd += ["--scope", str(scope_path)]
    if auth_profiles_path:
        cmd += ["--auth-profiles", str(auth_profiles_path)]
    cmd += ["--deep"] if full_mode else ["--quick"]
    log.info("$ %s", " ".join(cmd))
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=7200, check=False)
        rc = p.returncode
        log.debug("orchestrator rc=%d, stderr=%s", rc, p.stderr[:500])
    except subprocess.TimeoutExpired:
        log.error("orchestrator timed out after 7200s")
        return {"success": False, "error": "timeout", "duration_s": time.time() - t0}
    # Step 2: find the most recent workdir for this target (orchestrator created one)
    target_dir = output_dir / target.replace("/", "_")
    if not target_dir.exists():
        return {"success": False, "error": "no workdir created", "duration_s": time.time() - t0}
    workdirs = sorted([d for d in target_dir.iterdir() if d.is_dir()], reverse=True)
    if not workdirs:
        return {"success": False, "error": "no workdir found", "duration_s": time.time() - t0}
    latest = workdirs[0]
    log.info("latest workdir: %s", latest)
    # Step 3: extract assets from the latest workdir
    assets = _extract_assets_from_workdir(latest, target)
    # Step 4: diff against pipeline_state.asset_history
    state = PipelineState(db_path)
    try:
        diffs = state.diff_assets(target, **assets)
        # Step 5: emit alerts for new assets
        alerts = _emit_alerts(state, target, diffs)
        # Step 6: record the assets we just saw (so next cycle can diff against them)
        state.record_assets(target, scan_run_id=None, **assets)
        # Update watch_targets table
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        next_iso = (datetime.datetime.now(datetime.timezone.utc) +
                    datetime.timedelta(seconds=3600)).isoformat(timespec="seconds")
        with state._lock:
            state._conn.execute(
                """INSERT OR REPLACE INTO watch_targets
                   (target, scope_yaml, interval_sec, started_at, last_cycle_at, next_cycle_at,
                    active, cycles_completed, cycles_failed)
                   VALUES (?, ?, ?, COALESCE((SELECT started_at FROM watch_targets WHERE target = ?), ?),
                           ?, ?, 1,
                           COALESCE((SELECT cycles_completed FROM watch_targets WHERE target = ?), 0) + 1,
                           COALESCE((SELECT cycles_failed FROM watch_targets WHERE target = ?), 0))""",
                (target, str(scope_path), 3600, target, now_iso,
                 now_iso, next_iso, target, target),
            )
            state._conn.commit()
        log.info("=== watch cycle complete: %d new assets alerted ===", len(alerts))
        for a in alerts[:10]:
            log.info("  [%s] %s: %s", a.severity, a.asset_kind, a.asset_value[:60])
        if len(alerts) > 10:
            log.info("  ... and %d more", len(alerts) - 10)
        return {
            "success": True,
            "duration_s": time.time() - t0,
            "alerts": len(alerts),
            "alert_kinds": {k: len(v.added) for k, v in diffs.items() if v.added},
            "workdir": str(latest),
        }
    finally:
        state.close()


def run_watch(scope_path: Path, auth_profiles_path: Path | None,
              interval: int, output_dir: Path, db_path: Path, *,
              full_mode: bool = False, once: bool = False) -> int:
    """Main watch loop."""
    state = PipelineState(db_path)
    try:
        _ensure_watch_targets_table(state)
    finally:
        state.close()

    targets = _load_scope_targets(scope_path)
    if not targets:
        log.error("no in_scope targets found in %s", scope_path)
        return 2
    log.info("watching %d targets: %s", len(targets), ", ".join(targets))
    log.info("interval: %ds", interval)
    log.info("mode: %s", "deep" if full_mode else "quick")
    if once:
        log.info("--once: running a single cycle and exiting")

    interrupted = False

    def _sigint(sig, frame):
        nonlocal interrupted
        log.warning("Ctrl+C received — finishing current cycle then exiting...")
        interrupted = True
    original = signal.signal(signal.SIGINT, _sigint)

    try:
        cycle = 0
        while not interrupted:
            cycle += 1
            log.info("watch cycle #%d starting", cycle)
            for target in targets:
                if interrupted:
                    break
                try:
                    summary = run_one_cycle(target, scope_path, auth_profiles_path,
                                            output_dir, db_path, full_mode=full_mode)
                    if not summary.get("success"):
                        log.error("cycle failed for %s: %s", target, summary.get("error"))
                except Exception as exc:
                    log.exception("watch cycle for %s raised: %s", target, exc)
            if once:
                log.info("--once: exiting after single cycle")
                break
            log.info("next cycle in %ds (Ctrl+C to stop)", interval)
            # Sleep in 1s increments so Ctrl+C is responsive
            for _ in range(interval):
                if interrupted:
                    break
                time.sleep(1)
        return 0
    finally:
        signal.signal(signal.SIGINT, original)
        log.info("watch daemon stopped")


def stop_watch(target: str, db_path: Path) -> int:
    """Mark a target as inactive in watch_targets."""
    state = PipelineState(db_path)
    try:
        _ensure_watch_targets_table(state)
        with state._lock:
            cur = state._conn.execute(
                "UPDATE watch_targets SET active = 0 WHERE target = ?", (target,)
            )
            state._conn.commit()
        if cur.rowcount == 0:
            log.warning("no watch target found for %r", target)
            return 1
        log.info("watch stopped for %s", target)
        return 0
    finally:
        state.close()


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="watch_daemon.py",
        description="Continuous-monitoring daemon. Extends subtakeover10.py's monitor mode.",
    )
    ap.add_argument("--scope", help="scope.yaml path")
    ap.add_argument("--auth-profiles", help="auth_profiles.yaml path")
    ap.add_argument("--interval", type=int, default=3600, help="seconds between cycles (default: 3600)")
    ap.add_argument("--output-dir", default="./work", help="work directory root")
    ap.add_argument("--db", default="pipeline_state.db", help="pipeline_state.db path")
    ap.add_argument("--full-mode", action="store_true", help="run --deep instead of --quick per cycle")
    ap.add_argument("--once", action="store_true", help="run a single cycle and exit (no loop)")
    ap.add_argument("--stop", metavar="TARGET", help="stop watching the given target")
    ap.add_argument("--list", action="store_true", help="list active watch targets")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )

    if args.stop:
        return stop_watch(args.stop, Path(args.db))

    if args.list:
        state = PipelineState(args.db)
        try:
            _ensure_watch_targets_table(state)
            with state._lock:
                cur = state._conn.execute(
                    "SELECT target, last_cycle_at, next_cycle_at, cycles_completed, active FROM watch_targets"
                )
                rows = list(cur.fetchall())
        finally:
            state.close()
        if not rows:
            print("(no watch targets)")
            return 0
        for row in rows:
            active = "●" if row["active"] else "○"
            print(f"  {active} {row['target']:30s} last={row['last_cycle_at']} "
                  f"next={row['next_cycle_at']} cycles={row['cycles_completed']}")
        return 0

    if not args.scope:
        log.error("--scope is required (or use --stop / --list)")
        return 2

    return run_watch(Path(args.scope), Path(args.auth_profiles) if args.auth_profiles else None,
                     args.interval, Path(args.output_dir), Path(args.db),
                     full_mode=args.full_mode, once=args.once)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(0)
