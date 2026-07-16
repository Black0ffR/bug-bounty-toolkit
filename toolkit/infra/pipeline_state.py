#!/usr/bin/env python3
"""
pipeline_state.py — shared SQLite-backed pipeline state
========================================================

Purpose
-------
Thin wrapper around pipeline_state.db. Provides cross-run persistence for:

- findings_history: every normalized finding's id, first_seen, last_seen,
  and disposition (new | reviewed | submitted | rejected | duplicate_of).
  Lets triage_memory.py filter out already-submitted / already-rejected
  findings from the active queue — the piece nuclei-harvest.py's single-run
  dedup was missing.

- asset_history: subdomains, JS file hashes, params, CNAME chains observed
  per scan. Lets watch_daemon.py diff current vs. previous runs and alert
  only on genuinely new signal (new subdomain, new JS hash, new param,
  CNAME entering a takeover-eligible state).

- scan_runs: one row per orchestrator.py invocation. Tracks start/end time,
  target scope, stages completed, stages failed.

Builds on the SQLite pattern subtakeover10.py already uses (DatabaseManager
class), generalized pipeline-wide. Same DB file is shared deliberately
between triage_memory.py and watch_daemon.py — both are fundamentally
"what did we see before, and what's new."

Chain position
--------------
Layer 0 — depended on by triage_memory.py, watch_daemon.py, orchestrator.py.
No upstream dependencies.

Usage
-----
    from toolkit.infra.pipeline_state import PipelineState

    state = PipelineState()  # defaults to ./pipeline_state.db
    state.upsert_finding({
        "id": "abc123", "source_tool": "apifuzz.py", "host": "api.target.com",
        "vuln_class_key": "BOLA_POSSIBLE", "severity": "HIGH",
        "title": "...", "first_seen": "...", "last_seen": "...",
        "confidence": "candidate", "disposition": "new",
    })
    state.mark_disposition("abc123", "submitted")
    state.get_active_findings()  # → list, excludes submitted/rejected

    state.record_assets("acme.com", subdomains=["www.acme.com", "api.acme.com"])
    state.diff_assets("acme.com", subdomains=["www.acme.com", "new.acme.com"])
    # → {"added": ["new.acme.com"], "removed": []}

Author : Bug Bounty Toolkit / Layer 0
License : MIT (for authorized use only)
"""

from __future__ import annotations

import datetime
import json
import logging
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any


log = logging.getLogger("pipeline_state")

# Default DB location — match subtakeover10.py's convention of "next to the
# scripts/ dir". Override per-instance for tests.
DEFAULT_DB_PATH = Path("pipeline_state.db")


def _utcnow_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS findings_history (
    id               TEXT PRIMARY KEY,
    source_tool      TEXT NOT NULL,
    host             TEXT NOT NULL,
    url              TEXT NOT NULL,
    vuln_class_key   TEXT NOT NULL,
    severity         TEXT NOT NULL,
    title            TEXT NOT NULL,
    confidence       TEXT NOT NULL DEFAULT 'candidate',
    disposition      TEXT NOT NULL DEFAULT 'new',
    verified_by      TEXT,
    first_seen       TEXT NOT NULL,
    last_seen        TEXT NOT NULL,
    payload_json     TEXT,
    updated_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_fh_disposition ON findings_history(disposition);
CREATE INDEX IF NOT EXISTS idx_fh_host        ON findings_history(host);
CREATE INDEX IF NOT EXISTS idx_fh_source      ON findings_history(source_tool);
CREATE INDEX IF NOT EXISTS idx_fh_last_seen   ON findings_history(last_seen);

CREATE TABLE IF NOT EXISTS asset_history (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id      INTEGER NOT NULL,
    target           TEXT NOT NULL,
    asset_kind       TEXT NOT NULL,    -- subdomain | js_hash | param | cname_chain | endpoint
    asset_value      TEXT NOT NULL,
    first_seen       TEXT NOT NULL,
    last_seen        TEXT NOT NULL,
    UNIQUE(scan_run_id, target, asset_kind, asset_value),
    FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id)
);

CREATE INDEX IF NOT EXISTS idx_ah_target_kind ON asset_history(target, asset_kind);
CREATE INDEX IF NOT EXISTS idx_ah_last_seen   ON asset_history(last_seen);

CREATE TABLE IF NOT EXISTS scan_runs (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    target           TEXT NOT NULL,
    scope_yaml       TEXT,
    mode             TEXT,            -- quick | deep | resume | watch
    started_at       TEXT NOT NULL,
    finished_at      TEXT,
    stages_total     INTEGER DEFAULT 0,
    stages_completed INTEGER DEFAULT 0,
    stages_failed    INTEGER DEFAULT 0,
    failed_stage     TEXT,
    error            TEXT,
    summary_json     TEXT
);

CREATE INDEX IF NOT EXISTS idx_sr_target    ON scan_runs(target);
CREATE INDEX IF NOT EXISTS idx_sr_started   ON scan_runs(started_at);

CREATE TABLE IF NOT EXISTS triage_decisions (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id       TEXT NOT NULL,
    disposition      TEXT NOT NULL,
    decided_at       TEXT NOT NULL,
    decided_by       TEXT,             -- username or 'auto'
    note             TEXT,
    FOREIGN KEY (finding_id) REFERENCES findings_history(id)
);

CREATE INDEX IF NOT EXISTS idx_td_finding   ON triage_decisions(finding_id);
"""

# Current schema version. Bump and add a MIGRATION entry whenever the schema
# changes, so existing pipeline_state.db files migrate forward instead of
# erroring out on a missing column.
SCHEMA_VERSION = 1

SCHEMA_META_SQL = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

# version N -> list of DDL statements applied when migrating from N-1 to N.
# Each statement is wrapped in try/except so a partially-applied/crash-safe
# migration never bricks the DB (idempotent-friendly: re-running a skipped
# migration on a corrupted meta row degrades to a logged warning).
MIGRATIONS: dict[int, list[str]] = {
    1: [
        "ALTER TABLE findings_history ADD COLUMN tags TEXT",
    ],
}


@dataclass
class AssetDiff:
    added: list[str]
    removed: list[str]
    unchanged: list[str]


class PipelineState:
    """SQLite-backed pipeline state. Thread-safe via a single connection lock
    (sqlite3 default thread-safety mode is 'serialized' but we still serialize
    at the Python layer to avoid sharing the connection across threads)."""

    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH) -> None:
        self.path = Path(db_path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.path), timeout=10, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(SCHEMA_SQL)
            self._conn.executescript(SCHEMA_META_SQL)
            self._conn.commit()
            self._migrate()

    def _get_schema_version(self) -> int:
        row = self._conn.execute(
            "SELECT value FROM schema_meta WHERE key = 'version'"
        ).fetchone()
        if not row:
            return 0
        try:
            return int(row["value"])
        except (TypeError, ValueError):
            return 0

    def _set_schema_version(self, version: int) -> None:
        self._conn.execute(
            "INSERT INTO schema_meta(key, value) VALUES('version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (str(version),),
        )
        self._conn.commit()

    def _migrate(self) -> None:
        """Apply any pending migrations forward to SCHEMA_VERSION."""
        current = self._get_schema_version()
        while current < SCHEMA_VERSION:
            next_ver = current + 1
            for stmt in MIGRATIONS.get(next_ver, []):
                try:
                    self._conn.execute(stmt)
                except sqlite3.Error as exc:
                    log.warning("pipeline_state migration v%d failed (%s): %s",
                                next_ver, stmt, exc)
            self._conn.commit()
            self._set_schema_version(next_ver)
            current = next_ver
        if self._get_schema_version() != SCHEMA_VERSION:
            self._set_schema_version(SCHEMA_VERSION)

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except Exception:
                pass

    def __enter__(self) -> "PipelineState":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # ── Findings ────────────────────────────────────────────────────────────

    def upsert_finding(self, finding: dict[str, Any]) -> bool:
        """Insert or update a finding by id. Updates last_seen and any of the
        mutable fields (confidence, disposition, verified_by, severity, title).
        Returns True if this is a NEW finding (first time seen)."""
        fid = finding.get("id")
        if not fid:
            raise ValueError("finding must have an 'id' field")
        now = finding.get("last_seen") or _utcnow_iso()
        first_seen = finding.get("first_seen") or now
        with self._lock:
            cur = self._conn.execute(
                "SELECT id FROM findings_history WHERE id = ?", (fid,)
            )
            existing = cur.fetchone()
            if existing:
                self._conn.execute(
                    """UPDATE findings_history
                       SET last_seen = ?,
                           severity = COALESCE(NULLIF(?, ''), severity),
                           title    = COALESCE(NULLIF(?, ''), title),
                           confidence = COALESCE(NULLIF(?, ''), confidence),
                           disposition = COALESCE(NULLIF(?, ''), disposition),
                           verified_by = COALESCE(?, verified_by),
                           payload_json = COALESCE(?, payload_json),
                           updated_at = ?
                       WHERE id = ?""",
                    (
                        now,
                        finding.get("severity", ""),
                        finding.get("title", ""),
                        finding.get("confidence", ""),
                        finding.get("disposition", ""),
                        finding.get("verified_by"),
                        json.dumps(finding, default=str) if finding else None,
                        now,
                        fid,
                    ),
                )
                self._conn.commit()
                return False
            self._conn.execute(
                """INSERT INTO findings_history
                   (id, source_tool, host, url, vuln_class_key, severity, title,
                    confidence, disposition, verified_by, first_seen, last_seen,
                    payload_json, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    fid,
                    finding.get("source_tool", ""),
                    finding.get("host", ""),
                    finding.get("url", ""),
                    finding.get("vuln_class_key", ""),
                    finding.get("severity", ""),
                    finding.get("title", ""),
                    finding.get("confidence", "candidate"),
                    finding.get("disposition", "new"),
                    finding.get("verified_by"),
                    first_seen,
                    now,
                    json.dumps(finding, default=str),
                    now,
                ),
            )
            self._conn.commit()
            return True

    def mark_disposition(self, finding_id: str, disposition: str,
                         *, decided_by: str = "auto", note: str = "") -> None:
        """Update a finding's disposition and log the decision. Validates
        disposition is one of the allowed values."""
        allowed = {"new", "reviewed", "submitted", "rejected", "duplicate_of"}
        if disposition not in allowed:
            raise ValueError(f"disposition must be one of {allowed}, got {disposition!r}")
        now = _utcnow_iso()
        with self._lock:
            self._conn.execute(
                """UPDATE findings_history
                   SET disposition = ?, last_seen = ?, updated_at = ?
                   WHERE id = ?""",
                (disposition, now, now, finding_id),
            )
            self._conn.execute(
                """INSERT INTO triage_decisions
                   (finding_id, disposition, decided_at, decided_by, note)
                   VALUES (?, ?, ?, ?, ?)""",
                (finding_id, disposition, now, decided_by, note),
            )
            self._conn.commit()

    def get_finding(self, finding_id: str) -> dict[str, Any] | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM findings_history WHERE id = ?", (finding_id,)
            )
            row = cur.fetchone()
            if not row:
                return None
            d = dict(row)
            if d.get("payload_json"):
                try:
                    d["payload"] = json.loads(d["payload_json"])
                except Exception:
                    d["payload"] = {}
            return d

    def get_active_findings(self, *, include_reviewed: bool = True,
                            limit: int | None = None) -> list[dict[str, Any]]:
        """Return findings NOT yet submitted or rejected — i.e. the active queue.
        include_reviewed controls whether 'reviewed' (looked-at but undecided)
        findings are included (default True — they're still active)."""
        excluded = ("submitted", "rejected")
        sql = """SELECT * FROM findings_history
                 WHERE disposition NOT IN (%s)
                 ORDER BY
                   CASE severity
                     WHEN 'CRITICAL' THEN 0
                     WHEN 'HIGH' THEN 1
                     WHEN 'MEDIUM' THEN 2
                     WHEN 'LOW' THEN 3
                     ELSE 4
                   END,
                   last_seen DESC""" % ",".join("?" * len(excluded))
        params: list[Any] = list(excluded)
        if limit:
            sql += " LIMIT ?"
            params.append(int(limit))
        with self._lock:
            cur = self._conn.execute(sql, params)
            return [dict(r) for r in cur.fetchall()]

    def get_findings_by_host(self, host: str) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM findings_history WHERE host = ? ORDER BY last_seen DESC",
                (host,),
            )
            return [dict(r) for r in cur.fetchall()]

    def count_findings(self) -> dict[str, int]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT disposition, COUNT(*) AS n FROM findings_history GROUP BY disposition"
            )
            return {row["disposition"]: int(row["n"]) for row in cur.fetchall()}

    # ── Scan runs ───────────────────────────────────────────────────────────

    def start_run(self, target: str, *, scope_yaml: str = "", mode: str = "",
                  stages_total: int = 0) -> int:
        now = _utcnow_iso()
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO scan_runs
                   (target, scope_yaml, mode, started_at, stages_total,
                    stages_completed, stages_failed)
                   VALUES (?, ?, ?, ?, ?, 0, 0)""",
                (target, scope_yaml, mode, now, stages_total),
            )
            self._conn.commit()
            return int(cur.lastrowid or 0)

    def update_run(self, run_id: int, *,
                   stages_completed: int | None = None,
                   stages_failed: int | None = None,
                   failed_stage: str | None = None,
                   error: str | None = None,
                   finished: bool = False,
                   summary: dict[str, Any] | None = None) -> None:
        sets: list[str] = []
        params: list[Any] = []
        if stages_completed is not None:
            sets.append("stages_completed = ?")
            params.append(int(stages_completed))
        if stages_failed is not None:
            sets.append("stages_failed = ?")
            params.append(int(stages_failed))
        if failed_stage is not None:
            sets.append("failed_stage = ?")
            params.append(failed_stage)
        if error is not None:
            sets.append("error = ?")
            params.append(error)
        if finished:
            sets.append("finished_at = ?")
            params.append(_utcnow_iso())
        if summary is not None:
            sets.append("summary_json = ?")
            params.append(json.dumps(summary, default=str))
        if not sets:
            return
        params.append(run_id)
        with self._lock:
            self._conn.execute(
                f"UPDATE scan_runs SET {', '.join(sets)} WHERE id = ?", params
            )
            self._conn.commit()

    def get_last_run(self, target: str) -> dict[str, Any] | None:
        with self._lock:
            cur = self._conn.execute(
                """SELECT * FROM scan_runs WHERE target = ?
                   ORDER BY started_at DESC LIMIT 1""",
                (target,),
            )
            row = cur.fetchone()
            return dict(row) if row else None

    # ── Asset history (for watch_daemon.py diffs) ───────────────────────────

    def record_assets(self, target: str, *, scan_run_id: int | None = None,
                      subdomains: list[str] | None = None,
                      js_hashes: list[str] | None = None,
                      params: list[str] | None = None,
                      cname_chains: list[str] | None = None,
                      endpoints: list[str] | None = None) -> int:
        """Record observed assets for this target on this scan. Creates rows
        in asset_history. Returns the count of newly-inserted rows."""
        now = _utcnow_iso()
        if scan_run_id is None:
            scan_run_id = 0  # allow ad-hoc asset tracking without a scan_runs FK
        rows: list[tuple[int, str, str, str, str, str]] = []
        for kind, items in (
            ("subdomain", subdomains or []),
            ("js_hash", js_hashes or []),
            ("param", params or []),
            ("cname_chain", cname_chains or []),
            ("endpoint", endpoints or []),
        ):
            for v in items:
                rows.append((scan_run_id, target, kind, str(v), now, now))
        if not rows:
            return 0
        inserted = 0
        with self._lock:
            for r in rows:
                cur = self._conn.execute(
                    """INSERT OR IGNORE INTO asset_history
                       (scan_run_id, target, asset_kind, asset_value, first_seen, last_seen)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    r,
                )
                if cur.rowcount > 0:
                    inserted += 1
                else:
                    # Existing — bump last_seen
                    self._conn.execute(
                        """UPDATE asset_history SET last_seen = ?
                           WHERE scan_run_id = ? AND target = ? AND asset_kind = ? AND asset_value = ?""",
                        (now, r[0], r[1], r[2], r[3]),
                    )
            self._conn.commit()
        return inserted

    def diff_assets(self, target: str, *, subdomains: list[str] | None = None,
                    js_hashes: list[str] | None = None, params: list[str] | None = None,
                    cname_chains: list[str] | None = None,
                    endpoints: list[str] | None = None) -> dict[str, AssetDiff]:
        """Diff the provided current asset lists against the most-recent
        previously-recorded set. Returns {asset_kind: AssetDiff(added, removed, unchanged)}.
        Asset kinds not provided in this call are skipped (no diff)."""
        out: dict[str, AssetDiff] = {}
        with self._lock:
            for kind, current in (
                ("subdomain", subdomains),
                ("js_hash", js_hashes),
                ("param", params),
                ("cname_chain", cname_chains),
                ("endpoint", endpoints),
            ):
                if current is None:
                    continue
                current_set = set(str(x) for x in current)
                # Get the most recent previous asset set by looking at the
                # latest last_seen timestamp before "now" for this target+kind.
                cur = self._conn.execute(
                    """SELECT DISTINCT asset_value FROM asset_history
                       WHERE target = ? AND asset_kind = ?
                       ORDER BY last_seen DESC""",
                    (target, kind),
                )
                previous_set = {row["asset_value"] for row in cur.fetchall()}
                out[kind] = AssetDiff(
                    added=sorted(current_set - previous_set),
                    removed=sorted(previous_set - current_set),
                    unchanged=sorted(current_set & previous_set),
                )
        return out

    def get_asset_history(self, target: str, *, asset_kind: str | None = None,
                          limit: int = 1000) -> list[dict[str, Any]]:
        sql = "SELECT * FROM asset_history WHERE target = ?"
        params: list[Any] = [target]
        if asset_kind:
            sql += " AND asset_kind = ?"
            params.append(asset_kind)
        sql += " ORDER BY last_seen DESC LIMIT ?"
        params.append(int(limit))
        with self._lock:
            cur = self._conn.execute(sql, params)
            return [dict(r) for r in cur.fetchall()]


# ── Module-level singleton ───────────────────────────────────────────────────

_DEFAULT_STATE: PipelineState | None = None
_DEFAULT_LOCK = threading.Lock()


def get_default() -> PipelineState:
    global _DEFAULT_STATE
    if _DEFAULT_STATE is None:
        with _DEFAULT_LOCK:
            if _DEFAULT_STATE is None:
                _DEFAULT_STATE = PipelineState()
    return _DEFAULT_STATE


def configure(db_path: str | Path) -> PipelineState:
    global _DEFAULT_STATE
    with _DEFAULT_LOCK:
        if _DEFAULT_STATE is not None:
            try:
                _DEFAULT_STATE.close()
            except Exception:
                pass
        _DEFAULT_STATE = PipelineState(db_path)
        return _DEFAULT_STATE


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    state = PipelineState(sys.argv[1] if len(sys.argv) > 1 else "pipeline_state.db")
    print("counts by disposition:", state.count_findings())
    for row in state.get_active_findings(limit=10):
        print(f"  [{row['severity']:8s}] {row['id'][:16]:16s}  {row['title'][:60]}")
