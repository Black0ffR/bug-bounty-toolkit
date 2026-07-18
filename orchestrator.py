#!/usr/bin/env python3
"""
orchestrator.py — top-level pipeline entry point
==================================================

Tier 3 workflow multiplier.

Purpose
-------
Replaces WORKFLOW.md's manual 10-step process with one entry point, in the
spirit of js-extractor_3.py's run() restructuring: checkpoint-safe, Ctrl+C-safe.

Modes:
    orchestrator.py --target acme.com --quick       # subtakeover + jsreaper + headeraudit only
    orchestrator.py --target acme.com --deep        # full 15+ stage pipeline
    orchestrator.py --target acme.com --resume      # continue from last checkpoint
    orchestrator.py --scope scope.yaml --watch      # hands off to watch_daemon.py

Features:
    - Respects scope_guard.py and auth_profiles.yaml globally — no individual
      tool needs its own flags for these.
    - Writes one checkpoint file per stage (matching recon_pipeline_v4.py's
      atomic-write pattern).
    - On any stage's fatal error, skips to the next non-dependent stage rather
      than aborting the whole run (graceful degradation).
    - All stage outputs land in a per-target workdir: ./work/<target>/<timestamp>/
    - Final aggregation: runs nuclei-harvest.py over all stage outputs, then
      hands off to triage_memory.py for the interactive queue.

Chain position
--------------
Top-level — drives all stages. No upstream dependencies.

Usage
-----
    python orchestrator.py --target acme.com --quick
    python orchestrator.py --scope scope.yaml --deep --output-dir ./work
    python orchestrator.py --target acme.com --resume
    python orchestrator.py --scope scope.yaml --watch --interval 3600

Author : Bug Bounty Toolkit / Tier 3
License : MIT (for authorized use only)
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from toolkit.infra import scope_guard, auth_profiles
from toolkit.infra.pipeline_state import PipelineState


log = logging.getLogger("orchestrator")


# ── Stage definitions ────────────────────────────────────────────────────────
# Each stage is a function: (ctx) -> bool. Returns True on success, False on
# failure (the orchestrator logs and skips to the next non-dependent stage).
# Stages are run in order; some stages mark themselves as skippable depending
# on --quick / --deep mode.

@dataclass
class StageResult:
    name: str
    success: bool
    output_path: Path | None = None
    error: str = ""
    duration_s: float = 0.0
    skipped: bool = False


@dataclass
class OrchestratorContext:
    target: str
    work_dir: Path
    scope_path: Path | None
    auth_profiles_path: Path | None
    db_path: Path
    mode: str                    # quick | deep | resume | watch
    run_id: int = 0
    stage_results: list[StageResult] = field(default_factory=list)
    stages_filter: list[str] | None = None   # B14: explicit subset to run
    dry_run: bool = False                    # B15: plan only, no execution
    _interrupted: bool = False

    def stage_output(self, stage_name: str, suffix: str = ".json") -> Path:
        return self.work_dir / f"{stage_name}{suffix}"


def _subtakeover_scope_args(ctx: OrchestratorContext) -> list[str]:
    """Build the --scope arg for subtakeover10.py with the correct format.

    subtakeover10.py's ScopeFilter expects a flat HackerOne/Bugcrowd file
    (``*.host.com`` / ``!host.com``), but the toolkit's scope.yaml is a
    structured document (``in_scope:`` / ``out_of_scope:``). Handing the
    structured file over directly makes ScopeFilter mis-parse every line, so
    subtakeover would enforce the wrong (or no) scope. Convert the toolkit
    scope to the flat format (cached in the workdir) when needed.
    """
    if not ctx.scope_path or not Path(ctx.scope_path).exists():
        return []
    text = Path(ctx.scope_path).read_text(encoding="utf-8")
    # Already a flat HackerOne/Bugcrowd file? (no structured keys) -> pass through
    if not any(k in text for k in ("in_scope:", "out_of_scope:", "program:")):
        return ["--scope", str(ctx.scope_path)]
    try:
        data = scope_guard._fallback_yaml_parse(text)
    except Exception:
        return ["--scope", str(ctx.scope_path)]
    lines: list[str] = []
    for entry in data.get("in_scope", []) or []:
        if isinstance(entry, str):
            lines.append(entry.lstrip("!").lstrip("*."))
    for entry in data.get("out_of_scope", []) or []:
        if isinstance(entry, str):
            lines.append("!" + entry.lstrip("!").lstrip("*."))
    ctx.work_dir.mkdir(parents=True, exist_ok=True)
    out_path = ctx.work_dir / "subtakeover_scope.txt"
    out_path.write_text(("\n".join(lines) + "\n") if lines else "", encoding="utf-8")
    return ["--scope", str(out_path)]


# ── Stage implementations ────────────────────────────────────────────────────
# Each stage shells out to an existing script (in ../scripts/) and writes its
# output to ctx.stage_output(stage_name). On --resume, if the output exists,
# the stage is skipped.

# Repo root is the directory containing this file. Subtrees (toolkit/, scripts/,
# oob_catcher/) live under it, so spawned subprocesses need it on PYTHONPATH.
REPO_ROOT = Path(__file__).resolve().parent

# Scripts directory is at the SubTakeover root (sibling of this file).
SCRIPTS_DIR = REPO_ROOT / "scripts"


def _subprocess_env() -> dict[str, str]:
    """Return an environment dict with REPO_ROOT prepended to PYTHONPATH.

    Spawned scripts rely on importing sibling packages (``toolkit``,
    ``oob_catcher``). Injecting the repo root makes those imports resolve even
    when the orchestrator is launched from another working directory.
    """
    env = dict(os.environ)
    existing = env.get("PYTHONPATH", "")
    paths = [str(REPO_ROOT)] + ([existing] if existing else [])
    env["PYTHONPATH"] = os.pathsep.join(paths)
    return env


def _run_subprocess(cmd: list[str], *, timeout: int = 1800,
                     cwd: Path | None = None) -> tuple[int, str, str]:
    """Run a subprocess, capture stdout/stderr. Returns (rc, out, err)."""
    log.info("$ %s", " ".join(cmd))
    try:
        p = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout,
            check=False, env=_subprocess_env(),
        )
        return (p.returncode, p.stdout or "", p.stderr or "")
    except subprocess.TimeoutExpired:
        return (124, "", f"timeout after {timeout}s")
    except FileNotFoundError as exc:
        return (127, "", str(exc))


def _stage_subtakeover(ctx: OrchestratorContext) -> StageResult:
    out = ctx.stage_output("subtakeover")
    if ctx.mode == "resume" and out.with_suffix(".json").exists():
        return StageResult("subtakeover", True, out, skipped=True)
    t0 = time.time()
    cmd = [
        sys.executable, str(SCRIPTS_DIR / "subtakeover10.py"),
        "-d", ctx.target,
        "--output", str(out),
        "--db", str(ctx.work_dir / "subtakeover.db"),
        "--ct", "--passive", "--cluster", "--ns-check", "--whois",
        "--permute", "--tls", "--assets",
    ]
    cmd += _subtakeover_scope_args(ctx)
    rc, _, err = _run_subprocess(cmd, timeout=1800)
    return StageResult("subtakeover", rc == 0, out, err, time.time() - t0)


def _stage_reconharvest(ctx: OrchestratorContext) -> StageResult:
    out = ctx.stage_output("reconharvest")
    if ctx.mode == "resume" and out.with_suffix(".json").exists():
        return StageResult("reconharvest", True, out, skipped=True)
    subtake = ctx.stage_output("subtakeover").with_suffix(".json")
    if not subtake.exists():
        return StageResult("reconharvest", False, None,
                           "depends on subtakeover which did not produce output", 0.0,
                           skipped=True)
    t0 = time.time()
    cmd = [
        sys.executable, str(SCRIPTS_DIR / "reconharvest.py"),
        "--scan", str(subtake),
        "--domain", ctx.target,
        "--output", str(out),
    ]
    rc, _, err = _run_subprocess(cmd, timeout=1800)
    return StageResult("reconharvest", rc == 0, out, err, time.time() - t0)


def _stage_jsreaper(ctx: OrchestratorContext) -> StageResult:
    out = ctx.stage_output("jsreaper")
    if ctx.mode == "resume" and out.with_suffix(".json").exists():
        return StageResult("jsreaper", True, out, skipped=True)
    recon = ctx.stage_output("reconharvest").with_suffix(".json")
    if not recon.exists():
        return StageResult("jsreaper", False, None,
                           "depends on reconharvest which did not produce output", 0.0,
                           skipped=True)
    t0 = time.time()
    cmd = [
        sys.executable, str(SCRIPTS_DIR / "jsreaper.py"),
        "--scan", str(recon),
        "--domain", ctx.target,
        "--output", str(out),
    ]
    rc, _, err = _run_subprocess(cmd, timeout=1800)
    return StageResult("jsreaper", rc == 0, out, err, time.time() - t0)


def _stage_headeraudit(ctx: OrchestratorContext) -> StageResult:
    out = ctx.stage_output("headeraudit")
    if ctx.mode == "resume" and out.with_suffix(".json").exists():
        return StageResult("headeraudit", True, out, skipped=True)
    recon = ctx.stage_output("reconharvest").with_suffix(".json")
    if not recon.exists():
        return StageResult("headeraudit", False, None,
                           "depends on reconharvest which did not produce output", 0.0,
                           skipped=True)
    t0 = time.time()
    cmd = [
        sys.executable, str(SCRIPTS_DIR / "headeraudit.py"),
        "--scan", str(recon),
        "--domain", ctx.target,
        "--output", str(out),
    ]
    rc, _, err = _run_subprocess(cmd, timeout=900)
    return StageResult("headeraudit", rc == 0, out, err, time.time() - t0)


def _stage_apifuzz(ctx: OrchestratorContext) -> StageResult:
    out = ctx.stage_output("apifuzz")
    if ctx.mode == "resume" and out.with_suffix(".json").exists():
        return StageResult("apifuzz", True, out, skipped=True)
    js = ctx.stage_output("jsreaper").with_suffix(".json")
    if not js.exists():
        return StageResult("apifuzz", False, None, "depends on jsreaper", 0.0, skipped=True)
    t0 = time.time()
    cmd = [
        sys.executable, str(SCRIPTS_DIR / "apifuzz.py"),
        "--js", str(js),
        "--domain", ctx.target,
        "--output", str(out),
    ]
    # Pull session tokens from auth_profiles if available
    if ctx.auth_profiles_path:
        try:
            ap = auth_profiles.AuthProfiles(ctx.auth_profiles_path)
            for name in ("user_a", "user_b"):
                if name in ap.profiles:
                    p = ap.profiles[name]
                    if p.bearer:
                        cmd += [f"--session-{name.replace('_', '-')[-1]}", p.bearer]
        except Exception as exc:
            log.warning("could not load auth profiles for apifuzz: %s", exc)
    rc, _, err = _run_subprocess(cmd, timeout=1800)
    return StageResult("apifuzz", rc == 0, out, err, time.time() - t0)


def _stage_paramfuzz(ctx: OrchestratorContext) -> StageResult:
    out = ctx.stage_output("paramfuzz")
    if ctx.mode == "resume" and out.with_suffix(".json").exists():
        return StageResult("paramfuzz", True, out, skipped=True)
    js = ctx.stage_output("jsreaper").with_suffix(".json")
    if not js.exists():
        return StageResult("paramfuzz", False, None, "depends on jsreaper", 0.0, skipped=True)
    t0 = time.time()
    cmd = [
        sys.executable, str(SCRIPTS_DIR / "paramfuzz.py"),
        "--js", str(js),
        "--domain", ctx.target,
        "--output", str(out),
    ]
    rc, _, err = _run_subprocess(cmd, timeout=1800)
    return StageResult("paramfuzz", rc == 0, out, err, time.time() - t0)


def _stage_ssrfprobe(ctx: OrchestratorContext) -> StageResult:
    out = ctx.stage_output("ssrfprobe")
    if ctx.mode == "resume" and out.with_suffix(".json").exists():
        return StageResult("ssrfprobe", True, out, skipped=True)
    js = ctx.stage_output("jsreaper").with_suffix(".json")
    if not js.exists():
        return StageResult("ssrfprobe", False, None, "depends on jsreaper", 0.0, skipped=True)
    t0 = time.time()
    cmd = [
        sys.executable, str(SCRIPTS_DIR / "ssrfprobe.py"),
        "--js", str(js),
        "--domain", ctx.target,
        "--output", str(out),
    ]
    rc, _, err = _run_subprocess(cmd, timeout=1800)
    return StageResult("ssrfprobe", rc == 0, out, err, time.time() - t0)


def _stage_oauthprobe(ctx: OrchestratorContext) -> StageResult:
    out = ctx.stage_output("oauthprobe")
    if ctx.mode == "resume" and out.with_suffix(".json").exists():
        return StageResult("oauthprobe", True, out, skipped=True)
    js = ctx.stage_output("jsreaper").with_suffix(".json")
    if not js.exists():
        return StageResult("oauthprobe", False, None, "depends on jsreaper", 0.0, skipped=True)
    t0 = time.time()
    cmd = [
        sys.executable, str(SCRIPTS_DIR / "oauthprobe.py"),
        "--js", str(js),
        "--domain", ctx.target,
        "--output", str(out),
    ]
    rc, _, err = _run_subprocess(cmd, timeout=900)
    return StageResult("oauthprobe", rc == 0, out, err, time.time() - t0)


def _stage_cloudexpose(ctx: OrchestratorContext) -> StageResult:
    out = ctx.stage_output("cloudexpose")
    if ctx.mode == "resume" and out.with_suffix(".json").exists():
        return StageResult("cloudexpose", True, out, skipped=True)
    sub = ctx.stage_output("subtakeover").with_suffix(".json")
    t0 = time.time()
    cmd = [
        sys.executable, str(SCRIPTS_DIR / "cloudexpose.py"),
        "--subtakeover", str(sub),
        "--domain", ctx.target,
        "--output", str(out),
    ]
    rc, _, err = _run_subprocess(cmd, timeout=600)
    return StageResult("cloudexpose", rc == 0, out, err, time.time() - t0)


def _stage_4xxbypass(ctx: OrchestratorContext) -> StageResult:
    out = ctx.stage_output("4xxbypass")
    if ctx.mode == "resume" and out.with_suffix(".json").exists():
        return StageResult("4xxbypass", True, out, skipped=True)
    recon = ctx.stage_output("reconharvest").with_suffix(".json")
    t0 = time.time()
    cmd = [
        sys.executable, str(SCRIPTS_DIR / "4xxbypass.py"),
        "--recon", str(recon),
        "--domain", ctx.target,
        "--output", str(out),
    ]
    rc, _, err = _run_subprocess(cmd, timeout=900)
    return StageResult("4xxbypass", rc == 0, out, err, time.time() - t0)


def _stage_gitdump(ctx: OrchestratorContext) -> StageResult:
    out = ctx.stage_output("gitdump")
    if ctx.mode == "resume" and out.with_suffix(".json").exists():
        return StageResult("gitdump", True, out, skipped=True)
    sub = ctx.stage_output("subtakeover").with_suffix(".json")
    t0 = time.time()
    cmd = [
        sys.executable, str(SCRIPTS_DIR / "gitdump.py"),
        "--subtakeover", str(sub),
        "--domain", ctx.target,
        "--output", str(out),
    ]
    rc, _, err = _run_subprocess(cmd, timeout=600)
    return StageResult("gitdump", rc == 0, out, err, time.time() - t0)


# ── NEW toolkit stages (run as Python module calls) ──────────────────────────

def _stage_spa_router(ctx: OrchestratorContext) -> StageResult:
    out = ctx.stage_output("spa_router").with_suffix(".json")
    if ctx.mode == "resume" and out.exists():
        return StageResult("spa_router", True, out, skipped=True)
    js = ctx.stage_output("jsreaper").with_suffix(".json")
    if not js.exists():
        return StageResult("spa_router", False, None, "depends on jsreaper", 0.0, skipped=True)
    t0 = time.time()
    cmd = [
        sys.executable, "-m", "toolkit.discover.spa_router",
        "--input", str(js),
        "--output", str(out),
    ]
    if ctx.scope_path:
        cmd += ["--scope", str(ctx.scope_path)]
    rc, _, err = _run_subprocess(cmd, timeout=900, cwd=Path(__file__).resolve().parent)
    return StageResult("spa_router", rc == 0, out, err, time.time() - t0)


def _stage_xss_context(ctx: OrchestratorContext) -> StageResult:
    out = ctx.stage_output("xss_context").with_suffix(".json")
    if ctx.mode == "resume" and out.exists():
        return StageResult("xss_context", True, out, skipped=True)
    pf = ctx.stage_output("paramfuzz").with_suffix(".json")
    if not pf.exists():
        return StageResult("xss_context", False, None, "depends on paramfuzz", 0.0, skipped=True)
    t0 = time.time()
    cmd = [
        sys.executable, "-m", "toolkit.verify.xss_context",
        "--input", str(pf),
        "--output", str(out),
        "--db", str(ctx.db_path),
    ]
    if ctx.scope_path:
        cmd += ["--scope", str(ctx.scope_path)]
    rc, _, err = _run_subprocess(cmd, timeout=1200, cwd=Path(__file__).resolve().parent)
    return StageResult("xss_context", rc == 0, out, err, time.time() - t0)


def _stage_idor_crosssession(ctx: OrchestratorContext) -> StageResult:
    out = ctx.stage_output("idor_crosssession").with_suffix(".json")
    if ctx.mode == "resume" and out.exists():
        return StageResult("idor_crosssession", True, out, skipped=True)
    api = ctx.stage_output("apifuzz").with_suffix(".json")
    if not api.exists() or not ctx.auth_profiles_path:
        return StageResult("idor_crosssession", False, None,
                           "depends on apifuzz + auth_profiles", 0.0, skipped=True)
    t0 = time.time()
    cmd = [
        sys.executable, "-m", "toolkit.verify.idor_crosssession",
        "--input", str(api),
        "--auth-profiles", str(ctx.auth_profiles_path),
        "--output", str(out),
        "--db", str(ctx.db_path),
    ]
    if ctx.scope_path:
        cmd += ["--scope", str(ctx.scope_path)]
    rc, _, err = _run_subprocess(cmd, timeout=1800, cwd=Path(__file__).resolve().parent)
    return StageResult("idor_crosssession", rc == 0, out, err, time.time() - t0)


def _stage_secret_verify(ctx: OrchestratorContext) -> StageResult:
    out = ctx.stage_output("secret_verify").with_suffix(".json")
    if ctx.mode == "resume" and out.exists():
        return StageResult("secret_verify", True, out, skipped=True)
    js = ctx.stage_output("jsreaper").with_suffix(".json")
    if not js.exists():
        return StageResult("secret_verify", False, None, "depends on jsreaper", 0.0, skipped=True)
    t0 = time.time()
    cmd = [
        sys.executable, "-m", "toolkit.verify.secret_verify",
        "--input", str(js),
        "--output", str(out),
        "--db", str(ctx.db_path),
    ]
    if ctx.scope_path:
        cmd += ["--scope", str(ctx.scope_path)]
    rc, _, err = _run_subprocess(cmd, timeout=900, cwd=Path(__file__).resolve().parent)
    return StageResult("secret_verify", rc == 0, out, err, time.time() - t0)


def _stage_graphql_deep(ctx: OrchestratorContext) -> StageResult:
    out = ctx.stage_output("graphql_deep").with_suffix(".json")
    if ctx.mode == "resume" and out.exists():
        return StageResult("graphql_deep", True, out, skipped=True)
    js = ctx.stage_output("jsreaper").with_suffix(".json")
    if not js.exists():
        return StageResult("graphql_deep", False, None, "depends on jsreaper", 0.0, skipped=True)
    t0 = time.time()
    cmd = [
        sys.executable, "-m", "toolkit.testers.graphql_deep",
        "--input", str(js),
        "--output", str(out),
        "--db", str(ctx.db_path),
    ]
    if ctx.scope_path:
        cmd += ["--scope", str(ctx.scope_path)]
    rc, _, err = _run_subprocess(cmd, timeout=900, cwd=Path(__file__).resolve().parent)
    return StageResult("graphql_deep", rc == 0, out, err, time.time() - t0)


def _stage_upload_probe(ctx: OrchestratorContext) -> StageResult:
    out = ctx.stage_output("upload_probe").with_suffix(".json")
    if ctx.mode == "resume" and out.exists():
        return StageResult("upload_probe", True, out, skipped=True)
    js = ctx.stage_output("jsreaper").with_suffix(".json")
    if not js.exists():
        return StageResult("upload_probe", False, None, "depends on jsreaper", 0.0, skipped=True)
    t0 = time.time()
    cmd = [
        sys.executable, "-m", "toolkit.testers.upload_probe",
        "--input", str(js),
        "--output", str(out),
        "--db", str(ctx.db_path),
    ]
    if ctx.scope_path:
        cmd += ["--scope", str(ctx.scope_path)]
    rc, _, err = _run_subprocess(cmd, timeout=900, cwd=Path(__file__).resolve().parent)
    return StageResult("upload_probe", rc == 0, out, err, time.time() - t0)


def _stage_apk_static(ctx: OrchestratorContext) -> StageResult:
    """Conditional stage — only runs if --apk-dir is provided."""
    out = ctx.stage_output("apk_static").with_suffix(".json")
    apk_dir = ctx.__dict__.get("apk_dir")  # set externally if --apk-dir provided
    if not apk_dir:
        return StageResult("apk_static", False, None, "no --apk-dir provided", 0.0, skipped=True)
    if ctx.mode == "resume" and out.exists():
        return StageResult("apk_static", True, out, skipped=True)
    t0 = time.time()
    cmd = [
        sys.executable, "-m", "toolkit.testers.apk_static",
        "--apk-dir", str(apk_dir),
        "--output", str(out),
        "--db", str(ctx.db_path),
    ]
    rc, _, err = _run_subprocess(cmd, timeout=600, cwd=Path(__file__).resolve().parent)
    return StageResult("apk_static", rc == 0, out, err, time.time() - t0)


def _stage_nuclei_harvest(ctx: OrchestratorContext) -> StageResult:
    out = ctx.stage_output("nuclei-harvest")
    t0 = time.time()
    cmd = [
        sys.executable, str(SCRIPTS_DIR / "nuclei-harvest.py"),
        "--domain", ctx.target,
        "--output", str(out),
    ]
    # Wire all available stage outputs as inputs
    for stage_name, flag in (
        ("subtakeover", "--subtakeover"),
        ("reconharvest", "--scan"),
        ("headeraudit", "--headers"),
        ("4xxbypass", "--bypass"),
        ("apifuzz", "--api"),
        ("cloudexpose", "--cloud"),
        ("ssrfprobe", "--ssrf"),
        ("oauthprobe", "--oauth"),
        ("gitdump", "--git"),
        ("paramfuzz", "--params"),
    ):
        p = ctx.stage_output(stage_name).with_suffix(".json")
        if p.exists():
            cmd += [flag, str(p)]
    # New toolkit (Layer 4 verify/testers) stages emit canonical NormalizedFinding
    # JSON. Feed the whole working directory so nuclei-harvest ingests every
    # *-findings.json via its --all-findings normalized parser (secret_verify,
    # idor_crosssession, xss_context, graphql_deep, spa_router, upload_probe,
    # apk_static) in addition to the legacy per-tool flags above.
    cmd += ["--all-findings", str(ctx.work_dir)]
    rc, _, err = _run_subprocess(cmd, timeout=600)
    return StageResult("nuclei-harvest", rc == 0, out, err, time.time() - t0)


def _stage_triage_memory(ctx: OrchestratorContext) -> StageResult:
    out = ctx.stage_output("triage_queue").with_suffix(".md")
    final_json = ctx.stage_output("nuclei-harvest").with_suffix(".json")
    if not final_json.exists():
        return StageResult("triage_memory", False, None,
                           "depends on nuclei-harvest", 0.0, skipped=True)
    t0 = time.time()
    # Non-interactive: just produce the queue. User runs triage_memory.py
    # directly when ready to triage.
    cmd = [
        sys.executable, "-m", "toolkit.verify.triage_memory",
        "--input", str(final_json),
        "--output", str(out),
        "--db", str(ctx.db_path),
        "--print-queue",
    ]
    rc, out_text, err = _run_subprocess(cmd, timeout=120, cwd=Path(__file__).resolve().parent)
    if rc == 0:
        # --print-queue outputs to stdout; orchestrator captures and saves
        out.write_text(out_text, encoding="utf-8")
    return StageResult("triage_memory", rc == 0, out, err, time.time() - t0)


# ── Stage list ───────────────────────────────────────────────────────────────

QUICK_STAGES = [
    ("subtakeover", _stage_subtakeover),
    ("reconharvest", _stage_reconharvest),
    ("jsreaper", _stage_jsreaper),
    ("headeraudit", _stage_headeraudit),
    ("nuclei-harvest", _stage_nuclei_harvest),
    ("triage_memory", _stage_triage_memory),
]

DEEP_STAGES = [
    ("subtakeover", _stage_subtakeover),
    ("reconharvest", _stage_reconharvest),
    ("gitdump", _stage_gitdump),
    ("jsreaper", _stage_jsreaper),
    ("spa_router", _stage_spa_router),
    ("headeraudit", _stage_headeraudit),
    ("4xxbypass", _stage_4xxbypass),
    ("apifuzz", _stage_apifuzz),
    ("paramfuzz", _stage_paramfuzz),
    ("ssrfprobe", _stage_ssrfprobe),
    ("oauthprobe", _stage_oauthprobe),
    ("cloudexpose", _stage_cloudexpose),
    ("xss_context", _stage_xss_context),
    ("idor_crosssession", _stage_idor_crosssession),
    ("secret_verify", _stage_secret_verify),
    ("graphql_deep", _stage_graphql_deep),
    ("upload_probe", _stage_upload_probe),
    ("apk_static", _stage_apk_static),
    ("nuclei-harvest", _stage_nuclei_harvest),
    ("triage_memory", _stage_triage_memory),
]


# Superset of every stage (used for --stages validation and --list-stages).
ALL_STAGES: dict[str, Any] = dict(DEEP_STAGES)


def get_stage_fn(name: str) -> Any:
    """Return the stage callable for a name, or None if unknown."""
    return ALL_STAGES.get(name)


def resolve_stages(mode: str, stages_filter: list[str] | None = None) -> list[tuple[str, Any]]:
    """Return the (name, fn) list to execute.

    - If ``stages_filter`` is provided, validate each (case-insensitive) and
      return them in the requested order (B14: run a subset of stages).
    - Otherwise fall back to QUICK_STAGES / DEEP_STAGES by mode.
    """
    if stages_filter:
        known = {n.lower(): (n, fn) for n, fn in ALL_STAGES.items()}
        resolved: list[tuple[str, Any]] = []
        for s in stages_filter:
            key = s.strip().lower()
            if key not in known:
                raise ValueError(
                    f"unknown stage: {s!r} (known stages: {', '.join(sorted(ALL_STAGES))})")
            resolved.append(known[key])
        return resolved
    return QUICK_STAGES if mode == "quick" else DEEP_STAGES


# ── Main orchestrator ────────────────────────────────────────────────────────

def run_pipeline(ctx: OrchestratorContext) -> int:
    """Execute all stages for this ctx.mode. Returns 0 on full success, 1 on
    any stage failure (but still completes non-dependent stages)."""
    try:
        stages = resolve_stages(ctx.mode, ctx.stages_filter)
    except ValueError as exc:
        log.error("%s", exc)
        return 2
    if ctx.dry_run:
        log.info("dry-run: planned %d stages for target=%s mode=%s", len(stages), ctx.target, ctx.mode)
        for i, (name, _fn) in enumerate(stages, start=1):
            log.info("  [%d] %s", i, name)
        return 0
    log.info("=" * 70)
    log.info("Orchestrator starting: target=%s mode=%s stages=%d", ctx.target, ctx.mode, len(stages))
    log.info("work_dir=%s", ctx.work_dir)
    log.info("=" * 70)

    # Initialize pipeline_state
    state = PipelineState(ctx.db_path)
    ctx.run_id = state.start_run(ctx.target, scope_yaml=str(ctx.scope_path or ""),
                                 mode=ctx.mode, stages_total=len(stages))
    state.update_run(ctx.run_id, stages_completed=0)

    # Install Ctrl+C handler — set _interrupted flag, let current stage finish
    def _sigint(sig, frame):
        log.warning("Ctrl+C received — finishing current stage then exiting...")
        ctx._interrupted = True
    original_sigint = signal.signal(signal.SIGINT, _sigint)

    completed = 0
    failed = 0
    failed_stage_name = ""
    try:
        for i, (name, fn) in enumerate(stages, start=1):
            if ctx._interrupted:
                log.info("interrupted — stopping before stage %d (%s)", i, name)
                break
            log.info("─" * 70)
            log.info("Stage %d/%d: %s", i, len(stages), name)
            log.info("─" * 70)
            try:
                result = fn(ctx)
            except Exception as exc:
                log.exception("stage %s raised: %s", name, exc)
                result = StageResult(name, False, None, str(exc))
            ctx.stage_results.append(result)
            if result.skipped:
                log.info("  skipped (already done or precondition not met): %s", result.error)
                # Skipped doesn't count as completed or failed
            elif result.success:
                completed += 1
                state.update_run(ctx.run_id, stages_completed=completed)
                log.info("  ✓ %s (%.1fs)%s", name, result.duration_s,
                         f" → {result.output_path}" if result.output_path else "")
            else:
                failed += 1
                failed_stage_name = name
                state.update_run(ctx.run_id, stages_failed=failed, failed_stage=name,
                                 error=result.error[:500])
                log.error("  ✗ %s (%.1fs) — %s", name, result.duration_s, result.error[:200])
                log.warning("  continuing with non-dependent stages (graceful degradation)")
        # Done
        state.update_run(ctx.run_id, finished=True, error=None if not failed else f"failed: {failed_stage_name}",
                         summary={"completed": completed, "failed": failed, "skipped": sum(1 for r in ctx.stage_results if r.skipped)})
        log.info("=" * 70)
        log.info("Orchestrator complete: %d completed, %d failed, %d skipped",
                 completed, failed, sum(1 for r in ctx.stage_results if r.skipped))
        log.info("Work dir: %s", ctx.work_dir)
        log.info("Triage queue: %s", ctx.stage_output("triage_queue").with_suffix(".md"))
        log.info("=" * 70)
        return 0 if failed == 0 else 1
    finally:
        signal.signal(signal.SIGINT, original_sigint)
        state.close()


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="orchestrator.py",
        description="Top-level pipeline entry point. Replaces WORKFLOW.md's 10-step manual process.",
    )
    ap.add_argument("--target", "-t", help="target domain (e.g., acme.com)")
    ap.add_argument("--scope", help="scope.yaml path (required for --watch)")
    ap.add_argument("--auth-profiles", help="auth_profiles.yaml path")
    ap.add_argument("--quick", action="store_true", help="quick mode: subtakeover + jsreaper + headeraudit only")
    ap.add_argument("--deep", action="store_true", help="deep mode: full 15+ stage pipeline")
    ap.add_argument("--resume", action="store_true", help="resume from last checkpoint (skip stages with existing output)")
    ap.add_argument("--stages", help="B14: comma-separated subset of stages to run, e.g. jsreaper,headeraudit")
    ap.add_argument("--list-stages", action="store_true", help="B15: print all available stage names and exit")
    ap.add_argument("--dry-run", action="store_true", help="B15: print the planned stages without executing them")
    ap.add_argument("--watch", action="store_true", help="hand off to watch_daemon.py — continuous monitoring")
    ap.add_argument("--interval", type=int, default=3600, help="watch interval in seconds (default: 3600)")
    ap.add_argument("--output-dir", default="./work", help="root work directory (default: ./work)")
    ap.add_argument("--db", default="pipeline_state.db", help="pipeline_state.db path")
    ap.add_argument("--apk-dir", help="path to apktool-decoded APK directory (enables apk_static stage)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    if not SCRIPTS_DIR.is_dir():
        log.error(
            "scripts/ directory not found at %s. Orchestrator must run from the "
            "SubTakeover repo root, or SCRIPTS_DIR must be set.", REPO_ROOT,
        )
        return 2

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )

    if args.list_stages:
        print("Available orchestrator stages:")
        for name in sorted(ALL_STAGES):
            membership = []
            if name in dict(QUICK_STAGES):
                membership.append("quick")
            if name in dict(DEEP_STAGES):
                membership.append("deep")
            print(f"  - {name}  [{','.join(membership) or 'conditional'}]")
        return 0

    if args.watch:
        if not args.scope:
            log.error("--watch requires --scope")
            return 2
        # Hand off to watch_daemon
        from toolkit import watch_daemon
        return watch_daemon.run_watch(
            scope_path=Path(args.scope),
            auth_profiles_path=Path(args.auth_profiles) if args.auth_profiles else None,
            interval=args.interval,
            output_dir=Path(args.output_dir),
            db_path=Path(args.db),
        )

    if not args.target:
        log.error("--target is required (unless --watch)")
        return 2
    if not (args.quick or args.deep or args.resume):
        log.error("must specify --quick, --deep, or --resume")
        return 2

    # Determine mode
    mode = "resume" if args.resume else ("quick" if args.quick else "deep")
    if mode == "resume":
        # Look up the previous mode from pipeline_state
        state = PipelineState(args.db)
        try:
            last = state.get_last_run(args.target)
            if last and last.get("mode") in ("quick", "deep"):
                mode_for_resume = last["mode"]
                log.info("resuming last %s run for %s", mode_for_resume, args.target)
                # Use the same stage list — resume will skip stages that already produced output
                mode = mode_for_resume if mode_for_resume == "deep" else "quick"
            else:
                log.warning("no previous run found for %s — falling back to --deep", args.target)
                mode = "deep"
        finally:
            state.close()

    # Build workdir: ./work/<target>/<timestamp>/
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = args.target.replace("/", "_").replace(":", "_")
    work_dir = Path(args.output_dir) / safe_target / timestamp
    work_dir.mkdir(parents=True, exist_ok=True)
    log.info("work directory: %s", work_dir)

    ctx = OrchestratorContext(
        target=args.target,
        work_dir=work_dir,
        scope_path=Path(args.scope) if args.scope else None,
        auth_profiles_path=Path(args.auth_profiles) if args.auth_profiles else None,
        db_path=Path(args.db),
        mode=mode,
    )
    if args.stages:
        ctx.stages_filter = [s for s in args.stages.split(",") if s.strip()]
    ctx.dry_run = bool(args.dry_run)
    if args.apk_dir:
        ctx.__dict__["apk_dir"] = Path(args.apk_dir)

    # Configure scope_guard globally so stages inherit it
    if ctx.scope_path:
        scope_guard.configure(ctx.scope_path)
    if ctx.auth_profiles_path:
        auth_profiles.configure(ctx.auth_profiles_path)

    return run_pipeline(ctx)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(0)
