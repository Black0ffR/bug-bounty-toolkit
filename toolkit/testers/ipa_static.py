#!/usr/bin/env python3
"""
ipa_static.py — iOS .ipa static analysis
==========================================

Tier 4 tester (conditional — only runs when a program's scope includes a
mobile iOS client).

Purpose
-------
Static analysis of an iOS application package (.ipa), the mobile-side
equivalent of apk_static.py + secret_verify.py:
  - Info.plist — CFBundleURLSchemes (custom URL scheme hijacking surface),
    entitlements (get-task-allow = debug builds, keychain-access-groups),
    embedded provisioning profile
  - app binary + resources — hardcoded secrets / internal URLs, reusing the
    same provider-pattern engine as secret_verify.py

Chain position
--------------
Layer 3 (conditional) — Input: path to an .ipa file, or to an already
                        unzipped *.app bundle directory.
                        Output: ipa-findings.json.

Usage
-----
    python -m toolkit.testers.ipa_static --ipa-file ./app.ipa --output ipa.json
    python -m toolkit.testers.ipa_static --app-dir ./Payload/MyApp.app

Author : Bug Bounty Toolkit / Tier 4
License : MIT (for authorized use only)
"""

from __future__ import annotations

import argparse
import datetime
import json
import logging
import plistlib
import re
import shutil
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from toolkit.infra.finding import compute_finding_id
from toolkit.infra.pipeline_state import PipelineState
from toolkit.verify.secret_verify import (
    _PROVIDER_PATTERNS,
    _looks_like_placeholder,
)

log = logging.getLogger("ipa_static")


@dataclass
class IpaFinding:
    file: str
    finding_type: str          # url_scheme | entitlement | provisioning | hardcoded_secret | internal_url
    severity: str
    title: str
    detail: str
    evidence: str
    extra: dict[str, Any] = field(default_factory=dict)


# ── Info.plist helpers ────────────────────────────────────────────────────────

def parse_info_plist(path: Path) -> dict[str, Any]:
    """Parse an Info.plist (binary or XML) into a dict."""
    return plistlib.loads(Path(path).read_bytes())


def extract_url_schemes(info_plist: dict[str, Any]) -> list[str]:
    """Return all CFBundleURLSchemes declared in an Info.plist dict."""
    schemes: list[str] = []
    for entry in info_plist.get("CFBundleURLTypes", []) or []:
        if not isinstance(entry, dict):
            continue
        for s in entry.get("CFBundleURLSchemes", []) or []:
            if isinstance(s, str) and s not in schemes:
                schemes.append(s)
    return schemes


# ── Secret / URL scanning (reuses secret_verify engine) ───────────────────────

_INTERNAL_HOST_RE = re.compile(
    r"\b((?:https?://|wss?://)(?:[a-zA-Z0-9\-._~%]+|\[[0-9a-f:]+\])(?::\d+)?(?:/[^\s\"'<>]*)?)"
)


def _scan_text(path: Path, content: str) -> list[IpaFinding]:
    out: list[IpaFinding] = []
    for line_num, line in enumerate(content.splitlines(), start=1):
        for provider_name, pat in _PROVIDER_PATTERNS.items():
            for mt in pat.finditer(line):
                value = mt.group(0)
                if _looks_like_placeholder(value):
                    continue
                sev = "HIGH" if provider_name in (
                    "aws_access_key_id", "github_pat", "slack_bot_token",
                    "stripe_secret_key", "google_api_key",
                ) else "MEDIUM"
                out.append(IpaFinding(
                    file=str(path), finding_type="hardcoded_secret",
                    severity=sev,
                    title=f"Hardcoded {provider_name} in {path.name}",
                    detail=f"Found a {provider_name} pattern at line {line_num}. "
                           "Run secret_verify.py to confirm liveness.",
                    evidence=f"line {line_num}: ...{value[:8]}…{value[-4:]}...",
                    extra={"provider": provider_name,
                           "value_redacted": value[:4] + "…" + value[-4:]},
                ))
        for mt in _INTERNAL_HOST_RE.finditer(line):
            url = mt.group(1)
            host_m = re.match(r"\w+://([^/:]+)", url)
            if not host_m:
                continue
            host = host_m.group(1)
            if re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.)", host):
                out.append(IpaFinding(
                    file=str(path), finding_type="internal_url", severity="MEDIUM",
                    title=f"Internal URL in {path.name}",
                    detail=f"Found internal URL {url}.",
                    evidence=f"line {line_num}: {url}", extra={"url": url},
                ))
            elif any(k in host.lower() for k in ("staging", "stg", "dev.", "test.",
                                                  "internal.", "corp.", "local", "localhost")):
                out.append(IpaFinding(
                    file=str(path), finding_type="internal_url", severity="MEDIUM",
                    title=f"Dev/staging URL in {path.name}",
                    detail=f"Found dev/staging URL {url}.",
                    evidence=f"line {line_num}: {url}", extra={"url": url},
                ))
    return out


# ── Bundle / .ipa scanning ─────────────────────────────────────────────────────

def scan_app_dir(app_dir: Path) -> list[IpaFinding]:
    """Scan an unzipped *.app bundle directory."""
    app_dir = Path(app_dir)
    findings: list[IpaFinding] = []
    info = app_dir / "Info.plist"
    if info.exists():
        try:
            plist = parse_info_plist(info)
        except Exception as exc:  # pragma: no cover
            log.warning("could not parse %s: %s", info, exc)
            plist = None
        if plist is not None:
            for s in extract_url_schemes(plist):
                findings.append(IpaFinding(
                    file=str(info), finding_type="url_scheme", severity="LOW",
                    title=f"Custom URL scheme '{s}'",
                    detail=f"App registers the URL scheme '{s}'. Verify no sensitive "
                           "action can be triggered via a crafted link (URL scheme "
                           "hijacking / deep-link validation).",
                    evidence=f"CFBundleURLSchemes contains '{s}'",
                    extra={"scheme": s},
                ))
            ents = plist.get("Entitlements") or {}
            if ents.get("get-task-allow") is True:
                findings.append(IpaFinding(
                    file=str(info), finding_type="entitlement", severity="HIGH",
                    title="Entitlement get-task-allow=true",
                    detail="App is signed with get-task-allow=true (debug build). "
                           "Debugger attach / runtime inspection is possible.",
                    evidence="Entitlements.get-task-allow = true",
                    extra={"entitlement": "get-task-allow"},
                ))
    # Embedded provisioning profile
    if (app_dir / "embedded.mobileprovision").exists():
        findings.append(IpaFinding(
            file=str(app_dir / "embedded.mobileprovision"),
            finding_type="provisioning", severity="INFO",
            title="Embedded provisioning profile present",
            detail="App ships an embedded.mobileprovision — review for expired/"
                   "over-broad device/entitlement scope.",
            evidence="embedded.mobileprovision present", extra={},
        ))
    # Scan all files (binary + resources) for secrets / internal URLs
    for f in sorted(app_dir.rglob("*")):
        if not f.is_file():
            continue
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(_scan_text(f, content))
    return findings


def scan_ipa_file(ipa_file: Path, *, _workdir: Path | None = None) -> list[IpaFinding]:
    """Unzip an .ipa into a temp dir and scan the discovered .app bundle."""
    ipa_file = Path(ipa_file)
    if not ipa_file.is_file():
        raise FileNotFoundError(ipa_file)
    work = _workdir or Path(ipa_file.parent) / (ipa_file.stem + ".ipa_extract")
    work.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(ipa_file) as z:
            z.extractall(work)
        app_dirs = sorted(work.rglob("*.app"))
        if not app_dirs:
            log.warning("no *.app bundle found inside %s", ipa_file)
            return []
        return scan_app_dir(app_dirs[0])
    finally:
        if _workdir is None:
            shutil.rmtree(work, ignore_errors=True)


def to_normalized(findings: list[IpaFinding], source: str = "") -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for f in findings:
        evidence = f"{f.file}|{f.finding_type}|{f.evidence[:200]}"
        fid = compute_finding_id("ipa_static.py", source, "IPA_" + f.finding_type.upper(), evidence)
        out.append({
            "id": fid,
            "source_tool": "ipa_static.py",
            "host": "",
            "url": f"file://{f.file}",
            "vuln_class_key": "IPA_" + f.finding_type.upper(),
            "severity": f.severity,
            "title": f.title,
            "detail": f.detail,
            "evidence": f.evidence,
            "remediation": (
                "Validate all custom URL scheme / universal-link handlers. Strip "
                "secrets from the app binary; issue tokens server-side. Sign release "
                "builds without get-task-allow. Review embedded entitlements."
            ),
            "raw": {"file": f.file, **f.extra},
            "confidence": "candidate",
            "disposition": "new",
            "verified_by": None,
        })
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="ipa_static.py",
        description="iOS .ipa static analysis. Conditional stage — run when scope includes iOS.",
    )
    ap.add_argument("--ipa-file", help="path to a .ipa file")
    ap.add_argument("--app-dir", help="path to an unzipped *.app bundle directory")
    ap.add_argument("--output", "-o", default="ipa-findings.json")
    ap.add_argument("--db", default="pipeline_state.db")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )

    if bool(args.ipa_file) == bool(args.app_dir):
        log.error("specify exactly one of --ipa-file or --app-dir")
        return 2

    try:
        if args.ipa_file:
            findings = scan_ipa_file(Path(args.ipa_file))
            label = str(args.ipa_file)
        else:
            findings = scan_app_dir(Path(args.app_dir))
            label = str(args.app_dir)
    except FileNotFoundError as exc:
        log.error("input not found: %s", exc)
        return 2

    log.info("total findings: %d", len(findings))
    normalized = to_normalized(findings, source=label)

    state = PipelineState(args.db)
    try:
        for f in normalized:
            state.upsert_finding(f)
    finally:
        state.close()

    Path(args.output).write_text(
        json.dumps({
            "scan_time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "source": label,
            "total_findings": len(normalized),
            "findings": normalized,
        }, indent=2, default=str),
        encoding="utf-8",
    )
    log.info("wrote %s", args.output)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(0)
