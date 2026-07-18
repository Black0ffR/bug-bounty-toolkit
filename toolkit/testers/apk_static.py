#!/usr/bin/env python3
"""
apk_static.py — Android APK static analysis
============================================

Tier 4 tester (conditional — only runs when a program's scope includes a mobile client).

Purpose
-------
Reuses the secret-regex + entropy engine from secret_verify.py's normalization
layer against decompiled Android artifacts:
  - AndroidManifest.xml — exported components (activities/services/receivers/
    providers with android:exported="true"), debuggable flag, allowBackup,
    network security config
  - strings.xml — hardcoded strings (URLs, API keys, internal hostnames)
  - *.smali files — decompiled Dalvik bytecode; same secret patterns as JS
  - resources/*.xml — additional config leakage

This is the mobile-side equivalent of jsreaper.py + secret_verify.py.

Chain position
--------------
Layer 3 (conditional) — Input: path to a decompiled APK directory
                        (output of `apktool d app.apk -o app_decoded`).
                        Output: apk-findings.json.
                        Persisted: pipeline_state.db.

Prerequisites
-------------
- apktool must be installed and have decompiled the APK before this tool runs.
  We don't shell out to apktool — we read its output directory.

Usage
-----
    python -m toolkit.testers.apk_static \\
        --apk-dir ./app_decoded \\
        --output apk-findings.json

Author : Bug Bounty Toolkit / Tier 4
License : MIT (for authorized use only)
"""

from __future__ import annotations

import argparse
import datetime
import json
import logging
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from toolkit.infra.finding import compute_finding_id
from toolkit.infra.pipeline_state import PipelineState
# Reuse secret_verify's provider detection
from toolkit.verify.secret_verify import _PROVIDER_PATTERNS, _looks_like_placeholder, _detect_provider


log = logging.getLogger("apk_static")

# AndroidManifest.xml namespace
_ANDROID_NS = "http://schemas.android.com/apk/res/android"


@dataclass
class ApkFinding:
    file: str
    line: int
    finding_type: str           # exported_component | debuggable | allow_backup | cleartext_traffic | hardcoded_secret | internal_url | api_endpoint
    severity: str
    title: str
    detail: str
    evidence: str
    extra: dict[str, Any] = field(default_factory=dict)


def _parse_manifest(manifest_path: Path) -> list[ApkFinding]:
    """Parse an AndroidManifest.xml file (apktool output) for risky declarations."""
    try:
        tree = ET.parse(manifest_path)
    except ET.ParseError as exc:
        log.warning("could not parse %s: %s", manifest_path, exc)
        return []
    return _parse_manifest_root(tree.getroot(), manifest_path)


def _parse_manifest_root(root: Any, manifest_path: Path) -> list[ApkFinding]:
    """Parse an in-memory AndroidManifest root element for risky declarations."""
    out: list[ApkFinding] = []
    pkg = root.get("package", "?")
    # debuggable
    application = root.find("application")
    if application is not None:
        if application.get(f"{{{_ANDROID_NS}}}debuggable", "false").lower() == "true":
            out.append(ApkFinding(
                file=str(manifest_path), line=0,
                finding_type="debuggable",
                severity="HIGH",
                title="Android: debuggable=true",
                detail=f"App {pkg} has android:debuggable=\"true\". Anyone with USB access "
                       "can attach a debugger and inspect/modify the app's runtime state.",
                evidence=f"application@android:debuggable=true in {manifest_path.name}",
                extra={"package": pkg},
            ))
        if application.get(f"{{{_ANDROID_NS}}}allowBackup", "false").lower() == "true":
            out.append(ApkFinding(
                file=str(manifest_path), line=0,
                finding_type="allow_backup",
                severity="MEDIUM",
                title="Android: allowBackup=true",
                detail=f"App {pkg} has android:allowBackup=\"true\". Users with USB access can "
                       "extract the app's local data (SharedPreferences, databases) via adb backup.",
                evidence=f"application@android:allowBackup=true in {manifest_path.name}",
                extra={"package": pkg},
            ))
        if application.get(f"{{{_ANDROID_NS}}}usesCleartextTraffic", "false").lower() == "true":
            out.append(ApkFinding(
                file=str(manifest_path), line=0,
                finding_type="cleartext_traffic",
                severity="MEDIUM",
                title="Android: usesCleartextTraffic=true",
                detail=f"App {pkg} allows cleartext HTTP traffic. Network MITM can read/modify "
                       "all app traffic.",
                evidence=f"application@android:usesCleartextTraffic=true in {manifest_path.name}",
                extra={"package": pkg},
            ))
        # Network security config
        nsc = application.get(f"{{{_ANDROID_NS}}}networkSecurityConfig")
        if nsc:
            out.append(ApkFinding(
                file=str(manifest_path), line=0,
                finding_type="network_security_config",
                severity="INFO",
                title="Android: custom networkSecurityConfig",
                detail=f"App {pkg} uses a custom networkSecurityConfig ({nsc}). Review it for "
                       "trust-anchors / cleartext-permit / certificate pinning bypass.",
                evidence=f"application@android:networkSecurityConfig={nsc}",
                extra={"package": pkg, "config_resource": nsc},
            ))
    # Exported components
    for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
        for comp in root.iter(tag):
            exported = comp.get(f"{{{_ANDROID_NS}}}exported", "false").lower()
            if exported != "true":
                continue
            name = comp.get(f"{{{_ANDROID_NS}}}name", comp.get("name", "?"))
            permission = comp.get(f"{{{_ANDROID_NS}}}permission", "")
            # Providers with grantUriPermissions=true are higher risk
            grant_uri = comp.get(f"{{{_ANDROID_NS}}}grantUriPermissions", "false").lower() == "true"
            sev = "MEDIUM"
            if tag == "provider" and grant_uri:
                sev = "HIGH"
            if tag in ("activity", "activity-alias") and not permission:
                sev = "MEDIUM"
            if tag in ("service", "receiver") and not permission:
                sev = "MEDIUM"
            out.append(ApkFinding(
                file=str(manifest_path), line=0,
                finding_type="exported_component",
                severity=sev,
                title=f"Android: exported {tag} '{name}'",
                detail=f"Component {name} (type={tag}) is exported. "
                       + (f"Protected by permission '{permission}'." if permission else
                          "No permission required to invoke — any app on the device can call it.")
                       + (f" grantUriPermissions=true — URIs granted to callers can access "
                          f"any path under the provider." if grant_uri else ""),
                evidence=f"{tag}@android:name={name} android:exported=true "
                         + (f"android:permission={permission}" if permission else "(no permission)"),
                extra={"component_type": tag, "component_name": name,
                       "permission": permission, "grant_uri": grant_uri},
            ))
    return out


def _scan_text_file(path: Path, content: str) -> list[ApkFinding]:
    """Scan a text file (smali, strings.xml, etc.) for hardcoded secrets,
    internal URLs, and API endpoints. Reuses secret_verify's regex set."""
    out: list[ApkFinding] = []
    # Secrets
    for line_num, line in enumerate(content.splitlines(), start=1):
        for provider_name, pat in _PROVIDER_PATTERNS.items():
            for m in pat.finditer(line):
                value = m.group(0)
                if _looks_like_placeholder(value):
                    continue
                sev = "HIGH" if provider_name in ("aws_access_key_id", "github_pat",
                                                   "slack_bot_token", "stripe_secret_key",
                                                   "google_api_key") else "MEDIUM"
                out.append(ApkFinding(
                    file=str(path), line=line_num,
                    finding_type="hardcoded_secret",
                    severity=sev,
                    title=f"Hardcoded {provider_name} in {path.name}",
                    detail=f"Found a {provider_name} pattern at line {line_num} of {path.name}. "
                           f"Run secret_verify.py to confirm liveness.",
                    evidence=f"line {line_num}: ...{value[:8]}…{value[-4:]}...",
                    extra={"provider": provider_name, "value_redacted": value[:4] + "…" + value[-4:]},
                ))
        # Internal URLs / IP addresses
        for m in re.finditer(r"\b((?:https?://|wss?://)(?:[a-zA-Z0-9\-._~%]+|\[[0-9a-f:]+\])(?::\d+)?(?:/[^\s\"'<>]*)?)", line):
            url = m.group(1)
            # Filter common external SDKs
            if any(host in url for host in ("googleapis.com", "gstatic.com",
                                            "facebook.com", "fbcdn.net", "apple.com",
                                            "schema.org", "w3.org")):
                continue
            # Look for internal-looking hosts
            host = re.match(r"\w+://([^/:]+)", url)
            if host:
                hostname = host.group(1)
                # Internal IPs
                if re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.)", hostname):
                    out.append(ApkFinding(
                        file=str(path), line=line_num,
                        finding_type="internal_url",
                        severity="MEDIUM",
                        title=f"Internal/private URL in {path.name}",
                        detail=f"Found internal URL {url} at line {line_num}.",
                        evidence=f"line {line_num}: {url}",
                        extra={"url": url},
                    ))
                # Staging/dev hostnames
                elif any(k in hostname.lower() for k in ("staging", "stg", "dev.",
                                                          "test.", "internal.", "corp.",
                                                          "local", "localhost")):
                    out.append(ApkFinding(
                        file=str(path), line=line_num,
                        finding_type="internal_url",
                        severity="MEDIUM",
                        title=f"Internal/dev URL in {path.name}",
                        detail=f"Found dev/staging URL {url} at line {line_num} — internal "
                               "endpoint leaked in mobile client.",
                        evidence=f"line {line_num}: {url}",
                        extra={"url": url},
                    ))
    return out


def _import_androguard():
    """Lazy-import androguard's APK class, or return None if not installed."""
    try:
        from androguard.core.apk import APK
        return APK
    except Exception:
        return None


def scan_apk_file(apk_file: Path) -> list[ApkFinding]:
    """Directly analyze a .apk using androguard (no apktool decode step).
    Raises RuntimeError with an install hint if androguard is unavailable."""
    APK = _import_androguard()
    if APK is None:
        raise RuntimeError(
            "androguard is required to scan .apk files directly. "
            "Install it (`pip install androguard`) or decompile first with "
            "`apktool d app.apk -o app_decoded` and pass --apk-dir."
        )
    apk = APK(str(apk_file))
    findings: list[ApkFinding] = []
    # 1. Manifest — androguard returns an lxml element; re-parse with stdlib
    #    so we can reuse the same manifest-parsing logic as the apktool path.
    try:
        from lxml import etree as _lxml_etree  # type: ignore
        manifest_xml = apk.get_android_manifest_xml()
        manifest_bytes = _lxml_etree.tostring(manifest_xml) if manifest_xml is not None else b""
        if manifest_bytes:
            root = ET.fromstring(manifest_bytes)
            findings.extend(_parse_manifest_root(root, Path(str(apk_file))))
    except Exception as exc:  # pragma: no cover - depends on androguard
        log.warning("could not parse manifest from %s: %s", apk_file, exc)
    # 2. DEX strings — same secret/url patterns as the smali path
    try:
        strings = apk.get_strings() or set()
        content = "\n".join(str(s) for s in strings)
        findings.extend(_scan_text_file(Path(apk_file.name), content))
    except Exception as exc:  # pragma: no cover - depends on androguard
        log.warning("could not extract strings from %s: %s", apk_file, exc)
    return findings


def scan_apk_dir(apk_dir: Path) -> list[ApkFinding]:
    """Scan a decompiled APK directory."""
    findings: list[ApkFinding] = []
    # 1. AndroidManifest.xml
    manifest = apk_dir / "AndroidManifest.xml"
    if manifest.exists():
        log.info("parsing %s", manifest)
        findings.extend(_parse_manifest(manifest))
    else:
        log.warning("no AndroidManifest.xml found in %s", apk_dir)
    # 2. Scan smali files
    smali_dirs = sorted(apk_dir.glob("smali*"))
    if not smali_dirs:
        log.warning("no smali* directories found — was this decompiled with apktool?")
    total_smali = 0
    for sd in smali_dirs:
        for sf in sd.rglob("*.smali"):
            total_smali += 1
            try:
                content = sf.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            findings.extend(_scan_text_file(sf, content))
    log.info("scanned %d smali files", total_smali)
    # 3. Scan res/values/strings.xml
    strings_xml = apk_dir / "res" / "values" / "strings.xml"
    if strings_xml.exists():
        try:
            content = strings_xml.read_text(encoding="utf-8", errors="replace")
            findings.extend(_scan_text_file(strings_xml, content))
        except OSError:
            pass
    # 4. Scan res/xml/network_security_config.xml if present
    nsc = apk_dir / "res" / "xml" / "network_security_config.xml"
    if nsc.exists():
        try:
            content = nsc.read_text(encoding="utf-8", errors="replace")
            # Look for cleartextTrafficPermitted=true or trust-anchors
            if "cleartextTrafficPermitted" in content and '="true"' in content:
                findings.append(ApkFinding(
                    file=str(nsc), line=0,
                    finding_type="cleartext_traffic",
                    severity="MEDIUM",
                    title="Network security config permits cleartext traffic",
                    detail=f"{nsc.name} contains cleartextTrafficPermitted=\"true\" for at least "
                           "one domain. MITM can read app traffic for that domain.",
                    evidence=content[:300],
                ))
            if "trust-anchors" in content and "user" in content.lower():
                findings.append(ApkFinding(
                    file=str(nsc), line=0,
                    finding_type="user_ca_trust",
                    severity="LOW",
                    title="Network security config trusts user-installed CAs",
                    detail=f"{nsc.name} trusts user-installed CAs. Apps that should be MITM-"
                           "resistant should pin certificates instead.",
                    evidence=content[:300],
                ))
        except OSError:
            pass
    return findings


def to_normalized(findings: list[ApkFinding], apk_dir: str = "") -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for f in findings:
        evidence = f"{f.file}|{f.line}|{f.finding_type}|{f.evidence[:200]}"
        host = ""  # APK findings aren't host-scoped
        fid = compute_finding_id("apk_static.py", host or apk_dir, "APK_" + f.finding_type.upper(), evidence)
        out.append({
            "id": fid,
            "source_tool": "apk_static.py",
            "host": host,
            "url": f"file://{f.file}",
            "vuln_class_key": "APK_" + f.finding_type.upper(),
            "severity": f.severity,
            "title": f.title,
            "detail": f.detail,
            "evidence": f.evidence,
            "remediation": (
                "Set android:debuggable=false, android:allowBackup=false, "
                "android:usesCleartextTraffic=false in production builds. Audit exported "
                "components — set android:exported=false unless truly public. Move secrets "
                "out of the APK and into server-issued tokens. Use certificate pinning."
            ),
            "raw": {"file": f.file, "line": f.line, **f.extra},
            "confidence": "candidate",
            "disposition": "new",
            "verified_by": None,
        })
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="apk_static.py",
        description="Android APK static analysis. Conditional stage — run when scope includes mobile.",
    )
    ap.add_argument("--apk-dir", help="path to apktool-decoded APK directory")
    ap.add_argument("--apk-file", help="path to a .apk file (analyzed directly via androguard)")
    ap.add_argument("--output", "-o", default="apk-findings.json")
    ap.add_argument("--db", default="pipeline_state.db")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )

    # Exactly one input source is required.
    if bool(args.apk_dir) == bool(args.apk_file):
        log.error("specify exactly one of --apk-dir or --apk-file")
        return 2

    if args.apk_file:
        apk_file = Path(args.apk_file)
        if not apk_file.is_file():
            log.error("apk-file not found: %s", apk_file)
            return 2
        try:
            findings = scan_apk_file(apk_file)
        except RuntimeError as exc:
            log.error("%s", exc)
            return 2
        apk_label = str(apk_file)
    else:
        apk_dir = Path(args.apk_dir)
        if not apk_dir.is_dir():
            log.error("apk-dir not found or not a directory: %s", apk_dir)
            return 2
        findings = scan_apk_dir(apk_dir)
        apk_label = str(apk_dir)

    log.info("total findings: %d", len(findings))
    normalized = to_normalized(findings, apk_dir=apk_label)

    state = PipelineState(args.db)
    try:
        for f in normalized:
            state.upsert_finding(f)
    finally:
        state.close()

    out_path = Path(args.output)
    out_path.write_text(
        json.dumps({
            "scan_time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "apk_dir": apk_label,
            "total_findings": len(normalized),
            "findings": normalized,
        }, indent=2, default=str),
        encoding="utf-8",
    )
    log.info("wrote %s", out_path)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(0)
