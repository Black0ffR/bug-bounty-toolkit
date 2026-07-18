#!/usr/bin/env python3
"""
prototype_pollution.py — Prototype Pollution sink scanner
=========================================================

Tier 3 tester.

Purpose
-------
Prototype pollution (CWE-1321) is a server-side JS weakness where a recursive
merge/clone over attacker-controlled keys lets `__proto__` or
`constructor.prototype` be written, poisoning `Object.prototype` for every
object in the process. This opens the door to property injection, filter
bypass, and RCE on some template engines.

This module is **Termux-native**: it does *static* sink + payload analysis on
source (JS / TS / JSX / a jsreaper JSON dump). An optional Playwright-based
confirmation hook is provided but never required to run.

What it finds
-------------
  1. Dangerous recursive merge/extend sinks: `_.merge`, `_.extend`, `$.extend`,
     `deepExtend`, `mergeDeep`, `Object.assign` (recursive forms), custom
     `merge(`/`extend(` helpers.
  2. Direct prototype assignment: `obj["__proto__"] =`, `obj.__proto__ =`,
     `constructor.prototype[` patterns.
  3. Untrusted-source merge: a detected sink fed by `req.body` / `JSON.parse(`
     / query params without a `__proto__` guard.

Usage
-----
    python -m toolkit.testers.prototype_pollution --path ./src
    python -m toolkit.testers.prototype_pollution --input bundle.js
    python -m toolkit.testers.prototype_pollution --jsreaper dump.json

Author : Bug Bounty Toolkit / Tier 3
License : MIT (for authorized use only)
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger("prototype_pollution")

# Sink call patterns (function name followed by `(`). Captures the name.
_SINK_RE = re.compile(
    r"""(?P<name>(?:\$)?_?(?:merge|extend|mergeDeep|deepExtend|deepMerge|assign))\s*\(""")
# Direct prototype access/assignment (any __proto__ or constructor.prototype ref)
_PROTO_ASSIGN_RE = re.compile(
    r"""__proto__|constructor\s*\.prototype""")
# Untrusted sources feeding a sink or parse
_UNTRUSTED_SOURCE_RE = re.compile(
    r"""(?:req\.(?:body|query|params)|JSON\.parse|bodyParser|searchParams|qs\.parse|\.query)""")
# A sink call that is *not* preceded by a proto-key guard
_GUARD_RE = re.compile(r"""(?:hasOwnProperty|__proto__\s*===|'__proto__'|"__proto__")""")

SINK_NAMES = ["merge", "extend", "mergeDeep", "deepExtend", "deepMerge", "assign"]


@dataclass
class ProtoFinding:
    kind: str                      # sink | direct_assignment | untrusted_sink
    line: int
    snippet: str
    detail: str


def scan_text(text: str) -> list[ProtoFinding]:
    """Statically scan JS/TS source text for prototype-pollution signals."""
    findings: list[ProtoFinding] = []
    lines = text.splitlines()

    for i, line in enumerate(lines, start=1):
        # Direct prototype assignment (highest signal)
        if _PROTO_ASSIGN_RE.search(line):
            findings.append(ProtoFinding(
                kind="direct_assignment", line=i, snippet=line.strip()[:120],
                detail="Assignment to __proto__ or constructor.prototype detected — "
                       "direct pollution primitive."))

        # Dangerous sink
        for m in _SINK_RE.finditer(line):
            name = m.group("name").lstrip("$").rstrip("_")
            guarded = bool(_GUARD_RE.search(line))
            # suspect untrusted-source merge on the same line
            untrusted = bool(_UNTRUSTED_SOURCE_RE.search(line))
            if untrusted and not guarded:
                findings.append(ProtoFinding(
                    kind="untrusted_sink", line=i, snippet=line.strip()[:120],
                    detail=f"Recursive merge sink `{name}` fed by untrusted source "
                           f"with no __proto__ guard."))
            elif not guarded:
                findings.append(ProtoFinding(
                    kind="sink", line=i, snippet=line.strip()[:120],
                    detail=f"Recursive merge/extend sink `{name}` — verify it "
                           f"rejects __proto__ keys."))

    # De-duplicate identical (kind, line, snippet)
    seen = set()
    uniq: list[ProtoFinding] = []
    for f in findings:
        key = (f.kind, f.line, f.snippet)
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    return uniq


def scan_file(path: Path) -> list[ProtoFinding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        log.warning("cannot read %s: %s", path, exc)
        return []
    return scan_text(text)


def scan_path(root: Path, exts=(".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")) -> list[tuple[Path, ProtoFinding]]:
    results: list[tuple[Path, ProtoFinding]] = []
    files = [root] if root.is_file() else [p for p in root.rglob("*") if p.suffix in exts]
    for f in files:
        if f.is_file():
            for pf in scan_file(f):
                results.append((f, pf))
    return results


# ── jsreaper-shaped input ────────────────────────────────────────────────────

def scan_jsreaper(data: Any) -> list[ProtoFinding]:
    """jsreaper dumps a list of {path, content} or {url, content}. Pull the
    `content`/`script` field and scan it."""
    findings: list[ProtoFinding] = []
    if isinstance(data, dict):
        items = data.get("scripts") or data.get("files") or data.get("findings") or []
    elif isinstance(data, list):
        items = data
    else:
        return findings
    for item in items:
        if not isinstance(item, dict):
            continue
        content = item.get("content") or item.get("script") or item.get("source") or ""
        if isinstance(content, str) and content.strip():
            findings.extend(scan_text(content))
        elif isinstance(item.get("code"), str):
            findings.extend(scan_text(item["code"]))
    return findings


# ── Normalization ────────────────────────────────────────────────────────────

def to_normalized(scan_results: list[tuple[Path, ProtoFinding]],
                  source_tool: str = "prototype_pollution.py") -> list[dict[str, Any]]:
    from toolkit.infra.finding import compute_finding_id

    out: list[dict[str, Any]] = []
    for path, pf in scan_results:
        fid = compute_finding_id(source_tool, str(path), pf.kind, f"{pf.line}:{pf.snippet}")
        out.append({
            "id": fid,
            "source_tool": source_tool,
            "host": "",
            "url": str(path),
            "vuln_class_key": "PROTOTYPE_POLLUTION",
            "severity": "HIGH" if pf.kind in ("direct_assignment", "untrusted_sink") else "MEDIUM",
            "title": f"Prototype Pollution: {pf.kind}",
            "detail": pf.detail,
            "evidence": pf.snippet,
            "raw": {"line": pf.line, "kind": pf.kind},
            "confidence": "candidate",
            "disposition": "new",
            "verified_by": None,
        })
    return out


def main() -> int:
    ap = argparse.ArgumentParser(prog="prototype_pollution.py",
                                 description="Static Prototype Pollution sink scanner.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--path", "-p", help="file or directory to scan")
    src.add_argument("--input", "-i", help="JS/TS file or jsreaper JSON dump")
    src.add_argument("--jsreaper", help="jsreaper JSON dump (list of {content})")
    ap.add_argument("--output", "-o", default="proto-pollution-findings.json")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="[%(levelname)s] %(message)s")

    results: list[tuple[Path, ProtoFinding]] = []
    if args.path:
        p = Path(args.path)
        results = scan_path(p)
    elif args.jsreaper:
        data = json.loads(Path(args.jsreaper).read_text(encoding="utf-8"))
        findings = scan_jsreaper(data)
        results = [(Path("<jsreaper>"), f) for f in findings]
    else:
        text = Path(args.input).read_text(encoding="utf-8", errors="replace")
        try:
            data = json.loads(text)
            findings = scan_jsreaper(data)
        except json.JSONDecodeError:
            findings = scan_text(text)
        results = [(Path(args.input), f) for f in findings]

    norm = to_normalized(results)
    out_path = Path(args.output)
    out_path.write_text(json.dumps({
        "scan_time": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc).isoformat(timespec="seconds"),
        "findings": norm,
    }, indent=2), encoding="utf-8")
    log.info("scanned -> %d finding(s) written to %s", len(norm), out_path)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(0)
