#!/usr/bin/env python3
"""
triage_memory.py — cross-run triage queue with persistent disposition
======================================================================

Tier 1 verification tool — extends nuclei-harvest.py, does NOT replace it.

Purpose
-------
Runs immediately after nuclei-harvest.py produces final.json. Cross-references
every finding's id against pipeline_state.db; anything already marked
'submitted' or 'rejected' in a past run is filtered out of the active queue
entirely. This is the piece nuclei-harvest.py's single-run dedup was missing.

Then presents the top N findings (default 10, matching the 10:1 lead-to-deep-
test ratio from the elite-workflow research) as an interactive terminal
checklist, one at a time, requiring a disposition before moving to the next.
On disposition 'submitted', auto-generates the HackerOne/Bugcrowd-formatted
writeup nuclei-harvest.py already knows how to produce for that finding.

Chain position
--------------
Layer 5 — Input: final.json (from nuclei-harvest.py).
          Output: triage_queue.md (a checklist, not another JSON dump).
          Persisted: pipeline_state.db (findings_history, triage_decisions).

Usage
-----
    # Interactive (default — top 10 findings, one at a time)
    python -m toolkit.verify.triage_memory --input final.json

    # CI / non-interactive (dispositions pre-filled in CSV)
    python -m toolkit.verify.triage_memory --input final.json \\
        --batch --dispositions-csv triage.csv

    # Just print the active queue without prompting (e.g. for review)
    python -m toolkit.verify.triage_memory --input final.json --print-queue \\
        --top 20

CSV format for --batch:
    finding_id,disposition,note
    abc123def456...,submitted,confirmed via Burp replay
    789abc...,rejected,false positive — shared resource

Author : Bug Bounty Toolkit / Tier 1
License : MIT (for authorized use only)
"""

from __future__ import annotations

import argparse
import csv
import datetime
import json
import logging
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from toolkit.infra.finding import (
    NormalizedFinding,
    compute_finding_id,
    normalize_finding_dict,
)
from toolkit.infra.pipeline_state import PipelineState


log = logging.getLogger("triage_memory")

# Severity ordering — CRITICAL first
_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# Default CVSS 3.1 vector per vulnerability class, used when a finding arrives
# without an explicit cvss_vector (previously the writeup rendered 'n/a' and
# triage lost the severity signal). Conservative, defensible baselines.
_DEFAULT_CVSS_BY_CLASS: dict[str, str] = {
    "BOLA_CONFIRMED": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "BOLA_POSSIBLE": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
    "IDOR_PARAM": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
    "JWT_NONE": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "PRIV_ESCALATION": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "MASS_ASSIGN": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "SSRF_CLOUD_METADATA": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "SSRF_INTERNAL": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "SECRET_IN_GIT": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "SUBDOMAIN_TAKEOVER": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "GQL_INTROSPECTION": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "RATE_LIMIT_API": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "HIDDEN_PARAM": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "DEBUG_BYPASS": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "PARAM_POLLUTION": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "ARRAY_INJECTION": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
}


def resolve_cvss_vector(finding: NormalizedFinding) -> str:
    """Return the finding's explicit CVSS vector, falling back to a class-based
    default so writeups never silently lose the severity signal."""
    if finding.cvss_vector and finding.cvss_vector.strip():
        return finding.cvss_vector
    return _DEFAULT_CVSS_BY_CLASS.get(finding.vuln_class_key, "n/a")


@dataclass
class TriageEntry:
    finding: NormalizedFinding
    is_new: bool          # True if first time seen in pipeline_state.db
    previously_submitted: bool
    previously_rejected: bool


def load_final_json(path: str | Path) -> list[dict[str, Any]]:
    """Load nuclei-harvest.py's final.json (or any compatible aggregator output).
    Returns the 'findings' array; tolerates multiple top-level shapes:
      - {"findings": [...]}                ← nuclei-harvest.py
      - {"results": [...]}                 ← some variants
      - [...]                              ← bare list
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"input file not found: {p}")
    data = json.loads(p.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for k in ("findings", "results", "all_findings"):
            if k in data and isinstance(data[k], list):
                return data[k]
    raise ValueError(f"could not find a 'findings' list in {p}")


def build_triage_entries(findings: list[dict[str, Any]], state: PipelineState,
                         *, source_tool_hint: str = "") -> list[TriageEntry]:
    """Convert raw nuclei-harvest findings to NormalizedFinding + cross-reference
    against pipeline_state.db. Filter out findings already submitted/rejected."""
    entries: list[TriageEntry] = []
    for raw in findings:
        nf = NormalizedFinding.from_dict(
            normalize_finding_dict(raw, source_tool=source_tool_hint or raw.get("source_tool", "nuclei-harvest.py"))
        )
        if not nf.id:
            nf.id = compute_finding_id(nf.source_tool, nf.host, nf.vuln_class_key, nf.evidence)
        # Cross-reference against DB
        existing = state.get_finding(nf.id)
        is_new = existing is None
        prev_submitted = bool(existing and existing.get("disposition") == "submitted")
        prev_rejected = bool(existing and existing.get("disposition") == "rejected")
        # Persist / update
        state.upsert_finding(nf.to_dict())
        # Filter: if previously submitted or rejected, skip (per ARCHITECTURE.md spec)
        if prev_submitted or prev_rejected:
            log.debug("skipping %s (previously %s)", nf.id[:8],
                      "submitted" if prev_submitted else "rejected")
            continue
        # If existing, inherit its disposition if it was 'reviewed'
        if existing and existing.get("disposition") == "reviewed":
            nf.disposition = "reviewed"
        entries.append(TriageEntry(
            finding=nf, is_new=is_new,
            previously_submitted=prev_submitted,
            previously_rejected=prev_rejected,
        ))
    # Sort: CRITICAL > HIGH > MEDIUM > LOW > INFO, then new > previously-seen
    entries.sort(key=lambda e: (
        _SEV_ORDER.get(e.finding.severity.upper(), 99),
        0 if e.is_new else 1,
        e.finding.last_seen,
    ))
    return entries


def _parse_dt(s: str | None) -> datetime.datetime | None:
    if not s:
        return None
    try:
        return datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def apply_filters(entries: list[TriageEntry], *,
                  severity: str | None = None,
                  host: str | None = None,
                  vuln_class_key: str | None = None,
                  since: str | None = None,
                  until: str | None = None) -> list[TriageEntry]:
    """Narrow the active queue by severity / host / vuln class / date window.
    Case-insensitive substring match on host and class; exact (case-insensitive)
    match on severity. `since`/`until` filter on the finding's last_seen (ISO 8601)."""
    if not (severity or host or vuln_class_key or since or until):
        return entries
    out: list[TriageEntry] = []
    sev = severity.upper() if severity else None
    host_l = host.lower() if host else None
    cls_l = vuln_class_key.lower() if vuln_class_key else None
    since_dt = _parse_dt(since)
    until_dt = _parse_dt(until)
    for e in entries:
        f = e.finding
        if sev and f.severity.upper() != sev:
            continue
        if host_l and host_l not in f.host.lower():
            continue
        if cls_l and cls_l not in f.vuln_class_key.lower():
            continue
        seen = _parse_dt(f.last_seen)
        if since_dt and seen is not None and seen < since_dt:
            continue
        if until_dt and seen is not None and seen > until_dt:
            continue
        out.append(e)
    return out


def render_queue_md(entries: list[TriageEntry], *, top: int = 10) -> str:
    """Render the active triage queue as a Markdown checklist."""
    lines: list[str] = []
    lines.append("# Triage Queue")
    lines.append("")
    lines.append(f"_Generated: {datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')}_")
    lines.append(f"_Active findings: {len(entries)}_  (showing top {min(top, len(entries))})")
    lines.append("")
    lines.append("## Severity-ordered active findings")
    lines.append("")
    for i, entry in enumerate(entries[:top], start=1):
        f = entry.finding
        new_marker = " 🆕" if entry.is_new else ""
        review_marker = " 👁️" if f.disposition == "reviewed" else ""
        lines.append(f"### {i}. [{f.severity}] {f.title}{new_marker}{review_marker}")
        lines.append("")
        lines.append(f"- **id**: `{f.id}`")
        lines.append(f"- **tool**: `{f.source_tool}`  |  **class**: `{f.vuln_class_key}`")
        lines.append(f"- **host**: `{f.host}`  |  **url**: `{f.url}`")
        lines.append(f"- **confidence**: `{f.confidence}`  |  **payout**: {f.typical_payout or '—'}")
        if f.verified_by:
            lines.append(f"- **verified by**: `{f.verified_by}`")
        if f.evidence:
            ev = f.evidence[:500].replace("\n", " ")
            lines.append(f"- **evidence**: {ev}")
        if f.curl_command:
            lines.append(f"- **PoC**:")
            lines.append(f"  ```bash")
            lines.append(f"  {f.curl_command}")
            lines.append(f"  ```")
        if f.remediation:
            lines.append(f"- **remediation**: {f.remediation}")
        lines.append(f"- **disposition**: `{f.disposition}`  |  **first_seen**: {f.first_seen}  |  **last_seen**: {f.last_seen}")
        lines.append("")
        lines.append(f"  - [ ] review")
        lines.append(f"  - [ ] submit")
        lines.append(f"  - [ ] reject (false positive)")
        lines.append(f"  - [ ] mark duplicate")
        lines.append("")
    if not entries:
        lines.append("_No active findings — everything is submitted or rejected._")
        lines.append("")
    return "\n".join(lines)


def generate_writeup(finding: NormalizedFinding, *, format: str = "h1") -> str:
    """Generate a HackerOne- or Bugcrowd-formatted writeup for a single finding.
    Mirrors nuclei-harvest.py's write_hackerone_report() / write_bugcrowd_report()
    output shape, but operates on a NormalizedFinding from the unified schema
    so it works for findings from ANY source tool."""
    if format not in ("h1", "bc"):
        raise ValueError(f"format must be 'h1' or 'bc', got {format!r}")
    sev = finding.severity.upper()
    if format == "h1":
        lines = [
            f"# {finding.title}",
            "",
            f"**Severity**: {sev}",
            f"**Affected host**: `{finding.host}`",
            f"**Affected URL**: `{finding.url}`",
            f"**Vulnerability class**: `{finding.vuln_class_key}`",
            f"**Source tool**: `{finding.source_tool}`" + (f" (verified by `{finding.verified_by}`)" if finding.verified_by else ""),
            f"**CVSS**: {resolve_cvss_vector(finding)}",
            f"**CWE**: {finding.cwe or 'n/a'}",
            f"**OWASP**: {finding.owasp or 'n/a'}",
            "",
            "## Summary",
            "",
            finding.detail or finding.evidence or "_No summary provided._",
            "",
            "## Steps to Reproduce",
            "",
            "```bash",
            finding.curl_command or "# no curl PoC available",
            "```",
            "",
            finding.steps_to_reproduce or "",
            "",
            "## Evidence",
            "",
            "```",
            finding.evidence or "",
            "```",
            "",
            "## Impact",
            "",
            f"Typical payout range for this class: **{finding.typical_payout or 'n/a'}**.",
            f"Allows write: **{finding.allows_write}**.",
            "",
            "## Remediation",
            "",
            finding.remediation or "_No remediation guidance provided._",
            "",
            "---",
            f"_Generated by triage_memory.py at {datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')}_",
        ]
        return "\n".join(lines)
    # Bugcrowd: plain text, similar content, simpler formatting
    lines = [
        f"Title: {finding.title}",
        f"Severity: {sev}",
        f"Host: {finding.host}",
        f"URL: {finding.url}",
        f"Class: {finding.vuln_class_key}",
        "",
        "Summary:",
        finding.detail or finding.evidence or "n/a",
        "",
        "Steps to Reproduce:",
        finding.curl_command or "n/a",
        finding.steps_to_reproduce or "",
        "",
        "Impact:",
        f"Typical payout: {finding.typical_payout or 'n/a'}. Allows write: {finding.allows_write}.",
        "",
        "Remediation:",
        finding.remediation or "n/a",
        "",
        f"-- triage_memory.py @ {datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')}",
    ]
    return "\n".join(lines)


def _copy_to_clipboard(text: str) -> bool:
    """Best-effort clipboard copy. Tries pyperclip then platform CLIs
    (pbcopy / xclip / termux-clipboard-set). Returns True on success."""
    try:
        import pyperclip  # type: ignore
        pyperclip.copy(text)
        return True
    except Exception:
        pass
    import shutil
    import subprocess
    for cmd in (["pbcopy"], ["xclip", "-selection", "clipboard"],
                ["termux-clipboard-set"]):
        if shutil.which(cmd[0]):
            try:
                subprocess.run(cmd, input=text, text=True, check=False, timeout=5,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return True
            except Exception:
                pass
    return False


def _open_url_default(url: str) -> bool:
    """Best-effort URL open via xdg-open / open / termux-open-url. Returns True
    if a handler was launched."""
    import shutil
    import subprocess
    for cmd in (["xdg-open"], ["open"], ["termux-open-url"]):
        if shutil.which(cmd[0]):
            try:
                subprocess.Popen(cmd + [url], stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
                return True
            except Exception:
                pass
    return False


def format_finding_full(finding: NormalizedFinding) -> str:
    """Pretty JSON of the full finding record (the `full` inspect action)."""
    return json.dumps(finding.to_dict(), indent=2, default=str)


def copy_finding_field(finding: NormalizedFinding, field: str,
                       *, _clipboard=None) -> tuple[str, bool]:
    """Resolve a finding field and copy it to the clipboard. `field` is one of
    id|url|curl|poc|evidence|title. Returns (value, copied_ok)."""
    field = (field or "id").lower()
    if field in ("id",):
        value = finding.id
    elif field in ("url",):
        value = finding.url
    elif field in ("curl", "poc"):
        value = finding.curl_command or ""
    elif field in ("evidence",):
        value = finding.evidence or ""
    elif field in ("title",):
        value = finding.title
    else:
        value = ""
    clip = _clipboard or _copy_to_clipboard
    ok = bool(value) and clip(value)
    return value, ok


def interactive_triage(entries: list[TriageEntry], state: PipelineState, *,
                        top: int = 10, writeup_dir: Path | None = None,
                        decided_by: str = "interactive",
                        _clipboard=None, _opener=None) -> int:
    """Walk the user through each finding, prompting for disposition.
    Returns count of dispositions recorded."""
    if not entries:
        print("\n  No active findings to triage. Everything is submitted or rejected.\n")
        return 0
    print()
    print(f"  Triage queue: {len(entries)} active findings (showing top {min(top, len(entries))})")
    print(f"  Type one of: review | submit | reject | duplicate <id> | skip | quit")
    print(f"  Inspect actions (don't record a disposition): open | copy <id|url|curl|evidence|title> | full")
    print(f"  Submitting a finding writes a HackerOne-formatted writeup to {writeup_dir or 'reports/'}")
    print()
    count = 0
    for i, entry in enumerate(entries[:top], start=1):
        f = entry.finding
        print(f"  ┌─ [{i}/{min(top, len(entries))}] [{f.severity}] {f.title}")
        print(f"  │ id:    {f.id}")
        print(f"  │ tool:  {f.source_tool}  (confidence: {f.confidence})")
        print(f"  │ host:  {f.host}")
        print(f"  │ url:   {f.url}")
        if f.evidence:
            ev = f.evidence[:300].replace("\n", " ")
            print(f"  │ evid:  {ev}")
        if f.curl_command:
            print(f"  │ PoC:   {f.curl_command[:200]}...")
        new_marker = " (NEW)" if entry.is_new else ""
        review_marker = " (previously reviewed)" if f.disposition == "reviewed" else ""
        print(f"  │ disposition: {f.disposition}{new_marker}{review_marker}")
        while True:
            try:
                ans = input(f"  └─▶ [review|submit|reject|duplicate|skip|quit] > ").strip().lower()
            except EOFError:
                print()
                return count
            if ans in ("q", "quit", "exit"):
                print("  exiting triage (progress saved to pipeline_state.db)")
                return count
            # ── Inspect actions (no disposition recorded) ──
            if ans in ("o", "open"):
                opener = _opener or _open_url_default
                if opener(f.url):
                    print(f"     ↗ opened {f.url}")
                else:
                    print(f"     url: {f.url}")
                continue
            if ans.startswith("copy"):
                parts = ans.split(maxsplit=1)
                field = parts[1].strip() if len(parts) > 1 else "id"
                value, ok = copy_finding_field(f, field, _clipboard=_clipboard)
                if not value:
                    print(f"     no '{field}' value to copy")
                elif ok:
                    print(f"     ✓ copied {field} to clipboard")
                else:
                    print(f"     {field}: {value}")
                continue
            if ans in ("f", "full"):
                print(format_finding_full(f))
                continue
            if ans in ("s", "skip"):
                break
            if ans in ("r", "review"):
                state.mark_disposition(f.id, "reviewed", decided_by=decided_by, note="reviewed in interactive triage")
                print(f"     ✓ marked reviewed")
                count += 1
                break
            if ans in ("sub", "submit"):
                state.mark_disposition(f.id, "submitted", decided_by=decided_by, note="submitted via interactive triage")
                # Write the writeup
                if writeup_dir is not None:
                    writeup_dir.mkdir(parents=True, exist_ok=True)
                    safe_title = re.sub(r"[^a-zA-Z0-9]+", "_", f.title)[:60].strip("_")
                    fn = writeup_dir / f"h1_{f.severity}_{safe_title}_{f.id[:8]}.md"
                    fn.write_text(generate_writeup(f, format="h1"), encoding="utf-8")
                    print(f"     ✓ writeup: {fn}")
                else:
                    print(f"     ✓ marked submitted")
                count += 1
                break
            if ans in ("rej", "reject"):
                note = ""
                try:
                    note = input("     reason? > ").strip()
                except EOFError:
                    pass
                state.mark_disposition(f.id, "rejected", decided_by=decided_by, note=note)
                print(f"     ✓ marked rejected")
                count += 1
                break
            if ans.startswith("dup") or ans.startswith("duplicate"):
                parts = ans.split(maxsplit=1)
                if len(parts) < 2:
                    print("     usage: duplicate <other_finding_id>")
                    continue
                other = parts[1].strip()
                state.mark_disposition(f.id, "duplicate_of", decided_by=decided_by, note=f"duplicate of {other}")
                print(f"     ✓ marked duplicate of {other}")
                count += 1
                break
            print("     unknown command — try: review | submit | reject | duplicate <id> | skip | quit")
        print()
    return count


def batch_triage(entries: list[TriageEntry], state: PipelineState,
                 dispositions_csv: Path, *, writeup_dir: Path | None = None) -> int:
    """Apply dispositions from a pre-filled CSV. CSV columns:
    finding_id,disposition,note"""
    if not dispositions_csv.exists():
        raise FileNotFoundError(f"dispositions CSV not found: {dispositions_csv}")
    by_id = {e.finding.id: e for e in entries}
    count = 0
    with dispositions_csv.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            fid = (row.get("finding_id") or "").strip()
            disp = (row.get("disposition") or "").strip().lower()
            note = (row.get("note") or "").strip()
            if not fid or not disp:
                continue
            if disp not in ("new", "reviewed", "submitted", "rejected", "duplicate_of"):
                log.warning("unknown disposition %r in CSV row — skipping", disp)
                continue
            state.mark_disposition(fid, disp, decided_by="batch", note=note)
            if disp == "submitted" and writeup_dir is not None:
                entry = by_id.get(fid)
                if entry:
                    writeup_dir.mkdir(parents=True, exist_ok=True)
                    safe_title = re.sub(r"[^a-zA-Z0-9]+", "_", entry.finding.title)[:60].strip("_")
                    fn = writeup_dir / f"h1_{entry.finding.severity}_{safe_title}_{fid[:8]}.md"
                    fn.write_text(generate_writeup(entry.finding, format="h1"), encoding="utf-8")
                    log.info("writeup: %s", fn)
            count += 1
    return count


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="triage_memory.py",
        description="Cross-run triage queue with persistent disposition. "
                    "Extends nuclei-harvest.py — does NOT replace it.",
    )
    ap.add_argument("--input", "-i", required=True, help="nuclei-harvest.py final.json (or compatible)")
    ap.add_argument("--db", default="pipeline_state.db", help="pipeline_state.db path (default: ./pipeline_state.db)")
    ap.add_argument("--top", type=int, default=10, help="show top N findings (default: 10)")
    ap.add_argument("--print-queue", action="store_true", help="render the active queue as Markdown to stdout and exit")
    ap.add_argument("--output", "-o", default="triage_queue.md", help="write Markdown queue to this file (default: triage_queue.md)")
    ap.add_argument("--writeup-dir", default="reports", help="directory for HackerOne/Bugcrowd writeups (default: reports/)")
    ap.add_argument("--batch", action="store_true", help="non-interactive mode — read dispositions from CSV")
    ap.add_argument("--dispositions-csv", help="CSV with finding_id,disposition,note columns (for --batch)")
    ap.add_argument("--decided-by", default=os.environ.get("USER", "interactive"), help="who is deciding (logged in triage_decisions)")
    ap.add_argument("--filter-severity", help="only show findings of this severity (e.g. CRITICAL)")
    ap.add_argument("--filter-host", help="only show findings whose host contains this substring")
    ap.add_argument("--filter-class", help="only show findings whose vuln class contains this substring")
    ap.add_argument("--filter-since", help="only findings seen on/after this ISO-8601 timestamp")
    ap.add_argument("--filter-until", help="only findings seen on/before this ISO-8601 timestamp")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )

    raw_findings = load_final_json(args.input)
    log.info("loaded %d raw findings from %s", len(raw_findings), args.input)

    state = PipelineState(args.db)
    try:
        entries = build_triage_entries(raw_findings, state)
        entries = apply_filters(entries, severity=args.filter_severity,
                                host=args.filter_host, vuln_class_key=args.filter_class,
                                since=args.filter_since, until=args.filter_until)
        log.info("active queue: %d findings (after filtering previously submitted/rejected)", len(entries))

        md = render_queue_md(entries, top=args.top)
        Path(args.output).write_text(md, encoding="utf-8")
        log.info("wrote %s", args.output)

        if args.print_queue:
            print(md)
            return 0

        if args.batch:
            if not args.dispositions_csv:
                log.error("--batch requires --dispositions-csv")
                return 2
            n = batch_triage(entries, state, Path(args.dispositions_csv),
                             writeup_dir=Path(args.writeup_dir))
            log.info("applied %d dispositions from CSV", n)
            return 0

        # Interactive
        n = interactive_triage(entries, state, top=args.top,
                               writeup_dir=Path(args.writeup_dir),
                               decided_by=args.decided_by)
        log.info("recorded %d dispositions", n)
        return 0
    finally:
        state.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(0)
