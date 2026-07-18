#!/usr/bin/env python3
"""
reporter.py — shared report generation for normalized findings
=============================================================

Produces bug-bounty-platform-ready reports from the canonical
``NormalizedFinding`` shape (see toolkit/infra/finding.py):

  * ``generate_hackerone`` — HackerOne markdown report
  * ``generate_bugcrowd``   — Bugcrowd markdown report
  * ``generate_csv``        — flat CSV for spreadsheets / trackers
  * ``generate_sarif``      — SARIF 2.1.0 for CI security dashboards

Every function takes a list of finding dicts (``NormalizedFinding.to_dict()``
output or anything with the same keys) and returns a string / dict, so the
orchestrator and individual tools can render the same findings in any format.

CLI:
  python -m toolkit.infra.reporter --input findings.json \\
      --format hackerone --output report.md

Author : Bug Bounty Toolkit / Layer 0
License : MIT (for authorized use only)
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from typing import Any

# Severity → numeric rank + default CVSS base score (used for SARIF when no
# explicit cvss_vector/cvss_score is present on the finding).
_SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "": 0}
_SEVERITY_CVSS = {
    "CRITICAL": 9.8, "HIGH": 7.5, "MEDIUM": 5.3, "LOW": 3.1, "INFO": 0.0, "": 0.0,
}


def _severity(f: dict) -> str:
    return (f.get("severity") or "INFO").upper()


def _title(f: dict) -> str:
    return f.get("title") or f.get("vuln_class_key") or "Untitled finding"


def _sort(findings: list[dict]) -> list[dict]:
    """Highest severity first, stable by host then title."""
    return sorted(
        findings,
        key=lambda f: (-_SEVERITY_RANK.get(_severity(f), 0),
                       f.get("host", ""), _title(f)),
    )


def generate_hackerone(findings: list[dict]) -> str:
    """HackerOne-style markdown: one section per finding, most severe first."""
    findings = _sort(findings)
    lines: list[str] = ["# Security Findings Report", ""]
    if not findings:
        lines.append("_No findings._")
        return "\n".join(lines)
    lines.append(f"**Total findings:** {len(findings)}")
    lines.append("")
    for i, f in enumerate(findings, 1):
        lines.append(f"## {i}. {_title(f)}")
        lines.append("")
        lines.append(f"- **Severity:** {_severity(f)}")
        lines.append(f"- **Vulnerability class:** {f.get('vuln_class_key', 'UNKNOWN')}")
        lines.append(f"- **Host:** {f.get('host', '')}")
        lines.append(f"- **URL:** {f.get('url', '')}")
        if f.get("confidence"):
            lines.append(f"- **Confidence:** {f['confidence']}")
        if f.get("cvss_vector"):
            lines.append(f"- **CVSS:** {f['cvss_vector']}")
        if f.get("cwe"):
            lines.append(f"- **CWE:** {f['cwe']}")
        lines.append("")
        if f.get("detail"):
            lines.append("### Description")
            lines.append("")
            lines.append(f["detail"])
            lines.append("")
        if f.get("evidence"):
            lines.append("### Evidence")
            lines.append("")
            lines.append("```")
            lines.append(f["evidence"])
            lines.append("```")
            lines.append("")
        if f.get("steps_to_reproduce"):
            lines.append("### Steps to Reproduce")
            lines.append("")
            lines.append(f["steps_to_reproduce"])
            lines.append("")
        elif f.get("curl_command"):
            lines.append("### Reproduction")
            lines.append("")
            lines.append("```bash")
            lines.append(f["curl_command"])
            lines.append("```")
            lines.append("")
        if f.get("remediation"):
            lines.append("### Remediation")
            lines.append("")
            lines.append(f["remediation"])
            lines.append("")
        lines.append("---")
        lines.append("")
    return "\n".join(lines)


def generate_bugcrowd(findings: list[dict]) -> str:
    """Bugcrowd-style markdown (similar shape, explicit severity badge header)."""
    findings = _sort(findings)
    lines: list[str] = ["# Vulnerability Report", ""]
    if not findings:
        lines.append("_No vulnerabilities identified._")
        return "\n".join(lines)
    lines.append(f"**Summary:** {len(findings)} finding(s) across "
                 f"{len({f.get('host','') for f in findings})} host(s)")
    lines.append("")
    for i, f in enumerate(findings, 1):
        sev = _severity(f)
        lines.append(f"## [{sev}] {_title(f)}")
        lines.append("")
        lines.append(f"- **Target:** {f.get('host', '')}")
        lines.append(f"- **Endpoint:** {f.get('url', '')}")
        lines.append(f"- **Category:** {f.get('vuln_class_key', 'UNKNOWN')}")
        if f.get("cvss_vector"):
            lines.append(f"- **CVSS:** {f['cvss_vector']}")
        lines.append("")
        if f.get("detail"):
            lines.append(f["detail"])
            lines.append("")
        if f.get("evidence"):
            lines.append("**Evidence:**")
            lines.append("")
            lines.append("```")
            lines.append(f["evidence"])
            lines.append("```")
            lines.append("")
        if f.get("curl_command"):
            lines.append("**Proof of Concept:**")
            lines.append("")
            lines.append("```bash")
            lines.append(f["curl_command"])
            lines.append("```")
            lines.append("")
        if f.get("remediation"):
            lines.append(f"**Fix:** {f['remediation']}")
            lines.append("")
    return "\n".join(lines)


def generate_csv(findings: list[dict]) -> str:
    """Flat CSV: one row per finding with the canonical columns."""
    cols = ["id", "severity", "vuln_class_key", "host", "url", "title",
            "confidence", "disposition", "cvss_vector", "cwe", "evidence",
            "curl_command", "remediation", "source_tool"]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    writer.writeheader()
    for f in _sort(findings):
        row = {c: f.get(c, "") for c in cols}
        if isinstance(row.get("evidence"), str) and len(row["evidence"]) > 2000:
            row["evidence"] = row["evidence"][:2000]
        writer.writerow(row)
    return buf.getvalue()


def generate_sarif(findings: list[dict]) -> dict[str, Any]:
    """SARIF 2.1.0 document with one rule per vuln_class_key."""
    rules: list[dict] = []
    rule_index: dict[str, int] = {}
    results: list[dict] = []

    def _rule_for(vclass: str, title: str) -> int:
        if vclass in rule_index:
            return rule_index[vclass]
        idx = len(rules)
        rules.append({
            "id": vclass or "UNKNOWN",
            "name": vclass or "UNKNOWN",
            "shortDescription": {"text": title or vclass},
            "defaultConfiguration": {"level": "warning"},
            "properties": {"tags": ["security", "bugbounty"]},
        })
        rule_index[vclass] = idx
        return idx

    for f in findings:
        vclass = f.get("vuln_class_key") or "UNKNOWN"
        idx = _rule_for(vclass, _title(f))
        sev = _severity(f)
        score = f.get("cvss_score") or _SEVERITY_CVSS.get(sev, 0.0)
        results.append({
            "ruleId": vclass,
            "ruleIndex": idx,
            "level": "error" if sev in ("CRITICAL", "HIGH") else "warning",
            "message": {"text": _title(f)},
            "properties": {
                "severity": sev,
                "confidence": f.get("confidence", "candidate"),
                "cvssScore": score,
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.get("url") or f.get("host") or ""},
                },
            }],
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "bugbounty-toolkit",
                    "version": "1.0.0",
                    "rules": rules,
                },
            },
            "results": results,
        }],
    }


_FORMATS = {
    "hackerone": generate_hackerone,
    "bugcrowd": generate_bugcrowd,
    "csv": generate_csv,
    "sarif": generate_sarif,
}


def render(findings: list[dict], fmt: str) -> Any:
    """Dispatch to the requested renderer. Returns str for text formats,
    dict for sarif."""
    fn = _FORMATS.get(fmt)
    if fn is None:
        raise ValueError(f"unknown format {fmt!r}; choose from {sorted(_FORMATS)}")
    return fn(findings)


def main() -> int:
    ap = argparse.ArgumentParser(prog="reporter.py",
                                 description="Render normalized findings into a report.")
    ap.add_argument("--input", "-i", required=True,
                    help="JSON file with a list of NormalizedFinding dicts "
                         "(or an object with a 'findings' key)")
    ap.add_argument("--format", "-f", required=True,
                    choices=sorted(_FORMATS), help="Output format")
    ap.add_argument("--output", "-o", help="Output file (default: stdout)")
    args = ap.parse_args()

    with open(args.input) as fh:
        data = json.load(fh)
    findings = data.get("findings", data) if isinstance(data, dict) else data
    if not isinstance(findings, list):
        findings = [findings]

    out = render(findings, args.format)
    text = json.dumps(out, indent=2) if args.format == "sarif" else out

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"Wrote {args.format} report → {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
