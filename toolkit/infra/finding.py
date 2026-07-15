#!/usr/bin/env python3
"""
finding.py — canonical NormalizedFinding dataclass + helpers
=============================================================

Purpose
-------
One shared dataclass that every new tool speaks natively, instead of each
tool writing its own JSON shape. Extends nuclei-harvest.py's existing
NormalizedFinding with the four new fields from §3.1 of ARCHITECTURE.md
(confidence, disposition, first_seen, last_seen, verified_by).

The existing nuclei-harvest.py dataclass is patched (see scripts/patches/)
to import these new fields directly, so there is exactly one source of
truth. Tools that can't import this module (e.g. running standalone from
a different working directory) fall back to dict-based emission with the
same field names — see normalize_finding_dict().

Chain position
--------------
Layer 0 — depended on by every verify/, discover/, testers/ tool.

Usage
-----
    from toolkit.infra.finding import NormalizedFinding, compute_finding_id

    f = NormalizedFinding(
        source_tool="idor_crosssession.py",
        host="api.target.com",
        url="https://api.target.com/v1/users/8841",
        vuln_class_key="BOLA_CONFIRMED",
        severity="CRITICAL",
        title="BOLA/IDOR confirmed cross-session",
        confidence="confirmed",
        verified_by="idor_crosssession.py",
    )
    f.id = compute_finding_id(f)
    print(f.to_dict())

Author : Bug Bounty Toolkit / Layer 0
License : MIT (for authorized use only)
"""

from __future__ import annotations

import datetime
import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any


def _utcnow_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


@dataclass
class NormalizedFinding:
    """Canonical finding shape — extends nuclei-harvest.py's NormalizedFinding.

    The first 22 fields match nuclei-harvest.py's existing dataclass verbatim
    so existing code that consumes its JSON output continues to work. The five
    fields after the `# --- new fields ---` marker are the additions from
    ARCHITECTURE.md §3.1.
    """

    # --- existing nuclei-harvest.py fields, unchanged ---
    id: str = ""
    source_tool: str = ""
    host: str = ""
    url: str = ""
    vuln_class_key: str = ""
    severity: str = "INFO"
    title: str = ""
    detail: str = ""
    evidence: str = ""
    steps_to_reproduce: str = ""
    remediation: str = ""
    curl_command: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cwe: str = ""
    owasp: str = ""
    impact_tier: str = ""
    typical_payout: str = ""
    allows_write: bool = False
    chain_ids: list[str] = field(default_factory=list)
    nuclei_template: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    # --- new fields (ARCHITECTURE.md §3.1) ---
    confidence: str = "candidate"  # candidate | probable | confirmed
    disposition: str = "new"       # new | reviewed | submitted | rejected | duplicate_of
    first_seen: str = field(default_factory=_utcnow_iso)
    last_seen: str = field(default_factory=_utcnow_iso)
    verified_by: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # Normalize empty strings to "" (not None) for JSON friendliness
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "NormalizedFinding":
        """Tolerant constructor — ignores unknown keys, fills missing with defaults."""
        known = {f.name for f in cls.__dataclass_fields__.values()}
        kwargs = {k: v for k, v in d.items() if k in known}
        return cls(**kwargs)


def compute_finding_id(source_tool: str, host: str, vuln_class_key: str,
                       evidence: str) -> str:
    """sha256(source_tool+host+vuln_class_key+evidence) truncated to 16 hex chars.
    Stable across runs, so the same finding emitted by the same tool on the same
    host gets the same id — enabling cross-run dedup via pipeline_state.db."""
    h = hashlib.sha256(
        f"{source_tool}|{host}|{vuln_class_key}|{evidence}".encode("utf-8")
    ).hexdigest()
    return h[:16]


def normalize_finding_dict(d: dict[str, Any], *, source_tool: str = "") -> dict[str, Any]:
    """Take a finding dict in any of the existing tool's JSON shapes and return
    one in the canonical NormalizedFinding shape. This is the conversion layer
    nuclei-harvest.py was doing inline — formalized here so verify/ tools can
    consume any upstream finding without coupling.

    Recognized source shapes (best-effort):
      - apifuzz.py:      host, url, method, test_type, severity, title, detail,
                         evidence, curl_command, recommendation, cvss_estimate,
                         response_snippet
      - jsreaper.py:     secrets[] with host, js_url, secret_type, value,
                         raw_line, severity, confidence
      - paramfuzz.py:    host, url, method, param_name, inject_via, test_value,
                         finding_type, severity, title, detail, evidence,
                         curl_command, recommendation, cvss_estimate
      - ssrfprobe.py:    host, url, param, payload_url, payload_category,
                         severity, title, detail, evidence, curl_command,
                         recommendation, cvss_estimate, is_blind, is_reflective
      - subtakeover.py:  subdomain, cname_chain, verdict, provider_match,
                         fingerprint_matched, confidence (int), http_status
      - nuclei-harvest's NormalizedFinding: passes through unchanged
    """
    if not d:
        return {}
    out: dict[str, Any] = {}
    out["source_tool"] = source_tool or d.get("source_tool", "")

    # Direct NormalizedFinding passthrough
    if "vuln_class_key" in d and "host" in d:
        out.update(d)
        out.setdefault("confidence", "candidate")
        out.setdefault("disposition", "new")
        out.setdefault("first_seen", _utcnow_iso())
        out.setdefault("last_seen", _utcnow_iso())
        out.setdefault("verified_by", None)
        if not out.get("id"):
            out["id"] = compute_finding_id(
                out.get("source_tool", ""), out.get("host", ""),
                out.get("vuln_class_key", ""), out.get("evidence", ""),
            )
        return out

    # apifuzz.py finding
    if "test_type" in d and "host" in d:
        out["host"] = d.get("host", "")
        out["url"] = d.get("url", "")
        out["severity"] = (d.get("severity") or "INFO").upper()
        out["title"] = d.get("title", "")
        out["detail"] = d.get("detail", "")
        out["evidence"] = d.get("evidence", "")
        out["curl_command"] = d.get("curl_command", "")
        out["remediation"] = d.get("recommendation", "")
        out["cvss_vector"] = d.get("cvss_estimate", "")
        tt = (d.get("test_type") or "").upper()
        if tt == "BOLA":
            # Distinguish CRITICAL cross-user (confirmed) from HIGH single-session (possible)
            if out["severity"] in ("CRITICAL", "HIGH"):
                out["vuln_class_key"] = "BOLA_CONFIRMED" if out["severity"] == "CRITICAL" else "BOLA_POSSIBLE"
            else:
                out["vuln_class_key"] = "BOLA_POSSIBLE"
        elif tt == "JWT_NONE":
            out["vuln_class_key"] = "JWT_NONE"
        elif tt == "MASS_ASSIGN":
            out["vuln_class_key"] = "PRIV_ESCALATION"
        elif tt == "RATE_LIMIT":
            out["vuln_class_key"] = "RATE_LIMIT_API"
        elif tt == "GQL_INTROSPECTION":
            out["vuln_class_key"] = "GQL_INTROSPECTION"
        else:
            out["vuln_class_key"] = tt or "UNKNOWN"
        out["raw"] = {"method": d.get("method", ""), "test_type": tt,
                      "response_snippet": d.get("response_snippet", "")}
        out["confidence"] = "candidate"
        out["id"] = compute_finding_id(out["source_tool"], out["host"],
                                        out["vuln_class_key"], out["evidence"])
        return _fill_defaults(out)

    # paramfuzz.py finding
    if "finding_type" in d and "param_name" in d:
        out["host"] = d.get("host", "")
        out["url"] = d.get("url", "")
        out["severity"] = (d.get("severity") or "INFO").upper()
        out["title"] = d.get("title", "")
        out["detail"] = d.get("detail", "")
        out["evidence"] = d.get("evidence", "")
        out["curl_command"] = d.get("curl_command", "")
        out["remediation"] = d.get("recommendation", "")
        out["cvss_vector"] = d.get("cvss_estimate", "")
        ft = (d.get("finding_type") or "").upper()
        mapping = {
            "HIDDEN_PARAM": "HIDDEN_PARAM",
            "PRIV_ESCALATION": "PRIV_ESCALATION",
            "DEBUG_BYPASS": "DEBUG_BYPASS",
            "PARAM_POLLUTION": "PARAM_POLLUTION",
            "ARRAY_INJECTION": "ARRAY_INJECTION",
            "IDOR_PARAM": "BOLA_POSSIBLE",
        }
        out["vuln_class_key"] = mapping.get(ft, ft or "UNKNOWN")
        out["raw"] = {"param_name": d.get("param_name", ""),
                      "inject_via": d.get("inject_via", ""),
                      "test_value": str(d.get("test_value", "")),
                      "method": d.get("method", "")}
        out["confidence"] = "candidate"
        out["id"] = compute_finding_id(out["source_tool"], out["host"],
                                        out["vuln_class_key"], out["evidence"])
        return _fill_defaults(out)

    # ssrfprobe.py finding
    if "payload_url" in d and "param" in d:
        out["host"] = d.get("host", "")
        out["url"] = d.get("url", "")
        out["severity"] = (d.get("severity") or "INFO").upper()
        out["title"] = d.get("title", "")
        out["detail"] = d.get("detail", "")
        out["evidence"] = d.get("evidence", "")
        out["curl_command"] = d.get("curl_command", "")
        out["remediation"] = d.get("recommendation", "")
        out["cvss_vector"] = d.get("cvss_estimate", "")
        cat = (d.get("payload_category") or "").lower()
        if cat == "metadata":
            out["vuln_class_key"] = "SSRF_CLOUD_METADATA"
        elif cat == "internal":
            out["vuln_class_key"] = "SSRF_INTERNAL"
        else:
            out["vuln_class_key"] = "SSRF_INTERNAL"
        out["raw"] = {"param": d.get("param", ""),
                      "payload_url": d.get("payload_url", ""),
                      "is_blind": d.get("is_blind", False),
                      "is_reflective": d.get("is_reflective", False)}
        out["confidence"] = "probable" if d.get("is_blind") else "candidate"
        out["id"] = compute_finding_id(out["source_tool"], out["host"],
                                        out["vuln_class_key"], out["evidence"])
        return _fill_defaults(out)

    # subtakeover.py finding
    if "subdomain" in d and "verdict" in d:
        out["host"] = d.get("subdomain", "")
        out["url"] = f"http://{out['host']}/"
        out["severity"] = "HIGH" if d.get("verdict") == "VULNERABLE" else "MEDIUM"
        out["title"] = f"Subdomain takeover: {out['host']} ({d.get('provider_match', 'unknown')})"
        out["detail"] = " | ".join(d.get("cname_chain", []))
        out["evidence"] = (f"verdict={d.get('verdict')} "
                           f"provider={d.get('provider_match', '')} "
                           f"fingerprints={','.join(d.get('fingerprint_matched', []))}")
        out["vuln_class_key"] = "SUBDOMAIN_TAKEOVER"
        out["raw"] = {"verdict": d.get("verdict"),
                      "provider_match": d.get("provider_match"),
                      "cname_chain": d.get("cname_chain", []),
                      "fingerprint_matched": d.get("fingerprint_matched", []),
                      "http_status": d.get("http_status")}
        out["confidence"] = "candidate"
        out["id"] = compute_finding_id(out["source_tool"], out["host"],
                                        out["vuln_class_key"], out["evidence"])
        return _fill_defaults(out)

    # jsreaper.py secret
    if "secret_type" in d and "js_url" in d:
        out["host"] = d.get("host", "")
        out["url"] = d.get("js_url", "")
        out["severity"] = (d.get("severity") or "INFO").upper()
        out["title"] = f"Exposed secret: {d.get('secret_type', 'unknown')}"
        out["detail"] = d.get("note", "")
        out["evidence"] = (f"value={d.get('value', '<redacted>')} "
                           f"raw_line={d.get('raw_line', '')[:200]}")
        out["vuln_class_key"] = "SECRET_IN_GIT"  # closest existing class
        out["raw"] = {"secret_type": d.get("secret_type"),
                      "value": d.get("value", ""),
                      "raw_line": d.get("raw_line", "")}
        # Map jsreaper's confidence labels to ours
        jc = (d.get("confidence") or "").upper()
        out["confidence"] = {"HIGH": "probable", "MEDIUM": "candidate", "LOW": "candidate"}.get(jc, "candidate")
        out["id"] = compute_finding_id(out["source_tool"], out["host"],
                                        out["vuln_class_key"], out["evidence"])
        return _fill_defaults(out)

    # Fallback: pass through what we can
    out["host"] = d.get("host") or d.get("subdomain") or ""
    out["url"] = d.get("url") or ""
    out["severity"] = (d.get("severity") or "INFO").upper()
    out["title"] = d.get("title") or d.get("test_type") or "Unknown finding"
    out["detail"] = d.get("detail") or ""
    out["evidence"] = d.get("evidence") or json.dumps(d, default=str)[:500]
    out["vuln_class_key"] = d.get("vuln_class_key") or "UNKNOWN"
    out["raw"] = d
    out["confidence"] = "candidate"
    out["id"] = compute_finding_id(out["source_tool"], out["host"],
                                    out["vuln_class_key"], out["evidence"])
    return _fill_defaults(out)


def _fill_defaults(d: dict[str, Any]) -> dict[str, Any]:
    d.setdefault("disposition", "new")
    d.setdefault("first_seen", _utcnow_iso())
    d.setdefault("last_seen", _utcnow_iso())
    d.setdefault("verified_by", None)
    d.setdefault("detail", "")
    d.setdefault("evidence", "")
    d.setdefault("steps_to_reproduce", "")
    d.setdefault("remediation", "")
    d.setdefault("curl_command", "")
    d.setdefault("cvss_score", 0.0)
    d.setdefault("cvss_vector", "")
    d.setdefault("cwe", "")
    d.setdefault("owasp", "")
    d.setdefault("impact_tier", "")
    d.setdefault("typical_payout", "")
    d.setdefault("allows_write", False)
    d.setdefault("chain_ids", [])
    d.setdefault("nuclei_template", "")
    d.setdefault("raw", {})
    return d


if __name__ == "__main__":
    # Smoke test: emit a sample finding
    f = NormalizedFinding(
        source_tool="self_test",
        host="example.com",
        url="https://example.com/admin",
        vuln_class_key="AUTH_BYPASS",
        severity="HIGH",
        title="Auth bypass test",
        confidence="candidate",
    )
    f.id = compute_finding_id(f.source_tool, f.host, f.vuln_class_key, f.evidence)
    print(json.dumps(f.to_dict(), indent=2))
