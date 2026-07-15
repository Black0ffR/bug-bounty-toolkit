#!/usr/bin/env python3
"""
idor_crosssession.py — cross-session BOLA/IDOR verification
============================================================

Tier 1 verification tool — extends apifuzz.py's existing BOLA candidates.

Purpose
-------
apifuzz.py flags BOLA candidates with `test_type="BOLA"` and titles like
"Possible BOLA/IDOR — Predictable ID Access" — but with only one session,
it can only say "this might be a problem." nuclei-harvest.py's own output
flags this as "needs cross-session verification" — but the pipeline had no
tool to actually DO that verification. This is that tool.

Takes apifuzz.py's BOLA candidate findings + auth_profiles.yaml (needs at
least two non-anon profiles), replays the captured request under user_b's
session, and produces a three-way verdict:

  - user_b gets 200 + user_a's actual data  →  IDOR CONFIRMED
  - user_b gets 200 + empty/generic data    →  false positive (shared/public)
  - user_b gets 403 / 401                   →  correctly access-controlled

For confirmed IDORs, sweeps a small window of adjacent sequential IDs (or
UUIDv1-neighboring IDs — the exact technique from the elite-workflow research:
generate neighboring UUIDv1s, test which resolve) to estimate blast radius
(1 record vs. entire user table walkable).

Findings promoted from confidence: candidate → confirmed get verified_by
set to "idor_crosssession.py" so downstream tools (nuclei-harvest, triage)
know not to re-flag them as candidates.

Chain position
--------------
Layer 4 — Input: apifuzz.py output JSON filtered to test_type="BOLA" +
          auth_profiles.yaml (>= 2 authenticated profiles).
          Output: updated findings JSON with confidence + verified_by set.
          Persisted: pipeline_state.db (verified_by recorded).

Usage
-----
    python -m toolkit.verify.idor_crosssession \\
        --input api-findings.json \\
        --auth-profiles auth_profiles.yaml \\
        --scope scope.yaml \\
        --output idor-verified.json

Author : Bug Bounty Toolkit / Tier 1
License : MIT (for authorized use only)
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import json
import logging
import re
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from toolkit.infra.auth_profiles import AuthProfiles, redact_dict, redact_value
from toolkit.infra.finding import NormalizedFinding, compute_finding_id, normalize_finding_dict
from toolkit.infra.pipeline_state import PipelineState
from toolkit.infra import scope_guard


log = logging.getLogger("idor_crosssession")

# Match apifuzz.py's regex for predictable IDs in paths
_ID_PATTERN = re.compile(r"/(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", re.I)


@dataclass
class ReplayResult:
    finding_id: str
    user_a_status: int
    user_a_body_len: int
    user_a_body_hash: str
    user_b_status: int
    user_b_body_len: int
    user_b_body_hash: str
    body_similarity: float        # 0.0 to 1.0
    verdict: str                  # confirmed | false_positive | access_controlled | inconclusive
    blast_radius: int = 1         # number of additional IDs that resolved under user_b
    evidence: str = ""


def _hash(s: str) -> str:
    import hashlib
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]


def _similarity(a: str, b: str) -> float:
    """Cheap Jaccard-over-words similarity. apifuzz.py uses a richer shingle-based
    compare; we use a simpler one because we're comparing across sessions and
    mostly care about whether user_b sees user_a's data verbatim."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    # Normalize: lowercase, strip whitespace
    na = re.sub(r"\s+", " ", a.lower().strip())
    nb = re.sub(r"\s+", " ", b.lower().strip())
    if na == nb:
        return 1.0
    # Tokenize on non-word
    ta = set(re.findall(r"\w+", na))
    tb = set(re.findall(r"\w+", nb))
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def filter_bola_candidates(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Filter apifuzz.py findings to BOLA candidates only.
    Matches test_type="BOLA" OR vuln_class_key in (BOLA_POSSIBLE, BOLA_CONFIRMED)
    OR title contains 'BOLA'/'IDOR'.
    """
    out = []
    for f in findings:
        tt = (f.get("test_type") or "").upper()
        vk = (f.get("vuln_class_key") or "").upper()
        title = (f.get("title") or "").upper()
        if tt == "BOLA" or vk in ("BOLA_POSSIBLE", "BOLA_CONFIRMED") or "BOLA" in title or "IDOR" in title:
            out.append(f)
    return out


def parse_curl_command(curl: str) -> dict[str, Any]:
    """Best-effort parse of an apifuzz.py _build_curl() output back into a
    structured request dict. Returns {method, url, headers, body}.
    apifuzz.py's format:
        curl -sk -D - \\\n  [-X METHOD] \\\n  [-H "k: v"]... \\\n  [--data-raw '...'] \\\n  "URL"
    """
    if not curl:
        return {"method": "GET", "url": "", "headers": {}, "body": None}
    # Join line continuations
    flat = re.sub(r"\\\s*\n\s*", " ", curl).strip()
    method = "GET"
    headers: dict[str, str] = {}
    body: Any = None
    url = ""
    # Tokenize with shell-like splitting (handles quoted strings)
    try:
        import shlex
        tokens = shlex.split(flat)
    except ValueError:
        tokens = flat.split()
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t == "curl":
            i += 1
            continue
        if t in ("-sk", "-sS", "-s", "-k"):
            i += 1
            continue
        if t == "-D":
            i += 2  # skip -D and its arg
            continue
        if t == "-X":
            if i + 1 < len(tokens):
                method = tokens[i + 1].upper()
                i += 2
                continue
        if t == "-H":
            if i + 1 < len(tokens):
                hdr = tokens[i + 1]
                if ":" in hdr:
                    k, _, v = hdr.partition(":")
                    headers[k.strip()] = v.strip()
                i += 2
                continue
        if t == "--data-raw" or t == "-d":
            if i + 1 < len(tokens):
                body = tokens[i + 1]
                # Try to parse as JSON for structured comparison
                if body and body.strip().startswith("{"):
                    try:
                        body = json.loads(body)
                    except Exception:
                        pass
                i += 2
                continue
        # If it's the URL (last token, starts with http:// or https://)
        if t.startswith(("http://", "https://")):
            url = t.strip("'\"")
            i += 1
            continue
        i += 1
    return {"method": method, "url": url, "headers": headers, "body": body}


def _build_url_with_id(orig_url: str, new_id: str) -> str:
    """Replace the last ID-looking segment in orig_url with new_id.
    If orig_url has no ID segment, append new_id to the path."""
    m = list(_ID_PATTERN.finditer(orig_url))
    if m:
        last = m[-1]
        return orig_url[:last.start(1)] + new_id + orig_url[last.end(1):]
    # No ID found — append
    sep = "/" if not orig_url.endswith("/") else ""
    return f"{orig_url}{sep}{new_id}"


def gen_neighbor_ids(current_id: str, *, count: int = 5) -> list[str]:
    """Generate neighboring IDs to test blast radius.
    - Integer IDs: current-2, current-1, current+1, current+2, current+5
    - UUID v1 (timestamp-based): generate UUIDs with timestamp +/- a few ticks
      (the technique from the elite-workflow research)
    - UUID v4 (random): no useful neighbors — return [current_id] (no sweep)
    """
    if current_id.isdigit():
        n = int(current_id)
        return [str(n - 2), str(n - 1), str(n + 1), str(n + 2), str(n + 5)]
    # Try UUID v1 — first segment is time_low (little-endian 60-bit timestamp)
    try:
        u = uuid.UUID(current_id)
        if u.version == 1:
            # The 60-bit timestamp is in time_low (32 bits) + time_mid (16 bits) + time_hi (12 bits)
            # Generate neighbors by incrementing the timestamp
            # Simple approach: parse, increment time_low by 1-5, decrement by 1-5
            out: list[str] = []
            for delta in (-5, -2, -1, 1, 2, 5):
                # Reconstruct UUID with modified time_low
                # UUID fields: (time_low, time_mid, time_hi_and_version,
                #              clock_seq_hi_variant, clock_seq_low, node)
                fields = list(u.fields)
                # time_low is a 32-bit int; +/- delta
                tl = (fields[0] + delta) & 0xFFFFFFFF
                fields[0] = tl
                new_u = uuid.UUID(fields=tuple(fields))
                out.append(str(new_u))
            return out[:count]
    except (ValueError, AttributeError):
        pass
    # Fallback: just return current
    return []


async def replay_one_request(session, *, method: str, url: str, headers: dict[str, str],
                             body: Any, timeout: float = 12.0) -> tuple[int, str, int]:
    """Returns (status, body_text[:3000], body_len). Never raises."""
    try:
        kwargs: dict[str, Any] = {"headers": headers, "timeout": timeout}
        if body is not None:
            if isinstance(body, dict):
                kwargs["json"] = body
            else:
                kwargs["data"] = body
        if method.upper() == "GET":
            r = await session.get(url, **kwargs)
        elif method.upper() == "POST":
            r = await session.post(url, **kwargs)
        elif method.upper() == "PUT":
            r = await session.put(url, **kwargs)
        elif method.upper() == "PATCH":
            r = await session.patch(url, **kwargs)
        elif method.upper() == "DELETE":
            r = await session.delete(url, **kwargs)
        else:
            r = await session.request(method, url, **kwargs)
        text = r.text or ""
        return (int(getattr(r, "status_code", 0) or 0), text[:3000], len(text))
    except Exception as exc:
        log.debug("replay failed: %s %s — %s", method, url, exc)
        return (0, "", 0)


async def verify_finding(finding: dict[str, Any], profiles: AuthProfiles,
                         guard: scope_guard.ScopeGuard, *,
                         max_blast: int = 5) -> ReplayResult | None:
    """Verify a single BOLA candidate finding by replaying under user_b's session."""
    fid = finding.get("id") or compute_finding_id(
        finding.get("source_tool", "apifuzz.py"),
        finding.get("host", ""),
        finding.get("vuln_class_key") or "BOLA_POSSIBLE",
        finding.get("evidence", ""),
    )
    # Build the request from the finding's curl_command (preferred) or its url/method
    curl = finding.get("curl_command", "")
    parsed = parse_curl_command(curl)
    if not parsed["url"]:
        # Fallback to the finding's url + method fields
        parsed["url"] = finding.get("url", "")
        parsed["method"] = finding.get("method", "GET").upper()
    if not parsed["url"]:
        log.warning("finding %s has no replayable URL — skipping", fid[:8])
        return None
    # Scope check
    try:
        guard.check_url(parsed["url"], source_tool="idor_crosssession.py")
    except scope_guard.ScopeError as exc:
        log.warning("scope reject %s — %s", parsed["url"], exc)
        return None
    # Need two profiles
    try:
        prof_a, prof_b = profiles.require_two_users()
    except RuntimeError as exc:
        log.error("cannot verify IDOR: %s", exc)
        return None
    # Strip auth headers from parsed (the session provides them)
    user_a_headers = {k: v for k, v in parsed["headers"].items()
                      if k.lower() not in ("authorization", "cookie", "x-api-key")}
    user_b_headers = dict(user_a_headers)
    # Acquire rate-limit tokens — one for user_a replay, one for user_b
    if not (guard.acquire_token(timeout=30.0)):
        log.warning("rate limit timeout for %s", fid[:8])
        return None
    try:
        sess_a = profiles.get_session(prof_a.name, timeout=12.0)
        # We need to call the inner client.request directly to preserve the
        # AsyncClient surface. The AuthenticatedSession wraps sync httpx.Client.
        # For async, drop down to httpx.AsyncClient with the profile's auth headers.
        import httpx
        merged_a = {**sess_a.profile.auth_headers(), **user_a_headers}
        merged_b = {**profiles.get_profile(prof_b.name).auth_headers(), **user_b_headers}
        async with httpx.AsyncClient(timeout=12.0, verify=False, follow_redirects=False) as client:
            # User A replay
            s_a, body_a, len_a = await _replay_with_client(
                client, parsed["method"], parsed["url"], merged_a, parsed["body"]
            )
            # User B replay (same URL, different auth)
            s_b, body_b, len_b = await _replay_with_client(
                client, parsed["method"], parsed["url"], merged_b, parsed["body"]
            )
    finally:
        guard.release_token()
    sess_a.close()

    # Three-way verdict
    sim = _similarity(body_a, body_b)
    h_a = _hash(body_a)
    h_b = _hash(body_b)
    verdict = "inconclusive"
    evidence_parts = [
        f"user_a ({prof_a.name}): HTTP {s_a} {len_a}B hash={h_a}",
        f"user_b ({prof_b.name}): HTTP {s_b} {len_b}B hash={h_b}",
        f"body_similarity={sim:.2f}",
    ]
    if s_b in (200, 201) and s_a in (200, 201) and len_a > 50 and sim > 0.7:
        verdict = "confirmed"
    elif s_b in (200, 201) and (len_b < 50 or sim < 0.3):
        verdict = "false_positive"
        evidence_parts.append("(user_b got 200 but body too short/dissimilar — likely shared/public resource)")
    elif s_b in (401, 403):
        verdict = "access_controlled"
        evidence_parts.append("(user_b correctly denied)")
    elif s_b == 0:
        verdict = "inconclusive"
        evidence_parts.append("(user_b request failed)")
    # Blast radius sweep for confirmed IDORs only
    blast = 0
    if verdict == "confirmed":
        # Extract current ID from URL
        m = _ID_PATTERN.search(parsed["url"])
        if m:
            current_id = m.group(1)
            neighbors = gen_neighbor_ids(current_id, count=max_blast)
            log.info("sweeping %d neighbor IDs for blast radius", len(neighbors))
            for nid in neighbors:
                if nid == current_id:
                    continue
                test_url = _build_url_with_id(parsed["url"], nid)
                try:
                    guard.check_url(test_url, source_tool="idor_crosssession.py")
                except scope_guard.ScopeError:
                    continue
                if not guard.acquire_token(timeout=20.0):
                    continue
                try:
                    async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=False) as client:
                        s_n, body_n, len_n = await _replay_with_client(
                            client, "GET", test_url, merged_b, None
                        )
                finally:
                    guard.release_token()
                if s_n in (200, 201) and len_n > 50:
                    blast += 1
                    evidence_parts.append(f"  neighbor {nid}: HTTP {s_n} {len_n}B — RESOLVES")
    return ReplayResult(
        finding_id=fid,
        user_a_status=s_a, user_a_body_len=len_a, user_a_body_hash=h_a,
        user_b_status=s_b, user_b_body_len=len_b, user_b_body_hash=h_b,
        body_similarity=sim, verdict=verdict,
        blast_radius=blast + (1 if verdict == "confirmed" else 0),
        evidence="\n".join(evidence_parts),
    )


async def _replay_with_client(client, method: str, url: str, headers: dict[str, str],
                              body: Any) -> tuple[int, str, int]:
    """Adapter that calls the right method on an httpx.AsyncClient."""
    kwargs: dict[str, Any] = {"headers": headers}
    if body is not None:
        if isinstance(body, dict):
            kwargs["json"] = body
        else:
            kwargs["data"] = body
    method = method.upper()
    try:
        if method == "GET":
            r = await client.get(url, **kwargs)
        elif method == "POST":
            r = await client.post(url, **kwargs)
        elif method == "PUT":
            r = await client.put(url, **kwargs)
        elif method == "PATCH":
            r = await client.patch(url, **kwargs)
        elif method == "DELETE":
            r = await client.delete(url, **kwargs)
        else:
            r = await client.request(method, url, **kwargs)
        text = r.text or ""
        return (int(r.status_code or 0), text[:3000], len(text))
    except Exception as exc:
        log.debug("replay failed: %s %s — %s", method, url, exc)
        return (0, "", 0)


async def verify_all(findings: list[dict[str, Any]], profiles: AuthProfiles,
                     guard: scope_guard.ScopeGuard, *,
                     max_blast: int = 5, concurrency: int = 5) -> list[ReplayResult]:
    """Verify all findings concurrently (bounded by the scope_guard's rate limit)."""
    sem = asyncio.Semaphore(concurrency)

    async def _bounded(f: dict[str, Any]) -> ReplayResult | None:
        async with sem:
            return await verify_finding(f, profiles, guard, max_blast=max_blast)

    tasks = [_bounded(f) for f in findings]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    out: list[ReplayResult] = []
    for r in results:
        if isinstance(r, ReplayResult):
            out.append(r)
        elif isinstance(r, Exception):
            log.warning("verify_finding raised: %s", r)
    return out


def build_verified_findings(findings: list[dict[str, Any]],
                            results: list[ReplayResult]) -> list[dict[str, Any]]:
    """Merge verification results back into the findings list. Findings whose
    verdict is 'confirmed' get promoted to confidence=confirmed + verified_by.
    'false_positive' findings get disposition=rejected. 'access_controlled'
    findings get confidence=probable (still a candidate — just confirmed not
    currently exploitable; access control might regress)."""
    by_id = {r.finding_id: r for r in results}
    out: list[dict[str, Any]] = []
    for raw in findings:
        nf = NormalizedFinding.from_dict(normalize_finding_dict(raw, source_tool=raw.get("source_tool", "apifuzz.py")))
        if not nf.id:
            nf.id = compute_finding_id(nf.source_tool, nf.host, nf.vuln_class_key, nf.evidence)
        r = by_id.get(nf.id)
        if r is None:
            out.append(nf.to_dict())
            continue
        if r.verdict == "confirmed":
            nf.confidence = "confirmed"
            nf.verified_by = "idor_crosssession.py"
            nf.severity = "CRITICAL"
            nf.vuln_class_key = "BOLA_CONFIRMED"
            nf.title = f"IDOR CONFIRMED cross-session — blast radius ~{r.blast_radius} records"
            nf.evidence = (nf.evidence + "\n\n--- IDOR verification ---\n" + r.evidence).strip()
            nf.detail = (f"Cross-session replay with user_b confirmed access to user_a's data. "
                         f"Body similarity {r.body_similarity:.0%}, blast radius ~{r.blast_radius} records walkable.")
        elif r.verdict == "false_positive":
            nf.confidence = "candidate"
            nf.disposition = "rejected"
            nf.verified_by = "idor_crosssession.py"
            nf.detail = (nf.detail + "\n\n--- IDOR verification ---\n" +
                         "False positive: user_b got 200 but body was empty/generic — likely a shared/public resource.\n" +
                         r.evidence).strip()
        elif r.verdict == "access_controlled":
            nf.confidence = "probable"
            nf.verified_by = "idor_crosssession.py"
            nf.detail = (nf.detail + "\n\n--- IDOR verification ---\n" +
                         "Access correctly denied for user_b (HTTP " + str(r.user_b_status) + "). " +
                         "Still a candidate — access control may regress.\n" + r.evidence).strip()
        else:
            nf.detail = (nf.detail + "\n\n--- IDOR verification ---\n" +
                         "Inconclusive — replay did not produce a clear verdict.\n" + r.evidence).strip()
        out.append(nf.to_dict())
    return out


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="idor_crosssession.py",
        description="Cross-session BOLA/IDOR verifier. Extends apifuzz.py's BOLA candidates.",
    )
    ap.add_argument("--input", "-i", required=True, help="apifuzz.py output JSON (api-findings.json)")
    ap.add_argument("--auth-profiles", required=True, help="auth_profiles.yaml path")
    ap.add_argument("--scope", help="scope.yaml path (required for live replay)")
    ap.add_argument("--output", "-o", default="idor-verified.json", help="output JSON path (default: idor-verified.json)")
    ap.add_argument("--db", default="pipeline_state.db", help="pipeline_state.db path")
    ap.add_argument("--max-blast", type=int, default=5, help="max neighbor IDs to test for blast radius (default: 5)")
    ap.add_argument("--concurrency", type=int, default=5, help="max concurrent verifications (default: 5)")
    ap.add_argument("--dry-run", action="store_true", help="parse + filter only, no live requests")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )

    # Load findings
    in_path = Path(args.input)
    if not in_path.exists():
        log.error("input file not found: %s", in_path)
        return 2
    data = json.loads(in_path.read_text(encoding="utf-8"))
    findings: list[dict[str, Any]]
    if isinstance(data, list):
        findings = data
    elif isinstance(data, dict):
        findings = data.get("findings") or data.get("all_findings") or []
    else:
        log.error("input root must be a list or object with 'findings'")
        return 2
    log.info("loaded %d findings from %s", len(findings), in_path)

    # Filter BOLA candidates
    candidates = filter_bola_candidates(findings)
    log.info("BOLA candidates: %d / %d", len(candidates), len(findings))

    if args.dry_run:
        log.info("--dry-run: printing candidate ids and not replaying")
        for c in candidates:
            print(f"  {c.get('id', '?')[:16]:16s}  {c.get('host', '?'):30s}  {c.get('title', '')[:60]}")
        return 0

    # Load auth profiles
    profiles = AuthProfiles(args.auth_profiles)
    try:
        prof_a, prof_b = profiles.require_two_users()
        log.info("using profiles: user_a=%s user_b=%s", prof_a.name, prof_b.name)
    except RuntimeError as exc:
        log.error("cannot proceed: %s", exc)
        return 3

    # Load scope guard
    guard = scope_guard.ScopeGuard(args.scope) if args.scope else scope_guard.get_default()

    # Run verifications
    state = PipelineState(args.db)
    try:
        results = asyncio.run(verify_all(candidates, profiles, guard,
                                         max_blast=args.max_blast,
                                         concurrency=args.concurrency))
        log.info("verification complete: %d results", len(results))
        for r in results:
            log.info("  %s: %s (blast=%d)", r.finding_id[:8], r.verdict, r.blast_radius)
        # Merge back into findings + persist
        verified = build_verified_findings(findings, results)
        for f in verified:
            state.upsert_finding(f)
        # Write output
        out_path = Path(args.output)
        out_path.write_text(
            json.dumps({
                "scan_time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                "input": str(in_path),
                "candidates": len(candidates),
                "results": [
                    {"finding_id": r.finding_id, "verdict": r.verdict,
                     "blast_radius": r.blast_radius, "body_similarity": r.body_similarity,
                     "user_a_status": r.user_a_status, "user_b_status": r.user_b_status,
                     "evidence": r.evidence}
                    for r in results
                ],
                "findings": verified,
            }, indent=2, default=str),
            encoding="utf-8",
        )
        log.info("wrote %s", out_path)
        # Summary
        confirmed = sum(1 for r in results if r.verdict == "confirmed")
        fp = sum(1 for r in results if r.verdict == "false_positive")
        ac = sum(1 for r in results if r.verdict == "access_controlled")
        incon = sum(1 for r in results if r.verdict == "inconclusive")
        log.info("summary: confirmed=%d false_positive=%d access_controlled=%d inconclusive=%d",
                 confirmed, fp, ac, incon)
        return 0
    finally:
        state.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(0)
