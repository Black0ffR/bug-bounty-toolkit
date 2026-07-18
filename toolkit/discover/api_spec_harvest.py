#!/usr/bin/env python3
"""
api_spec_harvest.py — OpenAPI / Swagger specification harvester
===============================================================

Tier 2 discover.

Purpose
-------
Exposed API specifications are a goldmine: they enumerate every endpoint,
method, parameter, and (sometimes) the intended auth. This tool probes the
common spec locations (`/openapi.json`, `/swagger/v1/swagger.json`, ...),
parses the document, and emits candidate findings for the juicy bits:

  - Unauthenticated endpoints (no `security` scheme) — especially state-changing
  - PUT / DELETE / PATCH (destructive, often under-tested)
  - Parameter names matching IDOR/SSRF/injection patterns (`id`, `user`, `url`,
    `file`, `redirect`, `callback`, `token`, ...)
  - `summary`/`description` keywords hinting at admin/debug/internal routes

`openapi-spec-validator` is used when present for a conformance note, but is
**optional** — the harvester works with plain `json.loads` so it stays
Termux-native.

Usage
-----
    python -m toolkit.discover.api_spec_harvest --url https://target/api
    python -m toolkit.discover.api_spec_harvest --url ... --spec /path/to.json

Author : Bug Bounty Toolkit / Tier 2
License : MIT (for authorized use only)
"""

from __future__ import annotations

import argparse
import datetime
import json
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger("api_spec_harvest")

COMMON_SPEC_PATHS = [
    "/openapi.json", "/openapi.yaml",
    "/swagger.json", "/swagger.yaml",
    "/api/openapi.json", "/api/swagger.json",
    "/v1/swagger.json", "/v2/swagger.json", "/v3/swagger.json",
    "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/docs/openapi.json", "/api-docs/swagger.json",
    "/.well-known/openapi.json",
]

# Parameter-name tokens that frequently correlate with exploitable classes.
RISKY_PARAM_TOKENS = [
    "id", "user", "userid", "username", "email", "account", "uid",
    "uuid", "token", "session", "file", "filename", "path", "url",
    "redirect", "callback", "next", "proxy", "host", "ip", "target",
    "query", "q", "search", "role", "admin", "debug",
]

STATE_CHANGING = {"PUT", "POST", "DELETE", "PATCH"}


@dataclass
class Endpoint:
    path: str
    method: str
    operation_id: str = ""
    summary: str = ""
    security: list[Any] = field(default_factory=list)
    params: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    @property
    def unauthenticated(self) -> bool:
        return not self.security


def _normalize_security(op: dict[str, Any], global_security: list[Any]) -> list[Any]:
    if "security" in op:
        return op["security"]
    return global_security


def parse_spec(spec: dict[str, Any]) -> list[Endpoint]:
    """Parse an OpenAPI/Swagger dict into Endpoint records."""
    endpoints: list[Endpoint] = []
    global_security = spec.get("security", [])
    paths = spec.get("paths", {})
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() not in {"get", "post", "put", "delete",
                                       "patch", "head", "options"}:
                continue
            if not isinstance(op, dict):
                continue
            params = [p.get("name", "") for p in op.get("parameters", [])
                      if isinstance(p, dict)]
            endpoints.append(Endpoint(
                path=path,
                method=method.upper(),
                operation_id=op.get("operationId", ""),
                summary=op.get("summary", "") or op.get("description", ""),
                security=_normalize_security(op, global_security),
                params=params,
                tags=op.get("tags", []),
            ))
    return endpoints


def endpoint_risk(ep: Endpoint) -> list[str]:
    """Return a list of risk labels for an endpoint."""
    risks: list[str] = []
    if ep.unauthenticated:
        risks.append("unauthenticated")
    if ep.method in STATE_CHANGING:
        risks.append(f"state-changing:{ep.method}")
    low = (ep.summary + " " + " ".join(ep.tags)).lower()
    if any(k in low for k in ("admin", "internal", "debug", "test", "dev")):
        risks.append("sensitive-keyword")
    for p in ep.params:
        pl = p.lower()
        if any(tok in pl for tok in RISKY_PARAM_TOKENS):
            risks.append(f"risky-param:{p}")
            break
    return risks


# ── Live probing ─────────────────────────────────────────────────────────────

async def probe_spec(base_url: str, client=None, spec_path: str | None = None
                     ) -> tuple[dict[str, Any] | None, str | None]:
    """Fetch a spec from `base_url` (+ spec_path). Returns (spec_dict, url)."""
    import httpx

    own = client is None
    if own:
        client = httpx.AsyncClient(follow_redirects=True, timeout=15.0, verify=False)
    try:
        candidates = [spec_path] if spec_path else COMMON_SPEC_PATHS
        for cand in candidates:
            url = base_url.rstrip("/") + cand
            try:
                resp = await client.get(url, headers={"Accept": "application/json"})
            except Exception as exc:  # noqa: BLE001
                log.debug("probe %s failed: %s", url, exc)
                continue
            if resp.status_code != 200:
                continue
            ctype = resp.headers.get("content-type", "")
            text = resp.text
            if "json" not in ctype and not text.lstrip().startswith("{"):
                continue
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                continue
            if "paths" in data or "swagger" in data or "openapi" in data:
                return data, url
    finally:
        if own:
            await client.aclose()
    return None, None


# ── Normalization ────────────────────────────────────────────────────────────

def to_normalized(base_url: str, endpoints: list[Endpoint], spec_url: str = "",
                  source_tool: str = "api_spec_harvest.py") -> list[dict[str, Any]]:
    from urllib.parse import urlparse
    from toolkit.infra.finding import compute_finding_id

    out: list[dict[str, Any]] = []
    host = urlparse(base_url).hostname or ""
    for ep in endpoints:
        risks = endpoint_risk(ep)
        if not risks:
            continue
        fid = compute_finding_id(source_tool, host, "API_SPEC",
                                 f"{ep.method}:{ep.path}")
        severity = "HIGH" if (ep.unauthenticated and ep.method in STATE_CHANGING) else \
            ("MEDIUM" if ep.unauthenticated else "LOW")
        out.append({
            "id": fid,
            "source_tool": source_tool,
            "host": host,
            "url": base_url.rstrip("/") + ep.path,
            "vuln_class_key": "API_SPEC_ENDPOINT",
            "severity": severity,
            "title": f"API endpoint {ep.method} {ep.path} — {', '.join(risks)}",
            "detail": f"Discovered via spec {spec_url or '(provided)'}. "
                      f"Risks: {', '.join(risks)}.",
            "evidence": f"{ep.method} {ep.path} params={ep.params}",
            "raw": {"method": ep.method, "path": ep.path, "risks": risks,
                    "unauthenticated": ep.unauthenticated,
                    "operation_id": ep.operation_id},
            "confidence": "candidate",
            "disposition": "new",
            "verified_by": None,
        })
    return out


def main() -> int:
    ap = argparse.ArgumentParser(prog="api_spec_harvest.py",
                                 description="OpenAPI/Swagger spec harvester.")
    ap.add_argument("--url", "-u", help="base URL to probe for a spec")
    ap.add_argument("--spec", help="local spec file (skip probing)")
    ap.add_argument("--output", "-o", default="api-spec-findings.json")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="[%(levelname)s] %(message)s")

    import asyncio

    spec: dict[str, Any] | None = None
    spec_url = ""
    base_url = args.url or "http://localhost"
    if args.spec:
        spec = json.loads(Path(args.spec).read_text(encoding="utf-8"))
        spec_url = args.spec
    elif args.url:
        spec, spec_url = asyncio.run(probe_spec(args.url))
    else:
        ap.error("need --url or --spec")

    if not spec:
        log.warning("no spec found")
        return 1

    endpoints = parse_spec(spec)
    norm = to_normalized(base_url, endpoints, spec_url)
    out_path = Path(args.output)
    out_path.write_text(json.dumps({
        "scan_time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "spec_url": spec_url,
        "endpoints": [{"method": e.method, "path": e.path,
                       "unauthenticated": e.unauthenticated,
                       "params": e.params, "risks": endpoint_risk(e)}
                      for e in endpoints],
        "findings": norm,
    }, indent=2), encoding="utf-8")
    log.info("parsed %d endpoints, %d flagged → %s", len(endpoints), len(norm), out_path)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(0)
