#!/usr/bin/env python3
"""
spa_router.py — static SPA route-table reconstruction
=======================================================

Tier 2 discovery tool — extends jsreaper.py's existing webpack module
resolution.

Purpose
-------
--crawl in js-extractor_3.py is link-only: it follows <a href> links in HTML.
That works for server-rendered pages but completely misses JS-rendered routes
in modern SPAs (Next.js, Nuxt, Vite, CRA). A real SPA might have /admin/settings
/financial-reports, /internal/users — none of which appear in any HTML link,
only as strings inside the JS bundle.

spa_router.py closes that gap with static analysis (no headless browser —
stays Termux-native). It parses framework-specific route manifests directly:

  - Next.js:
      * __NEXT_DATA__ JSON blob in HTML
      * .next/build-manifest.json (route → chunk mapping)
      * _buildManifest.js, _ssgManifest.js
      * static regex extract of next/router + useRouter() calls
  - Nuxt:
      * __NUXT__ payload in HTML
      * _payload.json files
      * static regex extract of this.$router.push() calls
  - Vite / CRA / generic:
      * manifest.json (PWA-style) — start_url, scope
      * chunk-to-route mapping via import graph analysis
      * React Router: <Route path="..."> JSX, react-router useNavigate()
      * Vue Router: { path: "..." } object literals

Output: a route table (list of routes with framework + source file + line)
that gets fed back into jsreaper.py and paramfuzz.py as additional targets.

Chain position
--------------
Layer 2 — Input: jsreaper.py JSON output (its all_endpoints + js_assets).
          Output: spa-routes.json — a route table.
          Feeds into: jsreaper.py (re-analyze the new route URLs),
                      paramfuzz.py (test params on the new routes).

Usage
-----
    python -m toolkit.discover.spa_router \\
        --input js-findings.json \\
        --scope scope.yaml \\
        --output spa-routes.json

Author : Bug Bounty Toolkit / Tier 2
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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from toolkit.infra import scope_guard


log = logging.getLogger("spa_router")


@dataclass
class Route:
    path: str                     # e.g., "/users/:id"
    framework: str                # next | nuxt | vite | cra | react-router | vue-router | unknown
    source: str                   # JS URL or HTML URL where the route was found
    pattern: str                  # which regex/pattern matched
    line: int = 0                 # line number in source, if known
    extra: dict[str, Any] = field(default_factory=dict)


# ── Next.js route extraction ─────────────────────────────────────────────────

# __NEXT_DATA__ JSON blob: <script id="__NEXT_DATA__" type="application/json">{...}</script>
_NEXT_DATA_RE = re.compile(
    r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>([^<]+)</script>',
    re.IGNORECASE | re.DOTALL,
)
# next/router calls: router.push("/path"), router.replace("/path")
_NEXT_ROUTER_PUSH_RE = re.compile(
    r'(?:router|Router)\.(?:push|replace)\s*\(\s*(["\'])([^"\']+)\1',
)
# useRouter() + .push
_NEXT_USE_ROUTER_RE = re.compile(
    r'useRouter\(\)\s*\.\s*(?:push|replace)\s*\(\s*(["\'])([^"\']+)\1',
)
# _buildManifest.js content — usually contains: self.__BUILD_MANIFEST=function(...)
# Inside it: {"/path": [chunk1.js, chunk2.js], "/_next/static/...": [...]}
_NEXT_BUILD_MANIFEST_PATH_RE = re.compile(
    r'(["\'])(/[a-zA-Z0-9_:/\-\.]+)\1\s*:\s*\[',
)

# ── Nuxt route extraction ────────────────────────────────────────────────────

_NUXT_DATA_RE = re.compile(
    r'window\.__NUXT__\s*=\s*([^<]+?);?\s*</script>',
    re.IGNORECASE | re.DOTALL,
)
# this.$router.push("/path")
_NUXT_ROUTER_PUSH_RE = re.compile(
    r'\$router\.(?:push|replace)\s*\(\s*(["\'])([^"\']+)\1',
)
# Nuxt routes declared in nuxt.config.js: routes: [{ path: "/path" }]
_NUXT_ROUTE_DECL_RE = re.compile(
    r'path\s*:\s*(["\'])(/[a-zA-Z0-9_:/\-\.]+)\1',
)

# ── React Router / Vue Router (also covers Vite + CRA using these) ───────────

# React Router: <Route path="/path" ...>
_REACT_ROUTER_JSX_RE = re.compile(
    r'<Route[^>]+path\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
# React Router: <Route path="..." /> in JS-as-JSX strings
_REACT_ROUTER_OBJ_RE = re.compile(
    r'path\s*:\s*["\'](/[a-zA-Z0-9_:/\-\.]+)["\']',
)
# React Router: useNavigate()("/path") / navigate("/path")
_REACT_NAVIGATE_RE = re.compile(
    r'\bnavigate\s*\(\s*(["\'])(/[a-zA-Z0-9_:/\-\.]+)\1',
)
# Vue Router: { path: "/path", component: ... }
_VUE_ROUTER_OBJ_RE = re.compile(
    r'\bpath\s*:\s*(["\'])(/[a-zA-Z0-9_:/\-\.]+)\1',
)
# Vue: this.$router.push("/path") — same as Nuxt

# ── SvelteKit / Remix / Astro route extraction ────────────────────────────────

# SvelteKit: goto("/path") (from @sveltejs/kit) + <a href="/path">
_SVELTE_GOTO_RE = re.compile(r'\bgoto\s*\(\s*(["\'])(/[a-zA-Z0-9_:/\-\.]+)\1')
_SVELTE_AHREF_RE = re.compile(r'<\s*a[^>]+href\s*=\s*(["\'])(/[a-zA-Z0-9_:/\-\.]+)\1', re.I)

# Remix: redirect("/path") (from @remix-run) + <Link to="/path">
_REMIX_REDIRECT_RE = re.compile(r'\bredirect\s*\(\s*(["\'])(/[a-zA-Z0-9_:/\-\.]+)\1')
_REMIX_LINK_RE = re.compile(
    r'<\s*Link\b[^>]*\bto\s*=\s*(["\'])(/[a-zA-Z0-9_:/\-\.]+)\1', re.I)

# Astro: <a href="/path"> in .astro templates + Astro.redirect("/path")
_ASTRO_AHREF_RE = re.compile(r'<\s*a[^>]+href\s*=\s*(["\'])(/[a-zA-Z0-9_:/\-\.]+)\1', re.I)
_ASTRO_REDIRECT_RE = re.compile(r'\bAstro\.redirect\s*\(\s*(["\'])(/[a-zA-Z0-9_:/\-\.]+)\1')

# ── Vite / generic manifest.json ─────────────────────────────────────────────

# PWA manifest.json: start_url + scope
_MANIFEST_START_URL_RE = re.compile(
    r'"start_url"\s*:\s*["\']([^"\']+)["\']',
)
_MANIFEST_SCOPE_RE = re.compile(
    r'"scope"\s*:\s*["\']([^"\']+)["\']',
)


# ── Extractors ───────────────────────────────────────────────────────────────

def extract_routes_next_html(html: str, source_url: str) -> list[Route]:
    """Extract routes from a Next.js HTML page via __NEXT_DATA__ + regex
    fallbacks. Returns matching Route objects."""
    out: list[Route] = []
    m = _NEXT_DATA_RE.search(html)
    if m:
        try:
            data = json.loads(m.group(1).strip())
            # Navigate common shapes: data.props.pageProps, data.route, data.pages
            route = data.get("route") or {}
            if isinstance(route, dict) and route.get("pathname"):
                out.append(Route(
                    path=route["pathname"], framework="next",
                    source=source_url, pattern="__NEXT_DATA__.route.pathname",
                ))
            # pageProps might list dynamic route params
            props = data.get("props", {}).get("pageProps", {}) if isinstance(data.get("props"), dict) else {}
            if isinstance(props, dict):
                # Sometimes pages are listed in __NEXT_DATA__.pages
                pages = data.get("pages") or []
                if isinstance(pages, list):
                    for p in pages:
                        if isinstance(p, str) and p.startswith("/"):
                            out.append(Route(
                                path=p, framework="next",
                                source=source_url, pattern="__NEXT_DATA__.pages[]",
                            ))
        except json.JSONDecodeError:
            pass
    # Fallback regex extract
    for m in _NEXT_ROUTER_PUSH_RE.finditer(html):
        out.append(Route(
            path=m.group(2), framework="next",
            source=source_url, pattern="next/router.push|replace",
            line=html[:m.start()].count("\n") + 1,
        ))
    for m in _NEXT_USE_ROUTER_RE.finditer(html):
        out.append(Route(
            path=m.group(2), framework="next",
            source=source_url, pattern="useRouter().push|replace",
            line=html[:m.start()].count("\n") + 1,
        ))
    return out


def extract_routes_next_buildmanifest(js: str, source_url: str) -> list[Route]:
    """Extract routes from a Next.js _buildManifest.js file."""
    out: list[Route] = []
    for m in _NEXT_BUILD_MANIFEST_PATH_RE.finditer(js):
        path = m.group(2)
        # Skip _next/static/* chunk paths
        if path.startswith("/_next/static/"):
            continue
        out.append(Route(
            path=path, framework="next",
            source=source_url, pattern="_buildManifest.js entry",
            line=js[:m.start()].count("\n") + 1,
        ))
    return out


def extract_routes_nuxt_html(html: str, source_url: str) -> list[Route]:
    """Extract routes from a Nuxt HTML page via __NUXT__ + regex fallbacks."""
    out: list[Route] = []
    m = _NUXT_DATA_RE.search(html)
    if m:
        # __NUXT__ payload is JS, not strict JSON — try to find route paths in the raw text
        for m2 in re.finditer(r'path\s*:\s*["\'](/[a-zA-Z0-9_:/\-\.]+)["\']', m.group(1)):
            out.append(Route(
                path=m2.group(1), framework="nuxt",
                source=source_url, pattern="__NUXT__.routes[].path",
            ))
    for m in _NUXT_ROUTER_PUSH_RE.finditer(html):
        out.append(Route(
            path=m.group(2), framework="nuxt",
            source=source_url, pattern="$router.push|replace",
            line=html[:m.start()].count("\n") + 1,
        ))
    return out


def extract_routes_react_router(js: str, source_url: str) -> list[Route]:
    """Extract routes from React Router JSX/JS source."""
    out: list[Route] = []
    for m in _REACT_ROUTER_JSX_RE.finditer(js):
        out.append(Route(
            path=m.group(1), framework="react-router",
            source=source_url, pattern="<Route path=...>",
            line=js[:m.start()].count("\n") + 1,
        ))
    for m in _REACT_ROUTER_OBJ_RE.finditer(js):
        out.append(Route(
            path=m.group(1), framework="react-router",
            source=source_url, pattern="path: '/...'",
            line=js[:m.start()].count("\n") + 1,
        ))
    for m in _REACT_NAVIGATE_RE.finditer(js):
        out.append(Route(
            path=m.group(2), framework="react-router",
            source=source_url, pattern="navigate('/...')",
            line=js[:m.start()].count("\n") + 1,
        ))
    return out


def extract_routes_vue_router(js: str, source_url: str) -> list[Route]:
    """Extract routes from Vue Router config / push calls."""
    out: list[Route] = []
    for m in _VUE_ROUTER_OBJ_RE.finditer(js):
        out.append(Route(
            path=m.group(2), framework="vue-router",
            source=source_url, pattern="path: '/...'",
            line=js[:m.start()].count("\n") + 1,
        ))
    for m in _NUXT_ROUTER_PUSH_RE.finditer(js):
        out.append(Route(
            path=m.group(2), framework="vue-router",
            source=source_url, pattern="$router.push|replace",
            line=js[:m.start()].count("\n") + 1,
        ))
    return out


def extract_routes_manifest(manifest_json: str, source_url: str) -> list[Route]:
    """Extract start_url + scope from a PWA manifest.json."""
    out: list[Route] = []
    try:
        data = json.loads(manifest_json)
    except Exception:
        # Try regex extract
        for m in _MANIFEST_START_URL_RE.finditer(manifest_json):
            out.append(Route(
                path=m.group(1), framework="vite",
                source=source_url, pattern="manifest.json:start_url",
            ))
        for m in _MANIFEST_SCOPE_RE.finditer(manifest_json):
            out.append(Route(
                path=m.group(1), framework="vite",
                source=source_url, pattern="manifest.json:scope",
            ))
        return out
    if isinstance(data, dict):
        if data.get("start_url"):
            out.append(Route(
                path=data["start_url"], framework="vite",
                source=source_url, pattern="manifest.json:start_url",
            ))
        if data.get("scope"):
            out.append(Route(
                path=data["scope"], framework="vite",
                source=source_url, pattern="manifest.json:scope",
            ))
    return out


def extract_routes_svelte(js: str, source_url: str) -> list[Route]:
    """Extract routes from SvelteKit source (goto + anchor hrefs)."""
    out: list[Route] = []
    for m in _SVELTE_GOTO_RE.finditer(js):
        out.append(Route(
            path=m.group(2), framework="svelte",
            source=source_url, pattern="goto('/...')",
            line=js[:m.start()].count("\n") + 1,
        ))
    for m in _SVELTE_AHREF_RE.finditer(js):
        out.append(Route(
            path=m.group(2), framework="svelte",
            source=source_url, pattern="<a href='/...'>",
            line=js[:m.start()].count("\n") + 1,
        ))
    return out


def extract_routes_remix(js: str, source_url: str) -> list[Route]:
    """Extract routes from Remix source (redirect + <Link to=...>)."""
    out: list[Route] = []
    for m in _REMIX_REDIRECT_RE.finditer(js):
        out.append(Route(
            path=m.group(2), framework="remix",
            source=source_url, pattern="redirect('/...')",
            line=js[:m.start()].count("\n") + 1,
        ))
    for m in _REMIX_LINK_RE.finditer(js):
        out.append(Route(
            path=m.group(2), framework="remix",
            source=source_url, pattern="<Link to='/...'>",
            line=js[:m.start()].count("\n") + 1,
        ))
    return out


def extract_routes_astro(js: str, source_url: str) -> list[Route]:
    """Extract routes from Astro source (anchor hrefs + Astro.redirect)."""
    out: list[Route] = []
    for m in _ASTRO_AHREF_RE.finditer(js):
        out.append(Route(
            path=m.group(2), framework="astro",
            source=source_url, pattern="<a href='/...'>",
            line=js[:m.start()].count("\n") + 1,
        ))
    for m in _ASTRO_REDIRECT_RE.finditer(js):
        out.append(Route(
            path=m.group(2), framework="astro",
            source=source_url, pattern="Astro.redirect('/...')",
            line=js[:m.start()].count("\n") + 1,
        ))
    return out


_SOURCE_MAP_RE = re.compile(r'//#\s*sourceMappingURL=(\S+)')


def find_sourcemap_url(js_content: str, js_url: str) -> str | None:
    """Return the resolved .map URL referenced by a JS file, or None.

    Handles relative (resolved against the JS URL's directory), absolute, and
    inline (data:) comments (the latter returns None — its sourcesContent is
    already embedded in the bundle and handled by the normal extractors).
    """
    m = _SOURCE_MAP_RE.search(js_content)
    if not m:
        return None
    val = m.group(1).strip().strip('"\'')
    if val.startswith("data:"):
        return None
    if val.startswith("http://") or val.startswith("https://"):
        return val
    base = js_url.rsplit("/", 1)[0]
    return (base + "/" + val) if base else val


def _route_from_source_path(src: str) -> str | None:
    """Derive a web route path from a file-based routing source path.

    e.g. 'src/routes/admin/settings/+page.svelte' → '/admin/settings'.
    """
    s = src.replace("\\", "/")
    for marker in ("/routes/", "/pages/", "/app/", "/src/"):
        idx = s.find(marker)
        if idx != -1:
            seg = s[idx + len(marker):]
            break
    else:
        return None
    seg = re.sub(r"\.(svelte|astro|vue|tsx|ts|jsx|js)$", "", seg)
    seg = seg.replace("+page", "").replace("+layout", "").replace("+server", "")
    seg = re.sub(r"(^|/)index(/|$)", "/", seg)
    seg = seg.replace("//", "/")
    if not seg.startswith("/"):
        seg = "/" + seg
    seg = seg.rstrip("/") or "/"
    return seg


def extract_routes_from_sourcemap(map_json: str, source_url: str) -> list[Route]:
    """Extract routes from a parsed sourcemap.

    Two strategies (both pure, no network):
      1. File-based route derivation from `sources` entries.
      2. Runnable route regexes over `sourcesContent` originals.
    """
    out: list[Route] = []
    try:
        data = json.loads(map_json)
    except Exception:
        return out
    if not isinstance(data, dict):
        return out
    for src in (data.get("sources") or []):
        if not isinstance(src, str):
            continue
        route = _route_from_source_path(src)
        if route:
            out.append(Route(
                path=route, framework="sourcemap",
                source=source_url, pattern=f"sourcemap:sources:{src}",
            ))
    for content in (data.get("sourcesContent") or []):
        if isinstance(content, str):
            out.extend(extract_all_routes_from_js(content, source_url))
    return out


def detect_framework(js_url: str, js_content: str) -> str | None:
    """Quick heuristic to detect the SPA framework from a JS file's content + URL.
    Returns 'next' | 'nuxt' | 'react-router' | 'vue-router' | 'vite' | 'cra' | None.
    """
    u = js_url.lower()
    c = js_content[:5000]  # check first 5KB only
    if "/_next/" in u or "__NEXT_DATA__" in c or "next/router" in c or "useRouter" in c:
        return "next"
    if "/_nuxt/" in u or "__NUXT__" in c or "$router" in c:
        return "nuxt"
    if "@sveltejs" in c.lower() or ("svelte" in c.lower() and "goto" in c):
        return "svelte"
    if "@remix-run" in c.lower() or "remix" in c.lower() and "useLoaderData" in c:
        return "remix"
    if "astro" in c.lower() and ("Astro." in c or "client:" in c):
        return "astro"
    if "react-router" in c or "reactrouter" in c or "<Route " in c or "useNavigate" in c:
        return "react-router"
    if "vue-router" in c or "vuerouter" in c or "$route.path" in c:
        return "vue-router"
    if "/@vite/" in u or "vite" in c.lower():
        return "vite"
    if "react-dom" in c or "create-react-app" in c.lower():
        return "cra"
    return None


def extract_all_routes_from_js(js_content: str, js_url: str) -> list[Route]:
    """Run all framework extractors on a JS file. Returns deduped list."""
    out: list[Route] = []
    framework = detect_framework(js_url, js_content)
    # Always run all extractors — many sites mix frameworks
    out.extend(extract_routes_next_html(js_content, js_url))  # Next data lives in JS too sometimes
    out.extend(extract_routes_next_buildmanifest(js_content, js_url))
    out.extend(extract_routes_nuxt_html(js_content, js_url))
    out.extend(extract_routes_react_router(js_content, js_url))
    out.extend(extract_routes_vue_router(js_content, js_url))
    out.extend(extract_routes_svelte(js_content, js_url))
    out.extend(extract_routes_remix(js_content, js_url))
    out.extend(extract_routes_astro(js_content, js_url))
    # If we know the framework, tag routes that didn't have one set
    for r in out:
        if r.framework == "unknown" and framework:
            r.framework = framework
    return out


async def fetch_url(url: str, *, timeout: float = 15.0) -> tuple[int, str, dict[str, str]]:
    """Fetch a URL and return (status, body, headers). Never raises — returns
    (0, "", {}) on failure. Uses a shared httpx connection pool (B19) when
    available, urllib fallback otherwise."""
    try:
        from toolkit.infra import http_pool
        client = await http_pool.get_shared_client(timeout=timeout)
        r = await client.get(url)
        return (r.status_code, r.text or "", dict(r.headers))
    except Exception:
        pass
    # urllib fallback (sync, but wrapped in thread)
    import urllib.request
    import ssl
    import concurrent.futures
    def _fetch() -> tuple[int, str, dict[str, str]]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; SpaRouter/1.0)"})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return (resp.status, resp.read().decode("utf-8", errors="replace"), dict(resp.headers))
        except Exception as exc:
            log.debug("fetch %s failed: %s", url, exc)
            return (0, "", {})
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _fetch)


def extract_js_assets_from_input(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Pull a unique list of {url, host, html_url} from jsreaper.py output.
    jsreaper emits host_results[].js_assets[].url — those are the JS files."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for hr in data.get("host_results", []) or []:
        host = hr.get("host", "")
        for js in hr.get("js_assets", []) or []:
            url = js.get("url", "")
            if url and url not in seen:
                seen.add(url)
                out.append({"url": url, "host": host, "html_url": ""})
    # Also include top-level endpoints — they might be HTML pages we should fetch
    # for __NEXT_DATA__ / __NUXT__ extraction
    for ep in data.get("all_endpoints", []) or []:
        url = ep.get("endpoint") or ep.get("url", "")
        if url and url not in seen:
            seen.add(url)
            out.append({"url": url, "host": ep.get("host", ""), "html_url": ""})
    return out


async def scan_all(assets: list[dict[str, Any]], guard: scope_guard.ScopeGuard,
                   *, concurrency: int = 10) -> list[Route]:
    """Fetch each asset, detect framework, extract routes."""
    sem = asyncio.Semaphore(concurrency)
    all_routes: list[Route] = []

    async def _one(asset: dict[str, Any]) -> list[Route]:
        async with sem:
            url = asset["url"]
            try:
                guard.check_url(url, source_tool="spa_router.py")
            except scope_guard.ScopeError as exc:
                log.debug("scope reject %s — %s", url, exc)
                return []
            if not guard.acquire_token(timeout=20.0):
                return []
            try:
                status, body, _ = await fetch_url(url)
            finally:
                guard.release_token()
            if status == 0 or not body:
                return []
            routes = extract_all_routes_from_js(body, url)
            # If this looks like HTML, also run the HTML extractors
            if "<html" in body.lower()[:500] or "<!doctype html" in body.lower()[:500]:
                routes.extend(extract_routes_next_html(body, url))
                routes.extend(extract_routes_nuxt_html(body, url))
            # Sourcemap-aware extraction: follow //# sourceMappingURL= and mine
            # the original (unminified) sources for routes we'd otherwise miss.
            sm_url = find_sourcemap_url(body, url)
            if sm_url:
                try:
                    guard.check_url(sm_url, source_tool="spa_router.py")
                except scope_guard.ScopeError:
                    sm_url = None
                if sm_url and guard.acquire_token(timeout=20.0):
                    try:
                        st, sm_body, _ = await fetch_url(sm_url)
                        if st and sm_body:
                            routes.extend(extract_routes_from_sourcemap(sm_body, url))
                    finally:
                        guard.release_token()
            log.info("  %s: %d routes", url, len(routes))
            return routes

    results = await asyncio.gather(*[_one(a) for a in assets], return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            all_routes.extend(r)
        elif isinstance(r, Exception):
            log.warning("scan raised: %s", r)
    return all_routes


def dedupe_routes(routes: list[Route]) -> list[Route]:
    """Deduplicate by (path, framework)."""
    seen: set[tuple[str, str]] = set()
    out: list[Route] = []
    for r in routes:
        key = (r.path, r.framework)
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="spa_router.py",
        description="Static SPA route-table reconstruction. Extends jsreaper.py.",
    )
    ap.add_argument("--input", "-i", required=True, help="jsreaper.py JSON output")
    ap.add_argument("--scope", help="scope.yaml path")
    ap.add_argument("--output", "-o", default="spa-routes.json", help="output JSON (default: spa-routes.json)")
    ap.add_argument("--concurrency", type=int, default=10)
    ap.add_argument("--dry-run", action="store_true", help="extract JS assets only, no fetch")
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
    if not isinstance(data, dict):
        log.error("input must be a jsreaper.py JSON object")
        return 2
    assets = extract_js_assets_from_input(data)
    log.info("assets to scan: %d", len(assets))

    if args.dry_run:
        for a in assets:
            print(f"  {a['url']}")
        return 0

    guard = scope_guard.ScopeGuard(args.scope) if args.scope else scope_guard.get_default()
    routes = asyncio.run(scan_all(assets, guard, concurrency=args.concurrency))
    log.info("raw routes: %d", len(routes))
    routes = dedupe_routes(routes)
    log.info("after dedup: %d", len(routes))

    # Convert to JSON-serializable
    out_data = {
        "scan_time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "input": str(in_path),
        "total_assets_scanned": len(assets),
        "total_routes": len(routes),
        "frameworks_detected": sorted({r.framework for r in routes}),
        "routes": [
            {
                "path": r.path,
                "framework": r.framework,
                "source": r.source,
                "pattern": r.pattern,
                "line": r.line,
                "extra": r.extra,
            }
            for r in routes
        ],
    }
    out_path = Path(args.output)
    out_path.write_text(json.dumps(out_data, indent=2, default=str), encoding="utf-8")
    log.info("wrote %s", out_path)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(0)
