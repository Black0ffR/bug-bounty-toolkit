# spa_router

Static SPA route-table reconstruction. `js-extractor_3.py`'s `--crawl` is link-only: it follows `<a href>` links in HTML. That works for server-rendered pages but completely misses JS-rendered routes in modern SPAs (Next.js, Nuxt, Vite, CRA) — `/admin/settings`, `/financial-reports`, `/internal/users` etc. only exist as strings inside the JS bundle. This tool closes that gap with static analysis (no headless browser — stays Termux-native). Parses framework-specific route manifests directly: Next.js (`__NEXT_DATA__` JSON blob, `_buildManifest.js`, `next/router`/`useRouter()` calls), Nuxt (`__NUXT__` payload, `_payload.json`, `$router.push()`), React Router (`<Route path="...">` JSX, `useNavigate()`), Vue Router (`{ path: "..." }` object literals), Vite/CRA (PWA `manifest.json` `start_url`/`scope`).

## Layer / Tier
Tier 2 discover. Layer 2 in the pipeline.

## Depends on
- `toolkit.infra.scope_guard` — `ScopeGuard` for scope + rate-limit enforcement on every JS/HTML fetch.
- `httpx` (preferred) or `urllib.request` (fallback, wrapped in executor for async).
- Python stdlib: `re`, `json`, `asyncio`, `argparse`, `datetime`.

## Feeds into
- `spa-routes.json` — a route table (list of `{path, framework, source, pattern, line}`).
- Downstream: `jsreaper.py` (re-analyze the new route URLs), `paramfuzz.py` (test params on the new routes).

## Usage

```bash
python -m toolkit.discover.spa_router \
    --input js-findings.json \
    --scope scope.yaml \
    --output spa-routes.json

# List JS assets only, no fetch
python -m toolkit.discover.spa_router --input js-findings.json --dry-run
```

## Library use
```python
import asyncio
from toolkit.discover.spa_router import extract_js_assets_from_input, scan_all, dedupe_routes, detect_framework

assets = extract_js_assets_from_input(jsreaper_data)  # pulls js_assets + all_endpoints
guard = scope_guard.ScopeGuard("scope.yaml")
routes = asyncio.run(scan_all(assets, guard, concurrency=10))
routes = dedupe_routes(routes)
# Each Route has: path, framework, source, pattern, line, extra
```

## Input / Output
- **Input:** `jsreaper.py` JSON output. Pulls `host_results[].js_assets[].url` (the JS files) and `all_endpoints[]` (HTML pages that may contain `__NEXT_DATA__`/`__NUXT__` blobs).
- **Output:** `spa-routes.json` with `scan_time`, `total_assets_scanned`, `total_routes`, `frameworks_detected` (sorted unique), and `routes[]` (each `{path, framework, source, pattern, line, extra}`). Default output path `spa-routes.json`.
- **Side effects:** One HTTP GET per asset (JS file or HTML page). Rate-limited via `scope_guard`. No DB writes (this is a discovery tool — downstream consumers persist).

## Key classes / functions
| Name | Purpose |
|---|---|
| `Route` | `dataclass(path, framework, source, pattern, line, extra)`. `framework` is `next | nuxt | vite | cra | react-router | vue-router | unknown`. |
| `detect_framework(js_url, js_content)` | Heuristic: checks URL (`/_next/`, `/_nuxt/`, `/@vite/`) and first 5KB of content for framework signatures. |
| `extract_routes_next_html(html, source_url)` | `__NEXT_DATA__` JSON blob + `next/router.push|replace` + `useRouter().push|replace` regex fallback. |
| `extract_routes_next_buildmanifest(js, source_url)` | `_buildManifest.js` path-to-chunk entries. |
| `extract_routes_nuxt_html(html, source_url)` | `__NUXT__` payload + `$router.push|replace`. |
| `extract_routes_react_router(js, source_url)` | `<Route path="...">` JSX + `path: '/...'` object literals + `navigate('/...')` calls. |
| `extract_routes_vue_router(js, source_url)` | `{ path: "..." }` object literals + `$router.push|replace`. |
| `extract_routes_manifest(manifest_json, source_url)` | PWA `manifest.json` `start_url` + `scope`. |
| `extract_all_routes_from_js(js_content, js_url)` | Run all extractors; tag any `unknown`-framework routes with the detected framework. |
| `scan_all(assets, guard, concurrency)` | Fetch each asset, run extractors. Also runs HTML extractors if the response looks like HTML. |

## Configuration
- `--input` (required): `jsreaper.py` JSON output.
- `--scope`: `scope.yaml` for scope + rate-limit on fetches.
- `--output` (default `spa-routes.json`).
- `--concurrency` (default 10): max concurrent fetches.
- `--dry-run`: list JS assets only, no fetch.

## Safety notes
- Read-only HTTP GETs only — no mutations, no POSTs, no auth tokens sent.
- `scope_guard` enforces scope on every fetched URL. Out-of-scope JS files are skipped silently.
- TLS verification is OFF on httpx/urllib clients to match the existing toolkit pattern.
- No headless browser — pure static analysis. Cannot execute JS; routes discovered are limited to those appearing as string literals in the bundle.

## See also
- ARCHITECTURE.md §2.2 (SPA route discovery) and §Termux-native (no-headless-browser constraint)
- Related tools: `jsreaper.py` (upstream JS asset source), `paramfuzz.py` (downstream route consumer), `js-extractor_3.py` (upstream `--crawl` it complements)
