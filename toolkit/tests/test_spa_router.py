"""Unit tests for toolkit.discover.spa_router — SvelteKit/Remix/Astro + sourcemap."""
from __future__ import annotations

from toolkit.discover.spa_router import (
    Route,
    detect_framework,
    extract_all_routes_from_js,
    extract_routes_astro,
    extract_routes_from_sourcemap,
    extract_routes_remix,
    extract_routes_svelte,
    find_sourcemap_url,
    _route_from_source_path,
)


# ── B9: SvelteKit ─────────────────────────────────────────────────────────────

def test_svelte_goto_extraction():
    js = "import { goto } from '$app/navigation';\n  goto('/admin/settings');"
    routes = extract_routes_svelte(js, "https://x/app.js")
    assert any(r.path == "/admin/settings" and r.framework == "svelte" for r in routes)


def test_svelte_anchor_extraction():
    js = '<a href="/financial-reports">reports</a>'
    routes = extract_routes_svelte(js, "https://x/app.js")
    assert any(r.path == "/financial-reports" and r.framework == "svelte" for r in routes)


def test_svelte_detect():
    assert detect_framework("https://x/app.js", "import { goto } from '@sveltejs/kit'") == "svelte"


# ── B9: Remix ────────────────────────────────────────────────────────────────

def test_remix_redirect_extraction():
    js = "import { redirect } from '@remix-run/node';\n  return redirect('/login');"
    routes = extract_routes_remix(js, "https://x/app.js")
    assert any(r.path == "/login" and r.framework == "remix" for r in routes)


def test_remix_link_to_extraction():
    js = '<Link to="/internal/users">users</Link>'
    routes = extract_routes_remix(js, "https://x/app.js")
    assert any(r.path == "/internal/users" and r.framework == "remix" for r in routes)


def test_remix_detect():
    assert detect_framework("https://x/app.js",
                            "import { useLoaderData } from '@remix-run/react'") == "remix"


# ── B9: Astro ────────────────────────────────────────────────────────────────

def test_astro_anchor_extraction():
    js = '<a href="/blog/post-1">post</a>'
    routes = extract_routes_astro(js, "https://x/app.js")
    assert any(r.path == "/blog/post-1" and r.framework == "astro" for r in routes)


def test_astro_redirect_extraction():
    js = "return Astro.redirect('/auth');"
    routes = extract_routes_astro(js, "https://x/app.js")
    assert any(r.path == "/auth" and r.framework == "astro" for r in routes)


def test_astro_detect():
    assert detect_framework("https://x/app.js",
                            "import Layout from '../layouts/Base.astro';\nconst x = Astro.url;") == "astro"


# ── B9: framework dispatch coverage ──────────────────────────────────────────

def test_extract_all_covers_new_frameworks():
    js = "goto('/svelte-x'); <Link to='/remix-x'>r</Link>; <a href='/astro-x'>a</a>"
    routes = extract_all_routes_from_js(js, "https://x/app.js")
    frameworks = {r.framework for r in routes}
    assert {"svelte", "remix", "astro"}.issubset(frameworks)


# ── B10: sourcemap-aware extraction ──────────────────────────────────────────

def test_find_sourcemap_relative():
    js = "console.log(1);\n//# sourceMappingURL=app.js.map"
    assert find_sourcemap_url(js, "https://x/static/app.js") == "https://x/static/app.js.map"


def test_find_sourcemap_inline_none():
    js = "//# sourceMappingURL=data:application/json;base64,abc"
    assert find_sourcemap_url(js, "https://x/app.js") is None


def test_route_from_source_path_svelte():
    assert _route_from_source_path("src/routes/admin/settings/+page.svelte") == "/admin/settings"


def test_route_from_source_path_index():
    assert _route_from_source_path("src/routes/blog/index/+page.svelte") == "/blog"


def test_sourcemap_file_based_routes():
    map_json = json_dumps_sources([
        "src/routes/admin/settings/+page.svelte",
        "src/routes/api/users/+server.ts",
    ])
    routes = extract_routes_from_sourcemap(map_json, "https://x/app.js")
    paths = {r.path for r in routes}
    assert "/admin/settings" in paths
    assert "/api/users" in paths


def test_sourcemap_sourcescontent_mined():
    map_json = json_dumps_sources(
        [],
        contents=["goto('/internal/billing');"],
    )
    routes = extract_routes_from_sourcemap(map_json, "https://x/app.js")
    assert any(r.path == "/internal/billing" for r in routes)


def json_dumps_sources(sources, contents=None):
    import json
    return json.dumps({
        "version": 3,
        "sources": sources,
        "sourcesContent": contents if contents is not None else ["" for _ in sources],
    })
