"""Unit + integration tests for toolkit.verify.idor_crosssession."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from toolkit.verify.idor_crosssession import (
    filter_bola_candidates,
    parse_curl_command,
    gen_neighbor_ids,
    _similarity,
    _build_url_with_id,
    build_verified_findings,
    ReplayResult,
    _sweep_blast_radius,
)
from toolkit.infra import scope_guard
from toolkit.infra.auth_profiles import AuthProfiles


def test_filter_bola_candidates_keeps_bola_test_type(sample_apifuzz_findings):
    candidates = filter_bola_candidates(sample_apifuzz_findings)
    assert len(candidates) == 1
    assert candidates[0]["test_type"] == "BOLA"


def test_filter_bola_candidates_keeps_vuln_class_key():
    findings = [
        {"vuln_class_key": "BOLA_POSSIBLE", "host": "h", "url": "u"},
        {"vuln_class_key": "BOLA_CONFIRMED", "host": "h", "url": "u"},
        {"vuln_class_key": "SSRF_INTERNAL", "host": "h", "url": "u"},
    ]
    candidates = filter_bola_candidates(findings)
    assert len(candidates) == 2


def test_filter_bola_candidates_keeps_title_match():
    findings = [
        {"title": "BOLA/IDOR — Cross-User Access", "host": "h"},
        {"title": "Possible BOLA/IDOR — Predictable ID", "host": "h"},
        {"title": "Open Redirect", "host": "h"},
    ]
    candidates = filter_bola_candidates(findings)
    assert len(candidates) == 2


def test_parse_curl_command_simple_get():
    curl = 'curl -sk -D - \\\n  -H "Authorization: Bearer abc" \\\n  "https://api.example.com/v1/users/8841"'
    parsed = parse_curl_command(curl)
    assert parsed["method"] == "GET"
    assert parsed["url"] == "https://api.example.com/v1/users/8841"
    assert parsed["headers"]["Authorization"] == "Bearer abc"
    assert parsed["body"] is None


def test_parse_curl_command_post_with_json():
    curl = ('curl -sk -D - \\\n  -X POST \\\n  -H "Content-Type: application/json" \\\n  '
            "--data-raw '{\"name\":\"test\"}' \\\n  \"https://api.example.com/v1/users\"")
    parsed = parse_curl_command(curl)
    assert parsed["method"] == "POST"
    assert parsed["url"] == "https://api.example.com/v1/users"
    assert parsed["body"] == {"name": "test"}


def test_parse_curl_command_empty_returns_get():
    parsed = parse_curl_command("")
    assert parsed["method"] == "GET"
    assert parsed["url"] == ""


def test_parse_curl_command_put_with_body():
    """C5: PUT with a JSON body must parse method, url, and the body object."""
    curl = ('curl -sk -D - \\\n  -X PUT \\\n  -H "Authorization: Bearer xyz" \\\n  '
            "-H \"Content-Type: application/json\" \\\n  "
            "--data-raw '{\"role\":\"admin\"}' \\\n  "
            "\"https://api.example.com/v1/users/8841/role\"")
    parsed = parse_curl_command(curl)
    assert parsed["method"] == "PUT"
    assert parsed["url"] == "https://api.example.com/v1/users/8841/role"
    assert parsed["headers"]["Authorization"] == "Bearer xyz"
    assert parsed["body"] == {"role": "admin"}


def test_parse_curl_command_patch_with_plain_body():
    """C5: PATCH with a non-JSON body keeps the raw string."""
    curl = ('curl -sk -X PATCH --data-raw \'role=admin\' '
            "https://api.example.com/v1/users/8841/role")
    parsed = parse_curl_command(curl)
    assert parsed["method"] == "PATCH"
    assert parsed["body"] == "role=admin"


def test_gen_neighbor_ids_integer():
    out = gen_neighbor_ids("100")
    assert "98" in out
    assert "99" in out
    assert "101" in out
    assert "102" in out
    assert "105" in out


def test_gen_neighbor_ids_uuid_v1_has_neighbors():
    import uuid
    u1 = str(uuid.uuid1())
    out = gen_neighbor_ids(u1, count=3)
    assert len(out) >= 1
    # All neighbors should differ from the original
    assert all(n != u1 for n in out)


def test_gen_neighbor_ids_uuid_v4_returns_empty():
    import uuid
    u4 = str(uuid.uuid4())
    out = gen_neighbor_ids(u4, count=5)
    # v4 has no useful neighbors — return empty
    assert out == []


def test_similarity_identical_strings():
    assert _similarity("hello world", "hello world") == 1.0


def test_similarity_disjoint_strings():
    assert _similarity("alpha", "beta") < 0.5


def test_similarity_empty_strings():
    assert _similarity("", "") == 1.0
    assert _similarity("", "x") == 0.0


def test_build_url_with_id_replaces_numeric():
    url = "https://api.example.com/v1/users/8841/profile"
    new = _build_url_with_id(url, "9999")
    assert "9999" in new
    assert "8841" not in new


def test_build_url_with_id_replaces_uuid():
    url = "https://api.example.com/v1/users/abc12345-aaaa-bbbb-cccc-dddddddddddd"
    new = _build_url_with_id(url, "00000000-0000-0000-0000-000000000000")
    assert "00000000-0000-0000-0000-000000000000" in new


def test_build_verified_findings_confirmed_promotes():
    findings = [{
        "id": "abc", "source_tool": "apifuzz.py", "host": "h", "url": "u",
        "vuln_class_key": "BOLA_POSSIBLE", "severity": "HIGH", "title": "t",
        "evidence": "e", "curl_command": "c",
    }]
    results = [ReplayResult(
        finding_id="abc", user_a_status=200, user_a_body_len=500, user_a_body_hash="h1",
        user_b_status=200, user_b_body_len=500, user_b_body_hash="h1",
        body_similarity=0.9, verdict="confirmed", blast_radius=5,
        evidence="3-way check passed",
    )]
    out = build_verified_findings(findings, results)
    assert len(out) == 1
    assert out[0]["confidence"] == "confirmed"
    assert out[0]["verified_by"] == "idor_crosssession.py"
    assert out[0]["severity"] == "CRITICAL"
    assert out[0]["vuln_class_key"] == "BOLA_CONFIRMED"
    assert "blast radius ~5" in out[0]["title"]


def test_build_verified_findings_false_positive_rejects():
    findings = [{
        "id": "abc", "source_tool": "apifuzz.py", "host": "h", "url": "u",
        "vuln_class_key": "BOLA_POSSIBLE", "severity": "HIGH", "title": "t",
        "evidence": "e", "curl_command": "c",
    }]
    results = [ReplayResult(
        finding_id="abc", user_a_status=200, user_a_body_len=500, user_a_body_hash="h1",
        user_b_status=200, user_b_body_len=10, user_b_body_hash="h2",
        body_similarity=0.05, verdict="false_positive", blast_radius=0,
        evidence="user_b got 200 but empty body",
    )]
    out = build_verified_findings(findings, results)
    assert out[0]["disposition"] == "rejected"


def test_build_verified_findings_access_controlled_marks_probable():
    findings = [{
        "id": "abc", "source_tool": "apifuzz.py", "host": "h", "url": "u",
        "vuln_class_key": "BOLA_POSSIBLE", "severity": "HIGH", "title": "t",
        "evidence": "e", "curl_command": "c",
    }]
    results = [ReplayResult(
        finding_id="abc", user_a_status=200, user_a_body_len=500, user_a_body_hash="h1",
        user_b_status=403, user_b_body_len=20, user_b_body_hash="h2",
        body_similarity=0.0, verdict="access_controlled", blast_radius=0,
        evidence="user_b correctly denied",
    )]
    out = build_verified_findings(findings, results)
    assert out[0]["confidence"] == "probable"
    assert "may regress" in out[0]["detail"]


# ── Integration test: live replay against mock server ───────────────────────

def test_verify_finding_confirmed_idor(mock_http_server, temp_scope_yaml, temp_auth_profiles_yaml, tmp_path):
    """End-to-end: mock server returns user_a's data for user_b → confirmed IDOR."""
    base_url, server = mock_http_server
    # Set up a route that returns the same body regardless of Cookie
    user_a_body = '{"id": 1, "name": "Alice", "email": "alice@example.com", "secret": "AAA"}'
    server.routes = {
        ("GET", "/api/users/1"): {
            "status": 200,
            "headers": {"Content-Type": "application/json"},
            "body": user_a_body,
        },
    }
    profiles = AuthProfiles(temp_auth_profiles_yaml)
    guard = scope_guard.ScopeGuard(temp_scope_yaml)
    finding = {
        "id": "test-1",
        "source_tool": "apifuzz.py",
        "host": "127.0.0.1",
        "url": f"{base_url}/api/users/1",
        "method": "GET",
        "test_type": "BOLA",
        "severity": "HIGH",
        "title": "Possible BOLA/IDOR",
        "detail": "test",
        "evidence": "ev",
        "curl_command": f'curl -sk "{base_url}/api/users/1"',
    }
    result = asyncio.run(
        __import__("toolkit.verify.idor_crosssession", fromlist=["verify_finding"]).verify_finding(
            finding, profiles, guard, max_blast=2
        )
    )
    assert result is not None
    assert result.verdict == "confirmed"
    assert result.user_a_status == 200
    assert result.user_b_status == 200
    assert result.body_similarity > 0.7


def test_verify_finding_access_controlled(mock_http_server, temp_scope_yaml, temp_auth_profiles_yaml):
    """Mock server returns 403 for user_b → access_controlled."""
    base_url, server = mock_http_server
    server.routes = {
        ("GET", "/api/users/1"): {
            "status": 200,
            "body": '{"id":1,"name":"Alice"}',
            "headers": {"Content-Type": "application/json"},
        },
    }
    # Override to return 403 when the cookie is user-b
    def route_handler(method, path, headers, body):
        cookie = headers.get("Cookie", "")
        if "user-b" in cookie:
            return {"status": 403, "body": "Forbidden", "headers": {}}
        return {"status": 200, "body": '{"id":1,"name":"Alice"}',
                "headers": {"Content-Type": "application/json"}}
    server.routes = {("GET", "/api/users/1"): route_handler}

    profiles = AuthProfiles(temp_auth_profiles_yaml)
    guard = scope_guard.ScopeGuard(temp_scope_yaml)
    finding = {
        "id": "test-2",
        "source_tool": "apifuzz.py",
        "host": "127.0.0.1",
        "url": f"{base_url}/api/users/1",
        "method": "GET",
        "test_type": "BOLA",
        "severity": "HIGH",
        "title": "Possible BOLA/IDOR",
        "detail": "test",
        "evidence": "ev",
        "curl_command": f'curl -sk "{base_url}/api/users/1"',
    }
    result = asyncio.run(
        __import__("toolkit.verify.idor_crosssession", fromlist=["verify_finding"]).verify_finding(
            finding, profiles, guard, max_blast=0
        )
    )
    assert result is not None
    assert result.verdict == "access_controlled"
    assert result.user_b_status == 403


def test_sweep_blast_radius_concurrent(mock_http_server, temp_scope_yaml):
    """Neighbors that resolve under user_b are counted; sweep runs concurrently
    (all reachable neighbors resolve, not just the first)."""
    import asyncio
    import httpx

    from toolkit.infra import scope_guard

    base_url, server = mock_http_server
    long_body = '{"id": 1, "name": "Alice", "email": "alice@example.com", "x": "y"}'
    # Neighbors of id "1": -1, 0, 2, 3, 6 (gen_neighbor_ids count=5). Make all resolve.
    server.routes = {
        (method, f"{path}"): {
            "status": 200,
            "headers": {"Content-Type": "application/json"},
            "body": long_body,
        }
        for method, path in [
            ("GET", "/api/users/-1"),
            ("GET", "/api/users/0"),
            ("GET", "/api/users/2"),
            ("GET", "/api/users/3"),
            ("GET", "/api/users/6"),
        ]
    }
    guard = scope_guard.ScopeGuard(temp_scope_yaml)
    neighbors = ["-1", "0", "2", "3", "6"]
    headers = {"Cookie": "session=user-b"}

    async def _run() -> int:
        async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=False) as client:
            return await _sweep_blast_radius(
                client, guard, headers,
                f"{base_url}/api/users/1", "1", neighbors, concurrency=5,
            )

    assert asyncio.run(_run()) == 5


def test_verify_finding_strips_custom_auth_header(monkeypatch):
    from toolkit.infra.auth_profiles import Profile
    import toolkit.verify.idor_crosssession as idor

    profiles = AuthProfiles(None)
    profiles.profiles = {
        "user_a": Profile(name="user_a", cookie="a=1",
                          auth_header_names=["X-Auth-Token"]),
        "user_b": Profile(name="user_b", cookie="b=2",
                          auth_header_names=["X-Auth-Token"]),
    }
    profiles.auth_header_names = ["X-Auth-Token"]

    class FakeGuard:
        def check_url(self, *a, **k):
            return None
        def acquire_token(self, *a, **k):
            return True
        def release_token(self, *a, **k):
            return None

    seen = []
    async def fake(client, method, url, headers, body):
        seen.append({k.lower(): v for k, v in headers.items()})
        return 200, "same body data", 100
    monkeypatch.setattr(idor, "_replay_with_client", fake)

    finding = {
        "id": "f1", "source_tool": "apifuzz.py", "host": "h",
        "url": "https://h/v1/users/1", "vuln_class_key": "BOLA_POSSIBLE",
        "severity": "HIGH", "title": "BOLA",
        "curl_command": "curl -sk -H 'X-Auth-Token: aaaa' https://h/v1/users/1",
    }
    res = asyncio.run(idor.verify_finding(finding, profiles, FakeGuard()))
    assert res is not None
    # user_b replay is the second captured call
    user_b_headers = seen[1]
    assert "x-auth-token" not in user_b_headers
    # user_a replay (first call) also stripped it (session supplies auth)
    assert "x-auth-token" not in seen[0]
