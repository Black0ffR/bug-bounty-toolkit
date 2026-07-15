"""Pytest configuration + shared fixtures for the toolkit test suite.

Run tests with:
    cd /path/to/SubTakeover
    python -m pytest toolkit/tests/ -v
"""
from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

# Ensure the project root is on sys.path so `import toolkit.*` works
# regardless of where pytest is invoked from.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


# ── Mock HTTP server fixture ────────────────────────────────────────────────

class _MockHandler(BaseHTTPRequestHandler):
    """Configurable mock HTTP handler. Reads request routes from the server's
    `routes` dict, where keys are (method, path) tuples and values are dicts
    with status / headers / body. A special ('*', '*') entry is the default."""
    def log_message(self, fmt, *args):
        pass  # silence

    def _handle(self):
        # Read body if any
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length > 0 else b""
        # Find a matching route — try exact, then wildcard
        key = (self.command, self.path.split("?")[0])
        routes: dict = self.server.routes  # type: ignore[attr-defined]
        response = routes.get(key) or routes.get(("*", "*")) or {
            "status": 404, "headers": {}, "body": b"not found"
        }
        # If body is a callable, call it with the request info
        if callable(response):
            response = response(method=self.command, path=self.path,
                                headers=dict(self.headers), body=body)
        status = int(response.get("status", 200))
        resp_headers = response.get("headers", {})
        # Default Content-Type
        if "Content-Type" not in resp_headers:
            resp_headers["Content-Type"] = "text/plain"
        resp_body = response.get("body", b"")
        if isinstance(resp_body, str):
            resp_body = resp_body.encode("utf-8")
        # Optional: response.delay (for timing tests)
        delay = float(response.get("delay", 0))
        if delay > 0:
            time.sleep(delay)
        self.send_response(status)
        for k, v in resp_headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)
        # Record the request
        recorded = getattr(self.server, "recorded_requests", None)
        if recorded is not None:
            recorded.append({
                "method": self.command,
                "path": self.path,
                "headers": dict(self.headers),
                "body": body.decode("utf-8", errors="replace")[:500],
            })

    def do_GET(self): self._handle()
    def do_POST(self): self._handle()
    def do_PUT(self): self._handle()
    def do_PATCH(self): self._handle()
    def do_DELETE(self): self._handle()
    def do_HEAD(self): self._handle()
    def do_OPTIONS(self): self._handle()


@pytest.fixture
def mock_http_server():
    """Yields a (base_url, server) tuple. The server.routes dict can be mutated
    by tests to set up custom responses. Cleaned up after the test."""
    # Find a free port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = ThreadingHTTPServer(("127.0.0.1", port), _MockHandler)
    server.routes = {("*", "*"): {"status": 200, "body": b"OK"}}
    server.recorded_requests = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{port}"
    yield base_url, server
    server.shutdown()
    server.server_close()


# ── Temp DB fixture ─────────────────────────────────────────────────────────

@pytest.fixture
def temp_db(tmp_path):
    """A fresh pipeline_state.db in a temp directory."""
    from toolkit.infra.pipeline_state import PipelineState
    db_path = tmp_path / "test_pipeline_state.db"
    state = PipelineState(str(db_path))
    yield state
    state.close()


# ── Temp scope.yaml fixture ─────────────────────────────────────────────────

@pytest.fixture
def temp_scope_yaml(tmp_path):
    """A scope.yaml that allows 127.0.0.1 + localhost (for mock server tests)."""
    p = tmp_path / "scope.yaml"
    p.write_text(
        "program: test\n"
        "in_scope:\n"
        "  - '127.0.0.1'\n"
        "  - 'localhost'\n"
        "  - '*.localhost'\n"
        "out_of_scope: []\n"
        "rate_limit:\n"
        "  max_rps: 100\n"
        "  max_concurrent: 20\n"
        "automation_allowed: true\n",
        encoding="utf-8",
    )
    return p


@pytest.fixture
def temp_auth_profiles_yaml(tmp_path):
    """An auth_profiles.yaml with two user profiles for IDOR tests."""
    p = tmp_path / "auth_profiles.yaml"
    p.write_text(
        "profiles:\n"
        "  anon: {}\n"
        "  user_a:\n"
        "    cookie: 'session=user-a'\n"
        "    user_id: 1\n"
        "  user_b:\n"
        "    cookie: 'session=user-b'\n"
        "    user_id: 2\n",
        encoding="utf-8",
    )
    return p


# ── Sample findings fixtures ────────────────────────────────────────────────

@pytest.fixture
def sample_apifuzz_findings():
    """A sample apifuzz.py-style findings list with one BOLA candidate."""
    return [
        {
            "host": "api.example.com",
            "url": "https://api.example.com/v1/users/8841",
            "method": "GET",
            "test_type": "BOLA",
            "severity": "HIGH",
            "title": "Possible BOLA/IDOR — Predictable ID Access",
            "detail": "Accessing resource with ID=8842 returned 200.",
            "evidence": "Original: GET /v1/users/8841 → 200\nModified: GET /v1/users/8842 → 200",
            "curl_command": 'curl -sk -D - \\\n  -H "Authorization: Bearer abc" \\\n  "https://api.example.com/v1/users/8841"',
            "recommendation": "Verify object ownership.",
            "cvss_estimate": "7.5",
            "response_snippet": '{"id": 8841, "name": "Alice"}',
            "replay_request": {
                "method": "GET",
                "url": "https://api.example.com/v1/users/8841",
                "headers": {"Authorization": "Bearer abc"},
                "body": None,
            },
        },
        {
            "host": "api.example.com",
            "url": "https://api.example.com/v1/health",
            "method": "GET",
            "test_type": "AUTH_BYPASS",
            "severity": "MEDIUM",
            "title": "Auth bypass on /health",
            "detail": "Endpoint accessible without auth.",
            "evidence": "GET /v1/health → 200 without Authorization header",
            "curl_command": "curl -sk https://api.example.com/v1/health",
            "recommendation": "Require auth on all endpoints.",
            "cvss_estimate": "5.3",
        },
    ]


@pytest.fixture
def sample_nuclei_harvest_json():
    """A sample final.json (nuclei-harvest.py output) for triage_memory tests."""
    return {
        "domain": "example.com",
        "scan_time": "2026-07-15T09:12:00+00:00",
        "source_tools": ["apifuzz", "ssrfprobe", "subtakeover"],
        "findings": [
            {
                "id": "abc123def456",
                "source_tool": "apifuzz.py",
                "host": "api.example.com",
                "url": "https://api.example.com/v1/users/8841",
                "vuln_class_key": "BOLA_POSSIBLE",
                "severity": "HIGH",
                "title": "Possible BOLA/IDOR — Predictable ID Access",
                "detail": "Accessing with adjacent ID returned 200.",
                "evidence": "test",
                "curl": "curl -sk https://api.example.com/v1/users/8842",
                "confidence": "candidate",
                "disposition": "new",
            },
            {
                "id": "def789abc012",
                "source_tool": "ssrfprobe.py",
                "host": "api.example.com",
                "url": "https://api.example.com/v1/fetch",
                "vuln_class_key": "SSRF_INTERNAL",
                "severity": "CRITICAL",
                "title": "SSRF to internal metadata service",
                "detail": "Server fetched 169.254.169.254",
                "evidence": "test ssrf",
                "curl": "curl -sk 'https://api.example.com/v1/fetch?url=169.254.169.254'",
                "confidence": "probable",
                "disposition": "new",
            },
        ],
    }
