"""Tests for C22: toolkit/verify/replay_verifier.py scenario engine."""

import asyncio

import pytest

from toolkit.verify.replay_verifier import (
    Scenario, Step, _render, run_scenario,
)


class _FakeResp:
    def __init__(self, status_code: int, text: str):
        self.status_code = status_code
        self.text = text


class _FakeClient:
    """Records requests; returns scripted responses keyed by path + method."""
    def __init__(self, script):
        self.script = script
        self.calls = []

    async def request(self, method, url, headers=None, content=None):
        self.calls.append((method, url, headers, content))
        key = (method.upper(), url)
        return self.script[key]


def test_render_substitution():
    assert _render("x/{{ tok }}/y", {"tok": "abc"}) == "x/abc/y"
    assert _render("no vars", {}) == "no vars"
    assert _render("{{ missing }}", {}) == "{{ missing }}"


def test_run_scenario_passes_with_capture_and_assert():
    script = {
        ("POST", "https://api.x.com/login"):
            _FakeResp(200, '{"token":"SECRET123"}'),
        ("GET", "https://api.x.com/users/SECRET123"):
            _FakeResp(200, '{"email":"a@x.com"}'),
    }
    scn = Scenario(name="idor", base_url="https://api.x.com", steps=[
        Step(name="login", method="POST", path="/login",
             body='{"u":"a"}', extract={"tok": r'"token":"([^"]+)"'}),
        Step(name="grab", method="GET", path="/users/{{ tok }}",
             expect_status=200, expect_contains=["email"]),
    ])
    res = asyncio.run(run_scenario(scn, _FakeClient(script)))
    assert res.passed is True
    assert res.variables["tok"] == "SECRET123"
    assert len(res.steps) == 2


def test_run_scenario_fails_on_status_mismatch():
    script = {
        ("GET", "https://api.x.com/admin"):
            _FakeResp(403, "forbidden"),
    }
    scn = Scenario(name="s", base_url="https://api.x.com", steps=[
        Step(name="admin", method="GET", path="/admin", expect_status=200),
    ])
    res = asyncio.run(run_scenario(scn, _FakeClient(script)))
    assert res.passed is False
    assert res.steps[0].status == 403


def test_run_scenario_fails_on_forbidden_substring():
    script = {
        ("GET", "https://api.x.com/x"):
            _FakeResp(200, "leaked password here"),
    }
    scn = Scenario(name="s", base_url="https://api.x.com", steps=[
        Step(name="x", method="GET", path="/x", expect_not_contains=["password"]),
    ])
    res = asyncio.run(run_scenario(scn, _FakeClient(script)))
    assert res.passed is False
    assert "forbidden" in res.steps[0].detail


def test_run_scenario_fails_on_missing_substring():
    script = {
        ("GET", "https://api.x.com/x"):
            _FakeResp(200, "hello"),
    }
    scn = Scenario(name="s", base_url="https://api.x.com", steps=[
        Step(name="x", method="GET", path="/x", expect_contains=["world"]),
    ])
    res = asyncio.run(run_scenario(scn, _FakeClient(script)))
    assert res.passed is False
