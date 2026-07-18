#!/usr/bin/env python3
"""
replay_verifier.py — generalized replay / scenario verification engine (C22)
============================================================================

Lets you encode a multi-step exploit or verification flow as data (a
``Scenario``) and replay it against a target, with:

  * ``{{ var }}`` substitution between steps,
  * regex capture of values from responses into variables,
  * status / substring assertions on each step.

This replaces hand-written one-off replay scripts and is the engine the
orchestrator's ``verify`` stage uses for scenario-based confirmation. It is
pure where possible (``_render``, capture logic) so steps are unit-testable
without network; only ``run_scenario`` performs I/O via an httpx-like client.

Example scenario (YAML-friendly shape):
    Scenario(name="idorusr", base_url="https://api.x.com", steps=[
        Step(name="login", method="POST", path="/login",
             body='{"u":"a","p":"b"}',
             extract={"tok": r'"token":"([^"]+)"'}),
        Step(name="grab", method="GET", path="/users/{{ tok }}",
             expect_status=200, expect_contains=["email"]),
    ])

Author : Bug Bounty Toolkit / Layer 0
License : MIT (for authorized use only)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class Step:
    name: str
    method: str = "GET"
    path: str = "/"
    headers: dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    extract: dict[str, str] = field(default_factory=dict)  # var -> regex
    expect_status: Optional[int] = None
    expect_contains: list[str] = field(default_factory=list)
    expect_not_contains: list[str] = field(default_factory=list)


@dataclass
class Scenario:
    name: str
    base_url: str
    steps: list[Step] = field(default_factory=list)
    variables: dict[str, str] = field(default_factory=dict)


@dataclass
class StepResult:
    name: str
    status: Optional[int]
    ok: bool
    detail: str


@dataclass
class ScenarioResult:
    name: str
    passed: bool
    steps: list[StepResult]
    variables: dict[str, str]


_PLACEHOLDER = re.compile(r"{{\s*([\w]+)\s*}}")


def _render(template: str, variables: dict[str, str]) -> str:
    """Substitute ``{{ var }}`` tokens from ``variables``."""
    def _sub(m: re.Match) -> str:
        key = m.group(1)
        return variables.get(key, m.group(0))
    return _PLACEHOLDER.sub(_sub, template)


def _capture(response_text: str, extract: dict[str, str],
             variables: dict[str, str]) -> dict[str, str]:
    """Run each extract regex and store the first capture group."""
    for var, pattern in extract.items():
        m = re.search(pattern, response_text)
        if m:
            variables[var] = m.group(1)
    return variables


def _check(step: Step, status: Optional[int], text: str) -> tuple[bool, str]:
    if step.expect_status is not None and status != step.expect_status:
        return False, f"status {status} != expected {step.expect_status}"
    for need in step.expect_contains:
        if need not in text:
            return False, f"missing expected substring: {need!r}"
    return True, ""


async def run_scenario(scn: Scenario, client: Any) -> ScenarioResult:
    """Replay a scenario using an httpx-like async ``client``.

    ``client.request(method, url, headers=..., content=...)`` must be awaitable
    and return an object with ``.status_code`` and ``.text``.
    """
    variables = dict(scn.variables)
    step_results: list[StepResult] = []
    for step in scn.steps:
        url = _render(scn.base_url.rstrip("/") + "/" + step.path.lstrip("/"), variables)
        headers = {k: _render(v, variables) for k, v in step.headers.items()}
        body = _render(step.body, variables) if step.body else None
        resp = await client.request(step.method, url, headers=headers, content=body)
        status = getattr(resp, "status_code", None)
        text = getattr(resp, "text", "") or ""
        variables = _capture(text, step.extract, variables)
        ok, detail = _check(step, status, text)
        # expect_not_contains violations should fail the step
        for bad in step.expect_not_contains:
            if bad in text:
                ok, detail = False, f"found forbidden substring: {bad!r}"
        step_results.append(StepResult(name=step.name, status=status, ok=ok,
                                        detail=detail))
        if not ok:
            return ScenarioResult(name=scn.name, passed=False,
                                  steps=step_results, variables=variables)
    return ScenarioResult(name=scn.name, passed=True,
                          steps=step_results, variables=variables)
