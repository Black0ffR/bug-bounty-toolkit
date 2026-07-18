#!/usr/bin/env python3
"""Tests for C7: spa_router Route.params + param parsers."""

import pytest

from toolkit.discover import spa_router as m
from toolkit.discover.spa_router import Route


def test_extract_params_colon():
    assert m.extract_params("/users/:id") == ["id"]
    assert m.extract_params("/a/:b/:c") == ["b", "c"]


def test_extract_params_brace():
    assert m.extract_params("/users/{id}") == ["id"]
    assert m.extract_params("/users/{id?}") == ["id"]


def test_extract_params_bracket():
    assert m.extract_params("/p/[slug]") == ["slug"]
    assert m.extract_params("/p/[...slug]") == ["slug"]


def test_extract_params_angle():
    assert m.extract_params("/x/<id>") == ["id"]
    assert m.extract_params("/x/<$id>") == ["id"]


def test_extract_params_dedup():
    assert m.extract_params("/:id/x/:id") == ["id"]


def test_route_params_autoderived():
    r = Route(path="/users/:id", framework="vue-router", source="s", pattern="p")
    assert r.params == ["id"]


def test_infer_param_type():
    assert m.infer_param_type("userEmail") == "email"
    assert m.infer_param_type("uuid") == "uuid"
    assert m.infer_param_type("userId") == "id"
    assert m.infer_param_type("page") == "int"
    assert m.infer_param_type("name") == "string"


def test_param_samples_uses_registry():
    assert m.param_samples("email") == ["admin@example.com", "test@example.com"]
    assert "1" in m.param_samples("userId", "id")
    # explicit type overrides inference
    assert m.param_samples("weirdName", "uuid")[0].startswith("00000000")


def test_register_param_parser_override():
    m.register_param_parser("custom_t", lambda name: ["X"])
    assert m.param_samples("x", "custom_t") == ["X"]
