"""Tests for C21: toolkit/infra/config.py per-target YAML loader."""

import argparse

from toolkit.infra import config


def _base_ns() -> argparse.Namespace:
    ns = argparse.Namespace()
    ns.timeout = None
    ns.concurrency = None
    ns.verbose = False
    ns.user_agent = None
    ns.extra = None
    return ns


def test_load_config_reads_yaml(tmp_path):
    cfg = tmp_path / "t.yaml"
    cfg.write_text("timeout: 15.0\nconcurrency: 8\nuser_agent: moz\n")
    data = config.load_config(cfg)
    assert data["timeout"] == 15.0
    assert data["concurrency"] == 8
    assert data["user_agent"] == "moz"


def test_load_config_missing_raises():
    try:
        config.load_config("/no/such/file.yaml")
        assert False
    except FileNotFoundError:
        pass


def test_overlay_sets_unset_fields(tmp_path):
    cfg = tmp_path / "t.yaml"
    cfg.write_text("timeout: 15.0\nuser_agent: moz\n")
    ns = _base_ns()
    out = config.overlay_config(ns, cfg)
    assert out.timeout == 15.0
    assert out.user_agent == "moz"


def test_overlay_does_not_override_cli(tmp_path):
    cfg = tmp_path / "t.yaml"
    cfg.write_text("timeout: 15.0\nuser_agent: moz\n")
    ns = _base_ns()
    ns.user_agent = "cli-ua"   # explicitly provided
    out = config.overlay_config(ns, cfg)
    assert out.user_agent == "cli-ua"   # CLI wins
    assert out.timeout == 15.0          # config filled the unset field


def test_overlay_adds_unknown_keys(tmp_path):
    cfg = tmp_path / "t.yaml"
    cfg.write_text("mystery: 42\n")
    ns = _base_ns()
    out = config.overlay_config(ns, cfg)
    assert out.mystery == 42
