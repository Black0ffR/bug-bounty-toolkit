#!/usr/bin/env python3
"""Tests for C8: apk_static --apk-file (androguard direct scan) with fallback."""

import pytest

from toolkit.testers import apk_static as m


def test_import_androguard_missing_returns_none(monkeypatch):
    # androguard is not installed in CI; the lazy import must return None
    assert m._import_androguard() is None


def test_scan_apk_file_without_androguard_raises():
    with pytest.raises(RuntimeError, match="androguard"):
        m.scan_apk_file(__import__("pathlib").Path("/tmp/does-not-exist.apk"))


def test_main_requires_one_input(tmp_path, caplog):
    code = m.main(["--output", str(tmp_path / "o.json")])
    assert code == 2
    assert any("exactly one" in r.message.lower() for r in caplog.records)


def test_main_apk_file_missing_androguard(tmp_path, caplog):
    apk = tmp_path / "app.apk"
    apk.write_text("not really an apk")
    code = m.main(["--apk-file", str(apk)])
    assert code == 2
    assert any("androguard" in r.message.lower() for r in caplog.records)


def test_main_apk_file_not_found(tmp_path):
    code = m.main(["--apk-file", str(tmp_path / "missing.apk")])
    assert code == 2


def test_main_apk_dir_still_works(tmp_path):
    # decode-dir path remains supported; an empty dir yields zero findings, rc 0
    d = tmp_path / "decoded"
    d.mkdir()
    out = tmp_path / "o.json"
    code = m.main(["--apk-dir", str(d), "--output", str(out), "--db", str(tmp_path / "s.db")])
    assert code == 0
    assert out.exists()
