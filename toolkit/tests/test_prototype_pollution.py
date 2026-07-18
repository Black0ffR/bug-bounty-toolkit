#!/usr/bin/env python3
"""Tests for toolkit.testers.prototype_pollution (TDD for B24)."""

from toolkit.testers import prototype_pollution as m


def test_detects_lodash_merge_sink():
    src = 'const x = _.merge(target, source);\n'
    f = m.scan_text(src)
    assert any(p.kind == "sink" and "merge" in p.detail for p in f)


def test_detects_untrusted_sink_without_guard():
    src = 'merge(config, JSON.parse(input));\n'
    f = m.scan_text(src)
    assert any(p.kind == "untrusted_sink" for p in f)


def test_detects_direct_proto_assignment():
    src = 'obj.__proto__.polluted = true;\n'
    f = m.scan_text(src)
    assert any(p.kind == "direct_assignment" for p in f)
    src2 = 'obj["__proto__"]["x"] = 1;\n'
    f2 = m.scan_text(src2)
    assert any(p.kind == "direct_assignment" for p in f2)


def test_detects_constructor_prototype():
    src = 'a.constructor.prototype.admin = true;\n'
    f = m.scan_text(src)
    assert any(p.kind == "direct_assignment" for p in f)


def test_assign_is_sink():
    src = 'Object.assign({}, userInput);\n'
    f = m.scan_text(src)
    assert any(p.kind == "sink" for p in f)


def test_guarded_sink_not_flagged_untrusted():
    src = 'if (key === "__proto__") return; merge(a, b);\n'
    f = m.scan_text(src)
    # guarded merge on its own line should still be a (low) sink, but NOT untrusted
    assert not any(p.kind == "untrusted_sink" for p in f)


def test_scan_file_and_path(tmp_path):
    f = tmp_path / "app.js"
    f.write_text('const o = _.extend(a, req.body);\n')
    res = m.scan_path(tmp_path)
    assert any(pf.kind in ("sink", "untrusted_sink") for _, pf in res)


def test_to_normalized_emits_findings(tmp_path):
    f = tmp_path / "x.js"
    f.write_text('obj.__proto__.x = 1;\n')
    res = m.scan_path(tmp_path)
    norm = m.to_normalized(res)
    assert len(norm) == 1
    assert norm[0]["severity"] == "HIGH"
    assert norm[0]["vuln_class_key"] == "PROTOTYPE_POLLUTION"


def test_scan_jsreaper_list():
    dump = [{"content": '_.merge(a, req.query);'}, {"content": 'safe();'}]
    f = m.scan_jsreaper(dump)
    assert any(p.kind == "untrusted_sink" for p in f)


def test_scan_text_single_merge_once():
    src = '_.merge(a, b);\n'
    f = m.scan_text(src)
    assert len(f) == 1 and f[0].kind == "sink"
