#!/usr/bin/env python3
"""Tests for C10 (TCP DNS), C11 (time-range/limit query), C12 (webhook forward)."""

import datetime
import socket
import threading
import time

import pytest

from toolkit.infra_ext import oob_catcher as m
from toolkit.infra_ext.oob_catcher import Callback, CallbackStore


def _now_iso(offset_sec=0):
    return (datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(seconds=offset_sec)).isoformat(timespec="seconds")


def _build_dns_query(name, qtype=1):
    header = bytearray(12)
    header[4:6] = (1).to_bytes(2, "big")  # qdcount
    qname = b""
    for label in name.split("."):
        qname += bytes([len(label)]) + label.encode()
    qname += b"\x00"
    return bytes(header) + qname + qtype.to_bytes(2, "big") + (1).to_bytes(2, "big")


# ── C10: TCP DNS server ───────────────────────────────────────────────────────

def test_build_dns_response_is_valid():
    q = _build_dns_query("abc.oob.test", 1)
    resp = m.build_dns_response(q, "abc.oob.test", "A", "127.0.0.1")
    assert resp[2] & 0x80  # QR=1
    assert int.from_bytes(resp[6:8], "big") == 1  # ANCOUNT=1


def test_tcp_dns_server_records_callback(tmp_path):
    store = CallbackStore(tmp_path / "tcp_state.json", retention_hours=24)
    server = m.make_dns_tcp_server(store, "oob.test", "127.0.0.1", host="127.0.0.1", port=0)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        q = _build_dns_query("abc.oob.test", 1)
        for _ in range(20):
            try:
                s = socket.create_connection(("127.0.0.1", port), timeout=2)
                break
            except OSError:
                time.sleep(0.1)
        else:
            pytest.fail("could not connect to TCP DNS server")
        s.sendall(len(q).to_bytes(2, "big") + q)
        length = int.from_bytes(s.recv(2), "big")
        resp = b""
        while len(resp) < length:
            resp += s.recv(length - len(resp))
        s.close()
        assert resp[2] & 0x80
        hits = store.get("abc")
        assert len(hits) == 1
        assert hits[0].protocol == "dns"
    finally:
        server.shutdown()
        server.server_close()


# ── C11: time-range + limit query ──────────────────────────────────────────────

def test_query_filters_by_id_and_time_and_limit(tmp_path):
    store = CallbackStore(tmp_path / "s.json", retention_hours=24)
    ts_old = _now_iso(offset_sec=-3600)
    ts_new = _now_iso(offset_sec=-10)
    store.add(Callback(callback_id="x", timestamp=ts_old, protocol="dns", source_ip="1.2.3.4", details={}))
    store.add(Callback(callback_id="x", timestamp=ts_new, protocol="dns", source_ip="1.2.3.4", details={}))
    store.add(Callback(callback_id="y", timestamp=ts_new, protocol="http", source_ip="1.2.3.4", details={}))

    assert len(store.query(callback_id="x")) == 2
    assert len(store.query(callback_id="y")) == 1
    # limit
    assert len(store.query(limit=1)) == 1
    # since filters out the old one
    since = _now_iso(offset_sec=-600)
    assert len(store.query(callback_id="x", since=since)) == 1
    # until keeps only the old one
    until = _now_iso(offset_sec=-600)
    assert len(store.query(callback_id="x", until=until)) == 1


# ── C12: webhook forwarding ─────────────────────────────────────────────────────

def test_webhook_forward_called(tmp_path):
    captured = []
    store = CallbackStore(tmp_path / "s.json", retention_hours=24,
                          webhook_url="http://example.invalid/hook", _sender=captured.append)
    store.add(Callback(callback_id="z", timestamp=_now_iso(), protocol="http",
                       source_ip="9.9.9.9", details={"x": 1}))
    deadline = time.time() + 2
    while not captured and time.time() < deadline:
        time.sleep(0.05)
    assert len(captured) == 1
    assert captured[0]["callback_id"] == "z"
    assert captured[0]["protocol"] == "http"


def test_http_api_query_params(tmp_path):
    store = CallbackStore(tmp_path / "s.json", retention_hours=24)
    store.add(Callback(callback_id="abc", timestamp=_now_iso(), protocol="dns",
                       source_ip="1.1.1.1", details={}))
    store.add(Callback(callback_id="abc", timestamp=_now_iso(), protocol="dns",
                       source_ip="1.1.1.1", details={}))
    server = m.make_http_server(store, "oob.test", host="127.0.0.1", port=0)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        import urllib.request, json
        url = f"http://127.0.0.1:{port}/callbacks/abc?limit=1"
        with urllib.request.urlopen(url, timeout=2) as r:
            data = json.loads(r.read())
        assert data["callback_id"] == "abc"
        assert len(data["hits"]) == 1  # limited to 1
    finally:
        server.shutdown()
        server.server_close()
