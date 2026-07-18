#!/usr/bin/env python3
"""
oob_catcher.py — self-hosted interactsh-compatible OOB callback server
=======================================================================

Tier 4 infra_ext tool.

Purpose
-------
ssrfprobe.py, nuclei-go's OOB module, and Log4Shell-style templates all need
an out-of-band callback endpoint to confirm blind vulnerabilities. Public
interact.sh works but has reliability issues (rate limits, log retention,
shared instance). This tool is a self-hosted alternative — runs on a cheap
VPS with a wildcard DNS record, captures DNS + HTTP callbacks, and exposes
a simple JSON API for the pipeline to poll.

Architecture
------------
- DNS server:    listens on UDP/TCP 53, replies with 127.0.0.1 for any
                 subdomain of the configured base domain. Logs every query
                 with timestamp, query name, query type, source IP.
- HTTP server:   listens on TCP 80 (and optionally 443), responds with 200
                 OK to any path. Logs every request with timestamp, method,
                 host, path, headers, body.
- State API:     JSON file (pollable) listing all callbacks seen in the
                 last N hours (default 24). Tools filter by callback ID
                 (the subdomain they generated) to confirm a specific
                 blind vuln fired.

Chain position
--------------
Infra_ext — independent. ssrfprobe.py / nuclei-go use the --oob-domain flag
            to point at this server's base domain.

Usage
-----
    # Start the server (run on a VPS with a wildcard DNS A record pointing at it)
    python -m toolkit.infra_ext.oob_catcher \\
        --base-domain oob.yourdomain.com \\
        --state-file /var/lib/oob_catcher/state.json \\
        --dns-port 53 --http-port 80

    # Poll for callbacks (from any tool)
    curl http://oob.yourdomain.com:8080/callbacks/<callback_id>
    → {"callback_id": "abc123", "hits": [...]}

Author : Bug Bounty Toolkit / Tier 4 (infra_ext)
License : MIT (for authorized use only)
"""

from __future__ import annotations

import argparse
import datetime
import json
import logging
import re
import socket
import socketserver
import sys
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


log = logging.getLogger("oob_catcher")


@dataclass
class Callback:
    callback_id: str         # subdomain prefix the tool used
    timestamp: str           # ISO 8601 UTC
    protocol: str            # dns | http
    source_ip: str
    details: dict[str, Any] = field(default_factory=dict)


class CallbackStore:
    """Thread-safe in-memory store with periodic flush to JSON state file."""
    def __init__(self, state_file: Path, retention_hours: int = 24,
                 webhook_url: str | None = None, _sender=None) -> None:
        self.state_file = state_file
        self.retention_seconds = retention_hours * 3600
        self.webhook_url = webhook_url
        self._sender = _sender  # injectable for tests (callable taking a dict)
        self._lock = threading.Lock()
        self._callbacks: list[Callback] = []
        self._load()

    def _load(self) -> None:
        if not self.state_file.exists():
            return
        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
            for c in data.get("callbacks", []):
                self._callbacks.append(Callback(**c))
            log.info("loaded %d callbacks from %s", len(self._callbacks), self.state_file)
        except Exception as exc:
            log.warning("could not load state file: %s", exc)

    def add(self, cb: Callback) -> None:
        with self._lock:
            self._callbacks.append(cb)
            # Trim old entries
            now = time.time()
            self._callbacks = [
                c for c in self._callbacks
                if self._parse_iso(c.timestamp) > (now - self.retention_seconds)
            ]
            self._flush_locked()
        # Webhook forward happens outside the lock (network I/O)
        if self.webhook_url:
            sender = self._sender or self._default_sender
            threading.Thread(target=sender, args=(asdict(cb),), daemon=True).start()

    def _default_sender(self, payload: dict) -> None:
        if not self.webhook_url:
            return
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.webhook_url, data=body, headers={"Content-Type": "application/json"}
        )
        try:
            urllib.request.urlopen(req, timeout=5)
        except Exception as exc:  # pragma: no cover - network
            log.warning("webhook forward failed: %s", exc)

    def get(self, callback_id: str) -> list[Callback]:
        with self._lock:
            return [c for c in self._callbacks if c.callback_id == callback_id]

    def all_(self) -> list[Callback]:
        with self._lock:
            return list(self._callbacks)

    def query(self, callback_id: str | None = None, since: str | None = None,
              until: str | None = None, limit: int | None = None) -> list[Callback]:
        """C11: filter callbacks by id/time-range, optionally capped at `limit`."""
        with self._lock:
            results = list(self._callbacks)
        if callback_id is not None:
            results = [c for c in results if c.callback_id == callback_id]
        if since is not None:
            t = self._parse_iso(since)
            results = [c for c in results if self._parse_iso(c.timestamp) >= t]
        if until is not None:
            t = self._parse_iso(until)
            results = [c for c in results if self._parse_iso(c.timestamp) <= t]
        if limit is not None and limit > 0:
            results = results[-limit:]
        return results

    def _flush_locked(self) -> None:
        if not self.state_file:
            return
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.state_file.with_suffix(self.state_file.suffix + ".tmp")
            tmp.write_text(
                json.dumps({
                    "callbacks": [asdict(c) for c in self._callbacks],
                    "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                }, indent=2, default=str),
                encoding="utf-8",
            )
            tmp.replace(self.state_file)
        except OSError as exc:
            log.warning("could not flush state: %s", exc)

    @staticmethod
    def _parse_iso(s: str) -> float:
        try:
            return datetime.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
        except Exception:
            return 0.0


# ── DNS server ───────────────────────────────────────────────────────────────

class DNSHandler(socketserver.BaseRequestHandler):
    """Minimal DNS server. Replies to A queries with 127.0.0.1 (configurable).
    Logs every query to the callback store. Not a full resolver — only handles
    A, AAAA, and TXT records enough to confirm a callback fired."""

    # The store and base_domain are set by the factory in serve_forever
    store: CallbackStore
    base_domain: str
    reply_ip: str = "127.0.0.1"

    def handle(self) -> None:
        data, sock = self.request
        resp = process_dns_packet(
            self.store, self.base_domain, self.reply_ip, data, self.client_address[0]
        )
        if resp is not None:
            try:
                sock.sendto(resp, self.client_address)
            except OSError:
                pass

    @staticmethod
    def _parse_query(data: bytes) -> tuple[str, str]:
        """Parse the question section. Returns (qname, qtype_str)."""
        if len(data) < 12:
            return ("", "")
        # Header: id(2) flags(2) qdcount(2) ancount(2) nscount(2) arcount(2)
        qdcount = int.from_bytes(data[4:6], "big")
        if qdcount == 0:
            return ("", "")
        # Skip header (12 bytes), parse qname
        idx = 12
        labels: list[str] = []
        while idx < len(data):
            length = data[idx]
            if length == 0:
                idx += 1
                break
            idx += 1
            labels.append(data[idx:idx + length].decode("ascii", errors="replace"))
            idx += length
        qname = ".".join(labels)
        # qtype (2 bytes) + qclass (2 bytes)
        if idx + 4 > len(data):
            return (qname, "")
        qtype = int.from_bytes(data[idx:idx + 2], "big")
        qtype_map = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA"}
        return (qname, qtype_map.get(qtype, str(qtype)))

    def _extract_callback_id(self, qname: str) -> str:
        return extract_callback_id(qname, self.base_domain)


def extract_callback_id(qname: str, base_domain: str) -> str:
    """Extract the first label (callback_id) from a query/host name.
    If the name doesn't end with the base domain, return the first label."""
    qname = qname.lower().rstrip(".")
    base = base_domain.lower().rstrip(".")
    if qname.endswith("." + base) or qname == base:
        prefix = qname[:-len("." + base)] if qname != base else ""
        return prefix.split(".")[0] if prefix else "_root"
    return qname.split(".")[0]


def process_dns_packet(store: CallbackStore, base_domain: str, reply_ip: str,
                       data: bytes, source_ip: str) -> bytes | None:
    """Parse a single DNS query, log it as a callback, and return the response
    bytes. Shared by the UDP and TCP DNS servers. Returns None on malformed input."""
    if len(data) < 12:
        return None
    try:
        qname, qtype = DNSHandler._parse_query(data)
        if not qname:
            return None
        callback_id = extract_callback_id(qname, base_domain)
        store.add(Callback(
            callback_id=callback_id,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            protocol="dns",
            source_ip=source_ip,
            details={"query_name": qname, "query_type": qtype},
        ))
        log.info("DNS query from %s: %s (%s) — callback_id=%s", source_ip, qname, qtype, callback_id)
        return build_dns_response(data, qname, qtype, reply_ip)
    except Exception as exc:
        log.debug("process_dns_packet error: %s", exc)
        return None


def build_dns_response(query: bytes, qname: str, qtype: str, reply_ip: str) -> bytes:
    """Build a minimal DNS response: copy the query, set QR=1, append a single
    A record answer pointing to reply_ip. For non-A queries, return a response
    with no answers so the caller knows we received it."""
    header = bytearray(query[:12])
    header[2] |= 0x80  # QR=1
    header[3] |= 0x80  # RA=1
    ancount = 0
    answer_section = b""
    if qtype == "A":
        ancount = 1
        answer_section = (
            b"\xc0\x0c"
            b"\x00\x01"
            b"\x00\x01"
            b"\x00\x00\x00\x3c"
            b"\x00\x04"
            + bytes(int(p) for p in reply_ip.split("."))
        )
    elif qtype == "AAAA":
        ancount = 1
        answer_section = (
            b"\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x3c\x00\x10"
            + b"\x00" * 16
        )
    header[6:8] = ancount.to_bytes(2, "big")
    header[8:10] = (0).to_bytes(2, "big")
    header[10:12] = (0).to_bytes(2, "big")
    return bytes(header) + query[12:] + answer_section


class DNSServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


def make_dns_server(store: CallbackStore, base_domain: str, reply_ip: str,
                    host: str = "0.0.0.0", port: int = 53) -> DNSServer:
    """Build a configured DNS server instance."""
    # We can't use a factory class because socketserver instantiates the handler
    # per-request. Set class attributes on a closure subclass instead.
    class _Handler(DNSHandler):
        pass
    _Handler.store = store
    _Handler.base_domain = base_domain
    _Handler.reply_ip = reply_ip
    server = DNSServer((host, port), _Handler)
    return server


class DNSTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class TCPDNSHandler(socketserver.BaseRequestHandler):
    """TCP DNS server. DNS over TCP prepends each message with a 2-byte length."""

    def handle(self) -> None:
        sock = self.request
        length_bytes = self._recv_exact(sock, 2)
        if len(length_bytes) < 2:
            return
        length = int.from_bytes(length_bytes, "big")
        data = self._recv_exact(sock, length)
        resp = process_dns_packet(
            self.server.store, self.server.base_domain, self.server.reply_ip,
            data, self.client_address[0],
        )
        if resp is not None:
            try:
                sock.sendall(len(resp).to_bytes(2, "big") + resp)
            except OSError:
                pass

    @staticmethod
    def _recv_exact(sock: Any, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf


def make_dns_tcp_server(store: CallbackStore, base_domain: str, reply_ip: str,
                        host: str = "0.0.0.0", port: int = 53) -> DNSTCPServer:
    """Build a configured DNS-over-TCP server instance (C10)."""
    server = DNSTCPServer((host, port), TCPDNSHandler)
    server.store = store
    server.base_domain = base_domain
    server.reply_ip = reply_ip
    return server


# ── HTTP server ──────────────────────────────────────────────────────────────

class HTTPCallbackHandler(BaseHTTPRequestHandler):
    """HTTP catch-all: log every request, respond 200 OK. callback_id is the
    first label of the Host header."""
    store: CallbackStore
    base_domain: str

    def log_message(self, fmt, *args) -> None:
        # Suppress default stderr logging — we do our own
        pass

    def _handle(self) -> None:
        host = self.headers.get("Host", "")
        callback_id = self._extract_callback_id(host)
        body = b""
        if self.command in ("POST", "PUT", "PATCH"):
            length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(length) if length > 0 else b""
        cb = Callback(
            callback_id=callback_id,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            protocol="http",
            source_ip=self.client_address[0],
            details={
                "method": self.command,
                "host": host,
                "path": self.path,
                "headers": dict(self.headers),
                "body": body.decode("utf-8", errors="replace")[:2000],
            },
        )
        self.store.add(cb)
        log.info("HTTP %s from %s: %s %s — callback_id=%s",
                 self.command, self.client_address[0], self.command, self.path, callback_id)
        # State API: /callbacks[/<id>][?since=&until=&limit=]  (C11)
        if self.path.startswith("/callbacks"):
            parsed = urllib.parse.urlparse(self.path)
            rest = parsed.path[len("/callbacks"):]
            cid = rest[1:] if rest.startswith("/") else ""
            params = urllib.parse.parse_qs(parsed.query)
            since = params.get("since", [None])[0]
            until = params.get("until", [None])[0]
            limit = int(params.get("limit", ["0"])[0] or 0) or None
            if cid:
                hits = [asdict(c) for c in self.store.query(
                    callback_id=cid, since=since, until=until, limit=limit)]
            else:
                hits = [asdict(c) for c in self.store.query(
                    since=since, until=until, limit=limit)]
            payload = json.dumps({"callback_id": cid or None, "hits": hits}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        # Default: 200 OK with a small body
        body_out = b"OK\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body_out)))
        self.end_headers()
        self.wfile.write(body_out)

    def _extract_callback_id(self, host: str) -> str:
        host = host.lower().split(":")[0].rstrip(".")
        base = self.base_domain.lower().rstrip(".")
        if host.endswith("." + base) or host == base:
            prefix = host[:-len("." + base)] if host != base else ""
            return prefix.split(".")[0] if prefix else "_root"
        return host.split(".")[0]

    def do_GET(self) -> None: self._handle()
    def do_POST(self) -> None: self._handle()
    def do_PUT(self) -> None: self._handle()
    def do_PATCH(self) -> None: self._handle()
    def do_DELETE(self) -> None: self._handle()
    def do_HEAD(self) -> None: self._handle()
    def do_OPTIONS(self) -> None: self._handle()


def make_http_server(store: CallbackStore, base_domain: str,
                     host: str = "0.0.0.0", port: int = 80) -> ThreadingHTTPServer:
    class _Handler(HTTPCallbackHandler):
        pass
    _Handler.store = store
    _Handler.base_domain = base_domain
    return ThreadingHTTPServer((host, port), _Handler)


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="oob_catcher.py",
        description="Self-hosted interactsh-compatible OOB callback server (DNS + HTTP).",
    )
    ap.add_argument("--base-domain", required=True, help="wildcard DNS base domain, e.g. oob.yourdomain.com")
    ap.add_argument("--state-file", default="oob_state.json", help="JSON state file path")
    ap.add_argument("--dns-port", type=int, default=53)
    ap.add_argument("--tcp-dns-port", type=int, default=None,
                   help="also start a DNS-over-TCP server on this port (C10)")
    ap.add_argument("--http-port", type=int, default=80)
    ap.add_argument("--api-port", type=int, default=8080, help="state API port (HTTP server also serves /callbacks/<id>)")
    ap.add_argument("--reply-ip", default="127.0.0.1", help="IP to reply with for DNS A queries (default 127.0.0.1)")
    ap.add_argument("--retention-hours", type=int, default=24)
    ap.add_argument("--webhook-url", default=None, help="POST each callback as JSON to this URL (C12)")
    ap.add_argument("--no-dns", action="store_true", help="skip DNS server (HTTP-only mode)")
    ap.add_argument("--no-http", action="store_true", help="skip HTTP server (DNS-only mode)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )

    store = CallbackStore(Path(args.state_file), retention_hours=args.retention_hours,
                          webhook_url=args.webhook_url)

    servers: list[Any] = []
    threads: list[threading.Thread] = []

    if not args.no_dns:
        try:
            dns = make_dns_server(store, args.base_domain, args.reply_ip, port=args.dns_port)
            servers.append(dns)
            t = threading.Thread(target=dns.serve_forever, daemon=True, name="dns")
            threads.append(t)
            log.info("DNS server listening on :%d (base_domain=%s, reply_ip=%s)",
                     args.dns_port, args.base_domain, args.reply_ip)
        except PermissionError:
            log.error("cannot bind DNS port %d — need root? try sudo or use --dns-port 5353", args.dns_port)
            return 2
        except OSError as exc:
            log.error("cannot bind DNS port %d — %s", args.dns_port, exc)
            return 2

    if args.tcp_dns_port:
        try:
            tcp_dns = make_dns_tcp_server(
                store, args.base_domain, args.reply_ip, port=args.tcp_dns_port)
            servers.append(tcp_dns)
            t = threading.Thread(target=tcp_dns.serve_forever, daemon=True, name="dns-tcp")
            threads.append(t)
            log.info("DNS-over-TCP server listening on :%d", args.tcp_dns_port)
        except PermissionError:
            log.error("cannot bind TCP DNS port %d — need root?", args.tcp_dns_port)
            return 2
        except OSError as exc:
            log.error("cannot bind TCP DNS port %d — %s", args.tcp_dns_port, exc)
            return 2

    if not args.no_http:
        try:
            http = make_http_server(store, args.base_domain, port=args.http_port)
            servers.append(http)
            t = threading.Thread(target=http.serve_forever, daemon=True, name="http")
            threads.append(t)
            log.info("HTTP server listening on :%d", args.http_port)
        except PermissionError:
            log.error("cannot bind HTTP port %d — need root? try --http-port 8080", args.http_port)
            return 2
        except OSError as exc:
            log.error("cannot bind HTTP port %d — %s", args.http_port, exc)
            return 2

    if not servers:
        log.error("no servers started (--no-dns and --no-http both set)")
        return 2

    for t in threads:
        t.start()

    log.info("OOB catcher ready. Test with:")
    log.info("  curl http://test.%s/", args.base_domain)
    log.info("  dig @127.0.0.1 test.%s", args.base_domain)
    log.info("  curl http://%s:80/callbacks/test", args.base_domain)
    log.info("Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(60)
            log.info("callback count: %d", len(store.all_()))
    except KeyboardInterrupt:
        log.info("shutting down...")
        for s in servers:
            try:
                s.shutdown()
            except Exception:
                pass
        return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(0)
