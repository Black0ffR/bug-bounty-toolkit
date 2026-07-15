# oob_catcher

Self-hosted interactsh-compatible OOB callback server. `ssrfprobe.py`, nuclei-go's OOB module, and Log4Shell-style templates all need an out-of-band callback endpoint to confirm blind vulnerabilities. Public `interact.sh` works but has reliability issues (rate limits, log retention, shared instance). This tool is a self-hosted alternative — runs on a cheap VPS with a wildcard DNS record, captures DNS + HTTP callbacks, and exposes a simple JSON API for the pipeline to poll. Three components: a minimal DNS server (UDP/TCP 53, replies `127.0.0.1` for any subdomain of the configured base domain), an HTTP catch-all (TCP 80, responds `200 OK` to any path), and a state API (JSON file pollable via `GET /callbacks/<callback_id>` on the HTTP port).

## Layer / Tier
Tier 4 infra_ext. Independent — `ssrfprobe.py` / nuclei-go use the `--oob-domain` flag to point at this server's base domain.

## Depends on
- Python stdlib only: `socket`, `socketserver`, `http.server`, `threading`, `json`, `datetime`, `pathlib`, `argparse`.
- External: a VPS with a wildcard DNS A record pointing at the server's IP for the configured `--base-domain`.

## Feeds into
- Polled by `ssrfprobe.py` and any tool generating blind-vuln probes: each tool generates a unique `callback_id` (subdomain prefix), embeds `<callback_id>.<base-domain>` in the payload, then polls `GET http://<base-domain>:<http-port>/callbacks/<callback_id>` to confirm the callback fired.
- The JSON state file at `--state-file` is the durable record (24-hour retention by default).

## Usage

```bash
# Start the server (run on a VPS with wildcard DNS A record → this host's IP)
python -m toolkit.infra_ext.oob_catcher \
    --base-domain oob.yourdomain.com \
    --state-file /var/lib/oob_catcher/state.json \
    --dns-port 53 --http-port 80

# Test it (from anywhere)
curl http://test.oob.yourdomain.com/                 # → 200 OK, logs callback_id=test
dig @<server-ip> test.oob.yourdomain.com             # → A 127.0.0.1, logs callback_id=test
curl http://oob.yourdomain.com/callbacks/test        # → {"callback_id": "test", "hits": [...]}

# HTTP-only mode (e.g., for local testing without root)
python -m toolkit.infra_ext.oob_catcher --base-domain localhost \
    --no-dns --http-port 8080 --state-file ./oob_state.json
```

## Library use
```python
from toolkit.infra_ext.oob_catcher import CallbackStore, make_dns_server, make_http_server
import threading
from pathlib import Path

store = CallbackStore(Path("oob_state.json"), retention_hours=24)
dns = make_dns_server(store, "oob.yourdomain.com", "127.0.0.1", port=53)
http = make_http_server(store, "oob.yourdomain.com", port=80)
threading.Thread(target=dns.serve_forever, daemon=True).start()
threading.Thread(target=http.serve_forever, daemon=True).start()

# Later: poll for a specific callback_id
hits = store.get("abc123")
```

## Input / Output
- **Input:** None at startup (loads `--state-file` if it exists). At runtime: inbound DNS queries (UDP/TCP 53) and HTTP requests (TCP 80) — every query/request is logged as a `Callback`.
- **Output:** JSON state file at `--state-file` (atomically replaced via `tmp + rename` on every callback). State API: `GET /callbacks/<callback_id>` on the HTTP port returns `{"callback_id": "<id>", "hits": [Callback, ...]}`.
- **Side effects:** Binds UDP/TCP 53 (requires root or `CAP_NET_BIND_SERVICE`) and TCP 80 (same). Use `--dns-port 5353` and `--http-port 8080` for non-root testing. Periodic INFO log every 60s with total callback count.

## Key classes / functions
| Name | Purpose |
|---|---|
| `Callback` | `dataclass(callback_id, timestamp, protocol, source_ip, details)`. `protocol` ∈ `dns | http`. `details` includes query name/type for DNS, method/host/path/headers/body for HTTP. |
| `CallbackStore` | Thread-safe in-memory store with periodic atomic flush to JSON state file. `add(cb)`, `get(callback_id)`, `all_()`. Trims entries older than `retention_hours` on every add. |
| `DNSHandler` | Minimal DNS server. Replies to A queries with `--reply-ip` (default `127.0.0.1`), AAAA with `::1`. Logs every query. `callback_id` = first label of the query name before the base domain. |
| `HTTPCallbackHandler` | HTTP catch-all. Logs every request. Special path `/callbacks/<id>` returns that callback's hits as JSON; everything else returns `200 OK`. `callback_id` = first label of the `Host` header before the base domain. |
| `make_dns_server(store, base_domain, reply_ip, host, port)` | Build a configured `DNSServer` (closes over `store`/`base_domain`/`reply_ip` via subclass class attributes). |
| `make_http_server(store, base_domain, host, port)` | Build a configured `ThreadingHTTPServer`. |

## Configuration
- `--base-domain` (required): wildcard DNS base domain, e.g. `oob.yourdomain.com`. Requires a wildcard A record pointing at the server's IP.
- `--state-file` (default `oob_state.json`): JSON state file path.
- `--dns-port` (default 53), `--http-port` (default 80), `--api-port` (default 8080, currently unused — the state API is served on `--http-port`).
- `--reply-ip` (default `127.0.0.1`): IP returned for DNS A queries.
- `--retention-hours` (default 24).
- `--no-dns` / `--no-http`: skip one server (HTTP-only or DNS-only mode).
- No env vars. Ports 53/80 require root or `CAP_NET_BIND_SERVICE`.

## Safety notes
- This server is a callback collector — it never sends traffic outbound. It only replies to inbound DNS/HTTP.
- The DNS server is NOT a recursive resolver. It only handles A/AAAA/TXT queries for names under `--base-domain` (returns `127.0.0.1` / `::1` for any such name). Non-A/AAAA queries get an empty response with QR=1.
- The HTTP server logs the first 2KB of every request body. Sensitive data in callback bodies (e.g., SSRF exfil payloads) is persisted to the state file — secure the state file's permissions accordingly.
- The state file is written atomically (`tmp + rename`) so a crash mid-write does not corrupt the existing state.
- The HTTP server binds `0.0.0.0` by default — restrict at the firewall if you only want specific source IPs to reach it.

## See also
- ARCHITECTURE.md §6 (OOB infrastructure) and §infra_ext
- Related tools: `ssrfprobe.py` (consumer via `--oob-domain`), `nuclei-go` (consumer), public `interact.sh` (alternative)
