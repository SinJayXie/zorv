# Zorv — A Lightweight, Self-Protocol Intranet Penetration Tool

> Built with Rust. **Custom binary frame protocol + TLS 1.3 camouflage + single-connection multiplexing + built-in Web admin console** for TCP/UDP intranet penetration.
>
> Run `zorvd` on your public server, `zorv` on your internal machine, and expose intranet services to the public network securely — no public IP required on the internal side.

```
                        ┌─────────────────────┐
  Public user ─────────▶│  Server `zorvd`     │    Public server
  hits a listen port    │  listener + tunnel  │
                        └─────────┬───────────┘
                                  │ TLS 1.3 tunnel (custom frame protocol,
                                  │ single-connection multiplexing)
                                  │ Auth: HMAC-SHA256 + timestamp window / IP allowlist
                        ┌─────────┴───────────┐
                        │  Client `zorv`      │    Intranet machine / NAS
                        │  dialer + forwarder │
                        └─────────┬───────────┘
                                  │ local TCP/UDP
                        ┌─────────┴───────────┐
                        │  Intranet target    │    e.g. 127.0.0.1:8080
                        └─────────────────────┘
```

## ✨ Features

- **Custom private protocol** — binary frames (`MAGIC 0x5A3C` + type + stream ID + length + CRC32). No HTTP/WebSocket, no public fingerprint.
- **TLS 1.3 transport** — pure Rust (rustls). The handshake looks like ordinary HTTPS.
- **Single-connection multiplexing** — one tunnel carries up to 65535 concurrent business streams; the control frame uses stream ID `0xFFFFFFFF`.
- **TCP / UDP proxying** — port forwarding and UDP datagrams (e.g. DNS forwarding) out of the box.
- **Traffic obfuscation** — random padding flattens packet-length distribution; random heartbeat jitter (`[obfuscation]`).
- **Multi-client routing** — `client_id`-based routing; each proxy rule binds to a specific client.
- **Web admin console** — Vue 3 SPA (TypeScript + Vite + Tailwind + Pinia + vue-router + axios), online clients / overview / settings / traffic monitoring, mobile-responsive; auth via `Authorization: Bearer <token>` header:
  - Captcha + brute-force protection (5 failed password attempts per IP → 30 min lockout)
  - Token management (random generation / copy), visual proxy-rule CRUD (modal form + input validation), and password change (old-password verification, forces re-login)
  - Online client list with one-click **kick** (client exits immediately)
  - Traffic monitoring per `client_id` with TCP/UDP up/down stats, **persisted to disk** + 30s-sampled time-series curve (hand-drawn Canvas, ~100 minutes)
  - Hot config reload — edit `zorvd.toml` and it takes effect without a restart (token & proxy-rule diffs applied)
  - Audit log for login, token changes, rule CRUD, reload, kick, and proxy connection events (which public IP reached which service), persisted to `data/audit.log` and browsable via a paged Audit page
  - Optional HTTPS for the console (`[admin.tls]`); passwords stored as PBKDF2-HMAC-SHA256 hashes
- **Observability** — Prometheus `/metrics` (online clients / configured proxies / active streams / TCP·UDP traffic counters, unauthenticated for scraping), offline webhook notifications.
- **Robustness** — exponential-backoff auto-reconnect, heartbeat timeout cleanup, and reconnect race protection (cleaning up an old session never removes the new one).

## 🚀 Quick Start

### 1. Build

Requires a stable Rust toolchain (edition 2024; latest stable recommended) and Node.js (pnpm) for the admin console.

```bash
# 1) Build the Vue admin console (outputs to html/, which is embedded into the binaries)
cd zorv-ui && pnpm install && pnpm build && cd ..

# 2) Build the Rust binaries (build.rs embeds html/ at compile time)
cargo build --release
# Artifacts:
#   target/release/zorvd   server daemon
#   target/release/zorv    client (also `zorv server` / `zorv client`)
```

### 2. Generate certificates (first deployment)

The tunnel enforces TLS 1.3. Self-signed certificates are fine for testing; use a trusted CA in production.

```bash
# Option A: built-in generator (self-signed)
cargo run --release --example gen_cert -- server.crt server.key

# Option B: OpenSSL
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=your-server.example.com"
```

### 3. Configure the server

```bash
cp config/zorvd.example.toml zorvd.toml
```

Minimal working config (TLS cert + token + one TCP proxy + admin console):

```toml
tunnel_addr = "0.0.0.0:8443"

[tls]
cert_file = "/etc/zorv/server.crt"
key_file  = "/etc/zorv/server.key"

[auth]
token = "replace-with-a-long-random-string"

[[proxies]]
name      = "web"
type      = "tcp"
listen    = "0.0.0.0:18080"
client_id = "home-nas"
target    = "127.0.0.1:8080"

[admin]
enabled  = true
listen   = "127.0.0.1:9000"
username = "admin"
password = "change-me"          # plaintext is fine at first; switch to a hash after login

[log]
level  = "info"
output = "./app.log"            # "stdout" for console-only, or any file path
```

> Password hash: `zorvd hash-password <plaintext>`, then paste the output (`$pbkdf2-sha256$...`) into `admin.password`.
> Besides `[[proxies]]`, proxy rules can also be managed dynamically in the admin console's Settings page — no config file editing required.

### 4. Configure the client

```bash
cp config/zorv.example.toml zorv.toml
```

```toml
client_id   = "home-nas"                       # must match client_id in a server proxy rule
server_addr = "your-server.example.com:8443"

[auth]
token = "same-token-as-the-server"

[tls]
verify_cert = true                             # set false for testing with self-signed certs
# ca_file = "/etc/zorv/ca.crt"                 # self-signed CA: import the server cert as the CA

[reconnect]
initial_delay  = "2s"
max_delay      = "60s"
backoff_factor = 2.0
max_retries    = 0                             # 0 = reconnect forever
```

> The client does **not** declare forwarding targets: the target (the intranet service) is configured on the server, which pushes it to the client via a `STREAM_OPEN` frame so the client connects to the local target.

### 5. Start & verify

```bash
# Server
./target/release/zorvd --config zorvd.toml
# or equivalently: ./target/release/zorv server -c zorvd.toml

# Client
./target/release/zorv client -c zorv.toml

# Verify from the outside:
curl http://your-server.example.com:18080/
ssh -p 12222 user@your-server.example.com
```

Open `http://127.0.0.1:9000/` in a browser to enter the admin console (if the server has no direct access, forward it with `ssh -L 9000:127.0.0.1:9000 user@server`).

## 🗂 Deployment

### Linux / systemd

A hardened service unit is provided at [deploy/zorvd.service](deploy/zorvd.service). Full steps in [deploy/README.md](deploy/README.md). Summary:

```bash
sudo useradd --system --home /var/lib/zorv --create-home --shell /usr/sbin/nologin zorv
sudo install -m 755 target/release/zorvd /usr/local/bin/zorvd
sudo mkdir -p /etc/zorv
sudo cp config/zorvd.example.toml /etc/zorv/zorvd.toml   # edit: token, certs, data_dir = "/var/lib/zorv"
sudo cp server.crt server.key /etc/zorv/
sudo cp deploy/zorvd.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now zorvd
journalctl -u zorvd -f
```

Register the client the same way (`ExecStart=/usr/local/bin/zorv client -c /etc/zorv/zorv.toml`).

### Docker

A multi-stage build is provided at [deploy/Dockerfile](deploy/Dockerfile) (build stage `rust:1-bookworm`, runtime stage `debian:bookworm-slim`, bundled self-signed cert + default config):

```bash
docker build -f deploy/Dockerfile -t zorvd:latest .
docker run -d --name zorvd --restart unless-stopped \
  -p 8443:8443 -p 9000:9000 \
  -v /srv/zorv/config:/etc/zorv \
  -v /srv/zorv/data:/var/lib/zorv \
  zorvd:latest
```

Add `-p <port>:<port>` mappings for each proxy port. **Mount your own config and certificates** — the bundled ones are self-signed test certs.

### Windows service

Wrap it with [NSSM](https://nssm.cc); a one-click script is at [deploy/zorvd-windows-service.ps1](deploy/zorvd-windows-service.ps1):

```powershell
cargo build --release --bin zorvd
# install NSSM and add it to PATH, then in an elevated PowerShell:
powershell -ExecutionPolicy Bypass -File deploy\zorvd-windows-service.ps1
```

## 📋 Configuration Reference

### Server `zorvd.toml`

| Section | Field | Description |
| --- | --- | --- |
| top-level | `tunnel_addr` | Tunnel listen address; clients dial this |
| top-level | `data_dir` | Persistence directory (traffic stats on disk), default `data` |
| `[tls]` | `cert_file` / `key_file` | PEM certificate & private key; tunnel enforces TLS 1.3 |
| `[auth]` | `token` | Pre-shared token shared with clients |
| `[auth]` | `allowed_ips` | Optional client IP allowlist (exact IP / IPv4 CIDR) |
| `[[proxies]]` | `name` / `type` / `listen` / `client_id` / `target` | A public `listen` port forwards through the tunnel to the `target` of the client with this `client_id`; `type` is `tcp` or `udp` |
| `[performance]` | `max_streams_per_tunnel` / `stream_buffer_size` / `recv_buffer_size` | Concurrency & buffer limits |
| `[obfuscation]` | `padding` / `padding_max` | Frame random-padding toggle & max size |
| `[admin]` | `enabled` / `listen` / `username` / `password` | Web admin console; `password` accepts plaintext or a PBKDF2 hash (`zorvd hash-password`) |
| `[admin.tls]` | `cert_file` / `key_file` | Optional: serve the admin console over HTTPS |
| `[notify]` | `webhook` | Optional: POST JSON when a client goes offline |
| `[log]` | `level` / `output` | Log level and output (`"stdout"` or a file path) |

### Client `zorv.toml`

| Section | Field | Description |
| --- | --- | --- |
| top-level | `client_id` | Unique client identifier, bound to server rules |
| top-level | `server_addr` | Server tunnel address `host:port` |
| `[auth]` | `token` | Same pre-shared token as the server |
| `[tls]` | `verify_cert` / `ca_file` | Certificate verification toggle & custom CA |
| `[reconnect]` | `initial_delay` / `max_delay` / `backoff_factor` / `max_retries` | Exponential-backoff reconnect policy |
| `[obfuscation]` | `padding` / `padding_max` / `heartbeat_jitter` | Traffic obfuscation |
| `[log]` | `level` / `output` | Logging |

## 📈 Monitoring & Alerts

- **Prometheus** — `GET /metrics` emits text-format metrics without auth:
  - `zorv_online_clients`, `zorv_configured_proxies`, `zorv_active_streams` (gauges)
  - `zorv_traffic_{tcp,udp}_{up,down}_bytes_total{client_id="..."}` (counters)
- **Traffic history API** — `GET /api/traffic/history` returns 30s-sampled time-series history (~100 minutes, in-memory ring buffer); the console's curve chart consumes this data.
- **Audit API** — `GET /api/audit?page=1&page_size=50` returns paged audit entries (newest first): `{total, page, page_size, items}`; consumed by the console's Audit page.
- **Client connection log** — every time the tunnel opens a new stream, the client prints `new tunnel connection: peer=<caller ip> service=<target service>` to its console.
- **Offline webhook** — with `[notify] webhook` set, the server POSTs JSON `{"event":"offline","client_id":"..."}` when a client session ends.

## 🔒 Security Notes

- **Handshake auth** — HMAC-SHA256 + millisecond timestamp within a ±30s window, replay-resistant; optional `allowed_ips` allowlist.
- **Admin console** — captcha, per-IP brute-force lockout, bearer-token sessions (`Authorization` header, 24h TTL), XSS-safe rendering, audit logging, PBKDF2-HMAC-SHA256 password storage, optional HTTPS.
- **Deployment advice** — expose only the ports you need; firewalling the tunnel port to client IPs is recommended; rotate tokens regularly; the admin console listens on loopback by default — for remote access use a reverse proxy or SSH forwarding.
- **Compliance** — use it only on your own servers, home labs, and authorized test environments. Deploying reverse tunnels on enterprise or unauthorized networks may violate security policies and regulations.

## 🧪 Development & Testing

```bash
cargo test --lib                    # unit tests (protocol / auth / admin API / traffic / reconnect races)
cargo test                          # includes end-to-end integration tests (TCP/UDP forwarding, client reconnect)
cargo run --release --example fuzz_protocol -- --iters 100000   # deterministic protocol fuzzing (prints the seed on crash)
cargo run --release --example smoke # smoke demo
```

Project layout:

```
src/
├── main.rs             # zorv entry (server/client subcommands)
├── bin/server.rs       # zorvd entry (hash-password subcommand)
├── server/             # server: tunnel, proxy listeners, session management, admin API, audit, metrics, hot reload
├── client/             # client: dial & reconnect, traffic forwarding, UDP sessions
├── protocol/           # frame codec, handshake, fuzzing tools
└── common/             # config, TLS, logging, errors
html/                   # built Vue SPA admin console (embedded via build.rs; regenerate with `cd zorv-ui && pnpm build`)
zorv-ui/                # admin console source: Vue 3 + TypeScript + Vite + Tailwind + Pinia + vue-router + axios
config/                 # example configs for server & client
deploy/                 # systemd unit, Dockerfile, Windows service script, deployment docs
examples/               # gen_cert / smoke / fuzz_protocol
tests/                  # end-to-end integration tests, protocol tests
```

## License

MIT
