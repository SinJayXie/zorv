# Changelog

All notable changes to Zorv are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-08-20

### Added

- **Vue 3 admin console** — the hand-written HTML pages are replaced by a Vue 3
  SPA (TypeScript + Vite + Tailwind CSS + SCSS + Pinia + vue-router + axios).
  All JS/CSS is bundled into single hashed files and embedded into the binary.
- **Bearer-token auth** — login now returns a session token returned in the
  response body; every API call carries it via the `Authorization: Bearer <token>`
  header (replaces the cookie session).
- **Audit log** — records admin operations (login, token changes, proxy rule
  CRUD, hot reload, kicks, password changes) and proxy connection events
  (which public IP reached which service). Persisted to `data/audit.log`
  (JSON Lines) and browsable via the new paged `GET /api/audit` API + Audit page.
- **Client connection log** — the client prints
  `new tunnel connection: peer=<caller ip> service=<target service>` to its
  console whenever a new tunnel stream is opened.
- **UI upgrades** — sticky top navigation with route-aware highlighting and a
  mobile hamburger menu; login input validation; Token management and
  Change Password as modals; responsive table-to-card layouts on mobile.
- **Automatic frontend build** — `build.rs` runs `pnpm build` before embedding
  `html/`, so `cargo build` always embeds an up-to-date admin console.
- **Docker multi-stage frontend build** — the Dockerfile now builds the Vue
  console in a Node stage before the Rust stage.

### Fixed

- `/login` page served 404 after the SPA migration; it now serves the app shell.
- Static assets (`/assets/*`) were gated behind auth and returned 302 to the
  browser; they are now public (auth stays enforced on the APIs).
- Audit tests shared a single temp `audit.log`, causing flaky failures when run
  in parallel; each test state now uses a unique directory.
- `cargo build` hung under WSL because `build.rs` ran `pnpm build` against a
  Windows mount (DrvFS, massive cross-filesystem I/O). WSL is now auto-detected
  and the frontend build is skipped (existing `html/` output is embedded);
  set `ZORV_SKIP_UI_BUILD=1` to skip it on any platform.

## [1.0.0] - 2026-08-19

Stable release of the original implementation:

- Custom binary frame protocol (MAGIC `0x5A3C` + type + stream ID + length + CRC32).
- TLS 1.3 transport (rustls), single-connection multiplexing (up to 65535 streams).
- TCP / UDP proxying, multi-client routing, traffic obfuscation (padding + heartbeat jitter).
- Handshake auth: HMAC-SHA256 + millisecond timestamp window, optional IP allowlist.
- Web admin console with captcha + brute-force protection, token management,
  proxy rule CRUD, online client list with kick, traffic monitoring with
  persisted counters + time-series chart, hot config reload, audit log,
  optional HTTPS, PBKDF2-HMAC-SHA256 password hashing.
- Prometheus `/metrics`, offline webhook notifications, exponential-backoff
  reconnect, heartbeat timeout cleanup, reconnect race protection.
- systemd unit, Dockerfile, Windows service script, deployment docs.

## [0.1.0] - 2026-08-19

Initial commit: core tunnel server/client with the protocol, handshake auth,
TCP/UDP proxying, multiplexing, and a basic embedded web admin console.
