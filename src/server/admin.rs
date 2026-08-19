//! Server-side web admin UI: minimal HTTP server + JSON API + login authentication.
//!
//! No HTTP framework is used; HTTP/1.1 parsing and responses are hand-written on `tokio::net::TcpListener`.
//! Page assets are embedded via `include_str!`.
//!
//! Auth: when `AdminConfig.password` is non-empty, login is mandatory. A successful login issues a session token
//! (`Cookie: session=...`) that must be carried by subsequent pages and API calls; an empty password disables login.
//!
//! Pages: `/login.html`, `/` (or `/index.html`), `/clients.html`, `/settings.html`
//! API: `POST /api/login`, `POST /api/logout`, `GET /api/status`,
//!   `GET /api/clients`, `GET /api/proxies`, `POST /api/proxies`,
//!   `DELETE /api/proxies?name=xxx`, `PUT /api/token`

use std::sync::Arc;

use dashmap::DashMap;
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::common::config::{save_server, AdminTlsConfig, ProxyConfig, ServerConfig};
use crate::common::crypto::now_millis;
use crate::common::error::Result;
use crate::common::tls::build_server_acceptor;
use crate::server::manager::TunnelManager;
use crate::server::proxy::ProxyManager;
use crate::server::traffic::{TrafficCounter, TrafficTracker};

const LOGIN_HTML: &str = include_str!("../../html/login.html");
const INDEX_HTML: &str = include_str!("../../html/index.html");
const CLIENTS_HTML: &str = include_str!("../../html/clients.html");
const SETTINGS_HTML: &str = include_str!("../../html/settings.html");
const TRAFFIC_HTML: &str = include_str!("../../html/traffic.html");

/// Session TTL (ms): 24 hours.
const SESSION_TTL_MS: u64 = 24 * 60 * 60 * 1000;

/// Login failure threshold: ban the IP after this many consecutive failures.
const LOGIN_FAIL_LIMIT: u32 = 5;
/// Ban duration (ms): 30 minutes.
const BLOCK_DURATION_MS: u64 = 30 * 60 * 1000;
/// Failure counting window (ms): only consecutive failures within the window count.
const FAIL_WINDOW_MS: u64 = 30 * 60 * 1000;
/// Captcha TTL (ms): 5 minutes, single use.
const CAPTCHA_TTL_MS: u64 = 5 * 60 * 1000;
/// Captcha charset (ambiguous characters 0/O/1/I/L removed).
const CAPTCHA_CHARS: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";

/// Shared state for the admin interface.
pub struct AdminState {
    pub manager: Arc<TunnelManager>,
    pub token: Arc<RwLock<String>>,
    pub proxies: Arc<RwLock<Vec<ProxyConfig>>>,
    pub proxy_manager: Arc<ProxyManager>,
    pub config_path: String,
    /// Full config snapshot at startup; writes back only replace token and proxies.
    /// Reload synchronizes with the latest on-disk config.
    pub base: RwLock<ServerConfig>,
    /// Admin login username.
    pub username: String,
    /// Admin login password (empty disables login).
    pub password: String,
    /// Session table: `session_token -> expiry timestamp (ms)`.
    pub sessions: DashMap<String, u64>,
    /// Login failure counter: `ip -> (failure count, window start ms)`.
    pub login_failures: DashMap<String, (u32, u64)>,
    /// Blocked IPs: `ip -> ban expiry ms`; requests from banned IPs are dropped.
    pub blocked_ips: DashMap<String, u64>,
    /// Captchas: `captcha_id -> (answer, expiry ms)`, single use.
    pub captchas: DashMap<String, (String, u64)>,
    /// Traffic statistics tracker (cumulative counters + persistence).
    pub traffic: Arc<TrafficTracker>,
}

/// Starts the admin HTTP server (blocking accept loop).
pub async fn run_admin_server(
    addr: String,
    state: Arc<AdminState>,
    tls_config: Option<AdminTlsConfig>,
) -> Result<()> {
    let listener = TcpListener::bind(&addr).await?;
    // Optional HTTPS: when certs are configured, wrap every connection with a TLS acceptor
    let acceptor = match &tls_config {
        Some(c) => Some(build_server_acceptor(&c.cert_file, &c.key_file)?),
        None => None,
    };
    info!(
        "admin {} server started on {}",
        if acceptor.is_some() { "https" } else { "http" },
        addr
    );
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("admin accept error: {}", e);
                continue;
            }
        };
        let state = Arc::clone(&state);
        let ip = peer.ip().to_string();
        let acc = acceptor.clone();
        tokio::spawn(async move {
            let conn = match acc {
                Some(a) => {
                    // TLS handshake (HTTPS)
                    let tls = match a.accept(stream).await {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("admin tls handshake {} error: {}", peer, e);
                            return;
                        }
                    };
                    ConnStream::Tls(tls)
                }
                None => ConnStream::Plain(stream),
            };
            if let Err(e) = handle_conn(conn, state, ip).await {
                warn!("admin conn {} error: {}", peer, e);
            }
        });
    }
}

/// Admin connection stream: plain TCP or TLS (HTTPS).
enum ConnStream {
    Plain(TcpStream),
    Tls(tokio_rustls::server::TlsStream<TcpStream>),
}

impl ConnStream {
    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            ConnStream::Plain(s) => s.read(buf).await,
            ConnStream::Tls(s) => s.read(buf).await,
        }
    }

    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            ConnStream::Plain(s) => s.write_all(buf).await,
            ConnStream::Tls(s) => s.write_all(buf).await,
        }
    }

    async fn shutdown(&mut self) -> std::io::Result<()> {
        match self {
            ConnStream::Plain(s) => s.shutdown().await,
            ConnStream::Tls(s) => s.shutdown().await,
        }
    }
}

/// A parsed HTTP request.
struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
    /// Client IP (used for blocking on login failures).
    ip: String,
    /// Session token extracted from the Cookie.
    session: Option<String>,
    /// Captcha id extracted from the Cookie.
    captcha: Option<String>,
}

/// HTTP response (each extra header line ends with `\r\n`).
struct Response {
    status: &'static str,
    content_type: &'static str,
    extra_headers: String,
    body: Vec<u8>,
}

impl Response {
    fn into_bytes(self) -> Vec<u8> {
        let mut resp = format!(
            "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n{}",
            self.status,
            self.content_type,
            self.body.len(),
            self.extra_headers
        )
        .into_bytes();
        resp.extend_from_slice(b"\r\n");
        resp.extend_from_slice(&self.body);
        resp
    }
}

fn html_response(html: &str) -> Response {
    Response {
        status: "200 OK",
        content_type: "text/html; charset=utf-8",
        extra_headers: String::new(),
        body: html.as_bytes().to_vec(),
    }
}

fn json_response(status: &'static str, body: Vec<u8>) -> Response {
    Response {
        status,
        content_type: "application/json",
        extra_headers: String::new(),
        body,
    }
}

fn json_err_response(status: &'static str, msg: &str) -> Response {
    json_response(status, json_error(msg))
}

fn redirect_response(location: &str) -> Response {
    Response {
        status: "302 Found",
        content_type: "text/html; charset=utf-8",
        extra_headers: format!("Location: {}\r\n", location),
        body: Vec::new(),
    }
}

/// Reads a complete HTTP request from the stream (headers end at `\r\n\r\n`; the body follows Content-Length).
async fn read_request(stream: &mut ConnStream) -> Option<HttpRequest> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];

    // Read the header until \r\n\r\n
    let header_end = loop {
        let n = stream.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 16 * 1024 {
            return None; // guard against pathologically long requests
        }
    };

    let header_text = String::from_utf8_lossy(&buf[..header_end]);
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();

    let mut content_length = 0usize;
    let mut session = None;
    let mut captcha = None;
    for line in lines {
        if let Some(v) = line.strip_prefix("Content-Length:") {
            content_length = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("Cookie:") {
            for part in v.split(';') {
                if let Some(val) = part.trim().strip_prefix("session=") {
                    session = Some(val.trim().to_string());
                } else if let Some(val) = part.trim().strip_prefix("captcha=") {
                    captcha = Some(val.trim().to_string());
                }
            }
        }
    }

    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut tmp).await.ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_length);

    Some(HttpRequest {
        method,
        path,
        body,
        ip: String::new(), // filled in by handle_conn
        session,
        captcha,
    })
}

async fn handle_conn(mut stream: ConnStream, state: Arc<AdminState>, ip: String) -> Result<()> {
    // Blocked IP: drop all its requests (close the connection immediately without reading anything)
    if is_ip_blocked(&state, &ip) {
        return Ok(());
    }
    let mut req = match read_request(&mut stream).await {
        Some(r) => r,
        None => return Ok(()),
    };
    req.ip = ip;
    let resp = route(&req, &state).await;
    let bytes = resp.into_bytes();
    stream.write_all(&bytes).await?;
    let _ = stream.shutdown().await;
    Ok(())
}

/// Route dispatch.
async fn route(req: &HttpRequest, state: &AdminState) -> Response {
    let method = req.method.as_str();
    // Path with the query parameters stripped (e.g. /api/captcha?t=123 → /api/captcha)
    let path = req.path.split('?').next().unwrap_or(&req.path);

    // No auth required: captcha + login page + login API + Prometheus metrics (scraper has no cookie)
    if method == "GET" && path == "/api/captcha" {
        return api_captcha(state).await;
    }
    if method == "GET" && path == "/metrics" {
        return api_metrics(state).await;
    }
    if method == "GET" && (path == "/login.html" || path == "/login") {
        return html_response(LOGIN_HTML);
    }
    if method == "POST" && path == "/api/login" {
        return api_login(req, state).await;
    }

    // Auth (skipped when the password is empty)
    if !is_authenticated(state, req) {
        if method == "GET" && !path.starts_with("/api/") {
            return redirect_response("/login.html");
        }
        return json_err_response("401 Unauthorized", "unauthorized");
    }

    // Logout
    if method == "POST" && path == "/api/logout" {
        return api_logout(req, state);
    }

    // Page routes (authenticated)
    if method == "GET" {
        let html = match path {
            "/" | "/index.html" => Some(INDEX_HTML),
            "/clients.html" => Some(CLIENTS_HTML),
            "/settings.html" => Some(SETTINGS_HTML),
            "/traffic.html" => Some(TRAFFIC_HTML),
            _ => None,
        };
        if let Some(h) = html {
            return html_response(h);
        }
    }

    // Split path and query
    let (path, query) = match req.path.split_once('?') {
        Some((p, q)) => (p, q),
        None => (req.path.as_str(), ""),
    };

    match (method, path) {
        ("GET", "/api/status") => api_status(state).await,
        ("GET", "/api/clients") => api_clients(state).await,
        ("GET", "/api/traffic") => api_traffic(state).await,
        ("GET", "/api/traffic/history") => api_traffic_history(state).await,
        ("GET", "/api/proxies") => api_proxies(state).await,
        ("POST", "/api/proxies") => api_create_proxy(req, state).await,
        ("PUT", "/api/token") => api_update_token(req, state).await,
        ("POST", "/api/kick") => api_kick(req, state).await,
        ("POST", "/api/reload") => api_reload(state).await,
        ("DELETE", "/api/proxies") => api_delete_proxy(query, state).await,
        _ => json_err_response("404 Not Found", "not found"),
    }
}

// ---------------------------------------------------------------------------
// Auth and login
// ---------------------------------------------------------------------------

/// Whether the request is authenticated (always true when the password is empty, i.e. login disabled).
fn is_authenticated(state: &AdminState, req: &HttpRequest) -> bool {
    if state.password.is_empty() {
        return true;
    }
    match &req.session {
        Some(s) => match state.sessions.get(s) {
            Some(expire) => now_millis() < *expire,
            None => false,
        },
        None => false,
    }
}

fn gen_session_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// PBKDF2-HMAC-SHA256 iteration count (tion crecommendsnt (OWA). recommends ≥ 100k).
const PBKDF2_ITERATIONS: u32 = 100_000;

/// Generates anerates a PBKDF2-HMApassword hash (random6 p-byteasalt).d hash (random 16-byte salt).
/// Storage format: ge format: `$pbkdf2-sha256$<iterations>$<salt_hex>$<hash_hex>`
///
/// Used by thesed by the `zorvd hash-password < subcommand and adminplogin verification.ommand and admin login verification.
pub fn hash_password(password: &str) -> String {
    use rand::RngCore;
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let dk = pbkdf2_sha256(password.as_bytes(), &salt, PBKDF2_ITERATIONS);
    format!(
        "$pbkdf2-sha256${}${}${}",
        PBKDF2_ITERATIONS,
        to_hex(&salt),
        to_hex(&dk)
    )
}

/// Verify the admin password: supports `$pbkdf2-sha256$...` prefixed hashes and
/// plaintext (backward compatible).
fn verify_password(input: &str, stored: &str) -> bool {
    if let Some(rest) = stored.strip_prefix("$pbkdf2-sha256$") {
        let mut parts = rest.split('$');
        let (Some(iters), Some(salt), Some(hash)) =
            (parts.next(), parts.next(), parts.next())
        else {
            return false;
        };
        let (Ok(iters), Some(salt), Some(hash)) = (
            iters.parse::<u32>(),
            from_hex(salt),
            from_hex(hash),
        ) else {
            return false;
        };
        let dk = pbkdf2_sha256(input.as_bytes(), &salt, iters);
        dk.len() == hash.len() && constant_time_eq(&to_hex(&dk), &to_hex(&hash))
    } else {
        constant_time_eq(input, stored)
    }
}

/// PBKDF2-HMAC-SHA256 (RFC 8018), outputs 32 bytes.
fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<sha2::Sha256>;

    // U1 = PRF(password, salt || INT_32_BE(1))
    let mut mac = HmacSha256::new_from_slice(password).expect("hmac accepts any key length");
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let mut u = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&u);
    // F = U1 ^ U2 ^ ... ^ Uc
    for _ in 1..iterations {
        let mut mac = HmacSha256::new_from_slice(password).expect("hmac accepts any key length");
        mac.update(&u);
        u = mac.finalize().into_bytes();
        for (o, uu) in out.iter_mut().zip(u.iter()) {
            *o ^= uu;
        }
    }
    out
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Audit log: records key admin operations (login, token/rule changes, kicks, etc.).
fn audit(action: &str, detail: &str) {
    tracing::info!(target: "audit", "{action} {detail}");
}

/// Constant-time string comparison (avoids timing side channels).
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

async fn api_login(req: &HttpRequest, state: &AdminState) -> Response {
    #[derive(Deserialize)]
    struct LoginReq {
        username: String,
        password: String,
        #[serde(default)]
        captcha_code: String,
    }
    let lreq: LoginReq = match serde_json::from_slice(&req.body) {
        Ok(l) => l,
        Err(e) => {
            return json_err_response("400 Bad Request", &format!("invalid login json: {e}"));
        }
    };

    if state.password.is_empty() {
        return json_err_response("403 Forbidden", "login disabled");
    }

    // Captcha check (single-use, burned after use)
    if !check_captcha(state, req.captcha.as_deref(), &lreq.captcha_code) {
        return json_err_response("401 Unauthorized", "验证码错误或已过期");
    }

    if lreq.username == state.username && verify_password(&lreq.password, &state.password) {
        // Login succeeded: clear this IP's failure count
        audit("login", &format!("ok user={} ip={}", lreq.username, req.ip));
        state.login_failures.remove(&req.ip);
        let session = gen_session_token();
        let expire = now_millis() + SESSION_TTL_MS;
        state.sessions.insert(session.clone(), expire);
        let extra = format!("Set-Cookie: session={session}; Path=/; HttpOnly; SameSite=Lax\r\n");
        return Response {
            status: "200 OK",
            content_type: "application/json",
            extra_headers: extra,
            body: json_ok(),
        };
    }

    // Wrong password: accumulate failures, block the IP for 30 minutes at the threshold
    audit("login", &format!("failed user={} ip={}", lreq.username, req.ip));
    record_login_failure(state, &req.ip);
    json_err_response("401 Unauthorized", "用户名或密码错误")
}

/// Verify a captcha: the id must exist, be unexpired, and match the answer
/// (case-insensitive). Consumed on use (right or wrong).
fn check_captcha(state: &AdminState, id: Option<&str>, code: &str) -> bool {
    let Some(id) = id else { return false };
    let code = code.trim().to_uppercase();
    let valid = match state.captchas.get(id) {
        Some(v) => now_millis() < v.1 && constant_time_eq(&v.0.to_uppercase(), &code),
        None => false,
    };
    state.captchas.remove(id);
    valid
}

/// Records a login failure: consecutive failures within the window (30 minutes) reaching the threshold blocks the IP for 30 minutes.
fn record_login_failure(state: &AdminState, ip: &str) {
    let now = now_millis();
    {
        let mut entry = state.login_failures.entry(ip.to_string()).or_insert((0, now));
        let (count, first) = *entry;
        *entry = if now - first > FAIL_WINDOW_MS {
            (1, now)
        } else {
            (count + 1, first)
        };
    }
    if state.login_failures.get(ip).map(|v| v.0).unwrap_or(0) >= LOGIN_FAIL_LIMIT {
        state
            .blocked_ips
            .insert(ip.to_string(), now + BLOCK_DURATION_MS);
        state.login_failures.remove(ip);
    }
}

/// Whether the IP is currently in a ban period (expired bans are cleared here).
fn is_ip_blocked(state: &AdminState, ip: &str) -> bool {
    let now = now_millis();
    match state.blocked_ips.get(ip) {
        Some(until) => {
            if now < *until {
                true
            } else {
                drop(until);
                state.blocked_ips.remove(ip);
                false
            }
        }
        None => false,
    }
}

/// Generates a 4-character captcha code (from a set without confusable characters).
fn gen_captcha_code() -> String {
    let mut rng = rand::thread_rng();
    (0..4)
        .map(|_| CAPTCHA_CHARS[rng.gen_range(0..CAPTCHA_CHARS.len())] as char)
        .collect()
}

/// Generates an SVG captcha image (plain-text vector graphic, no extra image dependency).
fn gen_captcha_svg(code: &str) -> String {
    let mut rng = rand::thread_rng();
    let colors = ["#334155", "#b91c1c", "#1d4ed8", "#047857", "#7c3aed"];
    let mut svg = String::from(
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="140" height="48" viewBox="0 0 140 48">"#,
    );
    svg.push_str(r##"<rect width="140" height="48" rx="6" fill="#f8fafc"/>"##);
    // Noise lines
    for _ in 0..5 {
        let x1 = rng.gen_range(0..140);
        let y1 = rng.gen_range(0..48);
        let x2 = rng.gen_range(0..140);
        let y2 = rng.gen_range(0..48);
        let c = colors[rng.gen_range(0..colors.len())];
        svg.push_str(&format!(
            r#"<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{c}" stroke-width="1.5" opacity="0.45"/>"#
        ));
    }
    // Characters (random position/rotation/color)
    for (i, ch) in code.chars().enumerate() {
        let x = 18 + i as i32 * 27 + rng.gen_range(-3..4);
        let y = 34 + rng.gen_range(-4..5);
        let rot = rng.gen_range(-22..23);
        let c = colors[rng.gen_range(0..colors.len())];
        svg.push_str(&format!(
            r#"<text x="{x}" y="{y}" font-family="monospace" font-size="30" font-weight="bold" fill="{c}" transform="rotate({rot} {x} {y})">{ch}</text>"#
        ));
    }
    svg.push_str("</svg>");
    svg
}

/// `GET /api/captcha`: generates a captcha, delivers its id via Set-Cookie, and returns an SVG image.
async fn api_captcha(state: &AdminState) -> Response {
    // Clean up expired captchas to avoid unbounded growth
    let now = now_millis();
    state.captchas.retain(|_, v| now < v.1);

    let code = gen_captcha_code();
    let id = gen_session_token();
    state
        .captchas
        .insert(id.clone(), (code.clone(), now + CAPTCHA_TTL_MS));
    let svg = gen_captcha_svg(&code);
    Response {
        status: "200 OK",
        content_type: "image/svg+xml",
        extra_headers: format!(
            "Set-Cookie: captcha={id}; Path=/; HttpOnly; SameSite=Strict\r\nCache-Control: no-store\r\n"
        ),
        body: svg.into_bytes(),
    }
}

fn api_logout(req: &HttpRequest, state: &AdminState) -> Response {
    if let Some(s) = &req.session {
        state.sessions.remove(s);
    }
    Response {
        status: "200 OK",
        content_type: "application/json",
        extra_headers: "Set-Cookie: session=; Path=/; HttpOnly; Max-Age=0\r\n".to_string(),
        body: json_ok(),
    }
}

// ---------------------------------------------------------------------------
// API implementation
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ApiOk {
    ok: bool,
}

#[derive(Serialize)]
struct ApiError {
    ok: bool,
    error: String,
}

fn json_ok() -> Vec<u8> {
    serde_json::to_vec(&ApiOk { ok: true }).unwrap_or_else(|_| b"{}".to_vec())
}

fn json_error(msg: &str) -> Vec<u8> {
    serde_json::to_vec(&ApiError {
        ok: false,
        error: msg.to_string(),
    })
    .unwrap_or_else(|_| b"{}".to_vec())
}

fn json_body<T: Serialize>(v: &T) -> Vec<u8> {
    serde_json::to_vec(v).unwrap_or_else(|_| b"{}".to_vec())
}

async fn api_status(state: &AdminState) -> Response {
    #[derive(Serialize)]
    struct Status {
        clients: usize,
        proxies: usize,
        tunnel_addr: String,
        admin_listen: String,
        token: String,
    }
    let s = Status {
        clients: state.manager.len(),
        proxies: state.proxies.read().await.len(),
        tunnel_addr: state.base.read().await.tunnel_addr.clone(),
        admin_listen: state.base.read().await.admin.listen.clone(),
        token: state.token.read().await.clone(),
    };
    json_response("200 OK", json_body(&s))
}

async fn api_clients(state: &AdminState) -> Response {
    let list = state.manager.list();
    json_response("200 OK", json_body(&list))
}

/// Traffic summary for a single client (cumulative + live incremental delta).
#[derive(Serialize)]
struct TrafficEntry {
    client_id: String,
    online: bool,
    tcp_up: u64,
    tcp_down: u64,
    udp_up: u64,
    udp_down: u64,
}

/// Computes the total traffic for each client_id (persisted cumulative + live online session deltas).
async fn traffic_totals(state: &AdminState) -> std::collections::HashMap<String, TrafficCounter> {
    let mut totals = state.traffic.snapshot();
    for info in state.manager.list() {
        if let Some(session) = state.manager.get(&info.client_id) {
            let delta = session.traffic_snapshot();
            let e = totals.entry(info.client_id).or_default();
            e.tcp_up += delta.tcp_up;
            e.tcp_down += delta.tcp_down;
            e.udp_up += delta.udp_up;
            e.udp_down += delta.udp_down;
        }
    }
    totals
}

/// `GET /api/traffic`: returns cumulative traffic per client_id, with the live
/// per-session deltas (not yet persisted) added for online clients.
async fn api_traffic(state: &AdminState) -> Response {
    let totals = traffic_totals(state).await;
    let online: Vec<String> = state.manager.list().iter().map(|i| i.client_id.clone()).collect();

    let mut entries: Vec<TrafficEntry> = totals
        .iter()
        .map(|(client_id, t)| TrafficEntry {
            client_id: client_id.clone(),
            online: online.contains(client_id),
            tcp_up: t.tcp_up,
            tcp_down: t.tcp_down,
            udp_up: t.udp_up,
            udp_down: t.udp_down,
        })
        .collect();
    // Online clients with zero cumulative traffic must also be shown (their live deltas may be growing)
    for cid in online.iter() {
        if !totals.contains_key(cid) {
            entries.push(TrafficEntry {
                client_id: cid.clone(),
                online: true,
                tcp_up: 0,
                tcp_down: 0,
                udp_up: 0,
                udp_down: 0,
            });
        }
    }
    entries.sort_by(|a, b| a.client_id.cmp(&b.client_id));
    json_response("200 OK", json_body(&entries))
}

/// `GET /api/traffic/history`: returns time-series history samples (ascending),
/// used by the frontend to draw the traffic curve.
async fn api_traffic_history(state: &AdminState) -> Response {
    let hist = state.traffic.history();
    json_response("200 OK", json_body(&hist))
}

/// `GET /metrics`: Prometheus text-format metrics (`text/plain; version=0.0.4`).
/// No login required; scraped directly by Prometheus.
async fn api_metrics(state: &AdminState) -> Response {
    use std::fmt::Write;

    let mut out = String::new();
    let clients = state.manager.list();
    let totals = traffic_totals(state).await;

    // Number of online clients
    let _ = writeln!(out, "# HELP zorv_online_clients Current number of online clients");
    let _ = writeln!(out, "# TYPE zorv_online_clients gauge");
    let _ = writeln!(out, "zorv_online_clients {}", clients.len());

    // Number of configured proxy rules
    let _ = writeln!(out, "# HELP zorv_configured_proxies 已配置的代理规则数");
    let _ = writeln!(out, "# TYPE zorv_configured_proxies gauge");
    let _ = writeln!(out, "zorv_configured_proxies {}", state.proxies.read().await.len());

    // Total number of currently active streams
    let active_streams: usize = clients.iter().map(|c| c.active_streams).sum();
    let _ = writeln!(out, "# HELP zorv_active_streams 当前活动的业务流总数");
    let _ = writeln!(out, "# TYPE zorv_active_streams gauge");
    let _ = writeln!(out, "zorv_active_streams {active_streams}");

    // Cumulative traffic per client (including live online deltas)
    let _ = writeln!(out, "# HELP zorv_traffic_tcp_up_bytes_total 累计 TCP 上行字节数");
    let _ = writeln!(out, "# TYPE zorv_traffic_tcp_up_bytes_total counter");
    let _ = writeln!(out, "# HELP zorv_traffic_tcp_down_bytes_total 累计 TCP 下行字节数");
    let _ = writeln!(out, "# TYPE zorv_traffic_tcp_down_bytes_total counter");
    let _ = writeln!(out, "# HELP zorv_traffic_udp_up_bytes_total 累计 UDP 上行字节数");
    let _ = writeln!(out, "# TYPE zorv_traffic_udp_up_bytes_total counter");
    let _ = writeln!(out, "# HELP zorv_traffic_udp_down_bytes_total 累计 UDP 下行字节数");
    let _ = writeln!(out, "# TYPE zorv_traffic_udp_down_bytes_total counter");
    let mut keys: Vec<&String> = totals.keys().collect();
    keys.sort();
    for client_id in keys {
        let c = &totals[client_id];
        let cid = prom_escape(client_id);
        let _ = writeln!(out, "zorv_traffic_tcp_up_bytes_total{{client_id=\"{cid}\"}} {}", c.tcp_up);
        let _ = writeln!(out, "zorv_traffic_tcp_down_bytes_total{{client_id=\"{cid}\"}} {}", c.tcp_down);
        let _ = writeln!(out, "zorv_traffic_udp_up_bytes_total{{client_id=\"{cid}\"}} {}", c.udp_up);
        let _ = writeln!(out, "zorv_traffic_udp_down_bytes_total{{client_id=\"{cid}\"}} {}", c.udp_down);
    }

    Response {
        status: "200 OK",
        content_type: "text/plain; version=0.0.4; charset=utf-8",
        extra_headers: String::new(),
        body: out.into_bytes(),
    }
}

/// Escape a Prometheus label value: `\`, `"`, and newlines.
fn prom_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// `POST /api/kick`: kicks the online client with the given client_id.
///
/// Sends an `ERROR` frame to the client (reason: kicked by admin); the client exits on receipt;
/// the session is then removed from the session table, and the connection closes naturally when the client exits.
async fn api_kick(req: &HttpRequest, state: &AdminState) -> Response {
    #[derive(Deserialize)]
    struct KickReq {
        client_id: String,
    }
    let kreq: KickReq = match serde_json::from_slice(&req.body) {
        Ok(k) => k,
        Err(e) => {
            return json_err_response("400 Bad Request", &format!("invalid kick json: {e}"));
        }
    };
    if kreq.client_id.is_empty() {
        return json_err_response("400 Bad Request", "client_id is required");
    }

    let session = match state.manager.get(&kreq.client_id) {
        Some(s) => s,
        None => return json_err_response("404 Not Found", "client not online"),
    };

    let frame = crate::protocol::build_error_frame("已被管理员踢出");
    if session.frame_tx.send(frame).await.is_err() {
        return json_err_response("409 Conflict", "tunnel closed");
    }

    // Remove the session: after the kick, no new streams are accepted for this client_id (the connection closes itself once the client exits)
    state.manager.unregister(&kreq.client_id);
    audit("kick", &format!("client_id={}", kreq.client_id));
    info!("kicked client: {}", kreq.client_id);
    json_response("200 OK", json_ok())
}

async fn api_proxies(state: &AdminState) -> Response {
    let list = state.proxies.read().await.clone();
    json_response("200 OK", json_body(&list))
}

async fn api_create_proxy(req: &HttpRequest, state: &AdminState) -> Response {
    let proxy: ProxyConfig = match serde_json::from_slice(&req.body) {
        Ok(p) => p,
        Err(e) => {
            return json_err_response("400 Bad Request", &format!("invalid proxy json: {e}"));
        }
    };

    if proxy.name.is_empty() {
        return json_err_response("400 Bad Request", "name is required");
    }
    if proxy.listen.is_none() {
        return json_err_response("400 Bad Request", "listen is required");
    }

    // Same name already exists = edit/update: stop the old listener first (if running), then restart with the new config
    let existed = state
        .proxies
        .read()
        .await
        .iter()
        .any(|p| p.name == proxy.name);
    if existed {
        state.proxy_manager.stop(&proxy.name).await;
    }

    // Start the listener (a bind failure returns Err)
    if let Err(e) = state.proxy_manager.start(proxy.clone()).await {
        return json_err_response("400 Bad Request", &format!("start proxy failed: {e}"));
    }

    audit(
        "upsert_proxy",
        &format!(
            "name={} type={} listen={:?} client_id={:?} target={}",
            proxy.name, proxy.proxy_type, proxy.listen, proxy.client_id, proxy.target
        ),
    );

    // Update the in-memory list (replace by name)
    {
        let mut proxies = state.proxies.write().await;
        proxies.retain(|p| p.name != proxy.name);
        proxies.push(proxy);
    }

    persist(state).await;
    json_response("200 OK", json_ok())
}

async fn api_delete_proxy(query: &str, state: &AdminState) -> Response {
    let name = query
        .split('&')
        .find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            if k == "name" {
                Some(url_decode(v))
            } else {
                None
            }
        })
        .unwrap_or_default();

    if name.is_empty() {
        return json_err_response("400 Bad Request", "name is required");
    }

    let stopped = state.proxy_manager.stop(&name).await;
    if !stopped {
        return json_err_response("404 Not Found", "proxy not running");
    }

    {
        let mut proxies = state.proxies.write().await;
        proxies.retain(|p| p.name != name);
    }
    audit("delete_proxy", &format!("name={}", name));

    persist(state).await;
    json_response("200 OK", json_ok())
}

async fn api_update_token(req: &HttpRequest, state: &AdminState) -> Response {
    #[derive(Deserialize)]
    struct TokenReq {
        token: String,
    }
    let treq: TokenReq = match serde_json::from_slice(&req.body) {
        Ok(t) => t,
        Err(e) => {
            return json_err_response("400 Bad Request", &format!("invalid token json: {e}"));
        }
    };

    // Auto-generate a random token when left empty (128-bit entropy, 32 hex chars)
    let new_token = if treq.token.is_empty() {
        gen_token()
    } else {
        treq.token
    };

    *state.token.write().await = new_token.clone();
    audit("update_token", "token rotated");

    persist(state).await;
    // Return the new token for the admin UI to display and copy.
    let body = serde_json::json!({ "ok": true, "token": new_token });
    json_response("200 OK", json_body(&body))
}

/// Generates a random token: a 32-character hex string (128-bit entropy).
fn gen_token() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `POST /api/reload`: reloads the config file from disk, hot-updating the token and proxy rules (no restart).
///
/// Differential application: rules removed are stopped, new/changed rules are started with the new config, and the token is swapped immediately;
/// the startup snapshot `base` is also updated so subsequent `persist` calls do not lose other on-disk fields.
async fn api_reload(state: &AdminState) -> Response {
    if state.config_path.is_empty() {
        return json_err_response("400 Bad Request", "config path not set");
    }
    let cfg = match crate::common::config::load_server(&state.config_path) {
        Ok(c) => c,
        Err(e) => {
            return json_err_response("400 Bad Request", &format!("reload failed: {e}"));
        }
    };

    // 1. Sync the token
    *state.token.write().await = cfg.auth.token.clone();

    // 2. Apply proxy rules differentially
    let desired = cfg.proxies.clone();
    let current = state.proxies.read().await.clone();

    // 2a. Stop rules that were removed
    for p in &current {
        if !desired.iter().any(|d| d.name == p.name) {
            state.proxy_manager.stop(&p.name).await;
        }
    }
    // 2b. Start new/changed rules (changed: stop the old one first, then start the new one, to avoid port conflicts)
    for d in &desired {
        let same = current.iter().find(|p| p.name == d.name);
        let changed = same.map(|p| p != d).unwrap_or(true);
        if changed {
            if same.is_some() {
                state.proxy_manager.stop(&d.name).await;
            }
            if let Err(e) = state.proxy_manager.start(d.clone()).await {
                return json_err_response(
                    "400 Bad Request",
                    &format!("start proxy {} failed: {}", d.name, e),
                );
            }
        }
    }
    *state.proxies.write().await = desired;
    *state.base.write().await = cfg;
    audit("reload", "config reloaded from disk");
    info!("config reloaded from {}", state.config_path);
    json_response("200 OK", json_ok())
}

/// Writes the config back: starting from the startup snapshot, replacing the current token and proxies.
async fn persist(state: &AdminState) {
    let mut cfg = state.base.read().await.clone();
    cfg.auth.token = state.token.read().await.clone();
    cfg.proxies = state.proxies.read().await.clone();
    if let Err(e) = save_server(&state.config_path, &cfg) {
        error!("persist config failed: {e}");
    }
}

/// Minimal URL decoder (percent-decoding only).
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::config::{
        AdminConfig, AuthConfig, LogConfig, NotifyConfig, ObfuscationConfig, PerformanceConfig,
        ServerTlsConfig,
    };

    #[test]
    fn password_verification() {
        // Plaintext (backward compatible)t (backward compatible)
        assert!(verify_password("secret", "secret"));
        assert!(!verify_password("wrong", "secret"));
        // PBKDF2-HMAC-SHA256 hashsh
        let hash = hash_password("secret");
        assert!(hash.starts_with("$pbkdf2-sha256$"));
        assert!(verify_password("secret", &hash));
        assert!(!verify_password("wrong", &hash));
        // A corrupted hash must fail verificationd hash must fail verification
        let broken = format!("{}0", &hash[..hash.len() - 1]);
        assert!(!verify_password("secret", &broken));
    }

    fn make_state_with_password(password: &str) -> Arc<AdminState> {
        let manager = Arc::new(TunnelManager::new());
        let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&manager)));
        let base = ServerConfig {
            tunnel_addr: "127.0.0.1:8443".to_string(),
            tls: ServerTlsConfig {
                cert_file: "c.pem".to_string(),
                key_file: "k.pem".to_string(),
            },
            auth: AuthConfig {
                token: "init-token".to_string(),
                allowed_ips: None,
            },
            proxies: vec![],
            performance: PerformanceConfig::default(),
            log: LogConfig::default(),
            obfuscation: ObfuscationConfig::default(),
            admin: AdminConfig::default(),
            data_dir: std::env::temp_dir().to_string_lossy().into_owned(),
            notify: NotifyConfig::default(),
        };
        Arc::new(AdminState {
            manager,
            token: Arc::new(RwLock::new("init-token".to_string())),
            proxies: Arc::new(RwLock::new(vec![])),
            proxy_manager,
            config_path: String::new(),
            base: RwLock::new(base),
            username: "admin".to_string(),
            password: password.to_string(),
            sessions: DashMap::new(),
            login_failures: DashMap::new(),
            blocked_ips: DashMap::new(),
            captchas: DashMap::new(),
            traffic: Arc::new(TrafficTracker::load(&std::env::temp_dir().to_string_lossy())),
        })
    }

    fn make_state() -> Arc<AdminState> {
        make_state_with_password("")
    }

    fn req(method: &str, path: &str, body: Vec<u8>) -> HttpRequest {
        HttpRequest {
            method: method.to_string(),
            path: path.to_string(),
            body,
            ip: "127.0.0.1".to_string(),
            session: None,
            captcha: None,
        }
    }

    fn req_session(method: &str, path: &str, session: &str) -> HttpRequest {
        HttpRequest {
            method: method.to_string(),
            path: path.to_string(),
            body: Vec::new(),
            ip: "127.0.0.1".to_string(),
            session: Some(session.to_string()),
            captcha: None,
        }
    }

    /// Login request (with captcha).
    fn login_req(body: Vec<u8>, captcha_id: Option<&str>) -> HttpRequest {
        HttpRequest {
            method: "POST".to_string(),
            path: "/api/login".to_string(),
            body,
            ip: "127.0.0.1".to_string(),
            session: None,
            captcha: captcha_id.map(|s| s.to_string()),
        }
    }

    /// Presets a captcha (answer ABCD) and returns its id.
    fn add_captcha(state: &AdminState) -> String {
        let id = "captcha-test".to_string();
        state
            .captchas
            .insert(id.clone(), ("ABCD".to_string(), now_millis() + 60_000));
        id
    }

    #[test]
    fn url_decode_works() {
        assert_eq!(url_decode("home%20nas"), "home nas");
        assert_eq!(url_decode("a%2Fb"), "a/b");
        assert_eq!(url_decode("plain"), "plain");
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "ab"));
    }

    #[tokio::test]
    async fn route_serves_pages() {
        let state = make_state();
        let resp = route(&req("GET", "/", vec![]), &state).await;
        assert_eq!(resp.status, "200 OK");
        assert!(String::from_utf8_lossy(&resp.body).contains("Zorv"));

        let resp = route(&req("GET", "/clients.html", vec![]), &state).await;
        assert_eq!(resp.status, "200 OK");

        let resp = route(&req("GET", "/nope", vec![]), &state).await;
        assert_eq!(resp.status, "404 Not Found");
    }

    #[tokio::test]
    async fn api_status_returns_counts() {
        let state = make_state();
        let resp = route(&req("GET", "/api/status", vec![]), &state).await;
        assert_eq!(resp.status, "200 OK");
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["clients"], 0);
        assert_eq!(v["proxies"], 0);
        assert_eq!(v["token"], "init-token");
    }

    #[tokio::test]
    async fn api_proxy_crud() {
        let state = make_state();

        let proxy = ProxyConfig {
            name: "test-proxy".to_string(),
            proxy_type: "tcp".to_string(),
            listen: Some("127.0.0.1:0".to_string()),
            client_id: Some("c1".to_string()),
            target: "127.0.0.1:80".to_string(),
        };
        let body = serde_json::to_vec(&proxy).unwrap();
        let resp = route(&req("POST", "/api/proxies", body), &state).await;
        assert_eq!(resp.status, "200 OK", "body={}", String::from_utf8_lossy(&resp.body));

        let resp = route(&req("GET", "/api/proxies", vec![]), &state).await;
        let list: Vec<ProxyConfig> = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "test-proxy");

        let resp = route(&req("DELETE", "/api/proxies?name=test-proxy", vec![]), &state).await;
        assert_eq!(resp.status, "200 OK");

        let resp = route(&req("GET", "/api/proxies", vec![]), &state).await;
        let list: Vec<ProxyConfig> = serde_json::from_slice(&resp.body).unwrap();
        assert!(list.is_empty());
    }

    #[tokio::test]
    async fn api_traffic_history_returns_samples() {
        let state = make_state();
        state.traffic.merge(
            "c1",
            &crate::server::traffic::TrafficCounter {
                tcp_up: 100,
                tcp_down: 0,
                udp_up: 0,
                udp_down: 0,
            },
        );
        state.traffic.sample(&std::collections::HashMap::new());

        let resp = route(&req("GET", "/api/traffic/history", vec![]), &state).await;
        assert_eq!(resp.status, "200 OK", "body={}", String::from_utf8_lossy(&resp.body));
        let hist: Vec<serde_json::Value> = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(hist.len(), 1);
        assert_eq!(hist[0]["totals"]["c1"]["tcp_up"], 100);
        assert!(hist[0]["ts_ms"].as_u64().unwrap() > 0);
    }

    #[tokio::test]
    async fn api_traffic_returns_totals() {
        let state = make_state();
        state.traffic.merge(
            "c1",
            &crate::server::traffic::TrafficCounter {
                tcp_up: 100,
                tcp_down: 200,
                udp_up: 10,
                udp_down: 20,
            },
        );
        let resp = route(&req("GET", "/api/traffic", vec![]), &state).await;
        assert_eq!(resp.status, "200 OK", "body={}", String::from_utf8_lossy(&resp.body));
        let list: Vec<serde_json::Value> = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["client_id"], "c1");
        assert_eq!(list[0]["tcp_up"], 100);
        assert_eq!(list[0]["tcp_down"], 200);
        assert_eq!(list[0]["udp_up"], 10);
        assert_eq!(list[0]["udp_down"], 20);
        assert_eq!(list[0]["online"], false);
    }

    #[tokio::test]
    async fn api_traffic_includes_online_session() {
        let state = make_state();
        // Build an online session and inject traffic deltas
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let session = Arc::new(crate::server::manager::TunnelSession {
            client_id: "c2".to_string(),
            session_id: "s".to_string(),
            frame_tx: tx,
            streams: DashMap::new(),
            pending_opens: DashMap::new(),
            id_alloc: crate::protocol::StreamIdAllocator::new_server(),
            last_activity: std::sync::atomic::AtomicU64::new(now_millis()),
            udp: DashMap::new(),
            tcp_rx_bytes: std::sync::atomic::AtomicU64::new(7),
            tcp_tx_bytes: std::sync::atomic::AtomicU64::new(8),
            udp_rx_bytes: std::sync::atomic::AtomicU64::new(9),
            udp_tx_bytes: std::sync::atomic::AtomicU64::new(10),
        });
        state.manager.register(session);

        let resp = route(&req("GET", "/api/traffic", vec![]), &state).await;
        assert_eq!(resp.status, "200 OK");
        let list: Vec<serde_json::Value> = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["client_id"], "c2");
        assert_eq!(list[0]["online"], true);
        assert_eq!(list[0]["tcp_up"], 7);
        assert_eq!(list[0]["tcp_down"], 8);
        assert_eq!(list[0]["udp_up"], 9);
        assert_eq!(list[0]["udp_down"], 10);
    }

    #[tokio::test]
    async fn api_kick_removes_online_client() {
        let state = make_state();
        // Build an online session
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let session = Arc::new(crate::server::manager::TunnelSession {
            client_id: "kick-me".to_string(),
            session_id: "s".to_string(),
            frame_tx: tx,
            streams: DashMap::new(),
            pending_opens: DashMap::new(),
            id_alloc: crate::protocol::StreamIdAllocator::new_server(),
            last_activity: std::sync::atomic::AtomicU64::new(now_millis()),
            udp: DashMap::new(),
            tcp_rx_bytes: std::sync::atomic::AtomicU64::new(0),
            tcp_tx_bytes: std::sync::atomic::AtomicU64::new(0),
            udp_rx_bytes: std::sync::atomic::AtomicU64::new(0),
            udp_tx_bytes: std::sync::atomic::AtomicU64::new(0),
        });
        state.manager.register(session);
        assert_eq!(state.manager.len(), 1);

        // Kick a non-existent client → 404
        let body = br#"{"client_id":"ghost"}"#.to_vec();
        let resp = route(&req("POST", "/api/kick", body), &state).await;
        assert_eq!(resp.status, "404 Not Found");

        // Kick an online client → 200 and the session is removed
        let body = br#"{"client_id":"kick-me"}"#.to_vec();
        let resp = route(&req("POST", "/api/kick", body), &state).await;
        assert_eq!(resp.status, "200 OK", "body={}", String::from_utf8_lossy(&resp.body));
        assert_eq!(state.manager.len(), 0);
    }

    #[test]
    fn error_frame_roundtrip() {
        let frame = crate::protocol::build_error_frame("已被管理员踢出");
        assert_eq!(frame.frame_type, crate::protocol::FrameType::Error);
        assert_eq!(
            crate::protocol::parse_error_payload(&frame.payload).unwrap(),
            "已被管理员踢出"
        );
    }

    #[tokio::test]
    async fn api_update_token() {
        let state = make_state();
        let body = br#"{"token":"new-token"}"#.to_vec();
        let resp = route(&req("PUT", "/api/token", body), &state).await;
        assert_eq!(resp.status, "200 OK", "body={}", String::from_utf8_lossy(&resp.body));
        assert_eq!(*state.token.read().await, "new-token");
    }

    #[tokio::test]
    async fn api_reload_syncs_token_and_proxies() {
        let dir = std::env::temp_dir().join(format!("zorv-reload-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("zorvd.toml");
        let write_cfg = |content: &str| std::fs::write(&path, content).unwrap();

        write_cfg(
            r#"
            tunnel_addr = "127.0.0.1:8443"
            [tls]
            cert_file = "c.pem"
            key_file = "k.pem"
            [auth]
            token = "reloaded-token"
            [[proxies]]
            name = "p1"
            type = "tcp"
            listen = "127.0.0.1:0"
            client_id = "c1"
            target = "127.0.0.1:80"
            "#,
        );

        let mut state = make_state();
        let state_ref = Arc::get_mut(&mut state).unwrap();
        state_ref.config_path = path.to_str().unwrap().to_string();
        assert_eq!(*state.token.read().await, "init-token");

        // First reload: token and rules synced from disk
        let resp = route(&req("POST", "/api/reload", vec![]), &state).await;
        assert_eq!(resp.status, "200 OK", "body={}", String::from_utf8_lossy(&resp.body));
        assert_eq!(*state.token.read().await, "reloaded-token");
        assert_eq!(state.base.read().await.auth.token, "reloaded-token");
        {
            let proxies = state.proxies.read().await;
            assert_eq!(proxies.len(), 1);
            assert_eq!(proxies[0].name, "p1");
        }
        assert_eq!(state.proxy_manager.running_names(), vec!["p1".to_string()]);

        // Modify the on-disk config: remove p1, add p2 → differential apply: stop p1, start p2
        write_cfg(
            r#"
            tunnel_addr = "127.0.0.1:8443"
            [tls]
            cert_file = "c.pem"
            key_file = "k.pem"
            [auth]
            token = "reloaded-token"
            [[proxies]]
            name = "p2"
            type = "tcp"
            listen = "127.0.0.1:0"
            client_id = "c2"
            target = "127.0.0.1:81"
            "#,
        );
        let resp = route(&req("POST", "/api/reload", vec![]), &state).await;
        assert_eq!(resp.status, "200 OK", "body={}", String::from_utf8_lossy(&resp.body));
        {
            let proxies = state.proxies.read().await;
            assert_eq!(proxies.len(), 1);
            assert_eq!(proxies[0].name, "p2");
        }
        assert_eq!(state.proxy_manager.running_names(), vec!["p2".to_string()]);

        // Invalid config -> error and in-memory state unchanged
        write_cfg("tunnel_addr = not-a-toml");
        let resp = route(&req("POST", "/api/reload", vec![]), &state).await;
        assert_eq!(resp.status, "400 Bad Request");
        assert_eq!(*state.token.read().await, "reloaded-token");
        assert_eq!(state.proxy_manager.running_names(), vec!["p2".to_string()]);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn api_update_token_generates_random_when_empty() {
        let state = make_state();
        let body = br#"{"token":""}"#.to_vec();
        let resp = route(&req("PUT", "/api/token", body), &state).await;
        assert_eq!(resp.status, "200 OK", "body={}", String::from_utf8_lossy(&resp.body));
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["ok"], true);
        let new_token = v["token"].as_str().unwrap().to_string();
        // Randomly generated: non-empty and already updated in memory
        assert!(!new_token.is_empty());
        assert_eq!(new_token.len(), 32);
        assert_eq!(*state.token.read().await, new_token);
    }

    #[tokio::test]
    async fn auth_required_when_password_set() {
        let state = make_state_with_password("secret");

        // API access without login → 401
        let resp = route(&req("GET", "/api/status", vec![]), &state).await;
        assert_eq!(resp.status, "401 Unauthorized");

        // Visiting a page without login → redirect to the login page
        let resp = route(&req("GET", "/", vec![]), &state).await;
        assert_eq!(resp.status, "302 Found");
        assert!(resp.extra_headers.contains("Location: /login.html"));

        // The login page itself requires no auth
        let resp = route(&req("GET", "/login.html", vec![]), &state).await;
        assert_eq!(resp.status, "200 OK");
    }

    #[tokio::test]
    async fn login_flow_grants_access() {
        let state = make_state_with_password("secret");

        // Wrong password → 401
        let cid = add_captcha(&state);
        let body = br#"{"username":"admin","password":"wrong","captcha_code":"ABCD"}"#.to_vec();
        let resp = route(&login_req(body, Some(&cid)), &state).await;
        assert_eq!(resp.status, "401 Unauthorized");

        // Correct password → session cookie returned
        let cid = add_captcha(&state); // consumed last captcha
        let body = br#"{"username":"admin","password":"secret","captcha_code":"abcd"}"#.to_vec();
        let resp = route(&login_req(body, Some(&cid)), &state).await;
        assert_eq!(resp.status, "200 OK");
        let session = resp
            .extra_headers
            .split("session=")
            .nth(1)
            .and_then(|s| s.split(';').next())
            .unwrap()
            .to_string();
        assert!(!session.is_empty());

        // API access with session → allowed
        let resp = route(&req_session("GET", "/api/status", &session), &state).await;
        assert_eq!(resp.status, "200 OK");

        // Session is invalid after logout
        let resp = route(&req_session("POST", "/api/logout", &session), &state).await;
        assert_eq!(resp.status, "200 OK");
        let resp = route(&req_session("GET", "/api/status", &session), &state).await;
        assert_eq!(resp.status, "401 Unauthorized");
    }

    #[tokio::test]
    async fn captcha_required_and_consumed() {
        let state = make_state_with_password("secret");

        // No captcha provided → rejected
        let body = br#"{"username":"admin","password":"secret","captcha_code":""}"#.to_vec();
        let resp = route(&login_req(body, None), &state).await;
        assert_eq!(resp.status, "401 Unauthorized");
        assert!(String::from_utf8_lossy(&resp.body).contains("验证码"));

        // Wrong captcha → rejected and consumed (single use)
        let cid = add_captcha(&state);
        let body = br#"{"username":"admin","password":"secret","captcha_code":"ZZZZ"}"#.to_vec();
        let resp = route(&login_req(body, Some(&cid)), &state).await;
        assert_eq!(resp.status, "401 Unauthorized");
        assert!(state.captchas.get(&cid).is_none(), "captcha must be single use");

        // Correct captcha → allowed
        let cid = add_captcha(&state);
        let body = br#"{"username":"admin","password":"secret","captcha_code":"ABCD"}"#.to_vec();
        let resp = route(&login_req(body, Some(&cid)), &state).await;
        assert_eq!(resp.status, "200 OK");
    }

    #[tokio::test]
    async fn login_failures_block_ip() {
        let state = make_state_with_password("secret");
        // Consecutive wrong passwords ban the IP
        for i in 0..5 {
            let cid = add_captcha(&state);
            let body = br#"{"username":"admin","password":"wrong","captcha_code":"ABCD"}"#.to_vec();
            let resp = route(&login_req(body, Some(&cid)), &state).await;
            assert_eq!(resp.status, "401 Unauthorized", "attempt {}", i + 1);
        }
        assert!(state.blocked_ips.contains_key("127.0.0.1"), "IP should be banned");
        assert!(is_ip_blocked(&state, "127.0.0.1"));
    }

    #[tokio::test]
    async fn login_success_resets_failures() {
        let state = make_state_with_password("secret");
        // Login succeeds after 2 failures → failure count reset
        for _ in 0..2 {
            let cid = add_captcha(&state);
            let body = br#"{"username":"admin","password":"wrong","captcha_code":"ABCD"}"#.to_vec();
            let resp = route(&login_req(body, Some(&cid)), &state).await;
            assert_eq!(resp.status, "401 Unauthorized");
        }
        let cid = add_captcha(&state);
        let body = br#"{"username":"admin","password":"secret","captcha_code":"ABCD"}"#.to_vec();
        let resp = route(&login_req(body, Some(&cid)), &state).await;
        assert_eq!(resp.status, "200 OK");
        assert!(state.login_failures.get("127.0.0.1").is_none());
        assert!(state.blocked_ips.is_empty());
    }

    #[test]
    fn block_expires_and_clears() {
        let state = make_state();
        state
            .blocked_ips
            .insert("1.2.3.4".to_string(), now_millis() - 1);
        assert!(!is_ip_blocked(&state, "1.2.3.4"), "过期封禁应解除");
        assert!(state.blocked_ips.get("1.2.3.4").is_none(), "过期封禁应被清理");
    }

    #[tokio::test]
    async fn api_captcha_returns_svg_and_cookie() {
        let state = make_state();
        let resp = route(&req("GET", "/api/captcha", vec![]), &state).await;
        assert_eq!(resp.status, "200 OK");
        assert!(resp.content_type.starts_with("image/svg+xml"));
        assert!(resp.extra_headers.contains("Set-Cookie: captcha="));
        assert!(String::from_utf8_lossy(&resp.body).contains("<svg"));
        assert_eq!(state.captchas.len(), 1);
    }

    #[tokio::test]
    async fn api_captcha_with_query_needs_no_auth() {
        // Browsers actually request with a ?t= timestamp and no session before login; the image should be returned directly instead of a 401
        let state = make_state_with_password("secret");
        let resp = route(&req("GET", "/api/captcha?t=123456", vec![]), &state).await;
        assert_eq!(resp.status, "200 OK", "body={}", String::from_utf8_lossy(&resp.body));
        assert!(String::from_utf8_lossy(&resp.body).contains("<svg"));
    }

    #[test]
    fn prom_escape_works() {
        assert_eq!(prom_escape("plain"), "plain");
        assert_eq!(prom_escape(r#"a"b\c"#), r#"a\"b\\c"#);
        assert_eq!(prom_escape("x\ny"), "x\\ny");
    }

    #[tokio::test]
    async fn metrics_accessible_without_auth() {
        // Prometheus scrapers have no cookie: /metrics must stay accessible without auth
        let state = make_state_with_password("secret");
        let resp = route(&req("GET", "/metrics", vec![]), &state).await;
        assert_eq!(resp.status, "200 OK", "body={}", String::from_utf8_lossy(&resp.body));
        assert!(resp.content_type.starts_with("text/plain"));
        let body = String::from_utf8_lossy(&resp.body);
        assert!(body.contains("zorv_online_clients 0"));
        assert!(body.contains("zorv_configured_proxies 0"));
        assert!(body.contains("zorv_active_streams 0"));
    }

    #[tokio::test]
    async fn metrics_include_traffic_and_online() {
        let state = make_state();
        // Cumulative traffic (historical)
        state.traffic.merge(
            "c-hist",
            &crate::server::traffic::TrafficCounter {
                tcp_up: 100,
                tcp_down: 200,
                udp_up: 10,
                udp_down: 20,
            },
        );
        // Online session (live delta, not yet persisted)
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let session = Arc::new(crate::server::manager::TunnelSession {
            client_id: "c-online".to_string(),
            session_id: "s".to_string(),
            frame_tx: tx,
            streams: DashMap::new(),
            pending_opens: DashMap::new(),
            id_alloc: crate::protocol::StreamIdAllocator::new_server(),
            last_activity: std::sync::atomic::AtomicU64::new(now_millis()),
            udp: DashMap::new(),
            tcp_rx_bytes: std::sync::atomic::AtomicU64::new(7),
            tcp_tx_bytes: std::sync::atomic::AtomicU64::new(8),
            udp_rx_bytes: std::sync::atomic::AtomicU64::new(9),
            udp_tx_bytes: std::sync::atomic::AtomicU64::new(10),
        });
        state.manager.register(session);

        let resp = route(&req("GET", "/metrics", vec![]), &state).await;
        assert_eq!(resp.status, "200 OK", "body={}", String::from_utf8_lossy(&resp.body));
        let body = String::from_utf8_lossy(&resp.body);
        assert!(body.contains("zorv_online_clients 1"));
        // Historical cumulative
        assert!(body.contains("zorv_traffic_tcp_up_bytes_total{client_id=\"c-hist\"} 100"));
        assert!(body.contains("zorv_traffic_udp_down_bytes_total{client_id=\"c-hist\"} 20"));
        // Live online delta added on top
        assert!(body.contains("zorv_traffic_tcp_up_bytes_total{client_id=\"c-online\"} 7"));
        assert!(body.contains("zorv_traffic_udp_up_bytes_total{client_id=\"c-online\"} 9"));
    }

    #[tokio::test]
    async fn metrics_escapes_client_id_labels() {
        let state = make_state();
        // client_id contains double quotes: the label value must be escaped to avoid breaking the Prometheus format
        state.traffic.merge(
            r#"we"ird"#,
            &crate::server::traffic::TrafficCounter {
                tcp_up: 1,
                tcp_down: 0,
                udp_up: 0,
                udp_down: 0,
            },
        );
        let resp = route(&req("GET", "/metrics", vec![]), &state).await;
        let body = String::from_utf8_lossy(&resp.body);
        assert!(body.contains(r#"client_id="we\"ird""#), "body={body}");
    }
}
