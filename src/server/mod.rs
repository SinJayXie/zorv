//! Server module entry point.
//!
//! Combines the `tunnel`, `listener`, `manager`, and `auth` submodules, providing the `Server::run` entry point:
//! build the TLS acceptor → create a `TunnelManager` → spawn the tunnel acceptor →
//! spawn a public-port listener for each TCP proxy → wait for ctrl_c for graceful shutdown.

pub mod admin;
pub mod audit;
pub mod auth;
pub mod listener;
pub mod manager;
pub mod notify;
pub mod proxy;
pub mod traffic;
pub mod tunnel;
pub mod udp;

use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use crate::common::config::ServerConfig;
use crate::common::tls::build_server_acceptor;
use crate::server::admin::{run_admin_server, AdminState};
use crate::server::audit::AuditLog;
use crate::server::manager::TunnelManager;
use crate::server::proxy::ProxyManager;
use crate::server::traffic::{TrafficTracker, SAMPLE_INTERVAL};
use crate::server::auth::ip_allowed;
use crate::server::tunnel::run_tunnel;

/// Default heartbeat parameters (matching the client-side convention).
const DEFAULT_HEARTBEAT_MIN: u32 = 25;
const DEFAULT_HEARTBEAT_MAX: u32 = 55;

/// Server entry point.
pub struct Server {
    config: ServerConfig,
    /// Path to the config file, used when the admin UI writes the config back.
    config_path: String,
}

impl Server {
    pub fn new(config: ServerConfig, config_path: String) -> Self {
        Self {
            config,
            config_path,
        }
    }

    /// Starts the server main loop.
    ///
    /// All background tasks run via `tokio::spawn`; the main loop returns after awaiting `ctrl_c`.
    pub async fn run(self) -> anyhow::Result<()> {
        // 1. Build the TLS acceptor
        let acceptor = build_server_acceptor(&self.config.tls.cert_file, &self.config.tls.key_file)?;
        info!(
            "tls acceptor built, listening on tunnel_addr={}",
            self.config.tunnel_addr
        );

        // 2. Session manager
        let manager = Arc::new(TunnelManager::new());

        // 3. Traffic tracker (merges on session close; samples every 30s and persists to disk)
        let traffic = Arc::new(TrafficTracker::load(&self.config.data_dir));
        {
            let traffic = Arc::clone(&traffic);
            let sample_manager = Arc::clone(&manager);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(SAMPLE_INTERVAL);
                loop {
                    interval.tick().await;
                    traffic.sample(&sample_manager.online_traffic());
                    traffic.save();
                }
            });
        }

        // 4. Spawn the tunnel acceptor
        let tunnel_addr = self.config.tunnel_addr.clone();
        let tunnel_manager = Arc::clone(&manager);
        let tunnel_acceptor: TlsAcceptor = acceptor.clone();
        let tunnel_token = Arc::new(RwLock::new(self.config.auth.token.clone()));
        // The admin UI shares the same token (the tunnel closure moves tunnel_token, so clone it here in advance)
        let admin_token = Arc::clone(&tunnel_token);
        let tunnel_obfuscation = self.config.obfuscation.clone();
        let tunnel_traffic = Arc::clone(&traffic);
        // Client IP allowlist / offline-notification Webhook: clone in advance so the closure does not move self.config
        let tunnel_allowed_ips = self.config.auth.allowed_ips.clone();
        let tunnel_webhook = self.config.notify.webhook.clone();
        tokio::spawn(async move {
            let listener = match TcpListener::bind(&tunnel_addr).await {
                Ok(l) => l,
                Err(e) => {
                    error!("bind tunnel addr {} failed: {}", tunnel_addr, e);
                    return;
                }
            };
            info!("tunnel listener started on {}", tunnel_addr);
            let allowed_ips = tunnel_allowed_ips;
            let webhook_cfg = tunnel_webhook;
            loop {
                match listener.accept().await {
                    Ok((tcp, peer)) => {
                        info!("new tunnel connection from {}", peer);
                        // Client IP allowlist check: reject immediately if not allowed
                        if let Some(ips) = &allowed_ips {
                            if !ip_allowed(&peer.ip(), ips) {
                                warn!(
                                    "tunnel connection from {} rejected: ip not in auth.allowed_ips",
                                    peer
                                );
                                continue;
                            }
                        }
                        let mgr = Arc::clone(&tunnel_manager);
                        let acc = tunnel_acceptor.clone();
                        let tok = tunnel_token.clone();
                        let obfs = tunnel_obfuscation.clone();
                        let trf = Arc::clone(&tunnel_traffic);
                        let webhook = webhook_cfg.clone();
                        tokio::spawn(async move {
                            if let Err(e) = run_tunnel(
                                tcp,
                                acc,
                                mgr,
                                tok,
                                DEFAULT_HEARTBEAT_MIN,
                                DEFAULT_HEARTBEAT_MAX,
                                obfs,
                                trf,
                                webhook,
                            )
                            .await
                            {
                                error!("tunnel session ended with error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("tunnel accept error: {}", e);
                    }
                }
            }
        });

        // 5. Start a public-port listener for each proxy rule (tcp/udp), managed dynamically by ProxyManager
        let audit_log = Arc::new(AuditLog::new(&self.config.data_dir));
        let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&manager), Arc::clone(&audit_log)));
        for proxy in self.config.proxies.iter() {
            if let Err(e) = proxy_manager.start(proxy.clone()).await {
                error!("start proxy {} failed: {}", proxy.name, e);
            }
        }

        // 6. Start the web admin UI (if enabled)
        if self.config.admin.enabled {
            let admin_state = Arc::new(AdminState {
                manager: Arc::clone(&manager),
                token: admin_token,
                proxies: Arc::new(RwLock::new(self.config.proxies.clone())),
                proxy_manager: Arc::clone(&proxy_manager),
                config_path: self.config_path.clone(),
                base: RwLock::new(self.config.clone()),
                username: self.config.admin.username.clone(),
                password: Arc::new(RwLock::new(self.config.admin.password.clone())),
                audit_logs: Arc::clone(&audit_log),
                traffic: Arc::clone(&traffic),
                sessions: dashmap::DashMap::new(),
                login_failures: dashmap::DashMap::new(),
                blocked_ips: dashmap::DashMap::new(),
                captchas: dashmap::DashMap::new(),
            });
            let admin_addr = self.config.admin.listen.clone();
            let admin_tls = self.config.admin.tls.clone();
            tokio::spawn(async move {
                if let Err(e) = run_admin_server(admin_addr, admin_state, admin_tls).await {
                    error!("admin server ended with error: {}", e);
                }
            });
        }

        // 7. Wait for ctrl_c
        tokio::signal::ctrl_c().await?;
        info!("ctrl_c received, shutting down...");
        Ok(())
    }
}
