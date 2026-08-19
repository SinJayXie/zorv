//! Dynamic management of proxy rules: start/stop tcp/udp listener tasks.
//!
//! `ProxyManager` maintains a `name → JoinHandle` map, supporting runtime creation/deletion of proxy rules.
//! `start` binds first (a port conflict returns Err); only after success does it spawn the listen loop and register the task;
//! `stop` aborts the corresponding task and removes the registration. Shared by the startup flow and the admin UI.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;
use tracing::info;

use crate::common::config::ProxyConfig;
use crate::common::error::{Result, ZorvError};
use crate::server::listener::run_proxy_listener;
use crate::server::manager::TunnelManager;
use crate::server::udp::run_udp_proxy_listener;

/// Proxy rule manager.
pub struct ProxyManager {
    tasks: Mutex<HashMap<String, JoinHandle<()>>>,
    manager: Arc<TunnelManager>,
}

impl ProxyManager {
    pub fn new(manager: Arc<TunnelManager>) -> Self {
        Self {
            tasks: Mutex::new(HashMap::new()),
            manager,
        }
    }

    /// Starts listening for a proxy rule. Returns Err on bind failure (no task registered).
    pub async fn start(&self, proxy: ProxyConfig) -> Result<()> {
        {
            let tasks = self.tasks.lock().unwrap();
            if tasks.contains_key(&proxy.name) {
                return Err(ZorvError::Other(format!(
                    "proxy {} already running",
                    proxy.name
                )));
            }
        }

        let handle = match proxy.proxy_type.as_str() {
            "tcp" => {
                let listen = proxy.listen.as_ref().ok_or_else(|| {
                    ZorvError::Other(format!("proxy {} missing listen address", proxy.name))
                })?;
                let listener = TcpListener::bind(listen).await?;
                let p = proxy.clone();
                let mgr = Arc::clone(&self.manager);
                tokio::spawn(async move {
                    run_proxy_listener(listener, p, mgr).await;
                })
            }
            "udp" => {
                let listen = proxy.listen.as_ref().ok_or_else(|| {
                    ZorvError::Other(format!("proxy {} missing listen address", proxy.name))
                })?;
                let socket = Arc::new(UdpSocket::bind(listen).await?);
                let p = proxy.clone();
                let mgr = Arc::clone(&self.manager);
                tokio::spawn(async move {
                    run_udp_proxy_listener(socket, p, mgr).await;
                })
            }
            other => {
                return Err(ZorvError::Other(format!("unsupported proxy type: {}", other)));
            }
        };

        self.tasks
            .lock()
            .unwrap()
            .insert(proxy.name.clone(), handle);
        info!("proxy started: name={}", proxy.name);
        Ok(())
    }

    /// Stops listening for a proxy rule, returning whether it succeeded (false if absent).
    ///
    /// After abort, `await` the listener task to fully finish (releasing the socket),
    /// so the same port can be immediately re-bound afterwards (editing-a-rule scenario).
    pub async fn stop(&self, name: &str) -> bool {
        let handle = self.tasks.lock().unwrap().remove(name);
        match handle {
            Some(h) => {
                h.abort();
                let _ = h.await;
                info!("proxy stopped: name={}", name);
                true
            }
            None => false,
        }
    }

    /// Returns the names of currently running proxy rules.
    pub fn running_names(&self) -> Vec<String> {
        self.tasks.lock().unwrap().keys().cloned().collect()
    }
}
