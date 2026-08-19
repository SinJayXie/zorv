//! Client UDP session management: tunnel UDP_DATAGRAM ↔ local UDP socket.
//!
//! On receiving a `UDP_DATAGRAM(stream_id, target, data)` from the server, this module
//! creates/reuses a local `UdpSocket`, sends `data` to `target`, and wraps the target's
//! reply as `UDP_DATAGRAM(stream_id, "", reply)` back to the server.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify};
use tracing::warn;

use crate::common::crypto::now_millis;
use crate::protocol::{Frame, build_udp_datagram};

/// UDP session timeout in milliseconds; 120s by default.
pub const UDP_SESSION_TIMEOUT_MS: u64 = 120_000;
/// UDP receive buffer.
const UDP_RECV_BUF: usize = 65535;

/// A single client UDP session.
struct UdpSession {
    socket: Arc<UdpSocket>,
    last_activity: AtomicU64,
    cancel: Arc<Notify>,
}

impl UdpSession {
    /// Update the last-activity timestamp.
    fn update_activity(&self) {
        self.last_activity.store(now_millis(), Ordering::Relaxed);
    }
}

/// Client UDP session manager.
pub struct UdpManager {
    sessions: DashMap<u32, Arc<UdpSession>>,
}

impl UdpManager {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
        }
    }

    /// Handle a UDP_DATAGRAM received from the server:
    /// - On first sight of the sid: parse the target, create a local socket, and spawn a reply task.
    /// - Send `data` to the local target.
    pub async fn handle_incoming(
        &self,
        sid: u32,
        target: &str,
        data: Vec<u8>,
        frame_tx: mpsc::Sender<Frame>,
    ) {
        // 1. If target is non-empty and the sid is new → create a session
        if !target.is_empty() && !self.sessions.contains_key(&sid) {
            match self.create_session(sid, target, frame_tx.clone()).await {
                Ok(session) => {
                    self.sessions.insert(sid, session);
                }
                Err(e) => {
                    warn!("create udp session {} -> {} failed: {}", sid, target, e);
                    return;
                }
            }
        }
        // 2. Send the data
        if let Some(session) = self.sessions.get(&sid).map(|r| Arc::clone(r.value())) {
            session.update_activity();
            if let Err(e) = session.socket.send(&data).await {
                warn!("udp send to {} failed: {}", sid, e);
                self.close_session(&sid);
            }
        }
    }

    /// Create a local UDP socket and spawn a reply task.
    async fn create_session(
        &self,
        sid: u32,
        target: &str,
        frame_tx: mpsc::Sender<Frame>,
    ) -> Result<Arc<UdpSession>, std::io::Error> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(target).await?;
        let socket = Arc::new(socket);
        let cancel = Arc::new(Notify::new());
        let session = Arc::new(UdpSession {
            socket: Arc::clone(&socket),
            last_activity: AtomicU64::new(now_millis()),
            cancel: Arc::clone(&cancel),
        });

        // Spawn a reply task: read the target's response from the local socket → send it back to the server
        let recv_socket = Arc::clone(&socket);
        let recv_cancel = Arc::clone(&cancel);
        tokio::spawn(async move {
            let mut buf = vec![0u8; UDP_RECV_BUF];
            loop {
                tokio::select! {
                    res = recv_socket.recv(&mut buf) => {
                        match res {
                            Ok(n) => {
                                let _ = frame_tx.send(build_udp_datagram(sid, "", &buf[..n])).await;
                            }
                            Err(_) => break,
                        }
                    }
                    _ = recv_cancel.notified() => break,
                }
            }
        });

        Ok(session)
    }

    /// Close and remove the session.
    pub fn close_session(&self, sid: &u32) {
        if let Some((_, session)) = self.sessions.remove(sid) {
            session.cancel.notify_waiters();
        }
    }

    /// Clear all sessions (called when the tunnel disconnects).
    pub fn clear(&self) {
        // Notify each recv task to exit first, then clear the map, to avoid recv tasks leaking the socket Arc.
        for entry in self.sessions.iter() {
            entry.value().cancel.notify_waiters();
        }
        self.sessions.clear();
    }

    /// Sweep timed-out sessions.
    pub fn sweep(&self) {
        let now = now_millis();
        let expired: Vec<u32> = self
            .sessions
            .iter()
            .filter_map(|e| {
                let sid = *e.key();
                let expired = now.saturating_sub(e.value().last_activity.load(Ordering::Relaxed))
                    > UDP_SESSION_TIMEOUT_MS;
                if expired {
                    Some(sid)
                } else {
                    None
                }
            })
            .collect();
        for sid in expired {
            if let Some((_, s)) = self.sessions.remove(&sid) {
                s.cancel.notify_waiters();
            }
        }
    }
}
