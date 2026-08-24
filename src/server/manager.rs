//! Server-side tunnel session management.
//!
//! `TunnelManager` maintains a `client_id → Arc<TunnelSession>` mapping, supporting concurrent register/query/unregister.
//! `TunnelSession` holds the tunnel frame sender, the business-stream data channel table, the pending STREAM_OPEN table,
//! the server-side Stream ID allocator, and the last-activity timestamp.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use serde::Serialize;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, RwLock};

use crate::common::crypto::now_millis;
use crate::protocol::{Frame, StreamIdAllocator};

/// Server-side UDP session: stream_id → public source address + the corresponding UDP proxy socket.
pub struct UdpSessionEntry {
    /// Public UDP source address.
    pub peer_addr: SocketAddr,
    /// The public UDP socket exclusively owned by this proxy.
    pub socket: Arc<UdpSocket>,
    /// Most recent activity time (millisecond timestamp).
    pub last_activity: AtomicU64,
}

impl UdpSessionEntry {
    /// Updates the last-activity timestamp to the current millisecond time.
    pub fn update_activity(&self) {
        self.last_activity.store(now_millis(), Ordering::Relaxed);
    }
}

/// A single client tunnel session.
///
/// Shared between the reader/writer/listener tasks via `Arc<TunnelSession>`.
/// `last_activity` is an `AtomicU64` (millisecond timestamp) updated by the reader on every received frame.
pub struct TunnelSession {
    /// Client identifier.
    pub client_id: String,
    /// Session UUID (v4 string).
    pub session_id: String,
    /// Tunnel frame sender: all frames to be sent to the client go into this channel, consumed by the writer task.
    pub frame_tx: mpsc::Sender<Frame>,
    /// Business-stream data channel table: stream_id → data_tx.
    /// When the reader receives StreamData, it looks up the corresponding stream here and delivers the payload.
    pub streams: DashMap<u32, mpsc::Sender<Vec<u8>>>,
    /// Pending STREAM_OPEN table: stream_id → oneshot::Sender<bool>.
    /// Registered here by the listener after sending STREAM_OPEN; the reader takes the entry and delivers the result on STREAM_OPEN_ACK.
    pub pending_opens: DashMap<u32, oneshot::Sender<bool>>,
    /// Server-side Stream ID allocator (produces even numbers 2,4,6,...).
    pub id_alloc: StreamIdAllocator,
    /// Most recent activity time (millisecond timestamp). Updated by the reader on every received frame.
    pub last_activity: AtomicU64,
    /// UDP session table: stream_id → Arc<UdpSessionEntry> (server side).
    pub udp: DashMap<u32, Arc<UdpSessionEntry>>,
    /// Cumulative TCP upstream bytes (client → server → public).
    pub tcp_rx_bytes: AtomicU64,
    /// Cumulative TCP downstream bytes (public → server → client).
    pub tcp_tx_bytes: AtomicU64,
    /// Cumulative UDP upstream bytes (client → server → public).
    pub udp_rx_bytes: AtomicU64,
    /// Cumulative UDP downstream bytes (public → server → client).
    pub udp_tx_bytes: AtomicU64,
}

impl TunnelSession {
    /// Updates the last-activity timestamp to the current millisecond time.
    pub fn update_activity(&self) {
        self.last_activity.store(now_millis(), Ordering::Relaxed);
    }

    /// Reads this session's live traffic deltas (bytes).
    pub fn traffic_snapshot(&self) -> crate::server::traffic::TrafficCounter {
        crate::server::traffic::TrafficCounter {
            tcp_up: self.tcp_rx_bytes.load(Ordering::Relaxed),
            tcp_down: self.tcp_tx_bytes.load(Ordering::Relaxed),
            udp_up: self.udp_rx_bytes.load(Ordering::Relaxed),
            udp_down: self.udp_tx_bytes.load(Ordering::Relaxed),
        }
    }
}

/// Tunnel session manager: `client_id → Arc<TunnelSession>`.
pub struct TunnelManager {
    sessions: DashMap<String, Arc<TunnelSession>>,
    /// Kick blacklist: `client_id → kicked_at (millis)`.
    ///
    /// A kicked client's re-connect handshake is rejected within the rejection window,
    /// so a client auto-restarted by a service manager (systemd/Docker) cannot
    /// immediately re-join and make the kick appear ineffective.
    kicked: RwLock<HashMap<String, u64>>,
}

/// Online client snapshot (for admin UI JSON serialization).
#[derive(Debug, Clone, Serialize)]
pub struct SessionInfo {
    pub client_id: String,
    pub session_id: String,
    pub last_activity_ms: u64,
    pub active_streams: usize,
}

impl TunnelManager {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
            kicked: RwLock::new(HashMap::new()),
        }
    }

    /// Records a kick for `client_id` at the current time.
    pub async fn mark_kicked(&self, client_id: &str) {
        self.kicked
            .write()
            .await
            .insert(client_id.to_string(), now_millis());
    }

    /// Whether `client_id` was kicked within the last `window_secs`.
    ///
    /// Used during the tunnel handshake to reject a kicked client's immediate
    /// re-connect (e.g. an auto-restart by a service manager).
    pub async fn is_kicked(&self, client_id: &str, window_secs: u64) -> bool {
        let kicked = self.kicked.read().await;
        match kicked.get(client_id) {
            Some(ts) => now_millis().saturating_sub(*ts) <= window_secs.saturating_mul(1000),
            None => false,
        }
    }

    /// Registers (or replaces) a session.
    ///
    /// If a session with the same client_id already exists, the old session's Arc reference is replaced out of the table;
    /// its frame_tx clones are dropped as well. However, the old writer task may still hold the rx,
    /// so the caller must close it separately (the MVP accepts that the old writer is reaped
    /// by the idle monitor or a socket disconnect).
    pub fn register(&self, session: Arc<TunnelSession>) {
        let client_id = session.client_id.clone();
        if let Some(_old) = self.sessions.insert(client_id, session) {
            tracing::warn!("replaced existing tunnel session");
        }
    }

    /// Unregisters a session, returning the removed session (if any).
    pub fn unregister(&self, client_id: &str) -> Option<Arc<TunnelSession>> {
        self.sessions.remove(client_id).map(|(_, v)| v)
    }

    /// Unregisters a session only when the currently registered session matches its own `session_id`.
    ///
    /// Used by the tunnel cleanup path: after a client disconnects and reconnects, a new session already
    /// exists under the same client_id; removing by client_id when the old connection ends would wrongly
    /// delete the new session (reconnect race).
    pub fn unregister_if_current(&self, session: &TunnelSession) -> Option<Arc<TunnelSession>> {
        // Read and drop the read-lock guard first, then remove (write lock), to avoid a DashMap read/write lock deadlock.
        let current_id = {
            let entry = self.sessions.get(&session.client_id)?;
            entry.value().session_id.clone()
        };
        if current_id == session.session_id {
            return self.sessions.remove(&session.client_id).map(|(_, v)| v);
        }
        None
    }

    /// Looks up a session by client_id.
    pub fn get(&self, client_id: &str) -> Option<Arc<TunnelSession>> {
        self.sessions.get(client_id).map(|r| Arc::clone(&r))
    }

    /// Returns snapshots of all online clients (unordered).
    pub fn list(&self) -> Vec<SessionInfo> {
        self.sessions
            .iter()
            .map(|r| {
                let s = r.value();
                SessionInfo {
                    client_id: s.client_id.clone(),
                    session_id: s.session_id.clone(),
                    last_activity_ms: s.last_activity.load(Ordering::Relaxed),
                    active_streams: s.streams.len(),
                }
            })
            .collect()
    }

    /// Returns the number of online clients.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Aggregates live traffic deltas of all online sessions (for time-series sampling overlay; not persisted).
    pub fn online_traffic(&self) -> std::collections::HashMap<String, crate::server::traffic::TrafficCounter> {
        let mut map = std::collections::HashMap::new();
        for entry in self.sessions.iter() {
            let s = entry.value();
            map.insert(s.client_id.clone(), s.traffic_snapshot());
        }
        map
    }
}

impl Default for TunnelManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a dummy session for tests only.
    fn make_dummy_session(client_id: &str) -> Arc<TunnelSession> {
        make_dummy_session_with_id(client_id, "sid-test")
    }

    fn make_dummy_session_with_id(client_id: &str, session_id: &str) -> Arc<TunnelSession> {
        let (tx, _rx) = mpsc::channel::<Frame>(1);
        Arc::new(TunnelSession {
            client_id: client_id.to_string(),
            session_id: session_id.to_string(),
            frame_tx: tx,
            streams: DashMap::new(),
            pending_opens: DashMap::new(),
            id_alloc: StreamIdAllocator::new_server(),
            last_activity: AtomicU64::new(now_millis()),
            udp: DashMap::new(),
            tcp_rx_bytes: AtomicU64::new(0),
            tcp_tx_bytes: AtomicU64::new(0),
            udp_rx_bytes: AtomicU64::new(0),
            udp_tx_bytes: AtomicU64::new(0),
        })
    }

    #[test]
    fn register_get_unregister() {
        let mgr = TunnelManager::new();
        assert!(mgr.get("c1").is_none());
        mgr.register(make_dummy_session("c1"));
        assert!(mgr.get("c1").is_some());
        assert!(mgr.get("c2").is_none());
        let removed = mgr.unregister("c1");
        assert!(removed.is_some());
        assert!(mgr.get("c1").is_none());
    }

    #[tokio::test]
    async fn kick_blacklist_blocks_reconnect_within_window() {
        let mgr = TunnelManager::new();
        // Not kicked yet: allowed.
        assert!(!mgr.is_kicked("c1", 60).await);
        // After a kick: rejected within the window.
        mgr.mark_kicked("c1").await;
        assert!(mgr.is_kicked("c1", 60).await);
        // A different client is unaffected.
        assert!(!mgr.is_kicked("c2", 60).await);
    }

    #[test]
    fn register_replaces_existing() {
        let mgr = TunnelManager::new();
        mgr.register(make_dummy_session("c1"));
        mgr.register(make_dummy_session("c1"));
        assert!(mgr.get("c1").is_some());
        // Table is empty after unregister
        mgr.unregister("c1");
        assert!(mgr.get("c1").is_none());
    }

    #[test]
    fn unregister_if_current_only_removes_matching_session() {
        let mgr = TunnelManager::new();
        let old = make_dummy_session_with_id("c1", "sid-old");
        let new = make_dummy_session_with_id("c1", "sid-new");
        mgr.register(Arc::clone(&old));
        mgr.register(Arc::clone(&new));
        assert!(mgr.get("c1").is_some());

        // Old session (no longer in the table) cleanup: must not delete the new session.
        assert!(mgr.unregister_if_current(&old).is_none());
        assert!(mgr.get("c1").is_some(), "old session must not remove the new session");

        // New session's own cleanup: removed normally.
        let removed = mgr.unregister_if_current(&new);
        assert!(removed.is_some());
        assert!(mgr.get("c1").is_none());
    }
}
