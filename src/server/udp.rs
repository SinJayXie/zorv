//! Server-side UDP proxy listening: public UDP datagrams ↔ tunnel UDP_DATAGRAM frames.
//!
//! For each `ProxyConfig` (type=="udp"), a `run_udp_proxy_listener` is started:
//! bind the public UDP socket → when a public datagram arrives, allocate/reuse a stream_id by source address →
//! send `UDP_DATAGRAM(stream_id, target, data)` to the client → the client's reply is looked up
//! by the reader via `session.udp` and `send_to` back to the public side. Timed-out UDP sessions are swept periodically.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::net::UdpSocket;
use tracing::{info, warn};

use crate::common::config::ProxyConfig;
use crate::common::crypto::now_millis;
use crate::protocol::build_udp_datagram;
use crate::server::manager::{TunnelManager, TunnelSession, UdpSessionEntry};

/// UDP session timeout (milliseconds), default 120s.
const UDP_SESSION_TIMEOUT_MS: u64 = 120_000;
/// UDP receive buffer.
const UDP_RECV_BUF: usize = 65535;
/// Sweep interval (seconds).
const SWEEP_INTERVAL_SECS: u64 = 60;

/// Starts the public UDP listen loop for a single UDP proxy rule (the socket is bound by the caller).
///
/// Bind failures are handled by the caller (ProxyManager).
pub async fn run_udp_proxy_listener(
    socket: Arc<UdpSocket>,
    proxy: ProxyConfig,
    manager: Arc<TunnelManager>,
) {
    let client_id = match proxy.client_id.as_deref() {
        Some(id) => id,
        None => {
            warn!("udp proxy {} missing client_id", proxy.name);
            return;
        }
    };
    let listen = socket
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| proxy.name.clone());
    info!(
        "udp proxy listener started: name={} listen={}",
        proxy.name, listen
    );

    // Local mapping of public source address → stream_id (this proxy exclusively owns the socket)
    let peer_map: DashMap<SocketAddr, u32> = DashMap::new();

    let mut buf = vec![0u8; UDP_RECV_BUF];
    let mut sweep = tokio::time::interval(Duration::from_secs(SWEEP_INTERVAL_SECS));

    loop {
        tokio::select! {
            recv = socket.recv_from(&mut buf) => {
                let (n, peer_addr) = match recv {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("udp recv_from error: {}", e);
                        continue;
                    }
                };
                let data = buf[..n].to_vec();

                // Look up the client tunnel
                let session = match manager.get(client_id) {
                    Some(s) => s,
                    None => {
                        warn!("no tunnel for udp client_id={}", client_id);
                        continue;
                    }
                };

                // Look up or allocate a stream_id
                let stream_id = if let Some(sid) = peer_map.get(&peer_addr).map(|r| *r.value()) {
                    sid
                } else {
                    let sid = match session.id_alloc.next() {
                        Ok(v) => v,
                        Err(e) => {
                            warn!("alloc stream id: {}", e);
                            continue;
                        }
                    };
                    peer_map.insert(peer_addr, sid);
                    session.udp.insert(
                        sid,
                        Arc::new(UdpSessionEntry {
                            peer_addr,
                            socket: Arc::clone(&socket),
                            last_activity: AtomicU64::new(now_millis()),
                        }),
                    );
                    sid
                };

                // Update the activity time
                if let Some(e) = session.udp.get(&stream_id) {
                    e.update_activity();
                }

                // Count UDP downstream traffic (public → server → client)
                session
                    .udp_tx_bytes
                    .fetch_add(data.len() as u64, Ordering::Relaxed);

                // Send UDP_DATAGRAM to the client
                let frame = build_udp_datagram(stream_id, &proxy.target, &data);
                if session.frame_tx.send(frame).await.is_err() {
                    // Tunnel closed, clean up
                    session.udp.remove(&stream_id);
                    peer_map.remove(&peer_addr);
                }
            }
            _ = sweep.tick() => {
                // Sweep timed-out UDP sessions
                let now = now_millis();
                if let Some(session) = manager.get(client_id) {
                    let expired: Vec<u32> = peer_map
                        .iter()
                        .filter_map(|e| {
                            let sid = *e.value();
                            if session_udp_expired(&session, sid, now) {
                                Some(sid)
                            } else {
                                None
                            }
                        })
                        .collect();
                    for sid in expired {
                        session.udp.remove(&sid);
                        peer_map.retain(|_, v| *v != sid);
                    }
                }
            }
        }
    }
}

/// Checks whether the UDP session for the given stream_id has timed out.
fn session_udp_expired(session: &Arc<TunnelSession>, sid: u32, now: u64) -> bool {
    match session.udp.get(&sid) {
        Some(e) => {
            now.saturating_sub(e.last_activity.load(Ordering::Relaxed)) > UDP_SESSION_TIMEOUT_MS
        }
        None => false,
    }
}
