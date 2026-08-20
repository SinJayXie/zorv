//! Server-side public port listening and business-stream forwarding.
//!
//! For each `ProxyConfig` (type=="tcp"), a `run_proxy_listener` is started:
//! accept an external connection → find the client tunnel session via `manager.get(client_id)` →
//! allocate a stream_id → register it as pending → send STREAM_OPEN → wait for STREAM_OPEN_ACK (10s timeout) →
//! on success, establish the stream data channel and spawn bidirectional forwarding.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};

use crate::common::config::ProxyConfig;
use crate::common::error::{Result, ZorvError};
use crate::protocol::{build_stream_close, build_stream_data, build_stream_open, Frame};
use crate::server::audit::AuditLog;
use crate::server::manager::{TunnelManager, TunnelSession};

/// Timeout for waiting on STREAM_OPEN_ACK (seconds).
const STREAM_OPEN_TIMEOUT_SECS: u64 = 10;
/// Stream data channel buffer size.
const STREAM_DATA_CHANNEL_BUF: usize = 128;
/// Local socket read buffer size.
const SOCK_READ_BUF: usize = 32 * 1024;

/// Starts the public-port listen loop for a single proxy rule (the listener is bound by the caller).
///
/// Only handles rules with `proxy_type == "tcp"`; each accepted connection spawns a
/// `handle_public_conn` task. Bind failures are handled by the caller (ProxyManager).
pub async fn run_proxy_listener(
    listener: TcpListener,
    proxy: ProxyConfig,
    manager: Arc<TunnelManager>,
    audit: Arc<AuditLog>,
) {
    let listen = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| proxy.name.clone());
    info!("proxy listener started: name={} listen={}", proxy.name, listen);

    loop {
        let (conn, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("accept error on {} ({}): {}", listen, proxy.name, e);
                continue;
            }
        };
        info!(
            "new public connection: name={} peer={}",
            proxy.name, peer
        );
        // Connection audit: which public IP reached which proxy service
        audit.record(
            &peer.to_string(),
            "proxy_connect",
            &format!(
                "proxy={} target={} peer={}",
                proxy.name, proxy.target, peer
            ),
        );

        let manager = Arc::clone(&manager);
        let proxy = proxy.clone();
        let peer_str = peer.to_string();
        tokio::spawn(async move {
            if let Err(e) = handle_public_conn(conn, proxy, manager, peer_str).await {
                warn!("public conn handler error: {}", e);
            }
        });
    }
}

/// Handles a single public TCP connection: establishes a business stream via tunnel STREAM_OPEN and forwards bidirectionally.
async fn handle_public_conn(
    conn: TcpStream,
    proxy: ProxyConfig,
    manager: Arc<TunnelManager>,
    peer: String,
) -> Result<()> {
    let client_id = proxy.client_id.as_ref().ok_or_else(|| {
        ZorvError::Other(format!("proxy {} missing client_id", proxy.name))
    })?;
    let session = match manager.get(client_id) {
        Some(s) => s,
        None => {
            warn!("no tunnel session for client_id={}", client_id);
            return Ok(());
        }
    };

    // Allocate a stream_id (even numbers are used on the server side)
    let stream_id = session.id_alloc.next()?;

    // Register pending and wait for STREAM_OPEN_ACK
    let (ack_tx, ack_rx) = oneshot::channel::<bool>();
    session.pending_opens.insert(stream_id, ack_tx);

    // Send STREAM_OPEN (carries the external caller's address so the client can log it)
    let open_frame = build_stream_open(stream_id, &proxy.target, &peer);
    if let Err(_) = session.frame_tx.send(open_frame).await {
        // Tunnel closed
        session.pending_opens.remove(&stream_id);
        warn!("send stream_open failed (tunnel closed): stream_id={}", stream_id);
        return Ok(());
    }

    // Wait for the ACK (with timeout)
    let ack = tokio::time::timeout(
        Duration::from_secs(STREAM_OPEN_TIMEOUT_SECS),
        ack_rx,
    )
    .await;
    // Clean up pending regardless of the outcome
    session.pending_opens.remove(&stream_id);

    let ok = matches!(ack, Ok(Ok(true)));
    if !ok {
        warn!("stream_open rejected or timed out: stream_id={}", stream_id);
        return Ok(());
    }

    // Create the data channel and insert it into the streams table
    let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(STREAM_DATA_CHANNEL_BUF);
    session.streams.insert(stream_id, data_tx);

    // Bidirectional forwarding
    forward_session_conn(conn, stream_id, session.frame_tx.clone(), data_rx, Arc::clone(&session)).await;

    // Clean up the streams table (no-op if the reader already removed it on StreamClose)
    session.streams.remove(&stream_id);
    // Notify the client that the local stream is closed (the client should ignore duplicate StreamClose)
    let _ = session.frame_tx.send(build_stream_close(stream_id)).await;

    Ok(())
}

/// Bidirectional forwarding: public socket ↔ tunnel stream.
///
/// - socket → tunnel: wraps read data into StreamData frames and sends them to frame_tx; exits on EOF/error.
/// - tunnel → socket: receives data from data_rx and writes it back to the socket; exits when the channel closes.
/// Either direction ending breaks the loop, then a final StreamClose is sent to notify the peer.
async fn forward_session_conn(
    mut conn: TcpStream,
    stream_id: u32,
    frame_tx: mpsc::Sender<Frame>,
    mut data_rx: mpsc::Receiver<Vec<u8>>,
    session: Arc<TunnelSession>,
) {
    let mut read_buf = vec![0u8; SOCK_READ_BUF];
    loop {
        tokio::select! {
            res = conn.read(&mut read_buf) => {
                match res {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        // Count TCP downstream traffic (public → server → client)
                        session
                            .tcp_tx_bytes
                            .fetch_add(n as u64, Ordering::Relaxed);
                        if frame_tx
                            .send(build_stream_data(stream_id, &read_buf[..n]))
                            .await
                            .is_err()
                        {
                            break; // tunnel closed
                        }
                    }
                    Err(_) => break,
                }
            }
            data = data_rx.recv() => {
                match data {
                    Some(buf) => {
                        if conn.write_all(&buf).await.is_err() {
                            break; // Socket broken
                        }
                    }
                    None => break, // StreamClose from the tunnel side, or the stream was removed
                }
            }
        }
    }
    // Notify the client that the local side is closing
    let _ = frame_tx.send(build_stream_close(stream_id)).await;
}
