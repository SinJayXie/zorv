//! Server-side tunnel handling: TLS accept → application handshake → reader/writer/idle-monitor tasks running concurrently.
//!
//! I/O model:
//! - Write side: all frames to be sent to the client are queued into `frame_tx`, consumed exclusively by the writer task on the write half.
//! - Read side: the reader task exclusively owns the read half, decodes frames and dispatches by type (heartbeat replies with ACK,
//!   STREAM_OPEN_ACK delivers to pending_opens, StreamData delivers to the corresponding stream, StreamClose cleans up the stream).
//! - Idle monitor: checks `last_activity` every 5s; if it exceeds `hb_max*3+10` seconds, the client is deemed lost and the task exits.
//!
//! When any task ends, cleanup is triggered: abort the remaining tasks → unregister the session → return.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};
use uuid::Uuid;

use crate::common::config::ObfuscationConfig;
use crate::common::crypto::now_millis;
use crate::common::error::Result;
use crate::protocol::{
    auth_fail_frame, build_stream_close, heartbeat_ack_frame, parse_handshake_req,
    parse_stream_open_ack_payload, parse_timestamp, parse_udp_datagram, verify_version,
    HandshakeAck, Frame, FrameType, StreamIdAllocator,
};
use crate::server::auth::{authenticate, validate_client_id};
use crate::server::manager::{TunnelManager, TunnelSession};
use crate::server::notify::post_json;
use crate::server::traffic::TrafficTracker;

/// Initial buffer capacity for the reader.
const READ_BUF_CAP: usize = 16 * 1024;
/// Frame-send channel buffer (write side).
const FRAME_CHANNEL_BUF: usize = 1024;
/// Idle monitor polling interval (seconds).
const IDLE_CHECK_INTERVAL_SECS: u64 = 5;
/// Re-connect rejection window for a kicked client (seconds).
const KICK_REJECT_WINDOW_SECS: u64 = 60;

/// Handles a single client tunnel connection.
///
/// Steps:
/// 1. TLS accept → split into read/write halves.
/// 2. Application handshake: read the first frame → `parse_handshake_req` → `authenticate`;
///    on failure, reply with `AUTH_FAIL` and return; on success, generate a session_id and reply with `HandshakeAck`.
/// 3. Create `frame_tx` and a `TunnelSession`, then `manager.register`.
/// 4. Spawn reader/writer/idle-monitor tasks into a JoinSet.
/// 5. When any task ends → abort_all → unregister → return.
///
/// `webhook` is the optional client-offline notification URL: POST a JSON notification when the session ends.
pub async fn run_tunnel(
    tcp: TcpStream,
    acceptor: TlsAcceptor,
    manager: Arc<TunnelManager>,
    token: Arc<RwLock<String>>,
    hb_min: u32,
    hb_max: u32,
    obfuscation: ObfuscationConfig,
    traffic: Arc<TrafficTracker>,
    webhook: Option<String>,
) -> Result<()> {
    // 1. TLS handshake
    let tls_stream = acceptor.accept(tcp).await?;
    let (mut read_half, mut write_half) = tokio::io::split(tls_stream);

    // 2. Application handshake: read the first frame (loop: try to decode → keep reading if incomplete)
    let mut buf = BytesMut::with_capacity(READ_BUF_CAP);
    let first_frame = loop {
        match Frame::decode(&mut buf) {
            Ok(Some(frame)) => break frame,
            Ok(None) => {
                // Buffer holds less than one frame; keep reading
                let n = match read_half.read_buf(&mut buf).await {
                    Ok(n) => n,
                    Err(e) => {
                        warn!("read handshake bytes failed: {}", e);
                        return Ok(());
                    }
                };
                if n == 0 {
                    info!("tunnel closed before handshake");
                    return Ok(());
                }
            }
            Err(e) => {
                warn!("decode handshake frame failed: {}", e);
                return Ok(());
            }
        }
    };

    // Parse HandshakeReq
    let handshake_req = match parse_handshake_req(&first_frame) {
        Ok(req) => req,
        Err(e) => {
            warn!("parse handshake req failed: {}", e);
            return Ok(());
        }
    };
    let client_id = handshake_req.client_id.clone();

    // Validate client_id (prevents XSS / injection when it reaches the admin UI)
    if !validate_client_id(&client_id) {
        warn!("rejected invalid client_id: {:?}", client_id);
        let fail = auth_fail_frame("invalid client_id");
        let mut enc = BytesMut::new();
        fail.encode(&mut enc);
        let _ = write_half.write_all(&enc).await;
        return Ok(());
    }

    // Reject a kicked client's immediate re-connect (e.g. an auto-restart by a service manager),
    // so the kick actually takes effect instead of the client re-joining right away.
    if manager.is_kicked(&client_id, KICK_REJECT_WINDOW_SECS).await {
        warn!("rejected kicked client re-connect: {:?}", client_id);
        let fail = auth_fail_frame("Kicked by admin");
        let mut enc = BytesMut::new();
        fail.encode(&mut enc);
        let _ = write_half.write_all(&enc).await;
        return Ok(());
    }

    // Version gate: only clients running the exact same version may connect.
    if let Err(e) = verify_version(&handshake_req.version, env!("CARGO_PKG_VERSION")) {
        warn!("rejected client with version mismatch: client={}", client_id);
        let fail = auth_fail_frame(&e.to_string());
        let mut enc = BytesMut::new();
        fail.encode(&mut enc);
        let _ = write_half.write_all(&enc).await;
        return Ok(());
    }

    // Authenticate: read the shared token (the admin UI can modify it dynamically)
    let server_token = token.read().await.clone();
    match authenticate(&handshake_req, &server_token) {
        Ok(()) => {
            // 3. Create the session and register it first: if the client_id is already
            //    online, the new connection is rejected with AUTH_FAIL instead of
            //    replacing the existing session.
            let session_id = Uuid::new_v4().to_string();
            let (frame_tx, frame_rx) = mpsc::channel::<Frame>(FRAME_CHANNEL_BUF);
            let session = Arc::new(TunnelSession {
                client_id: client_id.clone(),
                session_id: session_id.clone(),
                frame_tx,
                streams: dashmap::DashMap::new(),
                pending_opens: dashmap::DashMap::new(),
                id_alloc: StreamIdAllocator::new_server(),
                last_activity: std::sync::atomic::AtomicU64::new(now_millis()),
                udp: dashmap::DashMap::new(),
                tcp_rx_bytes: std::sync::atomic::AtomicU64::new(0),
                tcp_tx_bytes: std::sync::atomic::AtomicU64::new(0),
                udp_rx_bytes: std::sync::atomic::AtomicU64::new(0),
                udp_tx_bytes: std::sync::atomic::AtomicU64::new(0),
            });
            if !manager.register(Arc::clone(&session)) {
                warn!("rejected duplicate client: client={} already online", client_id);
                let fail = auth_fail_frame("client already online");
                let mut enc = BytesMut::new();
                fail.encode(&mut enc);
                let _ = write_half.write_all(&enc).await;
                return Ok(());
            }
            // Reply with HandshakeAck only after a successful registration.
            let ack = HandshakeAck::build(&session_id, hb_min, hb_max).into_frame();
            let mut enc = BytesMut::new();
            ack.encode(&mut enc);
            if let Err(e) = write_half.write_all(&enc).await {
                warn!("write handshake ack failed: {}", e);
                return Ok(());
            }
            info!(
                "tunnel established: client={} session={}",
                client_id, session_id
            );

            // 4. Spawn the three tasks
            let reader_session = Arc::clone(&session);
            let monitor_session = Arc::clone(&session);

            let mut tasks: JoinSet<()> = JoinSet::new();
            tasks.spawn(async move {
                reader_task(read_half, reader_session, buf).await;
            });
            let padding = obfuscation.padding;
            let padding_max = obfuscation.padding_max;
            tasks.spawn(async move {
                writer_task(write_half, frame_rx, padding, padding_max).await;
            });
            tasks.spawn(async move {
                idle_monitor_task(monitor_session, hb_max).await;
            });

            // 5. Wait for any task to end
            let _ = tasks.join_next().await;
            // Abort the remaining tasks and reap them
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}

            // Cleanup: only remove the session whose session_id matches, to avoid deleting a new session after a reconnect
            manager.unregister_if_current(&session);
            // Merge this session's traffic into the cumulative totals (persisted periodically by TrafficTracker)
            traffic.merge(&session.client_id, &session.traffic_snapshot());
            // Client offline notification (Webhook; failures only log a warning and do not block session cleanup)
            if let Some(url) = &webhook {
                let url = url.clone();
                let client_id = session.client_id.clone();
                tokio::spawn(async move {
                    let payload =
                        serde_json::json!({ "client_id": client_id, "event": "offline" });
                    if let Err(e) = post_json(&url, &payload).await {
                        warn!("webhook notify failed: {}", e);
                    }
                });
            }
            info!(
                "tunnel closed: client={} session={}",
                session.client_id, session.session_id
            );
            Ok(())
        }
        Err(e) => {
            // Authentication failed: reply with AUTH_FAIL and close
            warn!("auth failed for client={}: {}", client_id, e);
            let fail = auth_fail_frame(&e.to_string());
            let mut enc = BytesMut::new();
            fail.encode(&mut enc);
            let _ = write_half.write_all(&enc).await;
            Ok(())
        }
    }
}

/// Reader task: exclusively owns the read half, reads bytes, decodes frames, and dispatches by type.
///
/// Frame dispatch:
/// - `Heartbeat`: parse the timestamp → reply with `HEARTBEAT_ACK`.
/// - `StreamOpenAck`: parse (ok, sid) → take the oneshot from `pending_opens` and deliver ok.
/// - `StreamData`: take data_tx from `streams` → deliver the payload.
/// - `StreamClose`: remove from `streams` (dropping data_tx makes the forward task exit).
/// - Others: ignored.
async fn reader_task<R>(mut read_half: R, session: Arc<TunnelSession>, mut buf: BytesMut)
where
    R: AsyncRead + Unpin,
{
    loop {
        // First consume any complete frames already buffered
        loop {
            let frame = match Frame::decode(&mut buf) {
                Ok(opt) => match opt {
                    Some(f) => f,
                    None => break, // buffer holds less than one frame; keep reading
                },
                Err(e) => {
                    warn!("tunnel decode error: {}", e);
                    return;
                }
            };
            session.update_activity();
            dispatch_frame(frame, &session).await;
        }
        // Read more bytes
        let n = match read_half.read_buf(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                warn!("tunnel read error: {}", e);
                return;
            }
        };
        if n == 0 {
            // EOF
            return;
        }
    }
}

/// Dispatches a single frame to its corresponding handler.
async fn dispatch_frame(frame: Frame, session: &TunnelSession) {
    match frame.frame_type {
        FrameType::Heartbeat => {
            if let Ok(ts) = parse_timestamp(&frame.payload) {
                let ack = heartbeat_ack_frame(ts);
                let _ = session.frame_tx.send(ack).await;
            }
        }
        FrameType::HeartbeatAck => {
            // The server does not proactively send heartbeats; receiving an ACK also counts as activity, already recorded via update_activity
        }
        FrameType::StreamOpenAck => {
            if let Ok((ok, sid)) = parse_stream_open_ack_payload(&frame.payload) {
                if let Some((_, tx)) = session.pending_opens.remove(&sid) {
                    let _ = tx.send(ok);
                }
            }
        }
        FrameType::StreamData => {
            let sid = frame.stream_id;
            // Count TCP upstream traffic (client → server → public)
            session
                .tcp_rx_bytes
                .fetch_add(frame.payload.len() as u64, Ordering::Relaxed);
            // Clone the Sender and drop the dashmap Ref immediately to avoid holding the lock across an await
            let data_tx = session.streams.get(&sid).map(|r| r.value().clone());
            if let Some(tx) = data_tx {
                let _ = tx.send(frame.payload).await;
            } else {
                // Stream not found; notify the client to close it
                let _ = session.frame_tx.send(build_stream_close(sid)).await;
            }
        }
        FrameType::StreamClose => {
            let sid = frame.stream_id;
            // Removing drops data_tx, causing the forward task's data_rx to return None
            session.streams.remove(&sid);
        }
        FrameType::HandshakeReq => {
            // Handled during the handshake; duplicate handshake frames are ignored
        }
        FrameType::UdpDatagram => {
            let sid = frame.stream_id;
            // Reply from the client: target is empty, data is the local target's response
            if let Ok((_target, data)) = parse_udp_datagram(&frame.payload) {
                // Count UDP upstream traffic (client → server → public)
                session
                    .udp_rx_bytes
                    .fetch_add(data.len() as u64, Ordering::Relaxed);
                // Look up stream_id → entry, get peer_addr + socket
                let entry = session.udp.get(&sid).map(|r| Arc::clone(r.value()));
                if let Some(e) = entry {
                    if let Err(err) = e.socket.send_to(&data, e.peer_addr).await {
                        warn!("udp send_to {} failed: {}", e.peer_addr, err);
                    }
                    e.update_activity();
                }
            }
        }
        _ => {
            // Other frames (Probe/Error/StreamOpen/AuthFail/HandshakeAck) are ignored by the server
        }
    }
}

/// Writer task: exclusively owns the write half, takes frames from frame_rx, encodes them, and writes to the TLS write half.
///
/// Exits when the channel closes (all Senders dropped), and attempts a shutdown before exiting.
async fn writer_task<W>(
    mut write_half: W,
    mut rx: mpsc::Receiver<Frame>,
    padding: bool,
    padding_max: usize,
) where
    W: AsyncWrite + Unpin,
{
    let mut enc_buf = BytesMut::with_capacity(READ_BUF_CAP);
    while let Some(mut frame) = rx.recv().await {
        if padding {
            frame.apply_random_padding(padding_max);
        }
        enc_buf.clear();
        frame.encode(&mut enc_buf);
        if let Err(e) = write_half.write_all(&enc_buf).await {
            warn!("tunnel write error: {}", e);
            break;
        }
    }
    let _ = write_half.shutdown().await;
}

/// Idle monitor task: checks `last_activity` every `IDLE_CHECK_INTERVAL_SECS` seconds.
///
/// If `now - last_activity > (hb_max*3+10)*1000` milliseconds, the client is deemed lost and returns to trigger cleanup.
async fn idle_monitor_task(session: Arc<TunnelSession>, hb_max: u32) {
    let timeout_ms = (hb_max as u64 * 3 + 10) * 1000;
    let mut interval = tokio::time::interval(Duration::from_secs(IDLE_CHECK_INTERVAL_SECS));
    loop {
        interval.tick().await;
        let now = now_millis();
        let last = session.last_activity.load(Ordering::Relaxed);
        if now.saturating_sub(last) > timeout_ms {
            info!(
                "tunnel idle timeout: client={} session={}",
                session.client_id, session.session_id
            );
            return;
        }
    }
}
