//! Client module entry point.
//!
//! Composes `dialer` + `forwarder` and provides the `Client::run` entry point:
//! reconnect-backoff loop → dial + handshake → reader/writer/heartbeat tasks run
//! concurrently → any completion triggers cleanup → back off and reconnect.
//!
//! The tunnel frame I/O model mirrors the server-side `server::tunnel`:
//! - Write side: all frames destined for the server go into `frame_tx`; the writer
//!   task exclusively consumes them from the write half.
//! - Read side: the reader (main loop) owns the read half exclusively and dispatches
//!   decoded frames by type.
//! - Heartbeat: the client sends `Heartbeat` at `HeartbeatState::next_interval()`
//!   intervals; a `HeartbeatAck` resets the miss counter; `miss >= HEARTBEAT_MISS_MAX`
//!   means the connection is considered dead.
//! - Business streams: the client is the receiver of `StreamOpen` (initiated by the
//!   server). The reader receives `StreamOpen(sid, target)` → dials the local target →
//!   replies `StreamOpenAck` → spawns `forward_local` to relay between the local socket
//!   and the tunnel stream.

pub mod dialer;
pub mod forwarder;
pub mod udp;

use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::common::config::{parse_duration_secs, ClientConfig};
use crate::common::error::Result;
use crate::protocol::*;

/// Initial buffer capacity for the reader.
const READ_BUF_CAP: usize = 16 * 1024;
/// Frame send channel buffer (write side).
const FRAME_CHANNEL_BUF: usize = 1024;
/// Data channel buffer per business stream.
const STREAM_DATA_CHANNEL_BUF: usize = 128;

/// Result of one connection lifecycle, deciding whether `run` should reconnect.
enum RunOutcome {
    /// Normal disconnect/error path: the caller should back off and reconnect.
    Reconnect,
    /// Kicked by the server: terminate the client process (no reconnect).
    Terminate,
}

/// Client entry point.
pub struct Client {
    config: ClientConfig,
}

impl Client {
    pub fn new(config: ClientConfig) -> Self {
        Self { config }
    }

    /// Runs the client main loop (with exponential-backoff reconnection).
    ///
    /// - `max_retries == 0` means reconnect forever.
    /// - After each reconnect `delay *= backoff_factor`, clamped to `[initial, max_delay]`.
    /// - Errors from `run_once` are logged but do not terminate the loop
    ///   (unless `max_retries` is reached).
    /// - Being kicked by the server terminates the loop: the client exits instead of reconnecting.
    pub async fn run(&self) -> anyhow::Result<()> {
        let reconnect = &self.config.reconnect;
        let initial = parse_duration_secs(&reconnect.initial_delay)?;
        let maxd = parse_duration_secs(&reconnect.max_delay)?;
        let mut delay = initial;
        let mut attempts = 0u32;
        loop {
            match self.run_once().await {
                Ok(RunOutcome::Terminate) => {
                    info!("client terminated by server kick");
                    return Ok(());
                }
                Ok(RunOutcome::Reconnect) => info!("client run_once ended"),
                Err(e) => warn!("client run_once error: {}", e),
            }
            // Reconnect check: max_retries=0 means reconnect forever
            if reconnect.max_retries != 0 && attempts >= reconnect.max_retries {
                return Err(anyhow::anyhow!("max retries reached"));
            }
            attempts += 1;
            info!("reconnect in {}s (attempt {})", delay, attempts);
            tokio::time::sleep(Duration::from_secs(delay)).await;
            delay = ((delay as f64 * reconnect.backoff_factor) as u64)
                .min(maxd)
                .max(initial);
        }
    }

    /// One full connection lifecycle: dial → handshake → read/write loop → cleanup → return.
    ///
    /// Returns `Terminate` when the server kicks the client (the caller must not reconnect);
    /// otherwise `Reconnect` after the session ends, and `run` handles the backoff.
    async fn run_once(&self) -> Result<RunOutcome> {
        let (tls_stream, ack) = dialer::dial_and_handshake(&self.config).await?;
        let hb_min = ack.heartbeat_min;
        let hb_max = ack.heartbeat_max;
        info!(
            "tunnel established: session={} hb=[{},{}]",
            ack.session_id, hb_min, hb_max
        );

        let (frame_tx, mut frame_rx) = mpsc::channel::<Frame>(FRAME_CHANNEL_BUF);
        let streams: Arc<DashMap<u32, mpsc::Sender<Vec<u8>>>> = Arc::new(DashMap::new());
        let udp_manager: Arc<udp::UdpManager> = Arc::new(udp::UdpManager::new());
        let (rd, wr) = tokio::io::split(tls_stream);

        // Cancel signal: when the main loop ends (normally or by being cancelled/aborted),
        // `cancel_tx` is dropped/signalled and the writer/heartbeat tasks exit, shutting down
        // the write half. Without this, cancelling `run_once` would leave a half-open
        // connection that keeps the client_id occupied on the server.
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);

        // Writer task: owns the write half exclusively, encodes frames from frame_rx and writes them out.
        // Exits when the channel closes, on write error, or when cancelled (then shuts down the write half).
        // The padding flag is read before spawn (a Copy type) to avoid borrowing self in the closure.
        let padding_enabled = self.config.obfuscation.padding;
        let padding_max = self.config.obfuscation.padding_max;
        let mut writer_cancel = cancel_rx.clone();
        let writer = tokio::spawn(async move {
            let mut wr = wr;
            let mut buf = BytesMut::with_capacity(READ_BUF_CAP);
            loop {
                let frame = tokio::select! {
                    f = frame_rx.recv() => f,
                    _ = writer_cancel.changed() => None,
                };
                let Some(mut frame) = frame else { break };
                if padding_enabled {
                    frame.apply_random_padding(padding_max);
                }
                buf.clear();
                frame.encode(&mut buf);
                if wr.write_all(&buf).await.is_err() {
                    break;
                }
            }
            let _ = wr.shutdown().await;
        });

        // Heartbeat state is shared between the heartbeat task and the main reader:
        // a std::sync::Mutex suffices since all locks are released before await
        // (no lock is held across an await point).
        let hb_state = Arc::new(std::sync::Mutex::new(HeartbeatState::new(hb_min, hb_max)));

        // Heartbeat task: sends heartbeats periodically, increments miss with saturation,
        // and returns when is_dead() is true.
        // heartbeat_jitter switch: when enabled, uses a random interval in [min,max]; otherwise a fixed min interval.
        let heartbeat_jitter = self.config.obfuscation.heartbeat_jitter;
        let hb_tx = frame_tx.clone();
        let hb_state_hb = Arc::clone(&hb_state);
        let mut hb_cancel = cancel_rx.clone();
        let heartbeat = tokio::spawn(async move {
            loop {
                let interval = {
                    let s = hb_state_hb.lock().unwrap();
                    if heartbeat_jitter {
                        s.next_interval()
                    } else {
                        Duration::from_secs(s.min_sec as u64)
                    }
                };
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {}
                    _ = hb_cancel.changed() => return,
                }
                let _ = hb_tx.send(heartbeat_frame()).await;
                let dead = {
                    let mut s = hb_state_hb.lock().unwrap();
                    s.on_heartbeat_sent();
                    s.is_dead()
                };
                if dead {
                    warn!("heartbeat dead, closing tunnel");
                    return;
                }
            }
        });

        // Reader main loop (owns the read half exclusively)
        let mut rd_buf = BytesMut::with_capacity(READ_BUF_CAP);
        let mut rd = rd;
        'outer: loop {
            // 1. Consume complete frames already accumulated in the buffer
            loop {
                let frame = match Frame::decode(&mut rd_buf) {
                    Ok(Some(f)) => f,
                    Ok(None) => break,     // Not a full frame yet; need to read more
                    Err(e) => {
                        warn!("decode err: {}", e);
                        break 'outer;
                    }
                };
                // Frame dispatch
                match frame.frame_type {
                    FrameType::HeartbeatAck => {
                        // Heartbeat ack: reset the miss counter to zero
                        let mut s = hb_state.lock().unwrap();
                        s.on_heartbeat_ack();
                    }
                    FrameType::Heartbeat => {
                        // The server should not initiate heartbeats, but handle it for compatibility: parse ts and reply with an ACK
                        if let Ok(ts) = parse_timestamp(&frame.payload) {
                            let _ = frame_tx.send(heartbeat_ack_frame(ts)).await;
                        }
                    }
                    FrameType::StreamOpen => {
                        let sid = frame.stream_id;
                        match parse_stream_open_payload(&frame.payload) {
                            Ok((target, peer)) => {
                                info!(
                                    "new tunnel connection: peer={} service={} stream_id={}",
                                    if peer.is_empty() { "unknown" } else { &peer },
                                    target,
                                    sid
                                );
                                match tokio::net::TcpStream::connect(&target).await {
                                    Ok(local) => {
                                        // Connected: reply ack + create stream + spawn forward
                                        let _ = frame_tx
                                            .send(build_stream_open_ack(sid, true))
                                            .await;
                                        let (data_tx, data_rx) =
                                            mpsc::channel::<Vec<u8>>(STREAM_DATA_CHANNEL_BUF);
                                        streams.insert(sid, data_tx);
                                        let ftx = frame_tx.clone();
                                        let streams2 = Arc::clone(&streams);
                                        tokio::spawn(async move {
                                            forwarder::forward_local(
                                                local, sid, ftx, data_rx,
                                            )
                                            .await;
                                            // Clean up the streams table once forward exits
                                            streams2.remove(&sid);
                                        });
                                    }
                                    Err(e) => {
                                        // Connection failed: reply nack, do not create the stream
                                        warn!("connect local {} failed: {}", target, e);
                                        let _ = frame_tx
                                            .send(build_stream_open_ack(sid, false))
                                            .await;
                                    }
                                }
                            }
                            Err(e) => warn!("parse stream open err: {}", e),
                        }
                    }
                    FrameType::StreamData => {
                        let sid = frame.stream_id;
                        let data = frame.payload;
                        // Clone the Sender to drop the dashmap Ref, avoiding holding the lock across await
                        let tx_opt = streams.get(&sid).map(|r| r.value().clone());
                        if let Some(tx) = tx_opt {
                            // A send failure means the forward task has exited (stream closed); ignore it
                            let _ = tx.send(data).await;
                        }
                    }
                    FrameType::StreamClose => {
                        // Server closed the stream: removing it drops data_tx, which makes forward exit
                        streams.remove(&frame.stream_id);
                    }
                    FrameType::UdpDatagram => {
                        let sid = frame.stream_id;
                        match parse_udp_datagram(&frame.payload) {
                            Ok((target, data)) => {
                                udp_manager
                                    .handle_incoming(sid, &target, data, frame_tx.clone())
                                    .await;
                            }
                            Err(e) => warn!("parse udp datagram err: {}", e),
                        }
                    }
                    FrameType::Error => {
                        // Kicked by the server: print the reason and terminate the client
                        // (no reconnect, unlike a plain disconnect).
                        let reason = parse_error_payload(&frame.payload)
                            .unwrap_or_else(|_| "unknown".to_string());
                        warn!("kicked by server: {}", reason);
                        return Ok(RunOutcome::Terminate);
                    }
                    _ => {
                        // Other frames (HandshakeReq/HandshakeAck/AuthFail/StreamOpenAck/
                        // Probe) are ignored by the client
                        tracing::debug!("ignore frame type {:?}", frame.frame_type);
                    }
                }
            }

            // 2. Sweep timed-out UDP sessions (once per round after processing frames)
            udp_manager.sweep();

            // 3. Heartbeat dead check (the heartbeat task updates miss; checked when the main loop reads data)
            let dead = {
                let s = hb_state.lock().unwrap();
                s.is_dead()
            };
            if dead {
                warn!("heartbeat dead in main loop");
                break 'outer;
            }

            // 4. Read more bytes into rd_buf
            let n = match rd.read_buf(&mut rd_buf).await {
                Ok(n) => n,
                Err(e) => {
                    warn!("read err: {}", e);
                    break 'outer;
                }
            };
            if n == 0 {
                // EOF: the server closed the connection
                break 'outer;
            }
        }

        // Cleanup: notify the writer/heartbeat tasks to exit and await them, so the write
        // half is shut down and the server sees the disconnect (no half-open connection
        // occupying the client_id). Clearing streams drops data_tx, making forwards exit.
        let _ = cancel_tx.send(true);
        streams.clear();
        udp_manager.clear();
        drop(frame_tx);
        let _ = writer.await;
        let _ = heartbeat.await;
        info!("client tunnel session ended");
        Ok(RunOutcome::Reconnect)
    }
}
