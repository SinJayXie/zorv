//! Client forward task: local socket ↔ tunnel business stream.
//!
//! Mirrors the server-side `server::listener::forward_session_conn`. After the reader
//! receives a `StreamOpen` it dials the local target and spawns this task with the
//! resulting `TcpStream`.
//!
//! - Local socket → tunnel: read data, wrap it in `StreamData`, and send it to `frame_tx`; exit on EOF.
//! - Tunnel → local socket: receive data from `data_rx` and write it to the local socket; exit when the channel closes.
//! - When either direction ends → the function returns; the caller is responsible for
//!   `streams.remove(sid)`, and this function sends a `StreamClose` before returning
//!   to notify the server.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::protocol::{build_stream_close, build_stream_data, Frame};

/// Local socket read buffer.
const SOCK_READ_BUF: usize = 32 * 1024;

/// Bidirectional forwarding between the local target socket and the tunnel business stream.
///
/// - `local`: the local target `TcpStream` (established by the reader on `StreamOpen`).
/// - `stream_id`: the business stream id (assigned by the server, even).
/// - `frame_tx`: the frame channel to the server. Data read locally → `StreamData`;
///   on EOF/error → exit, sending a trailing `StreamClose` before returning.
/// - `data_rx`: data for this stream received from the server (dispatched here by the reader on `StreamData`).
///
/// The loop exits when either direction ends, then a final `StreamClose` is sent to
/// notify the server of the local close (duplicate `StreamClose` frames are ignored by
/// the server, see `server::listener::forward_session_conn`).
pub async fn forward_local(
    mut local: TcpStream,
    stream_id: u32,
    frame_tx: mpsc::Sender<Frame>,
    mut data_rx: mpsc::Receiver<Vec<u8>>,
) {
    let mut read_buf = vec![0u8; SOCK_READ_BUF];
    loop {
        tokio::select! {
            // Local socket → tunnel
            res = local.read(&mut read_buf) => {
                match res {
                    Ok(0) => break, // Local EOF
                    Ok(n) => {
                        if frame_tx
                            .send(build_stream_data(stream_id, &read_buf[..n]))
                            .await
                            .is_err()
                        {
                            break; // Tunnel broken (frame_tx closed)
                        }
                    }
                    Err(_) => break,
                }
            }
            // Tunnel → local socket
            data = data_rx.recv() => {
                match data {
                    Some(buf) => {
                        if local.write_all(&buf).await.is_err() {
                            break; // Local socket closed
                        }
                    }
                    None => break, // Server sent StreamClose or the stream was removed by mod.rs
                }
            }
        }
    }
    // Notify the server of the local close (frame_tx may already be closed; ignore errors)
    let _ = frame_tx.send(build_stream_close(stream_id)).await;
}
