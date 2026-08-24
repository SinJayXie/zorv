//! Client dial + TLS + application-layer handshake.
//!
//! Mirrors the handshake flow of the server's `server::tunnel::run_tunnel`: the client
//! dials the server's `server_addr`, writes a `HandshakeReq` after the TLS handshake,
//! and waits for a `HandshakeAck` (or `AuthFail`). On success the established
//! `TlsStream` and `HandshakeAck` are handed over to the read/write loop in `mod.rs`.

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tracing::{info, warn};

use crate::common::config::ClientConfig;
use crate::common::error::{Result, ZorvError};
use crate::common::tls::build_client_connector;
use crate::protocol::{
    parse_error_payload, parse_handshake_ack, Frame, FrameType, HandshakeAck, HandshakeReq,
};

/// Initial buffer capacity for the reader.
const READ_BUF_CAP: usize = 16 * 1024;

/// Dials the server + TLS handshake + application-layer handshake, returning
/// `(TlsStream, HandshakeAck)`.
///
/// Steps:
/// 1. `TcpStream::connect(&config.server_addr)`.
/// 2. Build the `TlsConnector` with `build_client_connector(verify_cert, ca_file)`.
/// 3. Extract the host from `server_addr` (strip the port) and build the `ServerName`;
///    if the host cannot be parsed, fall back to `"localhost"`
///    (only usable in self-signed test scenarios with `verify_cert=false`).
/// 4. `connector.connect(server_name, tcp)` completes the TLS handshake.
/// 5. Write out `HandshakeReq::build(client_id, token, "tcp").into_frame()` (encoded into a BytesMut first).
/// 6. Read the first frame: `AuthFail` → `Err(Auth("rejected by server"))`;
///    `HandshakeAck` → parsed via `parse_handshake_ack`;
///    any other type → `Err(Other)`.
/// 7. Return the `TlsStream` as a whole for `mod.rs` to take over the read/write loop.
///
/// The handshake phase is a serial write-then-read flow, so no `split` is needed;
/// `TlsStream` itself implements `AsyncReadExt` / `AsyncWriteExt` and can be called
/// sequentially.
pub async fn dial_and_handshake(
    config: &ClientConfig,
) -> Result<(TlsStream<TcpStream>, HandshakeAck)> {
    // 1. TCP dial
    let tcp = TcpStream::connect(&config.server_addr).await?;
    info!("tcp connected to {}", config.server_addr);

    // 2. Build the TLS connector
    let connector = build_client_connector(config.tls.verify_cert, config.tls.ca_file.as_deref())?;

    // 3. Extract the host from server_addr (strip the port)
    let host = config
        .server_addr
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(&config.server_addr);

    // Build the ServerName: try parsing the host first, fall back to "localhost" on failure.
    // try_from(String) returns ServerName<'static>, satisfying the ownership requirements of connector.connect.
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .or_else(|_| rustls::pki_types::ServerName::try_from("localhost".to_string()))
        .map_err(|_| ZorvError::Tls("invalid server name".to_string()))?;

    // 4. TLS handshake (tokio-rustls 0.26 connect returns io::Result, convertible to ZorvError::Io via ? and #[from])
    let mut tls_stream = connector.connect(server_name, tcp).await?;
    info!("tls handshake ok");

    // 5. Write out the HandshakeReq
    let req = HandshakeReq::build(&config.client_id, &config.auth.token, "tcp");
    let req_frame = req.into_frame();
    let mut enc = BytesMut::new();
    req_frame.encode(&mut enc);
    tls_stream.write_all(&enc).await?;
    // tokio-rustls buffers internally; an explicit flush ensures the HandshakeReq is sent immediately
    tls_stream.flush().await?;

    // 6. Read the first frame (HandshakeAck or AuthFail)
    let mut buf = BytesMut::with_capacity(READ_BUF_CAP);
    let first_frame = loop {
        match Frame::decode(&mut buf) {
            Ok(Some(frame)) => break frame,
            Ok(None) => {
                // Not a full frame yet; keep reading
                let n = tls_stream.read_buf(&mut buf).await?;
                if n == 0 {
                    return Err(ZorvError::Other(
                        "server closed before handshake ack".to_string(),
                    ));
                }
            }
            Err(e) => {
                warn!("decode handshake response failed: {}", e);
                return Err(e);
            }
        }
    };

    // 7. Dispatch by frame type
    match first_frame.frame_type {
        FrameType::HandshakeAck => {
            let ack = parse_handshake_ack(&first_frame)?;
            info!("handshake ack: session={}", ack.session_id);
            Ok((tls_stream, ack))
        }
        FrameType::AuthFail => {
            // Rejected by the server (bad token / version mismatch / kicked re-connect).
            // Surface the server's reason so the operator can see, e.g., a version mismatch.
            let reason = parse_error_payload(&first_frame.payload)
                .unwrap_or_else(|_| "rejected by server".to_string());
            Err(ZorvError::Auth(reason))
        }
        other => Err(ZorvError::Other(format!(
            "unexpected handshake response frame type: {:?}",
            other
        ))),
    }
}
