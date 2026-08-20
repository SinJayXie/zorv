//! Zorv protocol multiplexing module (Task 4.3).
//!
//! Provides a Stream ID allocator, STREAM_OPEN / STREAM_OPEN_ACK / STREAM_DATA /
//! STREAM_CLOSE frame builders and parsers, plus the `mpsc` channel handles used to
//! bridge business streams with local sockets. The actual IO forwarding lives in
//! server/client.
//!
//! Stream ID conventions:
//! - Clients allocate odd IDs (1, 3, 5, ...)
//! - Servers allocate even IDs (2, 4, 6, ...); 0 is reserved for control, so evens start at 2
//!
//! `STREAM_OPEN_ACK` payload layout: `[status:u8][stream_id:u32_le]`
//! `STREAM_OPEN` payload layout: `[target_len:u16][target:bytes]`

use std::io::Cursor;
use std::sync::atomic::{AtomicU32, Ordering};

use bytes::{Buf, BufMut};
use tokio::sync::mpsc;

use crate::common::error::{ProtocolError, Result, ZorvError};
use crate::protocol::frame::{Frame, FrameType};

/// Maximum number of streams per tunnel.
pub const MAX_STREAMS: u32 = 65535;
/// Default flow-control window (256KB).
pub const DEFAULT_WINDOW: usize = 256 * 1024;

/// Stream ID allocator.
///
/// Clients use odd IDs (1,3,5,...), servers use even IDs (2,4,6,...).
/// Thread safety is guaranteed by an `AtomicU32` CAS loop; each call returns the
/// current value and increments by 2.
pub struct StreamIdAllocator {
    next: AtomicU32,
    /// Whether this side is the odd (client) side; only used to distinguish
    /// client/server semantics and does not participate in allocation.
    #[allow(dead_code)]
    odd: bool,
}

impl StreamIdAllocator {
    /// Client side: odd sequence starting from 1.
    pub fn new_client() -> Self {
        Self {
            next: AtomicU32::new(1),
            odd: true,
        }
    }

    /// Server side: even sequence starting from 2.
    pub fn new_server() -> Self {
        Self {
            next: AtomicU32::new(2),
            odd: false,
        }
    }

    /// Allocate the next Stream ID.
    ///
    /// Returns `ZorvError::Other("stream id exhausted")` once past `MAX_STREAMS`.
    pub fn next(&self) -> Result<u32> {
        loop {
            let cur = self.next.load(Ordering::Relaxed);
            if cur > MAX_STREAMS {
                return Err(ZorvError::Other("stream id exhausted".into()));
            }
            let nxt = cur
                .checked_add(2)
                .ok_or_else(|| ZorvError::Other("stream id overflow".into()))?;
            if self
                .next
                .compare_exchange(cur, nxt, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return Ok(cur);
            }
        }
    }
}

/// Build a `STREAM_OPEN` frame.
///
/// Payload layout: `[target_len:u16][target:bytes][peer_len:u16][peer:bytes]`.
/// `peer` is the address of the public-side caller (may be empty for legacy peers).
pub fn build_stream_open(stream_id: u32, target: &str, peer: &str) -> Frame {
    let mut payload = Vec::with_capacity(2 + target.len() + 2 + peer.len());
    payload.put_u16_le(target.len() as u16);
    payload.put_slice(target.as_bytes());
    payload.put_u16_le(peer.len() as u16);
    payload.put_slice(peer.as_bytes());
    Frame::new(FrameType::StreamOpen, stream_id, payload)
}

/// Parse a `STREAM_OPEN` payload and return `(target, peer)`.
///
/// The peer field is optional: frames from legacy servers (target only) yield an
/// empty peer string.
pub fn parse_stream_open_payload(payload: &[u8]) -> Result<(String, String)> {
    let mut cur = Cursor::new(payload);
    if cur.remaining() < 2 {
        return Err(ZorvError::Protocol(ProtocolError::Incomplete));
    }
    let target_len = cur.get_u16_le() as usize;
    if cur.remaining() < target_len {
        return Err(ZorvError::Protocol(ProtocolError::Incomplete));
    }
    let mut target_buf = vec![0u8; target_len];
    cur.copy_to_slice(&mut target_buf);
    let target = String::from_utf8(target_buf)
        .map_err(|e| ZorvError::Other(format!("invalid utf8 in target: {}", e)))?;

    let mut peer = String::new();
    if cur.remaining() >= 2 {
        let peer_len = cur.get_u16_le() as usize;
        if cur.remaining() >= peer_len {
            let mut peer_buf = vec![0u8; peer_len];
            cur.copy_to_slice(&mut peer_buf);
            peer = String::from_utf8_lossy(&peer_buf).into_owned();
        }
    }
    Ok((target, peer))
}

/// Build a `STREAM_OPEN_ACK` frame (payload is `[status:u8][stream_id:u32_le]`).
///
/// status=0 when `ok=true`, status=1 when `ok=false`.
pub fn build_stream_open_ack(stream_id: u32, ok: bool) -> Frame {
    let mut payload = Vec::with_capacity(5);
    payload.put_u8(if ok { 0 } else { 1 });
    payload.put_u32_le(stream_id);
    Frame::new(FrameType::StreamOpenAck, stream_id, payload)
}

/// Parse a `STREAM_OPEN_ACK` payload and return `(ok, stream_id)`.
pub fn parse_stream_open_ack_payload(payload: &[u8]) -> Result<(bool, u32)> {
    let mut cur = Cursor::new(payload);
    if cur.remaining() < 5 {
        return Err(ZorvError::Protocol(ProtocolError::Incomplete));
    }
    let status = cur.get_u8();
    let stream_id = cur.get_u32_le();
    Ok((status == 0, stream_id))
}

/// Build a `STREAM_DATA` frame.
pub fn build_stream_data(stream_id: u32, data: &[u8]) -> Frame {
    Frame::new(FrameType::StreamData, stream_id, data.to_vec())
}

/// Build a `STREAM_CLOSE` frame (empty payload).
pub fn build_stream_close(stream_id: u32) -> Frame {
    Frame::new(FrameType::StreamClose, stream_id, Vec::new())
}

/// Build an `ERROR` control frame (payload: u16 length + UTF-8 reason text).
///
/// Used by the server to actively disconnect/kick a client: the client prints the
/// reason and exits after receiving it.
pub fn build_error_frame(reason: &str) -> Frame {
    let mut payload = Vec::with_capacity(2 + reason.len());
    payload.put_u16_le(reason.len() as u16);
    payload.put_slice(reason.as_bytes());
    Frame::new_control(FrameType::Error, payload)
}

/// Parse an `ERROR` frame payload and return the reason text.
pub fn parse_error_payload(payload: &[u8]) -> Result<String> {
    let mut cur = Cursor::new(payload);
    let len = cur.get_u16_le() as usize;
    if cur.remaining() < len {
        return Err(ZorvError::Other("error payload truncated".to_string()));
    }
    let bytes = &payload[2..2 + len];
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

// ---------------------------------------------------------------------------
// UDP_DATAGRAM frame utilities (Phase 2 UDP proxy)
// ---------------------------------------------------------------------------
//
// UDP is connectionless; a stream_id is reused to identify one UDP session (even,
// allocated by the server, sharing the same `StreamIdAllocator` as server-initiated
// TCP streams, so stream_ids are globally unique and never collide).
//
// `UDP_DATAGRAM` payload layout (little-endian):
//   [target_len: u16][target: bytes][data: bytes]
//
// - Server → client: `target` is the local target bound to the proxy rule (e.g.
//   "8.8.8.8:53"), `data` is the public-side UDP datagram payload. The client
//   establishes a local UDP socket and forwards to that target.
// - Client → server: `target` is empty (length 0), `data` is the reply from the
//   local target. The server looks up the public source address by stream_id and
//   `send_to`s the reply back out.

/// Build a `UDP_DATAGRAM` frame.
pub fn build_udp_datagram(stream_id: u32, target: &str, data: &[u8]) -> Frame {
    let mut payload = Vec::with_capacity(2 + target.len() + data.len());
    payload.put_u16_le(target.len() as u16);
    payload.put_slice(target.as_bytes());
    payload.put_slice(data);
    Frame::new(FrameType::UdpDatagram, stream_id, payload)
}

/// Parse a `UDP_DATAGRAM` payload and return `(target, data)`.
pub fn parse_udp_datagram(payload: &[u8]) -> Result<(String, Vec<u8>)> {
    let mut cur = Cursor::new(payload);
    if cur.remaining() < 2 {
        return Err(ZorvError::Protocol(ProtocolError::Incomplete));
    }
    let target_len = cur.get_u16_le() as usize;
    if cur.remaining() < target_len {
        return Err(ZorvError::Protocol(ProtocolError::Incomplete));
    }
    let mut target_buf = vec![0u8; target_len];
    cur.copy_to_slice(&mut target_buf);
    let target = String::from_utf8(target_buf)
        .map_err(|e| ZorvError::Other(format!("invalid utf8 in udp target: {}", e)))?;
    let data = cur.copy_to_bytes(cur.remaining()).to_vec();
    Ok((target, data))
}

/// Stream handle: a pair of `mpsc` channels per business stream used to bridge
/// with the local socket.
///
/// - `tx_to_tunnel`: data read from the local socket is sent into this channel;
///   the tunnel reads it and emits `STREAM_DATA`
/// - `rx_from_tunnel`: the tunnel writes received `STREAM_DATA` into this channel;
///   the local socket side reads from it
pub struct StreamHandle {
    pub stream_id: u32,
    pub tx_to_tunnel: mpsc::Sender<Vec<u8>>,
    pub rx_from_tunnel: mpsc::Receiver<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocator_client_odd() {
        let a = StreamIdAllocator::new_client();
        assert_eq!(a.next().unwrap(), 1);
        assert_eq!(a.next().unwrap(), 3);
        assert_eq!(a.next().unwrap(), 5);
    }

    #[test]
    fn allocator_server_even() {
        let a = StreamIdAllocator::new_server();
        assert_eq!(a.next().unwrap(), 2);
        assert_eq!(a.next().unwrap(), 4);
        assert_eq!(a.next().unwrap(), 6);
    }

    #[test]
    fn stream_open_roundtrip() {
        let frame = build_stream_open(42, "127.0.0.1:8080", "203.0.113.7:54321");
        assert_eq!(frame.frame_type, FrameType::StreamOpen);
        assert_eq!(frame.stream_id, 42);
        let (target, peer) = parse_stream_open_payload(&frame.payload).unwrap();
        assert_eq!(target, "127.0.0.1:8080");
        assert_eq!(peer, "203.0.113.7:54321");
    }

    #[test]
    fn stream_open_roundtrip_empty_peer() {
        // Legacy frame without the peer field: peer must parse as empty
        let mut payload = Vec::new();
        payload.put_u16_le("127.0.0.1:8080".len() as u16);
        payload.put_slice(b"127.0.0.1:8080");
        let (target, peer) = parse_stream_open_payload(&payload).unwrap();
        assert_eq!(target, "127.0.0.1:8080");
        assert_eq!(peer, "");
    }

    #[test]
    fn stream_open_ack_roundtrip_ok() {
        let frame = build_stream_open_ack(7, true);
        assert_eq!(frame.frame_type, FrameType::StreamOpenAck);
        assert_eq!(frame.stream_id, 7);
        let (ok, sid) = parse_stream_open_ack_payload(&frame.payload).unwrap();
        assert!(ok);
        assert_eq!(sid, 7);
    }

    #[test]
    fn stream_open_ack_roundtrip_rejected() {
        let frame = build_stream_open_ack(11, false);
        let (ok, sid) = parse_stream_open_ack_payload(&frame.payload).unwrap();
        assert!(!ok);
        assert_eq!(sid, 11);
    }

    #[test]
    fn stream_data_and_close_frames() {
        let data = build_stream_data(99, b"hello");
        assert_eq!(data.frame_type, FrameType::StreamData);
        assert_eq!(data.stream_id, 99);
        assert_eq!(data.payload, b"hello");

        let close = build_stream_close(99);
        assert_eq!(close.frame_type, FrameType::StreamClose);
        assert_eq!(close.stream_id, 99);
        assert!(close.payload.is_empty());
    }

    #[test]
    fn parse_stream_open_payload_incomplete() {
        // fewer than 2 bytes
        assert!(parse_stream_open_payload(&[0u8]).is_err());
        // len=5 but not enough following bytes
        assert!(parse_stream_open_payload(&[5u8, 0u8, b'a']).is_err());
    }

    #[test]
    fn parse_stream_open_ack_payload_incomplete() {
        assert!(parse_stream_open_ack_payload(&[0u8, 1, 2]).is_err());
        assert!(parse_stream_open_ack_payload(&[]).is_err());
    }

    #[test]
    fn udp_datagram_roundtrip() {
        let frame = build_udp_datagram(42, "8.8.8.8:53", b"query");
        assert_eq!(frame.frame_type, FrameType::UdpDatagram);
        assert_eq!(frame.stream_id, 42);
        let (target, data) = parse_udp_datagram(&frame.payload).unwrap();
        assert_eq!(target, "8.8.8.8:53");
        assert_eq!(data, b"query");
    }

    #[test]
    fn udp_datagram_empty_target() {
        // client → server direction: target is empty
        let frame = build_udp_datagram(7, "", b"reply");
        let (target, data) = parse_udp_datagram(&frame.payload).unwrap();
        assert_eq!(target, "");
        assert_eq!(data, b"reply");
    }

    #[test]
    fn parse_udp_datagram_incomplete() {
        // fewer than 2 bytes
        assert!(parse_udp_datagram(&[0u8]).is_err());
        // target_len=5 but not enough bytes
        assert!(parse_udp_datagram(&[5u8, 0u8, b'a', b'b']).is_err());
    }
}
