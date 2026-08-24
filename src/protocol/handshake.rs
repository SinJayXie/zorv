//! Zorv protocol handshake module (Task 4.1).
//!
//! Defines the payload binary layout (all little-endian) of the three control frames
//! `HANDSHAKE_REQ` / `HANDSHAKE_ACK` / `AUTH_FAIL`, along with helpers for construction,
//! encoding/decoding, and server-side verification.
//!
//! Handshake payload layout (inside `Frame.payload`, all little-endian):
//! ```text
//! HANDSHAKE_REQ:
//!   client_id_len: u16
//!   client_id: bytes
//!   version_len: u16
//!   version: bytes          (the client's Cargo package version, e.g. "1.1.1")
//!   timestamp: u64 (milliseconds)
//!   hmac: 32 bytes (HMAC-SHA256(token, timestamp_le_bytes))
//!   capabilities_len: u16
//!   capabilities: bytes
//!
//! HANDSHAKE_ACK:
//!   session_id_len: u16
//!   session_id: bytes (uuid string)
//!   heartbeat_min: u32 (seconds)
//!   heartbeat_max: u32 (seconds)
//!
//! AUTH_FAIL:
//!   reason_len: u16
//!   reason: bytes
//! ```
//!
//! The server rejects clients whose `version` differs from its own
//! (`env!("CARGO_PKG_VERSION")`), see `verify_version`.

use std::io::Cursor;

use bytes::{Buf, BufMut};

use crate::common::crypto::{hmac_sha256, now_millis, verify_timestamp, TIMESTAMP_WINDOW_SECS};
use crate::common::error::{ProtocolError, Result, ZorvError};
use crate::protocol::frame::{Frame, FrameType};

/// HMAC byte length (SHA256 outputs 32 bytes).
const HMAC_LEN: usize = 32;

/// Handshake request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeReq {
    pub client_id: String,
    pub version: String,
    pub timestamp: u64,
    pub hmac: [u8; 32],
    pub capabilities: String,
}

/// Handshake acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeAck {
    pub session_id: String,
    pub heartbeat_min: u32,
    pub heartbeat_max: u32,
}

impl HandshakeReq {
    /// Build a handshake request on the client: take the current timestamp and compute the HMAC with `token`.
    ///
    /// The version is filled from the crate's own `CARGO_PKG_VERSION` so the client always
    /// reports the version it was actually built from.
    pub fn build(client_id: &str, token: &str, capabilities: &str) -> Self {
        let ts = now_millis();
        let ts_bytes = ts.to_le_bytes();
        let hmac = hmac_sha256(token.as_bytes(), &ts_bytes);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&hmac);
        Self {
            client_id: client_id.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: ts,
            hmac: arr,
            capabilities: capabilities.to_string(),
        }
    }

    /// Encode into payload bytes per the layout.
    pub fn encode_payload(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            2 + self.client_id.len() + 2 + self.version.len() + 8 + HMAC_LEN + 2
                + self.capabilities.len(),
        );
        buf.put_u16_le(self.client_id.len() as u16);
        buf.put_slice(self.client_id.as_bytes());
        buf.put_u16_le(self.version.len() as u16);
        buf.put_slice(self.version.as_bytes());
        buf.put_u64_le(self.timestamp);
        buf.put_slice(&self.hmac);
        buf.put_u16_le(self.capabilities.len() as u16);
        buf.put_slice(self.capabilities.as_bytes());
        buf
    }

    /// Decode from the payload. Returns `ProtocolError::Incomplete` if the data is too short.
    pub fn decode_payload(payload: &[u8]) -> Result<Self> {
        let mut cur = Cursor::new(payload);

        if cur.remaining() < 2 {
            return Err(ZorvError::Protocol(ProtocolError::Incomplete));
        }
        let client_id_len = cur.get_u16_le() as usize;
        if cur.remaining() < client_id_len {
            return Err(ZorvError::Protocol(ProtocolError::Incomplete));
        }
        let mut id_buf = vec![0u8; client_id_len];
        cur.copy_to_slice(&mut id_buf);
        let client_id = String::from_utf8(id_buf)
            .map_err(|e| ZorvError::Other(format!("invalid utf8 in client_id: {}", e)))?;

        if cur.remaining() < 2 {
            return Err(ZorvError::Protocol(ProtocolError::Incomplete));
        }
        let version_len = cur.get_u16_le() as usize;
        if cur.remaining() < version_len {
            return Err(ZorvError::Protocol(ProtocolError::Incomplete));
        }
        let mut ver_buf = vec![0u8; version_len];
        cur.copy_to_slice(&mut ver_buf);
        let version = String::from_utf8(ver_buf)
            .map_err(|e| ZorvError::Other(format!("invalid utf8 in version: {}", e)))?;

        if cur.remaining() < 8 {
            return Err(ZorvError::Protocol(ProtocolError::Incomplete));
        }
        let timestamp = cur.get_u64_le();

        if cur.remaining() < HMAC_LEN {
            return Err(ZorvError::Protocol(ProtocolError::Incomplete));
        }
        let mut hmac = [0u8; 32];
        cur.copy_to_slice(&mut hmac);

        if cur.remaining() < 2 {
            return Err(ZorvError::Protocol(ProtocolError::Incomplete));
        }
        let capabilities_len = cur.get_u16_le() as usize;
        if cur.remaining() < capabilities_len {
            return Err(ZorvError::Protocol(ProtocolError::Incomplete));
        }
        let mut cap_buf = vec![0u8; capabilities_len];
        cur.copy_to_slice(&mut cap_buf);
        let capabilities = String::from_utf8(cap_buf)
            .map_err(|e| ZorvError::Other(format!("invalid utf8 in capabilities: {}", e)))?;

        Ok(Self {
            client_id,
            version,
            timestamp,
            hmac,
            capabilities,
        })
    }

    /// Convert into a `HandshakeReq` control frame.
    pub fn into_frame(&self) -> Frame {
        Frame::new_control(FrameType::HandshakeReq, self.encode_payload())
    }
}

impl HandshakeAck {
    /// Build a handshake acknowledgement.
    pub fn build(session_id: &str, heartbeat_min: u32, heartbeat_max: u32) -> Self {
        Self {
            session_id: session_id.to_string(),
            heartbeat_min,
            heartbeat_max,
        }
    }

    /// Encode into payload bytes per the layout.
    pub fn encode_payload(&self) -> Vec<u8> {
        let mut buf =
            Vec::with_capacity(2 + self.session_id.len() + 4 + 4);
        buf.put_u16_le(self.session_id.len() as u16);
        buf.put_slice(self.session_id.as_bytes());
        buf.put_u32_le(self.heartbeat_min);
        buf.put_u32_le(self.heartbeat_max);
        buf
    }

    /// Decode from the payload. Returns `ProtocolError::Incomplete` if the data is too short.
    pub fn decode_payload(payload: &[u8]) -> Result<Self> {
        let mut cur = Cursor::new(payload);

        if cur.remaining() < 2 {
            return Err(ZorvError::Protocol(ProtocolError::Incomplete));
        }
        let session_id_len = cur.get_u16_le() as usize;
        if cur.remaining() < session_id_len + 8 {
            return Err(ZorvError::Protocol(ProtocolError::Incomplete));
        }
        let mut sid_buf = vec![0u8; session_id_len];
        cur.copy_to_slice(&mut sid_buf);
        let session_id = String::from_utf8(sid_buf)
            .map_err(|e| ZorvError::Other(format!("invalid utf8 in session_id: {}", e)))?;

        let heartbeat_min = cur.get_u32_le();
        let heartbeat_max = cur.get_u32_le();

        Ok(Self {
            session_id,
            heartbeat_min,
            heartbeat_max,
        })
    }

    /// Convert into a `HandshakeAck` control frame.
    pub fn into_frame(&self) -> Frame {
        Frame::new_control(FrameType::HandshakeAck, self.encode_payload())
    }
}

/// Server-side handshake verification: checks the timestamp window and the HMAC.
///
/// - Timestamp outside the window → `ZorvError::Auth("timestamp out of window")`
/// - HMAC mismatch → `ZorvError::Auth("invalid token")`
pub fn verify_handshake(req: &HandshakeReq, expected_token: &str) -> Result<()> {
    if !verify_timestamp(req.timestamp, TIMESTAMP_WINDOW_SECS) {
        return Err(ZorvError::Auth("timestamp out of window".into()));
    }
    let expected = hmac_sha256(expected_token.as_bytes(), &req.timestamp.to_le_bytes());
    if expected.as_slice() != req.hmac.as_ref() {
        return Err(ZorvError::Auth("invalid token".into()));
    }
    Ok(())
}

/// Server-side version gate: the client must run the exact same version as the server.
///
/// - Version mismatch → `ZorvError::Auth("version mismatch: client=... server=...")`
pub fn verify_version(client_version: &str, server_version: &str) -> Result<()> {
    if client_version == server_version {
        Ok(())
    } else {
        Err(ZorvError::Auth(format!(
            "version mismatch: client={} server={}",
            client_version, server_version
        )))
    }
}

/// Build an `AUTH_FAIL` control frame.
pub fn auth_fail_frame(reason: &str) -> Frame {
    let mut payload = Vec::with_capacity(2 + reason.len());
    payload.put_u16_le(reason.len() as u16);
    payload.put_slice(reason.as_bytes());
    Frame::new_control(FrameType::AuthFail, payload)
}

/// Check that the frame is a `HandshakeReq` and parse it.
pub fn parse_handshake_req(frame: &Frame) -> Result<HandshakeReq> {
    if frame.frame_type != FrameType::HandshakeReq {
        return Err(ZorvError::Protocol(ProtocolError::InvalidFrameType(
            frame.frame_type as u8,
        )));
    }
    HandshakeReq::decode_payload(&frame.payload)
}

/// Check that the frame is a `HandshakeAck` and parse it.
pub fn parse_handshake_ack(frame: &Frame) -> Result<HandshakeAck> {
    if frame.frame_type != FrameType::HandshakeAck {
        return Err(ZorvError::Protocol(ProtocolError::InvalidFrameType(
            frame.frame_type as u8,
        )));
    }
    HandshakeAck::decode_payload(&frame.payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::crypto::now_millis;

    #[test]
    fn handshake_req_roundtrip() {
        let req = HandshakeReq::build("client-1", "secret-token", "tcp");
        let payload = req.encode_payload();
        let decoded = HandshakeReq::decode_payload(&payload).unwrap();
        assert_eq!(decoded.client_id, req.client_id);
        assert_eq!(decoded.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(decoded.timestamp, req.timestamp);
        assert_eq!(decoded.hmac, req.hmac);
        assert_eq!(decoded.capabilities, req.capabilities);
    }

    #[test]
    fn handshake_req_into_frame_and_parse() {
        let req = HandshakeReq::build("client-7", "tok", "tcp");
        let frame = req.into_frame();
        assert_eq!(frame.frame_type, FrameType::HandshakeReq);
        let parsed = parse_handshake_req(&frame).unwrap();
        assert_eq!(parsed.client_id, "client-7");
        assert_eq!(parsed.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(parsed.capabilities, "tcp");
    }

    #[test]
    fn handshake_ack_roundtrip() {
        let ack = HandshakeAck::build("session-uuid-1234", 5, 30);
        let payload = ack.encode_payload();
        let decoded = HandshakeAck::decode_payload(&payload).unwrap();
        assert_eq!(decoded.session_id, ack.session_id);
        assert_eq!(decoded.heartbeat_min, 5);
        assert_eq!(decoded.heartbeat_max, 30);
    }

    #[test]
    fn handshake_ack_into_frame_and_parse() {
        let ack = HandshakeAck::build("sid-abc", 10, 60);
        let frame = ack.into_frame();
        assert_eq!(frame.frame_type, FrameType::HandshakeAck);
        let parsed = parse_handshake_ack(&frame).unwrap();
        assert_eq!(parsed.session_id, "sid-abc");
        assert_eq!(parsed.heartbeat_min, 10);
        assert_eq!(parsed.heartbeat_max, 60);
    }

    #[test]
    fn parse_handshake_req_wrong_type() {
        let ack = HandshakeAck::build("s", 1, 2);
        let frame = ack.into_frame();
        assert!(parse_handshake_req(&frame).is_err());
    }

    #[test]
    fn verify_handshake_correct_token() {
        let req = HandshakeReq::build("client-1", "secret-token", "tcp");
        assert!(verify_handshake(&req, "secret-token").is_ok());
    }

    #[test]
    fn verify_handshake_wrong_token() {
        let req = HandshakeReq::build("client-1", "secret-token", "tcp");
        let err = verify_handshake(&req, "wrong-token").unwrap_err();
        assert!(matches!(err, ZorvError::Auth(_)));
    }

    #[test]
    fn verify_handshake_expired_timestamp() {
        // Build a timestamp 60s in the past and compute the hmac with the correct token, bypassing build's now_millis.
        let old_ts = now_millis().saturating_sub(60_000);
        let ts_bytes = old_ts.to_le_bytes();
        let hmac_vec = hmac_sha256("secret-token".as_bytes(), &ts_bytes);
        let mut hmac_arr = [0u8; 32];
        hmac_arr.copy_from_slice(&hmac_vec);
        let req = HandshakeReq {
            client_id: "client-1".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: old_ts,
            hmac: hmac_arr,
            capabilities: "tcp".to_string(),
        };
        let err = verify_handshake(&req, "secret-token").unwrap_err();
        assert!(matches!(err, ZorvError::Auth(_)));
    }

    #[test]
    fn verify_version_matches() {
        let v = env!("CARGO_PKG_VERSION");
        assert!(verify_version(v, v).is_ok());
    }

    #[test]
    fn verify_version_mismatch() {
        let err = verify_version("9.9.9", env!("CARGO_PKG_VERSION")).unwrap_err();
        assert!(matches!(err, ZorvError::Auth(_)));
        assert!(err.to_string().contains("version mismatch"));
    }

    #[test]
    fn auth_fail_frame_layout() {
        let frame = auth_fail_frame("bad token");
        assert_eq!(frame.frame_type, FrameType::AuthFail);
        // payload: u16 len + bytes
        let mut cur = Cursor::new(&frame.payload[..]);
        let len = cur.get_u16_le() as usize;
        assert_eq!(len, "bad token".len());
        let mut buf = vec![0u8; len];
        cur.copy_to_slice(&mut buf);
        assert_eq!(String::from_utf8(buf).unwrap(), "bad token");
    }

    #[test]
    fn decode_payload_incomplete() {
        // Only 1 byte: not enough to read client_id_len(u16)
        assert!(HandshakeReq::decode_payload(&[0u8]).is_err());
        // client_id_len=3 but no further bytes
        assert!(HandshakeReq::decode_payload(&[3u8, 0u8]).is_err());
    }
}
