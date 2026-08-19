//! Zorv's proprietary protocol frame codec (Task 3, corresponds to product.md 3.2/3.3).
//!
//! Frame format (all little-endian):
//! ```text
//! | Magic(2B,0x5A3C) | Version(1B,0x01) | Type(1B) | StreamID(4B) |
//!   PayloadLen(4B) | Payload(variable) | PaddingLen(2B) | Padding(variable) | Checksum(4B,CRC32) |
//! ```
//! - CRC32 covers all bytes from Magic through Padding (excluding the Checksum itself).
//! - Control frames use StreamID = 0xFFFF_FFFF.

use bytes::{Buf, BufMut, BytesMut};
use rand::Rng;
use std::io::Cursor;

use crate::common::error::{ProtocolError, Result, ZorvError};

/// Protocol magic number.
pub const MAGIC: u16 = 0x5A3C;
/// Protocol version.
pub const VERSION: u8 = 0x01;
/// Stream ID used by control frames.
pub const CONTROL_STREAM_ID: u32 = 0xFFFF_FFFF;

/// Fixed header length: magic(2) + version(1) + type(1) + stream_id(4) + payload_len(4) = 12.
const HEADER_LEN: usize = 12;
/// Trailing CRC32 checksum length.
const CRC_LEN: usize = 4;

/// Frame type.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    HandshakeReq  = 0x01,
    HandshakeAck  = 0x02,
    AuthFail      = 0x03,
    StreamOpen    = 0x10,
    StreamOpenAck = 0x11,
    StreamData    = 0x12,
    StreamClose   = 0x13,
    Heartbeat     = 0x20,
    HeartbeatAck  = 0x21,
    UdpDatagram   = 0x30,
    Probe         = 0xFE,
    Error         = 0xFF,
}

impl TryFrom<u8> for FrameType {
    type Error = ZorvError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(FrameType::HandshakeReq),
            0x02 => Ok(FrameType::HandshakeAck),
            0x03 => Ok(FrameType::AuthFail),
            0x10 => Ok(FrameType::StreamOpen),
            0x11 => Ok(FrameType::StreamOpenAck),
            0x12 => Ok(FrameType::StreamData),
            0x13 => Ok(FrameType::StreamClose),
            0x20 => Ok(FrameType::Heartbeat),
            0x21 => Ok(FrameType::HeartbeatAck),
            0x30 => Ok(FrameType::UdpDatagram),
            0xFE => Ok(FrameType::Probe),
            0xFF => Ok(FrameType::Error),
            other => Err(ZorvError::Protocol(ProtocolError::InvalidFrameType(other))),
        }
    }
}

/// A protocol frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub version: u8,
    pub frame_type: FrameType,
    pub stream_id: u32,
    pub payload: Vec<u8>,
    pub padding: Vec<u8>,
}

impl Frame {
    /// Create a normal frame (version=VERSION, empty padding).
    pub fn new(frame_type: FrameType, stream_id: u32, payload: Vec<u8>) -> Self {
        Frame {
            version: VERSION,
            frame_type,
            stream_id,
            payload,
            padding: Vec::new(),
        }
    }

    /// Create a control frame (StreamID = CONTROL_STREAM_ID).
    pub fn new_control(frame_type: FrameType, payload: Vec<u8>) -> Self {
        Frame {
            version: VERSION,
            frame_type,
            stream_id: CONTROL_STREAM_ID,
            payload,
            padding: Vec::new(),
        }
    }

    /// Fill the padding with 0..=max random bytes to flatten packet-length
    /// distribution for traffic obfuscation.
    ///
    /// A `max` of 0 is equivalent to clearing the padding.
    pub fn apply_random_padding(&mut self, max: usize) {
        let mut rng = rand::thread_rng();
        let len = rng.gen_range(0..=max);
        let mut padding = vec![0u8; len];
        rng.fill(&mut padding[..]);
        self.padding = padding;
    }

    /// Encode the frame and append it to the end of `buf`.
    ///
    /// Order: magic, version, type, stream_id, payload_len, payload, padding_len, padding, crc32.
    pub fn encode(&self, buf: &mut BytesMut) {
        let start = buf.len();
        buf.put_u16_le(MAGIC);
        buf.put_u8(self.version);
        buf.put_u8(self.frame_type as u8);
        buf.put_u32_le(self.stream_id);
        buf.put_u32_le(self.payload.len() as u32);
        buf.put_slice(&self.payload);
        buf.put_u16_le(self.padding.len() as u16);
        buf.put_slice(&self.padding);
        // CRC32 covers magic..padding (excluding itself).
        let crc = crc32fast::hash(&buf[start..]);
        buf.put_u32_le(crc);
    }

    /// Try to decode one frame from the start of `buf`.
    ///
    /// - Returns `Ok(None)` if not enough bytes are available yet;
    /// - Returns a matching `Err` when the magic/version/type/CRC check fails;
    /// - Returns `Ok(Some(frame))` on success and removes the consumed bytes from `buf`.
    pub fn decode(buf: &mut BytesMut) -> Result<Option<Frame>> {
        // 1. Not even a header: return None.
        if buf.len() < HEADER_LEN {
            return Ok(None);
        }

        // 2. Parse the header without moving buf's read pointer (read-only cursor).
        let mut cur = Cursor::new(&buf[..]);
        let magic = cur.get_u16_le();
        if magic != MAGIC {
            return Err(ZorvError::Protocol(ProtocolError::InvalidMagic));
        }
        let version = cur.get_u8();
        if version != VERSION {
            return Err(ZorvError::Protocol(ProtocolError::InvalidVersion(version)));
        }
        let frame_type_byte = cur.get_u8();
        let frame_type = FrameType::try_from(frame_type_byte)?;
        let stream_id = cur.get_u32_le();
        let payload_len = cur.get_u32_le() as usize;

        // 3. Check whether the padding_len (2 bytes after the payload) is available.
        let padding_len_off = HEADER_LEN + payload_len;
        if buf.len() < padding_len_off + 2 {
            return Ok(None);
        }
        let mut pc = Cursor::new(&buf[padding_len_off..]);
        let padding_len = pc.get_u16_le() as usize;

        // 4. Check whether the whole frame is complete.
        let total = HEADER_LEN + payload_len + 2 + padding_len + CRC_LEN;
        if buf.len() < total {
            return Ok(None);
        }

        // 5. CRC32 check: covers [0..total-4), compared against the trailing 4 bytes.
        let expected_crc = crc32fast::hash(&buf[..total - CRC_LEN]);
        let mut cc = Cursor::new(&buf[total - CRC_LEN..total]);
        let actual_crc = cc.get_u32_le();
        if expected_crc != actual_crc {
            return Err(ZorvError::Protocol(ProtocolError::InvalidCrc));
        }

        // 6. Extract the payload / padding.
        let payload = buf[HEADER_LEN..HEADER_LEN + payload_len].to_vec();
        let padding = buf[padding_len_off + 2..padding_len_off + 2 + padding_len].to_vec();

        // 7. Remove the consumed bytes.
        buf.advance(total);

        Ok(Some(Frame {
            version,
            frame_type,
            stream_id,
            payload,
            padding,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_random_padding_within_range() {
        for _ in 0..100 {
            let mut frame = Frame::new(FrameType::StreamData, 1, vec![1, 2, 3]);
            frame.apply_random_padding(255);
            assert!(frame.padding.len() <= 255, "len={}", frame.padding.len());
        }
    }

    #[test]
    fn apply_random_padding_zero_max() {
        let mut frame = Frame::new(FrameType::StreamData, 1, vec![1, 2, 3]);
        frame.apply_random_padding(0);
        assert!(frame.padding.is_empty());
    }

    #[test]
    fn apply_random_padding_preserves_payload() {
        let mut frame = Frame::new(FrameType::StreamData, 7, vec![9, 9, 9]);
        frame.apply_random_padding(64);
        assert_eq!(frame.payload, vec![9, 9, 9]);
        assert!(frame.padding.len() <= 64);
    }
}
