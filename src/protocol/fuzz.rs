//! Deterministic protocol fuzz harness (no cargo-fuzz / nightly / libFuzzer needed).
//!
//! Mutation-based input testing of the protocol decoders with a fixed-seed PRNG:
//! - [`crate::protocol::frame::Frame::decode`] (frame parsing)
//! - [`crate::protocol::handshake::HandshakeReq::decode_payload`]
//! - [`crate::protocol::handshake::HandshakeAck::decode_payload`]
//!
//! Any panic / infinite loop counts as failure: the library functions are shared
//! with `examples/fuzz_protocol.rs`, which catches panics and prints the seed.

use bytes::{BufMut, BytesMut};

use crate::protocol::frame::{Frame, FrameType};
use crate::protocol::handshake::{HandshakeAck, HandshakeReq};

/// Cross-platform deterministic splitmix64 PRNG (independent of rand's thread entropy).
pub struct Prng(u64);

impl Prng {
    pub fn new(seed: u64) -> Self {
        Self(seed.wrapping_add(0x9E37_79B9_7F4A_7C15))
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Return an index in `[0, max)`; returns 0 when `max == 0`.
    pub fn next_usize(&mut self, max: usize) -> usize {
        if max == 0 {
            return 0;
        }
        (self.next_u64() % max as u64) as usize
    }

    pub fn next_bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    pub fn next_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(len);
        for _ in 0..len {
            v.push((self.next_u64() >> 56) as u8);
        }
        v
    }
}

/// Byte encoding of a valid frame used as the fuzz baseline.
fn base_frame_bytes(prng: &mut Prng) -> Vec<u8> {
    const TYPES: [FrameType; 12] = [
        FrameType::HandshakeReq,
        FrameType::HandshakeAck,
        FrameType::AuthFail,
        FrameType::StreamOpen,
        FrameType::StreamOpenAck,
        FrameType::StreamData,
        FrameType::StreamClose,
        FrameType::Heartbeat,
        FrameType::HeartbeatAck,
        FrameType::UdpDatagram,
        FrameType::Probe,
        FrameType::Error,
    ];
    let t = TYPES[prng.next_usize(TYPES.len())];
    let payload_len = prng.next_usize(128);
    let payload = prng.next_bytes(payload_len);
    // Build padding manually (avoid apply_random_padding's thread entropy, keep determinism).
    let padding_len = prng.next_usize(16);
    let padding = prng.next_bytes(padding_len);
    let frame = Frame {
        version: 0x01,
        frame_type: t,
        stream_id: prng.next_u64() as u32,
        payload,
        padding,
    };
    let mut buf = BytesMut::new();
    frame.encode(&mut buf);
    buf.to_vec()
}

/// Table of frame type bytes (used when mutating oversized length headers).
const FRAME_TYPE_BYTES: [u8; 12] = [
    0x01, 0x02, 0x03, 0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x30, 0xFE, 0xFF,
];

/// Mutate a byte sequence (covers truncation, bit flips, duplication, random
/// blocks, and oversized length headers).
fn mutate(prng: &mut Prng, base: &[u8], out: &mut Vec<u8>) {
    match prng.next_usize(5) {
        0 => {
            // Pure random block
            let len = prng.next_usize(256);
            out.extend_from_slice(&prng.next_bytes(len));
        }
        1 => {
            // Random truncation
            let n = prng.next_usize(base.len().saturating_add(1));
            out.extend_from_slice(&base[..n.min(base.len())]);
        }
        2 => {
            // single bit flip
            out.extend_from_slice(base);
            if !out.is_empty() {
                let i = prng.next_usize(out.len());
                let bit = prng.next_usize(8);
                out[i] ^= 1 << bit;
            }
        }
        3 => {
            // Concatenate a duplicate
            out.extend_from_slice(base);
            out.extend_from_slice(base);
        }
        _ => {
            // oversized length header attack: payload_len = u32::MAX, verifies the
            // decoder does not panic or wait forever
            out.put_u16_le(crate::protocol::frame::MAGIC);
            out.put_u8(0x01);
            let t = FRAME_TYPE_BYTES[prng.next_usize(FRAME_TYPE_BYTES.len())];
            out.push(t);
            out.put_u32_le(prng.next_u64() as u32);
            out.put_u32_le(u32::MAX);
            let len = prng.next_usize(64);
            out.extend_from_slice(&prng.next_bytes(len));
        }
    }
}

/// Stream-consuming decode: repeatedly call `Frame::decode` until `None` or an error.
/// Each `Some` consumes at least 18 bytes, guaranteeing termination.
fn drain_frame_decode(buf: &mut BytesMut) {
    loop {
        match Frame::decode(buf) {
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => break,
        }
    }
}

/// Handshake payload decode smoke: feed random bytes directly to the decoders.
fn drain_handshake_decode(payload: &[u8]) {
    let _ = HandshakeReq::decode_payload(payload);
    let _ = HandshakeAck::decode_payload(payload);
}

/// Run the deterministic fuzz. Returns the number of inputs fed to the decoders.
pub fn fuzz_protocol(seed: u64, iters: usize) -> u64 {
    let mut prng = Prng::new(seed);
    let mut executed: u64 = 0;

    for _ in 0..iters {
        let base = base_frame_bytes(&mut prng);

        // 1) Frame decode fuzz: mutate a valid frame
        let mut mutated = Vec::new();
        mutate(&mut prng, &base, &mut mutated);
        drain_frame_decode(&mut BytesMut::from(&mutated[..]));
        executed += 1;

        // 2) frame decode fuzz: pure random bytes (random length)
        let len = prng.next_usize(256);
        let random = prng.next_bytes(len);
        drain_frame_decode(&mut BytesMut::from(&random[..]));
        executed += 1;

        // 3) Handshake payload fuzz: mutate valid handshake payloads + random bytes
        let req = HandshakeReq::build("fuzz-client", "fuzz-token", "tcp");
        let ack = HandshakeAck::build("fuzz-session", 5, 30);
        let req_payload = req.encode_payload();
        let ack_payload = ack.encode_payload();
        let mut m1 = Vec::new();
        let mut m2 = Vec::new();
        mutate(&mut prng, &req_payload, &mut m1);
        mutate(&mut prng, &ack_payload, &mut m2);
        drain_handshake_decode(&m1);
        drain_handshake_decode(&m2);
        executed += 2;

        // 4) Manual splice: frame header followed by random payload, simulates
        //    fragmented/reassembled packets
        let mut spliced = Vec::new();
        spliced.extend_from_slice(&base);
        let len = prng.next_usize(64);
        spliced.extend_from_slice(&prng.next_bytes(len));
        drain_frame_decode(&mut BytesMut::from(&spliced[..]));
        executed += 1;

        // 5) truncated valid frame (prefix lengths from 1..len)
        let prefix_len = prng.next_usize(base.len().saturating_add(1));
        drain_frame_decode(&mut BytesMut::from(&base[..prefix_len.min(base.len())]));
        executed += 1;
    }

    executed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prng_is_deterministic() {
        let mut a = Prng::new(42);
        let mut b = Prng::new(42);
        for _ in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn prng_index_within_range() {
        let mut prng = Prng::new(7);
        for _ in 0..1000 {
            let i = prng.next_usize(64);
            assert!(i < 64);
        }
        assert_eq!(prng.next_usize(0), 0);
    }

    #[test]
    fn fuzz_frame_decode_smoke() {
        // Smoke test: a small number of iterations must not panic.
        let executed = fuzz_protocol(0xF00D, 500);
        assert!(executed > 0);
    }

    #[test]
    fn fuzz_handshake_payload_smoke() {
        let mut prng = Prng::new(0xBEEF);
        for _ in 0..2000 {
            let len = prng.next_usize(512);
            let payload = prng.next_bytes(len);
            drain_handshake_decode(&payload);
            drain_handshake_decode(&prng.next_bytes(0));
        }
    }

    #[test]
    fn fuzz_never_hangs_on_oversized_length() {
        // oversized length header (payload_len = u32::MAX) must return None/Err
        // immediately without blocking.
        let mut prng = Prng::new(1);
        for _ in 0..1000 {
            let mut mutated = Vec::new();
            let base = base_frame_bytes(&mut prng);
            mutate(&mut prng, &base, &mut mutated);
            drain_frame_decode(&mut BytesMut::from(&mutated[..]));
        }
    }
}
