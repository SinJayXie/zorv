//! Zorv protocol heartbeat module (Task 4.2).
//!
//! Provides HEARTBEAT / HEARTBEAT_ACK frame construction and timestamp parsing, plus a
//! lightweight `HeartbeatState` logic skeleton. The actual async scheduling (periodic
//! sending, timeout detection) lives in the tunnel read/write loops of server/client;
//! this module only provides data structures and utility functions.

use std::time::Duration;

use rand::Rng;

use crate::common::crypto::now_millis;
use crate::protocol::frame::{Frame, FrameType};

/// Threshold of consecutive missed heartbeats before declaring a disconnect.
pub const HEARTBEAT_MISS_MAX: u32 = 3;

/// Generate a random heartbeat interval within `[min_sec, max_sec]`.
///
/// If `min_sec > max_sec`, `gen_range` panics in debug builds and is undefined
/// in release builds, so callers must guarantee `min_sec <= max_sec`.
pub fn random_heartbeat_interval(min_sec: u32, max_sec: u32) -> Duration {
    let mut rng = rand::thread_rng();
    let secs = rng.gen_range(min_sec..=max_sec);
    Duration::from_secs(secs as u64)
}

/// Build a `HEARTBEAT` control frame whose payload is the current millisecond
/// timestamp as little-endian 8 bytes.
pub fn heartbeat_frame() -> Frame {
    let ts = now_millis();
    Frame::new_control(FrameType::Heartbeat, ts.to_le_bytes().to_vec())
}

/// Build a `HEARTBEAT_ACK` control frame echoing the peer's timestamp.
pub fn heartbeat_ack_frame(peer_timestamp: u64) -> Frame {
    Frame::new_control(
        FrameType::HeartbeatAck,
        peer_timestamp.to_le_bytes().to_vec(),
    )
}

/// Parse the timestamp from a HEARTBEAT / HEARTBEAT_ACK payload.
///
/// Returns `Err(())` if the payload is shorter than 8 bytes.
pub fn parse_timestamp(payload: &[u8]) -> Result<u64, ()> {
    if payload.len() < 8 {
        return Err(());
    }
    let mut a = [0u8; 8];
    a.copy_from_slice(&payload[..8]);
    Ok(u64::from_le_bytes(a))
}

/// Heartbeat logic state skeleton.
///
/// Tracks the heartbeat interval range and the consecutive missed count, driven by
/// the tunnel read/write loop: call `on_heartbeat_sent` (+1 to the miss count)
/// after each HEARTBEAT is sent, and `on_heartbeat_ack` (reset to 0) when the
/// matching HEARTBEAT_ACK is received. The connection is considered dead once
/// `miss_count >= max_miss`.
#[derive(Debug, Clone)]
pub struct HeartbeatState {
    pub min_sec: u32,
    pub max_sec: u32,
    pub miss_count: u32,
    pub max_miss: u32,
}

impl HeartbeatState {
    pub fn new(min_sec: u32, max_sec: u32) -> Self {
        Self {
            min_sec,
            max_sec,
            miss_count: 0,
            max_miss: HEARTBEAT_MISS_MAX,
        }
    }

    /// Compute the next heartbeat interval.
    pub fn next_interval(&self) -> Duration {
        random_heartbeat_interval(self.min_sec, self.max_sec)
    }

    /// Call after sending a heartbeat; the miss count is incremented with saturation.
    pub fn on_heartbeat_sent(&mut self) {
        self.miss_count = self.miss_count.saturating_add(1);
    }

    /// Call after receiving a heartbeat ack; resets the miss count to zero.
    pub fn on_heartbeat_ack(&mut self) {
        self.miss_count = 0;
    }

    /// Determine whether the connection is dead due to consecutive missed responses.
    pub fn is_dead(&self) -> bool {
        self.miss_count >= self.max_miss
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_interval_within_range() {
        for _ in 0..200 {
            let d = random_heartbeat_interval(5, 10);
            let secs = d.as_secs();
            assert!(secs >= 5 && secs <= 10, "got {}s", secs);
        }
        // Boundary case: equal min and max.
        let d = random_heartbeat_interval(7, 7);
        assert_eq!(d.as_secs(), 7);
    }

    #[test]
    fn heartbeat_frame_roundtrip() {
        let frame = heartbeat_frame();
        assert_eq!(frame.frame_type, FrameType::Heartbeat);
        let ts = parse_timestamp(&frame.payload).unwrap();
        // should be near the current time (allow 5s skew to tolerate CI scheduling jitter)
        let now = now_millis();
        let diff = if now > ts { now - ts } else { ts - now };
        assert!(diff < 5_000, "ts diff too large: {}ms", diff);
    }

    #[test]
    fn heartbeat_ack_echoes_timestamp() {
        let ts = now_millis().saturating_sub(1_000);
        let frame = heartbeat_ack_frame(ts);
        assert_eq!(frame.frame_type, FrameType::HeartbeatAck);
        assert_eq!(parse_timestamp(&frame.payload).unwrap(), ts);
    }

    #[test]
    fn parse_timestamp_too_short() {
        assert!(parse_timestamp(&[0u8, 1, 2]).is_err());
        assert!(parse_timestamp(&[]).is_err());
    }

    #[test]
    fn heartbeat_state_miss_and_dead() {
        let mut s = HeartbeatState::new(5, 10);
        assert!(!s.is_dead());
        s.on_heartbeat_sent();
        s.on_heartbeat_sent();
        assert!(!s.is_dead()); // miss=2
        s.on_heartbeat_sent();
        assert!(s.is_dead()); // miss=3
    }

    #[test]
    fn heartbeat_state_ack_resets() {
        let mut s = HeartbeatState::new(5, 10);
        s.on_heartbeat_sent();
        s.on_heartbeat_sent();
        assert_eq!(s.miss_count, 2);
        s.on_heartbeat_ack();
        assert_eq!(s.miss_count, 0);
        assert!(!s.is_dead());
    }
}
