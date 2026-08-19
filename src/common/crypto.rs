//! General-purpose cryptography and timestamp utilities.
//!
//! Provides HMAC-SHA256-based authentication MACs, millisecond timestamp
//! generation/verification, and one-time nonce generation for authentication and
//! anti-replay modules.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

/// HMAC-SHA256 algorithm alias.
type HmacSha256 = Hmac<Sha256>;

/// Default timestamp verification window: 30 seconds.
pub const TIMESTAMP_WINDOW_SECS: u64 = 30;

/// Calculate `HMAC-SHA256(key, msg)`, return 32-byte MAC.
///
/// `key` is arbitrary length (HMAC internally pads/hashses), `msg` is the data to be authenticated.
/// In Zorv, mainly used for token+timestamp derived authentication signatures.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    // new_from_slice succeeds for any key length (HMAC has no key-length limit);
    // it can only fail in extreme cases such as an empty key, treated as unreachable.
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

/// Return the current Unix millisecond timestamp.
///
/// Uses `SystemTime::now()`, cross-platform compatible (Windows/Linux/macOS).
/// Returns 0 if the system clock is before `UNIX_EPOCH` (extreme exception).
pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Verify if a timestamp is within `[now - window_secs, now + window_secs]` range.
///
/// `ts_millis` is the timestamp to verify, `window_secs` is the allowed offset in seconds.
/// Defaults to `TIMESTAMP_WINDOW_SECS`.

pub fn verify_timestamp(ts_millis: u64, window_secs: u64) -> bool {
    let now = now_millis();
    let diff = if now > ts_millis {
        now - ts_millis
    } else {
        ts_millis - now
    };
    diff <= window_secs.saturating_mul(1000)
}

/// Generate a random nonce string based on UUID v4.
///
/// Used as a random anti-replay identifier during the MVP (e.g. attached to the
/// handshake); recent nonces can later be cached server-side for deduplication.
pub fn gen_nonce() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_known_vector() {
        // RFC 4231 Test Case 1: key=0x0b*20, data="Hi There"
        let key = [0x0bu8; 20];
        let msg = b"Hi There";
        let mac = hmac_sha256(&key, msg);
        // basic length assertion on the 32-byte MAC
        assert_eq!(mac.len(), 32);
        // RFC 4231 expected first byte
        let expected_first = 0xb0u8;
        assert_eq!(mac[0], expected_first);
    }

    #[test]
    fn timestamp_window_accepts_now() {
        let now = now_millis();
        assert!(verify_timestamp(now, TIMESTAMP_WINDOW_SECS));
    }

    #[test]
    fn timestamp_window_rejects_old() {
        let old = now_millis().saturating_sub(60_000); // 60s ago
        assert!(!verify_timestamp(old, TIMESTAMP_WINDOW_SECS));
    }

    #[test]
    fn nonce_unique() {
        let a = gen_nonce();
        let b = gen_nonce();
        assert_ne!(a, b);
        assert_eq!(a.len(), 36); // standard UUID v4 length 8-4-4-4-12 = 36
    }
}
