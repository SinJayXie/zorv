//! Server-side authentication module.
//!
//! A thin wrapper around `protocol::verify_handshake` that checks the HMAC-SHA256 token and the timestamp window.
//! IP allowlist checking is a placeholder implementation, to be completed in a later phase.

use crate::common::error::Result;
use crate::protocol::{verify_handshake, HandshakeReq};

/// Validates the handshake request: Ok(()) on success, Err(Auth) on failure.
///
/// Checks HMAC-SHA256 and the timestamp window; the IP allowlist (auth.allowed_ips)
/// is validated in server::mod during tunnel accept.
pub fn authenticate(req: &HandshakeReq, expected_token: &str) -> Result<()> {
    verify_handshake(req, expected_token)
}

/// Checks whether the peer IP is in the allow list.
///
/// Supports exact IPs ("1.2.3.4") and IPv4 CIDR ("10.0.0.0/8") formats.
pub fn ip_allowed(peer_ip: &std::net::IpAddr, allowed: &[String]) -> bool {
    allowed.iter().any(|rule| {
        if let Some((base, prefix)) = rule.split_once('/') {
            let Ok(base_ip) = base.parse::<std::net::Ipv4Addr>() else {
                return false;
            };
            let Ok(prefix) = prefix.parse::<u8>() else {
                return false;
            };
            if prefix > 32 {
                return false;
            }
            let mask = if prefix == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix)
            };
            let std::net::IpAddr::V4(peer_v4) = peer_ip else {
                return false;
            };
            let peer_u32 = u32::from(*peer_v4);
            (peer_u32 & mask) == (u32::from(base_ip) & mask)
        } else {
            rule == &peer_ip.to_string()
        }
    })
}

/// Validates the `client_id` reported by the client.
///
/// Naming rules: length 1..=64, and only ASCII letters, digits, `-` and `_` are allowed.
/// Any special character or whitespace (incl. Chinese/other non-ASCII) is rejected,
/// which also prevents XSS / injection when the id reaches the admin UI.
pub fn validate_client_id(id: &str) -> bool {
    if id.is_empty() || id.len() > 64 {
        return false;
    }
    id.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::{ip_allowed, validate_client_id};

    #[test]
    fn ip_whitelist_matching() {
        let list = vec!["1.2.3.4".to_string(), "10.0.0.0/8".to_string()];
        assert!(ip_allowed(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), &list));
        assert!(ip_allowed(&IpAddr::V4(Ipv4Addr::new(10, 99, 0, 1)), &list));
        assert!(!ip_allowed(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), &list));
        // Invalid CIDR does not match
        assert!(!ip_allowed(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &["10.0.0.0/99".to_string()]));
    }

    #[test]
    fn client_id_validation() {
        // Allowed: ASCII letters, digits, `-`, `_`.
        assert!(validate_client_id("web-1"));
        assert!(validate_client_id("web_1"));
        assert!(validate_client_id("Client123"));
        assert!(validate_client_id("a-b_c"));
        // Rejected: empty, too long, special characters, whitespace, non-ASCII.
        assert!(!validate_client_id(""));
        assert!(!validate_client_id(&"x".repeat(65)));
        assert!(!validate_client_id("a<script>"));
        assert!(!validate_client_id("a\"b"));
        assert!(!validate_client_id("a'b"));
        assert!(!validate_client_id("a b"));
        assert!(!validate_client_id("a\nb"));
        assert!(!validate_client_id("客户A"));
        assert!(!validate_client_id("a@b"));
        assert!(!validate_client_id("a.b"));
        assert!(!validate_client_id("a/b"));
        assert!(!validate_client_id("a:b"));
    }
}
