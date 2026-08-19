//! Zorv unified error types.
//!
//! All modules return `Result<T, ZorvError>`. `thiserror` automatically derives
//! `Display` and `std::error::Error`, and `#[from]` enables automatic `?` conversion.

use thiserror::Error;

/// Zorv top-level error enum.
#[derive(Debug, Error)]
pub enum ZorvError {
    /// IO error (file, network read/write, etc.); auto-converted from `std::io::Error` via `#[from]`.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// TLS-related error; holds a rustls error or a self-describing Debug string.
    #[error("tls error: {0}")]
    Tls(String),

    /// Protocol error, wrapping the more specific `ProtocolError` variants.
    #[error("protocol error: {0:?}")]
    Protocol(ProtocolError),

    /// Authentication failure (invalid token, signature mismatch, IP not in allowlist, etc.).
    #[error("auth error: {0}")]
    Auth(String),

    /// Configuration error (TOML parsing, missing fields, invalid values, etc.).
    #[error("config error: {0}")]
    Config(String),

    /// Multiplexing stream-related errors.
    #[error("stream error: {0:?}")]
    Stream(StreamError),

    /// Other uncategorized errors.
    #[error("other error: {0}")]
    Other(String),
}

/// Protocol-layer errors (frame parsing, handshake, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    /// Magic number mismatch.
    InvalidMagic,
    /// CRC32 checksum failure.
    InvalidCrc,
    /// Incomplete frame; more data is needed.
    Incomplete,
    /// Unknown frame type.
    InvalidFrameType(u8),
    /// Unsupported protocol version.
    InvalidVersion(u8),
}

/// Multiplexing stream errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamError {
    /// Stream is closed.
    Closed(u32),
    /// No stream with the given id was found.
    NotFound(u32),
    /// Stream rejected by the peer.
    Rejected(u32),
}

/// Zorv unified Result alias.
pub type Result<T> = std::result::Result<T, ZorvError>;
