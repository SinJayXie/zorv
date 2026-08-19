//! Zorv's private protocol module: frame codec, handshake, heartbeat, and multiplexing.

pub mod frame;
pub mod fuzz;
pub mod handshake;
pub mod heartbeat;
pub mod multiplex;

// Convenient re-exports so the server/client modules can directly `use crate::protocol::*`.
pub use frame::{Frame, FrameType, MAGIC, VERSION, CONTROL_STREAM_ID};
pub use handshake::{HandshakeReq, HandshakeAck, verify_handshake, auth_fail_frame, parse_handshake_req, parse_handshake_ack};
pub use heartbeat::{HeartbeatState, HEARTBEAT_MISS_MAX, random_heartbeat_interval, heartbeat_frame, heartbeat_ack_frame, parse_timestamp};
pub use multiplex::{StreamIdAllocator, StreamHandle, MAX_STREAMS, DEFAULT_WINDOW, build_stream_open, parse_stream_open_payload, build_stream_open_ack, parse_stream_open_ack_payload, build_stream_data, build_stream_close, build_udp_datagram, parse_udp_datagram, build_error_frame, parse_error_payload};
