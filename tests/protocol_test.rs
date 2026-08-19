//! Integration tests for Zorv protocol frame encode/decode (Task 3).

use bytes::{BufMut, BytesMut};
use zorv::common::error::{ProtocolError, ZorvError};
use zorv::protocol::frame::{Frame, FrameType, CONTROL_STREAM_ID, MAGIC, VERSION};

/// Round-trip of a normal frame: encode -> decode should yield an equivalent frame.
#[test]
fn test_roundtrip() {
    let frame = Frame::new(FrameType::StreamData, 42, b"hello".to_vec());
    let mut buf = BytesMut::new();
    frame.encode(&mut buf);

    // header(12) + payload(5) + padding_len(2) + padding(0) + crc(4) = 23
    assert_eq!(buf.len(), 12 + 5 + 2 + 0 + 4);

    let decoded = Frame::decode(&mut buf).expect("decode err").expect("incomplete");
    assert_eq!(decoded, frame);
    assert!(buf.is_empty(), "buffer should be fully consumed");
}

/// Round-trip of a frame with padding.
#[test]
fn test_with_padding() {
    let mut frame = Frame::new(FrameType::StreamData, 7, b"hi".to_vec());
    frame.padding = vec![0xAB; 8];
    let mut buf = BytesMut::new();
    frame.encode(&mut buf);

    let decoded = Frame::decode(&mut buf).expect("decode err").expect("incomplete");
    assert_eq!(decoded, frame);
    assert!(buf.is_empty());
}

/// A control frame's StreamID should be CONTROL_STREAM_ID.
#[test]
fn test_control_frame() {
    let frame = Frame::new_control(FrameType::Heartbeat, b"ts".to_vec());
    assert_eq!(frame.stream_id, CONTROL_STREAM_ID);
    assert_eq!(frame.frame_type, FrameType::Heartbeat);

    let mut buf = BytesMut::new();
    frame.encode(&mut buf);
    let decoded = Frame::decode(&mut buf).expect("decode err").expect("incomplete");
    assert_eq!(decoded.stream_id, CONTROL_STREAM_ID);
    assert_eq!(decoded.frame_type, FrameType::Heartbeat);
}

/// A bad magic number should return InvalidMagic (checked before CRC).
#[test]
fn test_invalid_magic() {
    let frame = Frame::new(FrameType::StreamData, 1, b"x".to_vec());
    let mut buf = BytesMut::new();
    frame.encode(&mut buf);
    // Tamper with the low byte of the magic
    buf[0] = 0x00;

    let err = Frame::decode(&mut buf).unwrap_err();
    assert!(matches!(err, ZorvError::Protocol(ProtocolError::InvalidMagic)));
}

/// Tampering with one payload byte (leaving the trailing CRC untouched) should return InvalidCrc.
#[test]
fn test_crc_mismatch() {
    let frame = Frame::new(FrameType::StreamData, 9, b"payload".to_vec());
    let mut buf = BytesMut::new();
    frame.encode(&mut buf);
    // Payload occupies [12..19); flip buf[14] (payload[2]) without affecting the trailing 4-byte CRC
    buf[14] ^= 0xFF;

    let err = Frame::decode(&mut buf).unwrap_err();
    assert!(matches!(err, ZorvError::Protocol(ProtocolError::InvalidCrc)));
}

/// A truncated frame should return Ok(None).
#[test]
fn test_incomplete_frame() {
    let frame = Frame::new(FrameType::StreamData, 1, b"hello".to_vec());
    let mut buf = BytesMut::new();
    frame.encode(&mut buf);
    buf.truncate(5);
    assert!(buf.len() < 12);

    let res = Frame::decode(&mut buf).expect("decode should not error on incomplete");
    assert!(res.is_none());
}

/// An unknown frame type 0x99 (with correct magic/version/CRC) should return InvalidFrameType(0x99).
#[test]
fn test_invalid_frame_type() {
    let payload = b"data".to_vec();
    let mut buf = BytesMut::new();
    buf.put_u16_le(MAGIC);
    buf.put_u8(VERSION);
    buf.put_u8(0x99); // unknown type
    buf.put_u32_le(123);
    buf.put_u32_le(payload.len() as u32);
    buf.put_slice(&payload);
    buf.put_u16_le(0); // padding_len
    // CRC covers magic..padding
    let crc = crc32fast::hash(&buf[..]);
    buf.put_u32_le(crc);

    let err = Frame::decode(&mut buf).unwrap_err();
    assert!(matches!(
        err,
        ZorvError::Protocol(ProtocolError::InvalidFrameType(0x99))
    ));
}

/// Two consecutive frames in one buffer: two decode calls each yield one frame and drain the buffer.
#[test]
fn test_multiple_frames_in_buffer() {
    let f1 = Frame::new(FrameType::StreamData, 1, b"aaa".to_vec());
    let f2 = Frame::new_control(FrameType::Heartbeat, b"bb".to_vec());
    let mut buf = BytesMut::new();
    f1.encode(&mut buf);
    f2.encode(&mut buf);

    let d1 = Frame::decode(&mut buf)
        .expect("decode err 1")
        .expect("frame 1 missing");
    assert_eq!(d1, f1);

    let d2 = Frame::decode(&mut buf)
        .expect("decode err 2")
        .expect("frame 2 missing");
    assert_eq!(d2, f2);

    assert!(buf.is_empty(), "buffer should be empty after both frames");
}
