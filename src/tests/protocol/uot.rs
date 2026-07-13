// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! UDP-over-TCP frame tests.

use super::*;

#[tokio::test]
async fn setup_target_frame_round_trips() {
    let frame = write_uot_setup_frame("example.com:53").unwrap();
    let mut reader = frame.as_slice();

    assert_eq!(
        read_uot_setup_target(&mut reader).await.unwrap(),
        "example.com:53"
    );
}

#[tokio::test]
async fn typed_frames_distinguish_empty_data_ack_close_and_eof() {
    let mut bytes = encode_udp_stream_frame(UDP_STREAM_DATA, b"").unwrap();
    bytes.extend_from_slice(&encode_udp_stream_frame(UDP_STREAM_OPEN_ACK, b"").unwrap());
    bytes.extend_from_slice(&encode_udp_stream_frame(UDP_STREAM_CLOSE, b"").unwrap());
    let mut reader = bytes.as_slice();

    assert_eq!(
        read_udp_stream_frame(&mut reader).await.unwrap(),
        Some(UdpStreamFrame::Data(Vec::new()))
    );
    assert_eq!(
        read_udp_stream_frame(&mut reader).await.unwrap(),
        Some(UdpStreamFrame::OpenAck)
    );
    assert_eq!(
        read_udp_stream_frame(&mut reader).await.unwrap(),
        Some(UdpStreamFrame::Close)
    );
    assert_eq!(read_udp_stream_frame(&mut reader).await.unwrap(), None);
}

#[tokio::test]
async fn stream_writer_matches_encoded_frame() {
    let mut out = Vec::new();
    write_udp_stream_frame(&mut out, UDP_STREAM_DATA, b"abc")
        .await
        .unwrap();
    assert_eq!(
        out,
        encode_udp_stream_frame(UDP_STREAM_DATA, b"abc").unwrap()
    );
}

#[test]
fn rejects_invalid_stream_frames() {
    assert!(encode_udp_stream_frame(9, b"").is_err());
    assert!(encode_udp_stream_frame(UDP_STREAM_OPEN_ACK, b"bad").is_err());
    assert!(encode_udp_stream_frame(UDP_STREAM_DATA, &vec![0; u16::MAX as usize + 1]).is_err());
}

#[test]
fn rejects_invalid_setup_target() {
    assert!(write_uot_setup_frame("example.com").is_err());
}

#[tokio::test]
async fn rejects_oversized_setup_target() {
    let target = format!("{}:53", "a".repeat(510));
    let mut frame = Vec::with_capacity(2 + target.len());
    frame.extend_from_slice(&(target.len() as u16).to_be_bytes());
    frame.extend_from_slice(target.as_bytes());
    let mut reader = frame.as_slice();
    assert!(read_uot_setup_target(&mut reader).await.is_err());
}
