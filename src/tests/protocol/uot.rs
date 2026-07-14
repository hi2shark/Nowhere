// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! UDP-over-TCP frame tests.

use super::*;

#[tokio::test]
async fn typed_frames_distinguish_empty_data_ready_reject_close_and_eof() {
    let mut bytes = encode_udp_stream_frame(UDP_STREAM_DATA, b"").unwrap();
    bytes.extend_from_slice(&encode_udp_stream_frame(UDP_STREAM_READY, b"").unwrap());
    bytes.extend_from_slice(
        &encode_udp_stream_frame(UDP_STREAM_REJECT, &[FlowErrorCode::MetadataConflict as u8])
            .unwrap(),
    );
    bytes.extend_from_slice(&encode_udp_stream_frame(UDP_STREAM_CLOSE, b"").unwrap());
    let mut reader = bytes.as_slice();

    assert_eq!(
        read_udp_stream_frame(&mut reader).await.unwrap(),
        Some(UdpStreamFrame::Data(Vec::new()))
    );
    assert_eq!(
        read_udp_stream_frame(&mut reader).await.unwrap(),
        Some(UdpStreamFrame::Ready)
    );
    assert_eq!(
        read_udp_stream_frame(&mut reader).await.unwrap(),
        Some(UdpStreamFrame::Reject(FlowErrorCode::MetadataConflict))
    );
    assert_eq!(
        read_udp_stream_frame(&mut reader).await.unwrap(),
        Some(UdpStreamFrame::Close)
    );
    assert_eq!(read_udp_stream_frame(&mut reader).await.unwrap(), None);
}

#[test]
fn fixed_control_vectors_match_the_swift_codec() {
    assert_eq!(
        encode_udp_stream_frame(UDP_STREAM_READY, b"").unwrap(),
        [2, 0, 0]
    );
    assert_eq!(
        encode_udp_stream_frame(UDP_STREAM_CLOSE, b"").unwrap(),
        [3, 0, 0]
    );
    assert_eq!(
        encode_udp_stream_frame(UDP_STREAM_REJECT, &[5]).unwrap(),
        [4, 0, 1, 5]
    );
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

#[tokio::test]
async fn truncated_length_is_an_error_not_a_panic() {
    for bytes in [vec![UDP_STREAM_DATA], vec![UDP_STREAM_DATA, 0]] {
        let mut reader = bytes.as_slice();
        assert!(read_udp_stream_frame(&mut reader).await.is_err());
    }
}

#[test]
fn rejects_invalid_stream_frames() {
    assert!(encode_udp_stream_frame(9, b"").is_err());
    assert!(encode_udp_stream_frame(UDP_STREAM_READY, b"bad").is_err());
    assert!(encode_udp_stream_frame(UDP_STREAM_REJECT, b"").is_err());
    assert!(encode_udp_stream_frame(UDP_STREAM_REJECT, &[0]).is_err());
    assert!(encode_udp_stream_frame(UDP_STREAM_REJECT, &[8]).is_err());
    assert!(encode_udp_stream_frame(UDP_STREAM_REJECT, &[1, 2]).is_err());
    assert!(encode_udp_stream_frame(UDP_STREAM_DATA, &vec![0; u16::MAX as usize + 1]).is_err());
}
