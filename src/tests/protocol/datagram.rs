// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Fixed QUIC UDP frame codec tests.

use super::*;

#[test]
fn fixed_vectors_match_the_swift_codec() {
    let open = encode_udp_open_fragments(
        0x0102_0304_0506_0708,
        0x1122,
        Carrier::Udp,
        "x:1",
        &[0xaa, 0xbb],
        1_200,
    )
    .unwrap();
    assert_eq!(
        open[0],
        [
            b'N', b'O', b'W', b'U', 1, 1, 2, 3, 4, 5, 6, 7, 8, 2, 0, 3, b'x', b':', b'1', 0x11,
            0x22, 0, 1, 0, 2, 0xaa, 0xbb,
        ]
    );

    let empty = encode_udp_data_fragments(1, 2, &[], 1_200).unwrap();
    assert_eq!(
        empty[0],
        [
            b'N', b'O', b'W', b'U', 3, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 1, 0, 0,
        ]
    );
}

#[test]
fn control_frames_round_trip_and_reject_payloads() {
    let ack = encode_udp_control(UDP_FRAME_OPEN_ACK, 7).unwrap();
    assert_eq!(&ack[..4], b"NOWU");
    assert_eq!(
        decode_udp_frame(&ack).unwrap(),
        UdpFrame::OpenAck { flow_id: 7 }
    );

    let close = encode_udp_control(UDP_FRAME_CLOSE, 9).unwrap();
    assert_eq!(
        decode_udp_frame(&close).unwrap(),
        UdpFrame::Close { flow_id: 9 }
    );

    let mut invalid = ack;
    invalid.push(0);
    assert!(decode_udp_frame(&invalid).is_err());
    assert!(encode_udp_control(UDP_FRAME_DATA, 1).is_err());
    assert!(encode_udp_control(UDP_FRAME_CLOSE, 0).is_err());
}

#[test]
fn open_packet_fragments_round_trip() {
    let payload = vec![0x5a; 2_500];
    let frames =
        encode_udp_open_fragments(11, 23, Carrier::Tcp, "example.com:443", &payload, 1_200)
            .unwrap();
    assert_eq!(frames.len(), 3);

    let mut assembled = Vec::new();
    for (index, frame) in frames.iter().enumerate() {
        assert!(frame.len() <= 1_200);
        match decode_udp_frame(frame).unwrap() {
            UdpFrame::OpenData {
                flow_id,
                downlink,
                target,
                fragment,
            } => {
                assert_eq!(flow_id, 11);
                assert_eq!(downlink, Carrier::Tcp);
                assert_eq!(target, "example.com:443");
                assert_eq!(fragment.packet_id, 23);
                assert_eq!(fragment.fragment_id as usize, index);
                assert_eq!(fragment.fragment_count as usize, frames.len());
                assert_eq!(fragment.total_len as usize, payload.len());
                assembled.extend_from_slice(fragment.payload);
            }
            other => panic!("unexpected frame: {other:?}"),
        }
    }
    assert_eq!(assembled, payload);
}

#[test]
fn data_packet_preserves_empty_udp_payload() {
    let frames = encode_udp_data_fragments(5, 6, &[], 64).unwrap();
    assert_eq!(frames.len(), 1);
    match decode_udp_frame(&frames[0]).unwrap() {
        UdpFrame::Data { flow_id, fragment } => {
            assert_eq!(flow_id, 5);
            assert_eq!(fragment.packet_id, 6);
            assert_eq!(fragment.fragment_count, 1);
            assert_eq!(fragment.total_len, 0);
            assert!(fragment.payload.is_empty());
        }
        other => panic!("unexpected frame: {other:?}"),
    }
}

#[test]
fn data_packet_rejects_invalid_fragment_metadata() {
    let mut frame = encode_udp_data_fragments(5, 6, b"abc", 64)
        .unwrap()
        .remove(0);
    let fragment_count_offset = 4 + 1 + 8 + 2 + 1;
    frame[fragment_count_offset] = 0;
    assert!(decode_udp_frame(&frame).is_err());

    let mut wrong_total = encode_udp_data_fragments(5, 6, b"abc", 64)
        .unwrap()
        .remove(0);
    let total_len_offset = fragment_count_offset + 1;
    wrong_total[total_len_offset..total_len_offset + 2].copy_from_slice(&2u16.to_be_bytes());
    assert!(decode_udp_frame(&wrong_total).is_err());
}

#[test]
fn fragmentation_rejects_impossible_datagram_limits_and_oversized_udp() {
    assert!(encode_udp_data_fragments(1, 1, b"x", 19).is_err());
    assert!(encode_udp_data_fragments(1, 1, &vec![0; UDP_PACKET_MAX + 1], usize::MAX).is_err());
    let target = format!("{}:1", "a".repeat(510));
    assert!(encode_udp_open_fragments(1, 1, Carrier::Udp, &target, b"x", 500).is_err());
}

#[test]
fn fixed_magic_eliminates_legacy_layout_collisions() {
    let legacy_prefix = [0x01, 0x13, b'a', b'a'];
    assert!(decode_udp_frame(&legacy_prefix).is_err());
}
