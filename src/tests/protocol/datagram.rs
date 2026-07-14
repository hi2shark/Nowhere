// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Fixed QUIC UDP frame codec tests.

use super::*;

#[test]
fn fixed_vectors_match_the_swift_codec() {
    let data = encode_udp_data_fragments(0x0102_0304_0506_0708, 0x1122_3344, &[0xaa, 0xbb], 1_200)
        .unwrap();
    assert_eq!(
        data[0],
        [
            b'N', b'O', b'W', b'U', 1, 1, 2, 3, 4, 5, 6, 7, 8, 0x11, 0x22, 0x33, 0x44, 0, 1, 0, 2,
            0xaa, 0xbb,
        ]
    );

    let empty = encode_udp_data_fragments(1, 2, &[], 1_200).unwrap();
    assert_eq!(
        empty[0],
        [
            b'N', b'O', b'W', b'U', 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 1, 0, 0,
        ]
    );

    assert_eq!(
        encode_udp_close(0x0102_0304_0506_0708).unwrap(),
        [b'N', b'O', b'W', b'U', 2, 1, 2, 3, 4, 5, 6, 7, 8]
    );
}

#[test]
fn close_round_trips_and_rejects_payloads() {
    let close = encode_udp_close(9).unwrap();
    assert_eq!(
        decode_udp_frame(&close).unwrap(),
        UdpFrame::Close { flow_id: 9 }
    );

    let mut invalid = close;
    invalid.push(0);
    assert!(decode_udp_frame(&invalid).is_err());
    assert!(encode_udp_close(0).is_err());
}

#[test]
fn data_packet_fragments_round_trip() {
    let payload = vec![0x5a; 2_500];
    let frames = encode_udp_data_fragments(11, 0x1020_3040, &payload, 1_200).unwrap();
    assert_eq!(frames.len(), 3);

    let mut assembled = Vec::new();
    for (index, frame) in frames.iter().enumerate() {
        assert!(frame.len() <= 1_200);
        match decode_udp_frame(frame).unwrap() {
            UdpFrame::Data { flow_id, fragment } => {
                assert_eq!(flow_id, 11);
                assert_eq!(fragment.packet_id, 0x1020_3040);
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
    assert!(encode_udp_data_fragments(5, 0, b"abc", 64).is_err());

    let mut zero_packet = encode_udp_data_fragments(5, 6, b"abc", 64)
        .unwrap()
        .remove(0);
    zero_packet[13..17].fill(0);
    assert!(decode_udp_frame(&zero_packet).is_err());

    let mut zero_count = encode_udp_data_fragments(5, 6, b"abc", 64)
        .unwrap()
        .remove(0);
    zero_count[18] = 0;
    assert!(decode_udp_frame(&zero_count).is_err());

    let mut wrong_total = encode_udp_data_fragments(5, 6, b"abc", 64)
        .unwrap()
        .remove(0);
    wrong_total[19..21].copy_from_slice(&2u16.to_be_bytes());
    assert!(decode_udp_frame(&wrong_total).is_err());
}

#[test]
fn fragmentation_rejects_impossible_datagram_limits_and_oversized_udp() {
    assert!(encode_udp_data_fragments(1, 1, b"x", 21).is_err());
    assert!(encode_udp_data_fragments(1, 1, &vec![0; UDP_PACKET_MAX + 1], usize::MAX).is_err());
}

#[test]
fn fixed_magic_and_types_reject_older_udp_layouts() {
    assert!(decode_udp_frame(&[0x01, 0x13, b'a', b'a']).is_err());
    let mut old_data = encode_udp_data_fragments(1, 1, b"x", 64).unwrap().remove(0);
    old_data[4] = 3;
    assert!(decode_udp_frame(&old_data).is_err());
}
