// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! QUIC UDP reassembly tests.

use super::*;

fn fragment<'a>(
    packet_id: u16,
    fragment_id: u8,
    fragment_count: u8,
    total_len: u16,
    payload: &'a [u8],
) -> UdpFragment<'a> {
    UdpFragment {
        packet_id,
        fragment_id,
        fragment_count,
        total_len,
        payload,
    }
}

#[test]
fn reassembles_out_of_order_and_releases_budget_with_packet() {
    let budget = Arc::new(Semaphore::new(32));
    let mut reassembler = UdpReassembler::default();
    assert!(matches!(
        reassembler.push(
            7,
            fragment(1, 1, 2, 6, b"def"),
            Bytes::from_static(b"def"),
            None,
            budget.clone(),
        ),
        ReassemblyOutcome::Pending { .. }
    ));
    let datagram = match reassembler.push(
        7,
        fragment(1, 0, 2, 6, b"abc"),
        Bytes::from_static(b"abc"),
        None,
        budget.clone(),
    ) {
        ReassemblyOutcome::Complete { datagram, .. } => datagram,
        _ => panic!("packet should complete"),
    };
    assert_eq!(datagram.payload, b"abcdef"[..]);
    assert_eq!(budget.available_permits(), 26);
    drop(datagram);
    assert_eq!(budget.available_permits(), 32);
}

#[test]
fn preserves_empty_udp_packet_and_open_metadata() {
    let budget = Arc::new(Semaphore::new(1));
    let mut reassembler = UdpReassembler::default();
    let metadata = OpenMetadata {
        downlink: Carrier::Udp,
        target: "example.com:53".to_string(),
    };
    match reassembler.push(
        8,
        fragment(2, 0, 1, 0, b""),
        Bytes::new(),
        Some(metadata.clone()),
        budget,
    ) {
        ReassemblyOutcome::Complete {
            datagram,
            metadata: actual,
            ..
        } => {
            assert!(datagram.payload.is_empty());
            assert_eq!(actual, Some(metadata));
        }
        _ => panic!("empty packet should complete"),
    }
}

#[test]
fn packet_budget_rejects_oversized_reassembly() {
    let budget = Arc::new(Semaphore::new(5));
    let mut reassembler = UdpReassembler::default();
    assert!(matches!(
        reassembler.push(
            9,
            fragment(3, 0, 2, 6, b"abc"),
            Bytes::from_static(b"abc"),
            None,
            budget,
        ),
        ReassemblyOutcome::Dropped("connection queue byte limit reached")
    ));
}
