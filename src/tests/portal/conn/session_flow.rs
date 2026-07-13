// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! QUIC UDP reassembly tests.

use super::*;

fn fragment<'a>(
    packet_id: u32,
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
            budget.clone(),
        ),
        ReassemblyOutcome::Pending { .. }
    ));
    let datagram = match reassembler.push(
        7,
        fragment(1, 0, 2, 6, b"abc"),
        Bytes::from_static(b"abc"),
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
fn preserves_empty_udp_packet_and_holds_one_budget_unit() {
    let budget = Arc::new(Semaphore::new(1));
    let mut reassembler = UdpReassembler::default();
    let datagram =
        match reassembler.push(8, fragment(2, 0, 1, 0, b""), Bytes::new(), budget.clone()) {
            ReassemblyOutcome::Complete { datagram, .. } => datagram,
            _ => panic!("empty packet should complete"),
        };
    assert!(datagram.payload.is_empty());
    assert_eq!(budget.available_permits(), 0);
    drop(datagram);
    assert_eq!(budget.available_permits(), 1);
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
            budget.clone(),
        ),
        ReassemblyOutcome::Dropped("connection queue byte limit reached")
    ));
    assert_eq!(budget.available_permits(), 5);
}

#[test]
fn remove_flow_releases_only_that_flows_partial_packets() {
    let budget = Arc::new(Semaphore::new(20));
    let mut reassembler = UdpReassembler::default();
    for (flow_id, packet_id) in [(10, 1), (11, 2)] {
        assert!(matches!(
            reassembler.push(
                flow_id,
                fragment(packet_id, 0, 2, 6, b"abc"),
                Bytes::from_static(b"abc"),
                budget.clone(),
            ),
            ReassemblyOutcome::Pending { .. }
        ));
    }
    assert_eq!(budget.available_permits(), 8);

    reassembler.remove_flow(10);
    assert_eq!(budget.available_permits(), 14);

    let datagram = match reassembler.push(
        11,
        fragment(2, 1, 2, 6, b"def"),
        Bytes::from_static(b"def"),
        budget.clone(),
    ) {
        ReassemblyOutcome::Complete { datagram, .. } => datagram,
        _ => panic!("unremoved flow should still complete"),
    };
    assert_eq!(datagram.payload, b"abcdef"[..]);
    assert_eq!(budget.available_permits(), 14);
    drop(datagram);
    assert_eq!(budget.available_permits(), 20);
}

#[test]
fn expiry_releases_partial_packet_budget_at_ttl() {
    let budget = Arc::new(Semaphore::new(8));
    let mut reassembler = UdpReassembler::default();
    assert!(matches!(
        reassembler.push(
            12,
            fragment(3, 0, 2, 6, b"abc"),
            Bytes::from_static(b"abc"),
            budget.clone(),
        ),
        ReassemblyOutcome::Pending { .. }
    ));
    assert_eq!(budget.available_permits(), 2);

    let expiry = reassembler
        .slots
        .values()
        .next()
        .expect("partial packet slot")
        .created_at
        + UDP_REASSEMBLY_TTL;
    assert!(!reassembler.expire(expiry));
    assert_eq!(budget.available_permits(), 2);

    assert!(reassembler.expire(expiry + Duration::from_nanos(1)));
    assert_eq!(budget.available_permits(), 8);
}

#[test]
fn conflicting_duplicate_drops_slot_and_releases_budget() {
    let budget = Arc::new(Semaphore::new(6));
    let mut reassembler = UdpReassembler::default();
    assert!(matches!(
        reassembler.push(
            13,
            fragment(4, 0, 2, 6, b"abc"),
            Bytes::from_static(b"abc"),
            budget.clone(),
        ),
        ReassemblyOutcome::Pending { .. }
    ));
    assert_eq!(budget.available_permits(), 0);
    assert!(matches!(
        reassembler.push(
            13,
            fragment(4, 0, 2, 6, b"xyz"),
            Bytes::from_static(b"xyz"),
            budget.clone(),
        ),
        ReassemblyOutcome::Dropped("conflicting duplicate UDP fragment")
    ));
    assert_eq!(budget.available_permits(), 6);
}

#[test]
fn cumulative_fragment_bytes_cannot_exceed_reserved_total() {
    let budget = Arc::new(Semaphore::new(6));
    let mut reassembler = UdpReassembler::default();
    for fragment_id in 0..2 {
        assert!(matches!(
            reassembler.push(
                14,
                fragment(5, fragment_id, 3, 6, b"abc"),
                Bytes::from_static(b"abc"),
                budget.clone(),
            ),
            ReassemblyOutcome::Pending { .. }
        ));
    }
    assert_eq!(budget.available_permits(), 0);
    assert!(matches!(
        reassembler.push(
            14,
            fragment(5, 2, 3, 6, b"abc"),
            Bytes::from_static(b"abc"),
            budget.clone(),
        ),
        ReassemblyOutcome::Dropped("UDP fragments exceed total length")
    ));
    assert_eq!(budget.available_permits(), 6);
    assert!(reassembler.slots.is_empty());
}
