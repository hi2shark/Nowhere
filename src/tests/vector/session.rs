// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

use tokio::io::AsyncWriteExt;

use super::*;

#[tokio::test]
async fn idle_health_poll_accepts_pending_and_rejects_data_or_eof() {
    let (mut pending, _peer) = tokio::io::duplex(8);
    assert!(idle_stream_usable(&mut pending));

    let (mut readable, mut peer) = tokio::io::duplex(8);
    peer.write_all(b"x").await.unwrap();
    assert!(!idle_stream_usable(&mut readable));

    let (mut eof, peer) = tokio::io::duplex(8);
    drop(peer);
    assert!(!idle_stream_usable(&mut eof));
}

#[test]
fn quic_flow_control_matches_authenticated_portal_capacity() {
    assert_eq!(QUIC_STREAM_RECEIVE_WINDOW, 16 * 1024 * 1024);
    assert_eq!(QUIC_RECEIVE_WINDOW, 32 * 1024 * 1024);
    assert_eq!(QUIC_SEND_WINDOW, 32 * 1024 * 1024);
}

#[test]
fn idle_pool_uses_oldest_lane_first() {
    let mut idle = VecDeque::new();
    store_idle(&mut idle, 1);
    store_idle(&mut idle, 2);
    store_idle(&mut idle, 3);

    assert_eq!(take_oldest_idle(&mut idle), Some(1));
    assert_eq!(take_oldest_idle(&mut idle), Some(2));
    assert_eq!(take_oldest_idle(&mut idle), Some(3));
}
