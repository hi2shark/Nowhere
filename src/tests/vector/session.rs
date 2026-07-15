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
