// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Transport-independent flow envelope tests.

use super::*;

#[tokio::test]
async fn round_trip() {
    let expected = FlowHeader {
        role: FlowRole::Attach,
        flow_id: 42,
        kind: FlowKind::Udp,
        uplink: Carrier::Tcp,
        downlink: Carrier::Udp,
    };
    let bytes = write_flow_header(expected);
    assert_eq!(bytes, [0xf1, 1, 2, 0, 0, 0, 0, 0, 0, 0, 42, 2, 1, 2]);
    assert_eq!(
        read_flow_header(&mut bytes.as_slice()).await.unwrap(),
        expected
    );
}
