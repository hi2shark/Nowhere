// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

use std::net::SocketAddr;

use tokio::io::AsyncReadExt;

use super::*;
use crate::protocol::{encode_target, write_flow_header};

#[tokio::test]
async fn cold_lane_coalesces_auth_flow_and_target() {
    let (writer, mut reader) = tokio::io::duplex(512);
    let mut writer: BoxWriter = Box::pin(writer);
    let auth = [0xa5; AUTH_FRAME_LEN];
    let header = FlowHeader {
        role: FlowRole::Duplex,
        flow_id: 7,
        kind: FlowKind::Tcp,
        uplink: Carrier::TlsTcp,
        downlink: Carrier::TlsTcp,
    };
    let target = Target::ip(SocketAddr::from(([127, 0, 0, 1], 443))).unwrap();

    write_open_request(&mut writer, Some(auth), header, &target)
        .await
        .unwrap();
    drop(writer);

    let mut wire = Vec::new();
    reader.read_to_end(&mut wire).await.unwrap();
    let encoded_target = encode_target(&target).unwrap();
    assert_eq!(&wire[..AUTH_FRAME_LEN], &auth);
    assert_eq!(
        &wire[AUTH_FRAME_LEN..AUTH_FRAME_LEN + FLOW_HEADER_LEN],
        &write_flow_header(header)
    );
    assert_eq!(&wire[AUTH_FRAME_LEN + FLOW_HEADER_LEN..], encoded_target);
}

#[tokio::test]
async fn cold_attach_lane_coalesces_auth_and_flow_header() {
    let (writer, mut reader) = tokio::io::duplex(128);
    let mut writer: BoxWriter = Box::pin(writer);
    let auth = [0x5a; AUTH_FRAME_LEN];
    let header = FlowHeader {
        role: FlowRole::Attach,
        flow_id: 9,
        kind: FlowKind::Udp,
        uplink: Carrier::TlsTcp,
        downlink: Carrier::Quic,
    };

    write_header(&mut writer, Some(auth), header).await.unwrap();
    drop(writer);

    let mut wire = Vec::new();
    reader.read_to_end(&mut wire).await.unwrap();
    assert_eq!(&wire[..AUTH_FRAME_LEN], &auth);
    assert_eq!(&wire[AUTH_FRAME_LEN..], &write_flow_header(header));
}
