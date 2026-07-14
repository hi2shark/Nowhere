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
        uplink: Carrier::TlsTcp,
        downlink: Carrier::Quic,
    };
    let bytes = write_flow_header(expected);
    assert_eq!(bytes, [0xf1, 1, 2, 0, 0, 0, 0, 0, 0, 0, 42, 2, 1, 2]);
    assert_eq!(
        read_flow_header(&mut bytes.as_slice()).await.unwrap(),
        expected
    );
}

#[tokio::test]
async fn duplex_and_result_vectors_match_the_swift_codec() {
    let header = FlowHeader {
        role: FlowRole::Duplex,
        flow_id: 0x0102_0304_0506_0708,
        kind: FlowKind::Tcp,
        uplink: Carrier::Quic,
        downlink: Carrier::Quic,
    };
    let bytes = write_flow_header(header);
    assert_eq!(bytes, [0xf1, 1, 3, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 2]);
    assert_eq!(
        read_flow_header(&mut bytes.as_slice()).await.unwrap(),
        header
    );

    assert_eq!(encode_flow_result(FlowResult::Ready), [0xf2, 1, 1, 0]);
    assert_eq!(
        encode_flow_result(FlowResult::Reject(FlowErrorCode::PairTimeout)),
        [0xf2, 1, 2, 3]
    );
    assert_eq!(
        read_flow_result(&mut [0xf2, 1, 2, 6].as_slice())
            .await
            .unwrap(),
        FlowResult::Reject(FlowErrorCode::SessionReplaced)
    );
}

#[tokio::test]
async fn rejects_invalid_role_carrier_shapes_and_results() {
    let mut split = write_flow_header(FlowHeader {
        role: FlowRole::Open,
        flow_id: 1,
        kind: FlowKind::Udp,
        uplink: Carrier::TlsTcp,
        downlink: Carrier::Quic,
    });
    split[13] = Carrier::TlsTcp as u8;
    assert!(read_flow_header(&mut split.as_slice()).await.is_err());

    let mut duplex = write_flow_header(FlowHeader {
        role: FlowRole::Duplex,
        flow_id: 1,
        kind: FlowKind::Udp,
        uplink: Carrier::Quic,
        downlink: Carrier::Quic,
    });
    duplex[13] = Carrier::TlsTcp as u8;
    assert!(read_flow_header(&mut duplex.as_slice()).await.is_err());

    for invalid in [[0xf2, 1, 1, 1], [0xf2, 1, 2, 0], [0xf2, 1, 2, 8]] {
        assert!(read_flow_result(&mut invalid.as_slice()).await.is_err());
    }
}
