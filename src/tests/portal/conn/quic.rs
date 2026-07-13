// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! QUIC portal connection tests for reliable flow setup plus UDP DATAGRAM data.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::portal::{Portal, UdpFlowLimits};
use crate::protocol::{
    Carrier, FlowErrorCode, FlowHeader, FlowKind, FlowResult, FlowRole, UdpFrame, decode_udp_frame,
    encode_udp_close, encode_udp_data_fragments, read_flow_result, write_auth_frame,
    write_flow_header, write_request_frame,
};

use super::support::{
    connect_test_quic, connect_test_quic_to, connect_test_quic_with_url_and_limits, stop_test_quic,
};

async fn authenticate_test_connection(portal: &Portal, connection: &quinn::Connection) {
    let (mut auth_send, _auth_recv) = connection.open_bi().await.unwrap();
    auth_send
        .write_all(&write_auth_frame(
            portal.inner.credentials.key,
            &portal.inner.credentials.protocol_spec,
            [31; 32],
        ))
        .await
        .unwrap();
    auth_send.finish().unwrap();
    // Authentication raises the conservative pre-auth stream limit.
    timeout(Duration::from_secs(2), connection.open_bi())
        .await
        .unwrap()
        .unwrap();
}

async fn setup_quic_udp(
    portal: &Portal,
    connection: &quinn::Connection,
    flow_id: u64,
    target: &str,
) -> (FlowResult, quinn::RecvStream) {
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send.write_all(&write_flow_header(FlowHeader {
        role: FlowRole::Duplex,
        flow_id,
        kind: FlowKind::Udp,
        uplink: Carrier::Quic,
        downlink: Carrier::Quic,
    }))
    .await
    .unwrap();
    send.write_all(&write_request_frame(target, &portal.inner.credentials.protocol_spec).unwrap())
        .await
        .unwrap();
    send.finish().unwrap();
    let result = timeout(Duration::from_secs(3), read_flow_result(&mut recv))
        .await
        .unwrap()
        .unwrap();
    (result, recv)
}

fn send_udp_data(connection: &quinn::Connection, flow_id: u64, packet_id: u32, payload: &[u8]) {
    let frames = encode_udp_data_fragments(flow_id, packet_id, payload, 1_200).unwrap();
    for frame in frames {
        connection.send_datagram(Bytes::from(frame)).unwrap();
    }
}

async fn read_udp_packet(connection: &quinn::Connection) -> (u64, Vec<u8>) {
    let mut flow_id = None;
    let mut packet_id = None;
    let mut total_len = None;
    let mut fragments: Vec<Option<Vec<u8>>> = Vec::new();
    loop {
        let frame = timeout(Duration::from_secs(3), connection.read_datagram())
            .await
            .unwrap()
            .unwrap();
        let UdpFrame::Data {
            flow_id: frame_flow_id,
            fragment,
        } = decode_udp_frame(&frame).unwrap()
        else {
            continue;
        };
        flow_id.get_or_insert(frame_flow_id);
        packet_id.get_or_insert(fragment.packet_id);
        if packet_id != Some(fragment.packet_id) {
            continue;
        }
        total_len.get_or_insert(fragment.total_len as usize);
        if fragments.is_empty() {
            fragments.resize(fragment.fragment_count as usize, None);
        }
        fragments[fragment.fragment_id as usize] = Some(fragment.payload.to_vec());
        if fragments.iter().all(Option::is_some) {
            let payload = fragments
                .into_iter()
                .flatten()
                .flatten()
                .collect::<Vec<_>>();
            assert_eq!(payload.len(), total_len.unwrap());
            return (flow_id.unwrap(), payload);
        }
    }
}

async fn wait_for_udp_active(portal: &Portal, expected: i32) {
    timeout(Duration::from_secs(2), async {
        while portal.inner.stats.udp_active.load(Ordering::Relaxed) != expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn unknown_udp_data_is_ignored_without_blocking_dispatch() {
    let (portal, server_endpoint, client_endpoint, connection, shutdown, server_task) =
        connect_test_quic().await;
    authenticate_test_connection(&portal, &connection).await;

    send_udp_data(&connection, 77, 1, b"target-free");
    assert!(
        timeout(Duration::from_millis(200), connection.read_datagram())
            .await
            .is_err()
    );

    connection.close(quinn::VarInt::from_u32(0), b"");
    stop_test_quic(server_endpoint, client_endpoint, shutdown, server_task).await;
}

#[tokio::test]
async fn reliable_setup_precedes_fragmented_udp_data() {
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap().to_string();
    let large = vec![0x5a; 4_000];
    let expected = large.clone();
    let target_task = tokio::spawn(async move {
        let mut buf = [0u8; 16];
        let (_, peer) = target.recv_from(&mut buf).await.unwrap();
        target.send_to(&large, peer).await.unwrap();
        let (_, peer) = target.recv_from(&mut buf).await.unwrap();
        target.send_to(b"ok", peer).await.unwrap();
    });
    let (portal, server_endpoint, client_endpoint, connection, shutdown, server_task) =
        connect_test_quic().await;
    authenticate_test_connection(&portal, &connection).await;

    let (result, _) = setup_quic_udp(&portal, &connection, 79, &target_addr).await;
    assert_eq!(result, FlowResult::Ready);
    send_udp_data(&connection, 79, 1, b"first");
    let (flow_id, received) = read_udp_packet(&connection).await;
    assert_eq!(flow_id, 79);
    assert_eq!(received, expected);

    send_udp_data(&connection, 79, 2, b"second");
    let (flow_id, received) = read_udp_packet(&connection).await;
    assert_eq!(flow_id, 79);
    assert_eq!(received, b"ok");

    connection.close(quinn::VarInt::from_u32(0), b"");
    stop_test_quic(server_endpoint, client_endpoint, shutdown, server_task).await;
    target_task.await.unwrap();
}

#[tokio::test]
async fn zero_length_udp_packet_round_trips_as_data() {
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap().to_string();
    let target_task = tokio::spawn(async move {
        let mut buf = [0u8; 1];
        let (length, peer) = target.recv_from(&mut buf).await.unwrap();
        assert_eq!(length, 0);
        assert_eq!(target.send_to(&[], peer).await.unwrap(), 0);
    });
    let (portal, server_endpoint, client_endpoint, connection, shutdown, server_task) =
        connect_test_quic().await;
    authenticate_test_connection(&portal, &connection).await;

    assert_eq!(
        setup_quic_udp(&portal, &connection, 80, &target_addr)
            .await
            .0,
        FlowResult::Ready
    );
    send_udp_data(&connection, 80, 1, &[]);
    let (flow_id, received) = read_udp_packet(&connection).await;
    assert_eq!(flow_id, 80);
    assert!(received.is_empty());

    connection.close(quinn::VarInt::from_u32(0), b"");
    stop_test_quic(server_endpoint, client_endpoint, shutdown, server_task).await;
    target_task.await.unwrap();
}

#[tokio::test]
async fn udp_close_releases_the_session_global_flow_permit() {
    let limits = UdpFlowLimits {
        max_flows: 1,
        queue_bytes: 64 * 1024,
    };
    let (portal, server_endpoint, client_endpoint, connection, shutdown, server_task) =
        connect_test_quic_with_url_and_limits(
            "portal://secret@127.0.0.1:0?log=none&net=udp",
            Some(limits),
        )
        .await;
    authenticate_test_connection(&portal, &connection).await;
    let first_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let second_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    assert_eq!(
        setup_quic_udp(
            &portal,
            &connection,
            90,
            &first_target.local_addr().unwrap().to_string(),
        )
        .await
        .0,
        FlowResult::Ready
    );
    let (result, mut rejected) = setup_quic_udp(
        &portal,
        &connection,
        91,
        &second_target.local_addr().unwrap().to_string(),
    )
    .await;
    assert_eq!(result, FlowResult::Reject(FlowErrorCode::FlowLimit));
    let mut eof = [0u8; 1];
    assert_eq!(rejected.read(&mut eof).await.unwrap(), None);

    connection
        .send_datagram(Bytes::from(encode_udp_close(90).unwrap()))
        .unwrap();
    wait_for_udp_active(&portal, 0).await;
    assert_eq!(
        setup_quic_udp(
            &portal,
            &connection,
            91,
            &second_target.local_addr().unwrap().to_string(),
        )
        .await
        .0,
        FlowResult::Ready
    );

    connection.close(quinn::VarInt::from_u32(0), b"");
    stop_test_quic(server_endpoint, client_endpoint, shutdown, server_task).await;
}

#[tokio::test]
async fn authenticated_quic_reconnect_replaces_stale_carrier() {
    let (portal, server_endpoint, client_endpoint, first, shutdown, server_task) =
        connect_test_quic().await;
    authenticate_test_connection(&portal, &first).await;

    let (second_endpoint, second) =
        connect_test_quic_to(server_endpoint.local_addr().unwrap()).await;
    authenticate_test_connection(&portal, &second).await;

    timeout(Duration::from_secs(2), first.closed())
        .await
        .unwrap();
    assert_eq!(portal.inner.stats.link_udp.load(Ordering::Relaxed), 1);

    second.close(quinn::VarInt::from_u32(0), b"");
    second_endpoint.close(quinn::VarInt::from_u32(0), b"");
    stop_test_quic(server_endpoint, client_endpoint, shutdown, server_task).await;
}

#[tokio::test]
async fn quic_auth_failure_waits_for_one_deadline_and_uses_access_denied() {
    let (portal, server_endpoint, client_endpoint, connection, shutdown, server_task) =
        connect_test_quic().await;
    let (mut auth_send, _auth_recv) = connection.open_bi().await.unwrap();
    let mut auth = write_auth_frame(
        portal.inner.credentials.key,
        &portal.inner.credentials.protocol_spec,
        [10; 32],
    );
    auth[0] ^= 0xff;
    let started = Instant::now();
    auth_send.write_all(&auth).await.unwrap();
    auth_send.finish().unwrap();

    let error = timeout(Duration::from_secs(7), connection.closed())
        .await
        .unwrap();
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_secs(4), "elapsed: {elapsed:?}");
    assert!(elapsed <= Duration::from_secs(6) + Duration::from_millis(500));
    match error {
        quinn::ConnectionError::ApplicationClosed(close) => {
            assert_eq!(close.error_code.into_inner(), 1);
            assert_eq!(close.reason.as_ref(), b"access denied");
        }
        other => panic!("unexpected close: {other:?}"),
    }
    assert_eq!(portal.inner.unauthenticated_admission.active(), 0);

    stop_test_quic(server_endpoint, client_endpoint, shutdown, server_task).await;
}

#[tokio::test]
async fn authenticated_idle_quic_connection_receives_no_server_ping() {
    let (portal, server_endpoint, client_endpoint, connection, shutdown, server_task) =
        connect_test_quic().await;
    authenticate_test_connection(&portal, &connection).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let ping_count = connection.stats().frame_rx.ping;
    tokio::time::sleep(Duration::from_millis(5_200)).await;
    assert_eq!(connection.stats().frame_rx.ping, ping_count);

    connection.close(quinn::VarInt::from_u32(0), b"");
    stop_test_quic(server_endpoint, client_endpoint, shutdown, server_task).await;
}
