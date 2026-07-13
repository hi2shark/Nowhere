// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! QUIC portal connection tests.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::portal::{
    DEFAULT_QUIC_MAX_UDP_FLOWS, DEFAULT_QUIC_UDP_QUEUE_BYTES, Portal, UdpFlowLimits,
};
use crate::protocol::{
    Carrier, UDP_FRAME_CLOSE, UdpFrame, decode_udp_frame, encode_udp_control,
    encode_udp_data_fragments, encode_udp_open_fragments, write_auth_frame,
};

use super::super::*;
use super::support::{
    TestSocksAuth, connect_test_quic, connect_test_quic_to, connect_test_quic_with_url,
    connect_test_quic_with_url_and_limits, spawn_test_socks5_udp, spawn_test_socks5_udp_isolation,
    spawn_test_socks5_udp_reject, stop_test_quic,
};

async fn authenticate_test_connection(portal: &Portal, connection: &quinn::Connection) {
    let (mut auth_send, _auth_recv) = connection.open_bi().await.unwrap();
    let auth = write_auth_frame(
        portal.inner.credentials.key,
        &portal.inner.credentials.protocol_spec,
        [31; 32],
    );
    auth_send.write_all(&auth).await.unwrap();
    auth_send.finish().unwrap();
    timeout(Duration::from_secs(2), connection.open_bi())
        .await
        .unwrap()
        .unwrap();
}

fn test_udp_datagram(flow_id: u64, target: &str, payload: &[u8]) -> Bytes {
    let frames =
        encode_udp_open_fragments(flow_id, 1, Carrier::Udp, target, payload, 1200).unwrap();
    assert_eq!(frames.len(), 1);
    Bytes::from(frames.into_iter().next().unwrap())
}

async fn wait_for_udp_active(portal: &Portal, expected: i32) {
    timeout(Duration::from_secs(1), async {
        while portal.inner.stats.udp_active.load(Ordering::Relaxed) != expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

async fn read_udp_data(connection: &quinn::Connection) -> Bytes {
    loop {
        let frame = timeout(Duration::from_secs(2), connection.read_datagram())
            .await
            .unwrap()
            .unwrap();
        if matches!(decode_udp_frame(&frame).unwrap(), UdpFrame::Data { .. }) {
            return frame;
        }
    }
}

async fn read_udp_packet(connection: &quinn::Connection) -> (u64, Vec<u8>) {
    let mut flow_id = None;
    let mut total_len = None;
    let mut fragments: Vec<Option<Vec<u8>>> = Vec::new();
    loop {
        let frame = timeout(Duration::from_secs(2), connection.read_datagram())
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

#[tokio::test]
async fn unknown_udp_data_requests_flow_reopen() {
    let (portal, server_endpoint, client_endpoint, connection, shutdown, server_task) =
        connect_test_quic().await;
    authenticate_test_connection(&portal, &connection).await;

    let data = encode_udp_data_fragments(77, 1, b"target-free", 1200).unwrap();
    connection
        .send_datagram(Bytes::from(data.into_iter().next().unwrap()))
        .unwrap();

    let response = timeout(Duration::from_secs(2), connection.read_datagram())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        decode_udp_frame(&response).unwrap(),
        UdpFrame::Close { flow_id: 77 }
    ));

    connection.close(VarInt::from_u32(0), b"");
    stop_test_quic(server_endpoint, client_endpoint, shutdown, server_task).await;
}

#[tokio::test]
async fn repeated_open_data_resends_open_ack() {
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap().to_string();
    let (portal, server_endpoint, client_endpoint, connection, shutdown, server_task) =
        connect_test_quic().await;
    authenticate_test_connection(&portal, &connection).await;

    for payload in [b"first".as_slice(), b"second".as_slice()] {
        connection
            .send_datagram(test_udp_datagram(78, &target_addr, payload))
            .unwrap();
        let ack = timeout(Duration::from_secs(2), connection.read_datagram())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            decode_udp_frame(&ack).unwrap(),
            UdpFrame::OpenAck { flow_id: 78 }
        ));
    }

    connection.close(VarInt::from_u32(0), b"");
    stop_test_quic(server_endpoint, client_endpoint, shutdown, server_task).await;
}

#[tokio::test]
async fn large_target_packet_is_fragmented_without_closing_flow() {
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

    connection
        .send_datagram(test_udp_datagram(79, &target_addr, b"first"))
        .unwrap();
    let (flow_id, received) = read_udp_packet(&connection).await;
    assert_eq!(flow_id, 79);
    assert_eq!(received, expected);

    let data = encode_udp_data_fragments(79, 2, b"second", 1_200).unwrap();
    connection
        .send_datagram(Bytes::from(data.into_iter().next().unwrap()))
        .unwrap();
    let (flow_id, received) = read_udp_packet(&connection).await;
    assert_eq!(flow_id, 79);
    assert_eq!(received, b"ok");

    connection.close(VarInt::from_u32(0), b"");
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

    connection
        .send_datagram(test_udp_datagram(80, &target_addr, &[]))
        .unwrap();
    let (flow_id, received) = read_udp_packet(&connection).await;
    assert_eq!(flow_id, 80);
    assert!(received.is_empty());

    connection.close(VarInt::from_u32(0), b"");
    stop_test_quic(server_endpoint, client_endpoint, shutdown, server_task).await;
    target_task.await.unwrap();
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

    second.close(VarInt::from_u32(0), b"");
    second_endpoint.close(VarInt::from_u32(0), b"");
    stop_test_quic(server_endpoint, client_endpoint, shutdown, server_task).await;
}

#[tokio::test]
async fn quic_pre_auth_stream_limit_is_raised_and_early_datagram_is_preserved() {
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let (portal, server_endpoint, client_endpoint, connection, shutdown, server_task) =
        connect_test_quic().await;

    let (mut auth_send, _auth_recv) = connection.open_bi().await.unwrap();
    assert!(
        timeout(Duration::from_millis(200), connection.open_bi())
            .await
            .is_err()
    );

    connection
        .send_datagram(test_udp_datagram(7, &target_addr.to_string(), b"early"))
        .unwrap();

    let auth = write_auth_frame(
        portal.inner.credentials.key,
        &portal.inner.credentials.protocol_spec,
        [9; 32],
    );
    auth_send.write_all(&auth).await.unwrap();
    auth_send.finish().unwrap();

    let (_send, _recv) = timeout(Duration::from_secs(2), connection.open_bi())
        .await
        .unwrap()
        .unwrap();
    let mut received = [0u8; 5];
    let (length, _) = timeout(Duration::from_secs(2), target.recv_from(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&received[..length], b"early");
    assert_eq!(portal.inner.unauthenticated_admission.active(), 0);

    connection.close(VarInt::from_u32(0), b"");
    stop_test_quic(server_endpoint, client_endpoint, shutdown, server_task).await;
}

#[tokio::test]
async fn quic_datagram_relays_through_socks5_udp_associate() {
    let (socks_addr, socks_task) = spawn_test_socks5_udp(TestSocksAuth::None, "dns.test").await;
    let url = format!("portal://secret@127.0.0.1:0?log=none&net=udp&socks={socks_addr}");
    let (portal, server_endpoint, client_endpoint, connection, shutdown, server_task) =
        connect_test_quic_with_url(&url).await;

    let (mut auth_send, _auth_recv) = connection.open_bi().await.unwrap();
    let auth = write_auth_frame(
        portal.inner.credentials.key,
        &portal.inner.credentials.protocol_spec,
        [23; 32],
    );
    auth_send.write_all(&auth).await.unwrap();
    auth_send.finish().unwrap();
    timeout(Duration::from_secs(2), connection.open_bi())
        .await
        .unwrap()
        .unwrap();

    connection
        .send_datagram(test_udp_datagram(11, "dns.test:53", b"ping"))
        .unwrap();

    let response = read_udp_data(&connection).await;
    let UdpFrame::Data { flow_id, fragment } = decode_udp_frame(&response).unwrap() else {
        panic!("expected DATA");
    };
    assert_eq!(flow_id, 11);
    assert_eq!(fragment.payload, b"pong");

    connection.close(VarInt::from_u32(0), b"");
    stop_test_quic(server_endpoint, client_endpoint, shutdown, server_task).await;
    socks_task.await.unwrap();
    wait_for_udp_active(&portal, 0).await;
}

#[tokio::test]
async fn stalled_udp_dial_does_not_block_an_existing_flow() {
    let (socks_addr, stalled, socks_task) = spawn_test_socks5_udp_isolation().await;
    let url = format!("portal://secret@127.0.0.1:0?log=none&net=udp&socks={socks_addr}");
    let (portal, server_endpoint, client_endpoint, connection, shutdown, server_task) =
        connect_test_quic_with_url(&url).await;
    authenticate_test_connection(&portal, &connection).await;

    connection
        .send_datagram(test_udp_datagram(1, "fast.test:53", b"one"))
        .unwrap();
    let first = read_udp_data(&connection).await;
    let UdpFrame::Data { fragment, .. } = decode_udp_frame(&first).unwrap() else {
        panic!("expected DATA");
    };
    assert_eq!(fragment.payload, b"one");

    connection
        .send_datagram(test_udp_datagram(2, "slow.test:53", b"blocked"))
        .unwrap();
    timeout(Duration::from_secs(2), stalled)
        .await
        .unwrap()
        .unwrap();

    let started = Instant::now();
    connection
        .send_datagram(test_udp_datagram(1, "fast.test:53", b"two"))
        .unwrap();
    let second = timeout(Duration::from_millis(500), read_udp_data(&connection))
        .await
        .unwrap();
    let UdpFrame::Data { flow_id, fragment } = decode_udp_frame(&second).unwrap() else {
        panic!("expected DATA");
    };
    assert_eq!(flow_id, 1);
    assert_eq!(fragment.payload, b"two");
    assert!(started.elapsed() < Duration::from_millis(500));

    connection.close(VarInt::from_u32(0), b"");
    stop_test_quic(server_endpoint, client_endpoint, shutdown, server_task).await;
    socks_task.await.unwrap();
}

#[tokio::test]
async fn udp_flow_limit_is_released_by_close_frame() {
    let first_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let first_addr = first_target.local_addr().unwrap().to_string();
    let second_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let second_addr = second_target.local_addr().unwrap().to_string();
    let limits = UdpFlowLimits {
        max_flows: 1,
        queue_bytes: DEFAULT_QUIC_UDP_QUEUE_BYTES,
    };
    let (portal, server_endpoint, client_endpoint, connection, shutdown, server_task) =
        connect_test_quic_with_url_and_limits(
            "portal://secret@127.0.0.1:0?log=none&net=udp",
            Some(limits),
        )
        .await;
    authenticate_test_connection(&portal, &connection).await;

    connection
        .send_datagram(test_udp_datagram(10, &first_addr, b"first"))
        .unwrap();
    let mut received = [0u8; 16];
    let (size, _) = timeout(
        Duration::from_secs(2),
        first_target.recv_from(&mut received),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&received[..size], b"first");

    connection
        .send_datagram(test_udp_datagram(11, &second_addr, b"limited"))
        .unwrap();
    assert!(
        timeout(
            Duration::from_millis(200),
            second_target.recv_from(&mut received)
        )
        .await
        .is_err()
    );

    connection
        .send_datagram(Bytes::from(
            encode_udp_control(UDP_FRAME_CLOSE, 10).unwrap(),
        ))
        .unwrap();
    wait_for_udp_active(&portal, 0).await;

    connection
        .send_datagram(test_udp_datagram(11, &second_addr, b"accepted"))
        .unwrap();
    let (size, _) = timeout(
        Duration::from_secs(2),
        second_target.recv_from(&mut received),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&received[..size], b"accepted");

    connection.close(VarInt::from_u32(0), b"");
    stop_test_quic(server_endpoint, client_endpoint, shutdown, server_task).await;
}

#[tokio::test]
async fn udp_queue_budget_is_checked_before_flow_creation() {
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap().to_string();
    let limits = UdpFlowLimits {
        max_flows: DEFAULT_QUIC_MAX_UDP_FLOWS,
        queue_bytes: 1,
    };
    let (portal, server_endpoint, client_endpoint, connection, shutdown, server_task) =
        connect_test_quic_with_url_and_limits(
            "portal://secret@127.0.0.1:0?log=none&net=udp",
            Some(limits),
        )
        .await;
    authenticate_test_connection(&portal, &connection).await;

    connection
        .send_datagram(test_udp_datagram(20, &target_addr, b"dropped"))
        .unwrap();
    let mut received = [0u8; 16];
    assert!(
        timeout(Duration::from_millis(200), target.recv_from(&mut received))
            .await
            .is_err()
    );
    assert_eq!(portal.inner.stats.udp_active.load(Ordering::Relaxed), 0);
    connection.close(VarInt::from_u32(0), b"");
    stop_test_quic(server_endpoint, client_endpoint, shutdown, server_task).await;
}

#[tokio::test]
async fn udp_uses_connection_queue_budget() {
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap().to_string();
    let limits = UdpFlowLimits {
        max_flows: DEFAULT_QUIC_MAX_UDP_FLOWS,
        queue_bytes: 1,
    };
    let (portal, server_endpoint, client_endpoint, connection, shutdown, server_task) =
        connect_test_quic_with_url_and_limits(
            "portal://secret@127.0.0.1:0?log=none&net=udp",
            Some(limits),
        )
        .await;
    authenticate_test_connection(&portal, &connection).await;

    connection
        .send_datagram(test_udp_datagram(21, &target_addr, b"dropped"))
        .unwrap();

    let mut received = [0u8; 16];
    assert!(
        timeout(Duration::from_millis(200), target.recv_from(&mut received))
            .await
            .is_err()
    );
    assert_eq!(portal.inner.stats.udp_active.load(Ordering::Relaxed), 0);

    connection.close(VarInt::from_u32(0), b"");
    stop_test_quic(server_endpoint, client_endpoint, shutdown, server_task).await;
}

#[tokio::test]
async fn udp_dial_failure_releases_flow_accounting() {
    let (socks_addr, socks_task) = spawn_test_socks5_udp_reject().await;
    let url = format!("portal://secret@127.0.0.1:0?log=none&net=udp&socks={socks_addr}");
    let (portal, server_endpoint, client_endpoint, connection, shutdown, server_task) =
        connect_test_quic_with_url(&url).await;
    authenticate_test_connection(&portal, &connection).await;

    connection
        .send_datagram(test_udp_datagram(30, "rejected.test:53", b"request"))
        .unwrap();
    socks_task.await.unwrap();
    wait_for_udp_active(&portal, 0).await;

    connection.close(VarInt::from_u32(0), b"");
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
    let (mut auth_send, _auth_recv) = connection.open_bi().await.unwrap();
    let auth = write_auth_frame(
        portal.inner.credentials.key,
        &portal.inner.credentials.protocol_spec,
        [12; 32],
    );
    auth_send.write_all(&auth).await.unwrap();
    auth_send.finish().unwrap();

    timeout(Duration::from_secs(2), connection.open_bi())
        .await
        .unwrap()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let ping_count = connection.stats().frame_rx.ping;
    tokio::time::sleep(Duration::from_millis(5_200)).await;
    assert_eq!(connection.stats().frame_rx.ping, ping_count);

    connection.close(VarInt::from_u32(0), b"");
    stop_test_quic(server_endpoint, client_endpoint, shutdown, server_task).await;
}
