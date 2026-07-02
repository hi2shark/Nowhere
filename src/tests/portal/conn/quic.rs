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
    DATAGRAM_UDP_CLOSE, DATAGRAM_UDP_REQUEST, DATAGRAM_UDP_RESPONSE, decode_udp_datagram,
    new_udp_datagram_header, write_auth_frame,
};

use super::super::*;
use super::support::{
    TestSocksAuth, connect_test_quic, connect_test_quic_with_url,
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

fn test_udp_datagram(
    portal: &Portal,
    frame_type: u8,
    flow_id: u64,
    target: &str,
    payload: &[u8],
) -> Bytes {
    let mut frame = new_udp_datagram_header(
        frame_type,
        flow_id,
        target,
        &portal.inner.credentials.protocol_spec,
    )
    .unwrap();
    frame.extend_from_slice(payload);
    Bytes::from(frame)
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

    let mut datagram = new_udp_datagram_header(
        DATAGRAM_UDP_REQUEST,
        7,
        &target_addr.to_string(),
        &portal.inner.credentials.protocol_spec,
    )
    .unwrap();
    datagram.extend_from_slice(b"early");
    connection.send_datagram(Bytes::from(datagram)).unwrap();

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

    let mut request = new_udp_datagram_header(
        DATAGRAM_UDP_REQUEST,
        11,
        "dns.test:53",
        &portal.inner.credentials.protocol_spec,
    )
    .unwrap();
    request.extend_from_slice(b"ping");
    connection.send_datagram(Bytes::from(request)).unwrap();

    let response = timeout(Duration::from_secs(3), connection.read_datagram())
        .await
        .unwrap()
        .unwrap();
    let (frame_type, flow_id, target, payload) =
        decode_udp_datagram(&response, &portal.inner.credentials.protocol_spec).unwrap();
    assert_eq!(frame_type, DATAGRAM_UDP_RESPONSE);
    assert_eq!(flow_id, 11);
    assert_eq!(target, "dns.test:53");
    assert_eq!(payload, b"pong");

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
        .send_datagram(test_udp_datagram(
            &portal,
            DATAGRAM_UDP_REQUEST,
            1,
            "fast.test:53",
            b"one",
        ))
        .unwrap();
    let first = timeout(Duration::from_secs(2), connection.read_datagram())
        .await
        .unwrap()
        .unwrap();
    let (_, _, _, payload) =
        decode_udp_datagram(&first, &portal.inner.credentials.protocol_spec).unwrap();
    assert_eq!(payload, b"one");

    connection
        .send_datagram(test_udp_datagram(
            &portal,
            DATAGRAM_UDP_REQUEST,
            2,
            "slow.test:53",
            b"blocked",
        ))
        .unwrap();
    timeout(Duration::from_secs(2), stalled)
        .await
        .unwrap()
        .unwrap();

    let started = Instant::now();
    connection
        .send_datagram(test_udp_datagram(
            &portal,
            DATAGRAM_UDP_REQUEST,
            1,
            "fast.test:53",
            b"two",
        ))
        .unwrap();
    let second = timeout(Duration::from_millis(500), connection.read_datagram())
        .await
        .unwrap()
        .unwrap();
    let (_, flow_id, _, payload) =
        decode_udp_datagram(&second, &portal.inner.credentials.protocol_spec).unwrap();
    assert_eq!(flow_id, 1);
    assert_eq!(payload, b"two");
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
        .send_datagram(test_udp_datagram(
            &portal,
            DATAGRAM_UDP_REQUEST,
            10,
            &first_addr,
            b"first",
        ))
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
        .send_datagram(test_udp_datagram(
            &portal,
            DATAGRAM_UDP_REQUEST,
            11,
            &second_addr,
            b"limited",
        ))
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
        .send_datagram(test_udp_datagram(
            &portal,
            DATAGRAM_UDP_CLOSE,
            10,
            &first_addr,
            b"",
        ))
        .unwrap();
    wait_for_udp_active(&portal, 0).await;

    connection
        .send_datagram(test_udp_datagram(
            &portal,
            DATAGRAM_UDP_REQUEST,
            11,
            &second_addr,
            b"accepted",
        ))
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
        .send_datagram(test_udp_datagram(
            &portal,
            DATAGRAM_UDP_REQUEST,
            20,
            &target_addr,
            b"dropped",
        ))
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
        .send_datagram(test_udp_datagram(
            &portal,
            DATAGRAM_UDP_REQUEST,
            30,
            "rejected.test:53",
            b"request",
        ))
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
