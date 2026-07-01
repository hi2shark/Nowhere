// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! QUIC portal connection tests.

use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::protocol::{
    DATAGRAM_UDP_REQUEST, DATAGRAM_UDP_RESPONSE, decode_udp_datagram, new_udp_datagram_header,
    write_auth_frame,
};

use super::super::*;
use super::support::{
    TestSocksAuth, connect_test_quic, connect_test_quic_with_url, spawn_test_socks5_udp,
    stop_test_quic,
};

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
