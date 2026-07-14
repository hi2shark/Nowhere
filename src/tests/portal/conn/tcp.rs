// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! TCP/TLS portal connection tests.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::common::{LogLevel, Logger, handshake_timeout};
use crate::portal::Portal;
use crate::protocol::{
    Carrier, FlowHeader, FlowKind, FlowResult, FlowRole, UDP_STREAM_DATA, UdpStreamFrame,
    encode_udp_stream_frame, read_flow_result, read_udp_stream_frame, write_auth_frame,
    write_flow_header, write_request_frame,
};

use super::super::*;
use super::support::{
    TestSocksAuth, connect_test_tls, spawn_test_socks5_tcp, spawn_test_socks5_udp,
};

fn duplex_setup(portal: &Portal, flow_id: u64, kind: FlowKind, target: &str) -> Vec<u8> {
    let mut setup = write_flow_header(FlowHeader {
        role: FlowRole::Duplex,
        flow_id,
        kind,
        uplink: Carrier::TlsTcp,
        downlink: Carrier::TlsTcp,
    })
    .to_vec();
    setup.extend_from_slice(
        &write_request_frame(target, &portal.inner.credentials.protocol_spec).unwrap(),
    );
    setup
}

#[tokio::test]
async fn tls_tcp_pool_waits_beyond_handshake_timeout_then_relays() {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = echo_listener.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let (mut stream, _) = echo_listener.accept().await.unwrap();
        let mut request = [0u8; 4];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").await.unwrap();
    });

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let portal = Portal::new(
        Url::parse("portal://secret@127.0.0.1:2077?log=none&net=tcp").unwrap(),
        Logger::new(LogLevel::None, false),
    )
    .unwrap();
    let portal_inner = portal.inner.clone();
    let shutdown = CancellationToken::new();
    let child_shutdown = shutdown.clone();
    let server_task = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let admission = portal_inner
            .unauthenticated_admission
            .try_acquire(peer.ip())
            .unwrap();
        handle_tcp_incoming(portal_inner, stream, peer, admission, child_shutdown).await;
    });

    let mut tls = connect_test_tls(listen_addr).await;

    let auth = write_auth_frame(
        portal.inner.credentials.key,
        &portal.inner.credentials.protocol_spec,
        [7; 32],
    );
    tls.write_all(&auth).await.unwrap();

    timeout(Duration::from_secs(1), async {
        while portal.inner.pool_active.load(Ordering::Relaxed) != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    tokio::time::sleep(handshake_timeout() + Duration::from_millis(100)).await;
    assert_eq!(portal.inner.pool_active.load(Ordering::Relaxed), 1);

    let mut request = duplex_setup(&portal, 1, FlowKind::Tcp, &target.to_string());
    request.extend_from_slice(b"ping");
    tls.write_all(&request).await.unwrap();

    assert_eq!(read_flow_result(&mut tls).await.unwrap(), FlowResult::Ready);

    let mut response = [0u8; 4];
    timeout(Duration::from_secs(3), tls.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response, b"pong");
    assert_eq!(portal.inner.pool_active.load(Ordering::Relaxed), 0);

    shutdown.cancel();
    let _ = tls.shutdown().await;
    echo_task.await.unwrap();
    server_task.await.unwrap();
}

#[tokio::test]
async fn tls_tcp_relays_through_socks5_connect() {
    let (socks_addr, socks_task) = spawn_test_socks5_tcp(TestSocksAuth::None, "target.test").await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let portal = Portal::new(
        Url::parse(&format!(
            "portal://secret@127.0.0.1:2077?log=none&net=tcp&socks={socks_addr}"
        ))
        .unwrap(),
        Logger::new(LogLevel::None, false),
    )
    .unwrap();
    let portal_inner = portal.inner.clone();
    let shutdown = CancellationToken::new();
    let child_shutdown = shutdown.clone();
    let server_task = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let admission = portal_inner
            .unauthenticated_admission
            .try_acquire(peer.ip())
            .unwrap();
        handle_tcp_incoming(portal_inner, stream, peer, admission, child_shutdown).await;
    });

    let mut tls = connect_test_tls(listen_addr).await;
    let mut request = write_auth_frame(
        portal.inner.credentials.key,
        &portal.inner.credentials.protocol_spec,
        [21; 32],
    );
    request.extend_from_slice(&duplex_setup(&portal, 2, FlowKind::Tcp, "target.test:443"));
    request.extend_from_slice(b"ping");
    tls.write_all(&request).await.unwrap();

    assert_eq!(read_flow_result(&mut tls).await.unwrap(), FlowResult::Ready);

    let mut response = [0u8; 4];
    timeout(Duration::from_secs(3), tls.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response, b"pong");

    let _ = tls.shutdown().await;
    shutdown.cancel();
    socks_task.await.unwrap();
    server_task.await.unwrap();
}

#[tokio::test]
async fn tls_tcp_uot_relays_udp_and_counts_logical_udp() {
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let mut request = [0u8; 4];
        let (n, peer) = target.recv_from(&mut request).await.unwrap();
        assert_eq!(&request[..n], b"ping");
        target.send_to(b"pong", peer).await.unwrap();
    });

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let portal = Portal::new(
        Url::parse("portal://secret@127.0.0.1:2077?log=none&net=tcp").unwrap(),
        Logger::new(LogLevel::None, false),
    )
    .unwrap();
    let portal_inner = portal.inner.clone();
    let shutdown = CancellationToken::new();
    let child_shutdown = shutdown.clone();
    let server_task = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let admission = portal_inner
            .unauthenticated_admission
            .try_acquire(peer.ip())
            .unwrap();
        handle_tcp_incoming(portal_inner, stream, peer, admission, child_shutdown).await;
    });

    let mut tls = connect_test_tls(listen_addr).await;
    let mut bootstrap = write_auth_frame(
        portal.inner.credentials.key,
        &portal.inner.credentials.protocol_spec,
        [13; 32],
    );
    bootstrap.extend_from_slice(&duplex_setup(
        &portal,
        3,
        FlowKind::Udp,
        &target_addr.to_string(),
    ));
    bootstrap.extend_from_slice(&encode_udp_stream_frame(UDP_STREAM_DATA, b"ping").unwrap());
    tls.write_all(&bootstrap).await.unwrap();

    assert_eq!(
        read_udp_stream_frame(&mut tls).await.unwrap(),
        Some(UdpStreamFrame::Ready)
    );
    let response = timeout(Duration::from_secs(3), read_udp_stream_frame(&mut tls))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(response, UdpStreamFrame::Data(b"pong".to_vec()));
    assert_eq!(portal.inner.stats.udp_active.load(Ordering::Relaxed), 1);
    assert_eq!(portal.inner.stats.udp_rx.load(Ordering::Relaxed), 4);
    assert_eq!(portal.inner.stats.udp_tx.load(Ordering::Relaxed), 4);
    assert_eq!(portal.inner.stats.tcp_active.load(Ordering::Relaxed), 0);

    let _ = tls.shutdown().await;
    shutdown.cancel();
    echo_task.await.unwrap();
    server_task.await.unwrap();
    timeout(Duration::from_secs(1), async {
        while portal.inner.stats.udp_active.load(Ordering::Relaxed) != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(portal.inner.stats.udp_active.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn tls_tcp_uot_relays_through_authenticated_socks5_udp() {
    let (socks_addr, socks_task) =
        spawn_test_socks5_udp(TestSocksAuth::Password("user", "pass"), "dns.test").await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let portal = Portal::new(
        Url::parse(&format!(
            "portal://secret@127.0.0.1:2077?log=none&net=tcp&socks=user:pass@{socks_addr}"
        ))
        .unwrap(),
        Logger::new(LogLevel::None, false),
    )
    .unwrap();
    let portal_inner = portal.inner.clone();
    let shutdown = CancellationToken::new();
    let child_shutdown = shutdown.clone();
    let server_task = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let admission = portal_inner
            .unauthenticated_admission
            .try_acquire(peer.ip())
            .unwrap();
        handle_tcp_incoming(portal_inner, stream, peer, admission, child_shutdown).await;
    });

    let mut tls = connect_test_tls(listen_addr).await;
    let mut bootstrap = write_auth_frame(
        portal.inner.credentials.key,
        &portal.inner.credentials.protocol_spec,
        [22; 32],
    );
    bootstrap.extend_from_slice(&duplex_setup(&portal, 4, FlowKind::Udp, "dns.test:53"));
    bootstrap.extend_from_slice(&encode_udp_stream_frame(UDP_STREAM_DATA, b"ping").unwrap());
    tls.write_all(&bootstrap).await.unwrap();

    assert_eq!(
        read_udp_stream_frame(&mut tls).await.unwrap(),
        Some(UdpStreamFrame::Ready)
    );
    let response = timeout(Duration::from_secs(3), read_udp_stream_frame(&mut tls))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(response, UdpStreamFrame::Data(b"pong".to_vec()));
    assert_eq!(portal.inner.stats.udp_rx.load(Ordering::Relaxed), 4);
    assert_eq!(portal.inner.stats.udp_tx.load(Ordering::Relaxed), 4);

    let _ = tls.shutdown().await;
    shutdown.cancel();
    socks_task.await.unwrap();
    server_task.await.unwrap();
}

#[tokio::test]
async fn tls_tcp_auth_failure_waits_for_deadline_without_application_response() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let portal = Portal::new(
        Url::parse("portal://secret@127.0.0.1:2077?log=none&net=tcp").unwrap(),
        Logger::new(LogLevel::None, false),
    )
    .unwrap();
    let portal_inner = portal.inner.clone();
    let shutdown = CancellationToken::new();
    let child_shutdown = shutdown.clone();
    let server_task = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let admission = portal_inner
            .unauthenticated_admission
            .try_acquire(peer.ip())
            .unwrap();
        handle_tcp_incoming(portal_inner, stream, peer, admission, child_shutdown).await;
    });

    let mut tls = connect_test_tls(listen_addr).await;
    let mut auth = write_auth_frame(
        portal.inner.credentials.key,
        &portal.inner.credentials.protocol_spec,
        [11; 32],
    );
    auth[0] ^= 0xff;
    let started = Instant::now();
    tls.write_all(&auth).await.unwrap();

    let mut response = [0u8; 1];
    let read = timeout(Duration::from_secs(7), tls.read(&mut response))
        .await
        .unwrap();
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_secs(4), "elapsed: {elapsed:?}");
    assert!(elapsed <= Duration::from_secs(6) + Duration::from_millis(500));
    assert!(!matches!(read, Ok(length) if length != 0));

    server_task.await.unwrap();
    shutdown.cancel();
}

#[tokio::test]
async fn tls_tcp_pool_ttl_closes_unused_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let portal = Portal::new(
        Url::parse("portal://secret@127.0.0.1:2077?log=none&net=tcp").unwrap(),
        Logger::new(LogLevel::None, false),
    )
    .unwrap();
    let portal_inner = portal.inner.clone();
    let shutdown = CancellationToken::new();
    let child_shutdown = shutdown.clone();
    let server_task = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let admission = portal_inner
            .unauthenticated_admission
            .try_acquire(peer.ip())
            .unwrap();
        handle_tcp_incoming_with_pool_ttl(
            portal_inner,
            stream,
            peer,
            admission,
            child_shutdown,
            Duration::from_millis(100),
        )
        .await;
    });

    let mut tls = connect_test_tls(listen_addr).await;
    let auth = write_auth_frame(
        portal.inner.credentials.key,
        &portal.inner.credentials.protocol_spec,
        [8; 32],
    );
    tls.write_all(&auth).await.unwrap();

    timeout(Duration::from_secs(1), async {
        while portal.inner.pool_active.load(Ordering::Relaxed) != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    timeout(Duration::from_secs(1), server_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(portal.inner.pool_active.load(Ordering::Relaxed), 0);

    shutdown.cancel();
    let _ = tls.shutdown().await;
}

#[tokio::test]
async fn tls_tcp_idle_pool_limit_closes_excess_authenticated_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let portal = Portal::new(
        Url::parse("portal://secret@127.0.0.1:2077?log=none&net=tcp").unwrap(),
        Logger::new(LogLevel::None, false),
    )
    .unwrap();
    portal.inner.tcp_idle_pool_budget.close();
    let portal_inner = portal.inner.clone();
    let shutdown = CancellationToken::new();
    let child_shutdown = shutdown.clone();
    let server_task = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let admission = portal_inner
            .unauthenticated_admission
            .try_acquire(peer.ip())
            .unwrap();
        handle_tcp_incoming(portal_inner, stream, peer, admission, child_shutdown).await;
    });

    let mut tls = connect_test_tls(listen_addr).await;
    let auth = write_auth_frame(
        portal.inner.credentials.key,
        &portal.inner.credentials.protocol_spec,
        [9; 32],
    );
    tls.write_all(&auth).await.unwrap();

    timeout(Duration::from_secs(1), server_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(portal.inner.pool_active.load(Ordering::Relaxed), 0);
    let mut byte = [0u8; 1];
    match timeout(Duration::from_secs(1), tls.read(&mut byte))
        .await
        .unwrap()
    {
        Ok(0) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {}
        result => panic!("expected closed excess pool connection, got {result:?}"),
    }
    shutdown.cancel();
}
