// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::common::{LogLevel, Logger};
use crate::portal::Portal;
use crate::protocol::{
    Carrier, FlowHeader, FlowKind, FlowResult, FlowRole, UDP_STREAM_DATA, UdpFrame, UdpStreamFrame,
    decode_udp_frame, encode_udp_data_fragments, encode_udp_stream_frame, read_flow_result,
    read_udp_stream_frame, write_flow_header, write_request_frame, write_session_auth_frame,
};

use super::support::{connect_test_quic_to, connect_test_tls};

async fn connect_tls_from_separate_loopback(
    port: u16,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    connect_test_tls(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], port))).await
}

async fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn start_mixed(
    port: u16,
) -> (
    Portal,
    quinn::Endpoint,
    quinn::Endpoint,
    quinn::Connection,
    CancellationToken,
    tokio::task::JoinHandle<()>,
    tokio::task::JoinHandle<()>,
) {
    let portal = Portal::new_with_listen_host(
        Url::parse(&format!(
            "portal://secret@localhost:{port}?log=none&net=mix"
        ))
        .unwrap(),
        Some(""),
        Logger::new(LogLevel::None, false),
    )
    .unwrap();
    let endpoint = portal
        .listen_endpoints()
        .unwrap()
        .into_iter()
        .find(|endpoint| endpoint.local_addr().unwrap().is_ipv4())
        .unwrap();
    let listener = portal
        .listen_tcp_listeners()
        .unwrap()
        .into_iter()
        .find(|listener| listener.local_addr().unwrap().is_ipv6())
        .unwrap();
    let shutdown = CancellationToken::new();
    let quic_task = tokio::spawn(crate::portal::listener::accept_endpoint_loop(
        portal.inner.clone(),
        endpoint.clone(),
        shutdown.clone(),
    ));
    let tcp_task = tokio::spawn(crate::portal::listener::accept_tcp_loop(
        portal.inner.clone(),
        listener,
        shutdown.clone(),
    ));
    let (client_endpoint, quic) =
        connect_test_quic_to(SocketAddr::from(([127, 0, 0, 1], port))).await;
    (
        portal,
        endpoint,
        client_endpoint,
        quic,
        shutdown,
        quic_task,
        tcp_task,
    )
}

async fn authenticate_quic(portal: &Portal, conn: &quinn::Connection, session: [u8; 16]) {
    let (mut send, _) = conn.open_bi().await.unwrap();
    send.write_all(&write_session_auth_frame(
        portal.inner.credentials.key,
        &portal.inner.credentials.protocol_spec,
        [0x31; 32],
        session,
    ))
    .await
    .unwrap();
    send.finish().unwrap();
    timeout(Duration::from_secs(2), conn.open_bi())
        .await
        .unwrap()
        .unwrap();
}

fn request(portal: &Portal, header: FlowHeader, target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut out = write_flow_header(header).to_vec();
    if matches!(header.role, FlowRole::Open | FlowRole::Duplex) {
        out.extend_from_slice(
            &write_request_frame(&target.to_string(), &portal.inner.credentials.protocol_spec)
                .unwrap(),
        );
    }
    out.extend_from_slice(payload);
    out
}

#[tokio::test]
async fn asymmetric_tcp_flows_pair_in_both_directions() {
    let port = free_port().await;
    let (portal, endpoint, client_endpoint, quic, shutdown, quic_task, tcp_task) =
        start_mixed(port).await;
    let session = [0x5a; 16];
    authenticate_quic(&portal, &quic, session).await;

    for (flow_id, uplink, downlink) in [
        (1, Carrier::TlsTcp, Carrier::Quic),
        (2, Carrier::Quic, Carrier::TlsTcp),
    ] {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut ping = [0; 4];
            stream.read_exact(&mut ping).await.unwrap();
            assert_eq!(&ping, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });
        let open = FlowHeader {
            role: FlowRole::Open,
            flow_id,
            kind: FlowKind::Tcp,
            uplink,
            downlink,
        };
        let attach = FlowHeader {
            role: FlowRole::Attach,
            ..open
        };
        let mut tls = connect_tls_from_separate_loopback(port).await;
        tls.write_all(&write_session_auth_frame(
            portal.inner.credentials.key,
            &portal.inner.credentials.protocol_spec,
            [flow_id as u8; 32],
            session,
        ))
        .await
        .unwrap();
        let (mut quic_send, mut quic_recv) = quic.open_bi().await.unwrap();

        if uplink == Carrier::TlsTcp {
            tls.write_all(&request(&portal, open, target_addr, b"ping"))
                .await
                .unwrap();
            quic_send
                .write_all(&request(&portal, attach, target_addr, b""))
                .await
                .unwrap();
            quic_send.finish().unwrap();
            assert_eq!(
                read_flow_result(&mut quic_recv).await.unwrap(),
                FlowResult::Ready
            );
            let mut pong = [0; 4];
            timeout(Duration::from_secs(3), quic_recv.read_exact(&mut pong))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&pong, b"pong");
        } else {
            tls.write_all(&request(&portal, attach, target_addr, b""))
                .await
                .unwrap();
            quic_send
                .write_all(&request(&portal, open, target_addr, b"ping"))
                .await
                .unwrap();
            quic_send.finish().unwrap();
            assert_eq!(read_flow_result(&mut tls).await.unwrap(), FlowResult::Ready);
            let mut pong = [0; 4];
            timeout(Duration::from_secs(3), tls.read_exact(&mut pong))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&pong, b"pong");
        }
        echo.await.unwrap();
    }

    shutdown.cancel();
    endpoint.close(quinn::VarInt::from_u32(0), b"");
    client_endpoint.close(quinn::VarInt::from_u32(0), b"");
    quic_task.await.unwrap();
    tcp_task.await.unwrap();
}

#[tokio::test]
async fn asymmetric_udp_flows_pair_in_both_directions() {
    let port = free_port().await;
    let (portal, endpoint, client_endpoint, quic, shutdown, quic_task, tcp_task) =
        start_mixed(port).await;
    let session = [0x6b; 16];
    authenticate_quic(&portal, &quic, session).await;

    // QUIC upload, TLS/TCP download.
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let mut buf = [0; 16];
        let (n, peer) = target.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping");
        target.send_to(b"pong", peer).await.unwrap();
    });
    let attach = FlowHeader {
        role: FlowRole::Attach,
        flow_id: 11,
        kind: FlowKind::Udp,
        uplink: Carrier::Quic,
        downlink: Carrier::TlsTcp,
    };
    let mut tls = connect_tls_from_separate_loopback(port).await;
    let mut bootstrap = write_session_auth_frame(
        portal.inner.credentials.key,
        &portal.inner.credentials.protocol_spec,
        [0x11; 32],
        session,
    );
    bootstrap.extend_from_slice(&request(&portal, attach, target_addr, b""));
    tls.write_all(&bootstrap).await.unwrap();
    let open = FlowHeader {
        role: FlowRole::Open,
        ..attach
    };
    let (mut open_send, _) = quic.open_bi().await.unwrap();
    open_send
        .write_all(&request(&portal, open, target_addr, b""))
        .await
        .unwrap();
    open_send.finish().unwrap();
    assert_eq!(
        read_udp_stream_frame(&mut tls).await.unwrap(),
        Some(UdpStreamFrame::Ready)
    );
    let data = encode_udp_data_fragments(11, 1, b"ping", 1200).unwrap();
    quic.send_datagram(bytes::Bytes::from(data.into_iter().next().unwrap()))
        .unwrap();
    assert_eq!(
        read_udp_stream_frame(&mut tls).await.unwrap(),
        Some(UdpStreamFrame::Data(b"pong".to_vec()))
    );
    echo.await.unwrap();

    // TLS/TCP upload, QUIC download.
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let mut buf = [0; 16];
        let (n, peer) = target.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping");
        target.send_to(b"pong", peer).await.unwrap();
    });
    let open = FlowHeader {
        role: FlowRole::Open,
        flow_id: 12,
        kind: FlowKind::Udp,
        uplink: Carrier::TlsTcp,
        downlink: Carrier::Quic,
    };
    let attach = FlowHeader {
        role: FlowRole::Attach,
        ..open
    };
    let mut tls = connect_tls_from_separate_loopback(port).await;
    let mut bootstrap = write_session_auth_frame(
        portal.inner.credentials.key,
        &portal.inner.credentials.protocol_spec,
        [0x12; 32],
        session,
    );
    bootstrap.extend_from_slice(&request(&portal, open, target_addr, b""));
    tls.write_all(&bootstrap).await.unwrap();
    let (mut attach_send, mut attach_recv) = quic.open_bi().await.unwrap();
    attach_send
        .write_all(&request(&portal, attach, target_addr, b""))
        .await
        .unwrap();
    attach_send.finish().unwrap();
    assert_eq!(
        read_flow_result(&mut attach_recv).await.unwrap(),
        FlowResult::Ready
    );
    tls.write_all(&encode_udp_stream_frame(UDP_STREAM_DATA, b"ping").unwrap())
        .await
        .unwrap();
    let frame = timeout(Duration::from_secs(3), quic.read_datagram())
        .await
        .unwrap()
        .unwrap();
    let UdpFrame::Data { flow_id, fragment } = decode_udp_frame(&frame).unwrap() else {
        panic!("expected UDP DATA");
    };
    assert_eq!(flow_id, 12);
    assert_eq!(fragment.payload, b"pong");
    echo.await.unwrap();

    shutdown.cancel();
    endpoint.close(quinn::VarInt::from_u32(0), b"");
    client_endpoint.close(quinn::VarInt::from_u32(0), b"");
    quic_task.await.unwrap();
    tcp_task.await.unwrap();
}
