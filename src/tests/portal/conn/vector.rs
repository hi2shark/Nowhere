// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! End-to-end Portal/Vector carrier matrix through Vector's SOCKS5 ingress.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::common::{LogLevel, Logger};
use crate::portal::Portal;
use crate::vector::Vector;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const CARRIER_MATRIX: [(&str, &str); 4] = [
    ("tcp", "tcp"),
    ("tcp", "udp"),
    ("udp", "tcp"),
    ("udp", "udp"),
];

struct TestRuntime {
    shutdown: CancellationToken,
    endpoint: quinn::Endpoint,
    portal_tasks: Vec<JoinHandle<()>>,
    vector_task: JoinHandle<anyhow::Result<()>>,
    socks: SocketAddr,
}

impl TestRuntime {
    async fn stop(self) {
        self.vector_task.abort();
        let _ = self.vector_task.await;
        self.shutdown.cancel();
        self.endpoint.close(quinn::VarInt::from_u32(0), b"");
        for task in self.portal_tasks {
            task.abort();
            let _ = task.await;
        }
    }
}

async fn free_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn start_runtime(up: &str, down: &str) -> TestRuntime {
    let portal_port = free_tcp_port().await;
    let socks_port = free_tcp_port().await;
    let portal = Portal::new(
        Url::parse(&format!(
            "portal://secret@127.0.0.1:{portal_port}?log=none&net=mix"
        ))
        .unwrap(),
        Logger::new(LogLevel::None, false),
    )
    .unwrap();
    let endpoint = portal.listen_endpoints().unwrap().pop().unwrap();
    let listener = portal.listen_tcp_listeners().unwrap().pop().unwrap();
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
    let vector = Vector::new(
        Url::parse(&format!(
            "vector://secret@127.0.0.1:{portal_port}?log=none&up={up}&down={down}&pool=0&socks=127.0.0.1:{socks_port}"
        ))
        .unwrap(),
        Logger::new(LogLevel::None, false),
    )
    .unwrap();
    let vector_task = tokio::spawn(vector.run());
    let socks = SocketAddr::from(([127, 0, 0, 1], socks_port));
    wait_for_socks(socks).await;
    TestRuntime {
        shutdown,
        endpoint,
        portal_tasks: vec![quic_task, tcp_task],
        vector_task,
        socks,
    }
}

async fn wait_for_socks(address: SocketAddr) {
    timeout(TEST_TIMEOUT, async {
        loop {
            if TcpStream::connect(address).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

async fn negotiate_socks(stream: &mut TcpStream) {
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [5, 0]);
}

fn ip_request(command: u8, address: SocketAddr) -> Vec<u8> {
    let SocketAddr::V4(address) = address else {
        panic!("test endpoint must be IPv4")
    };
    let mut request = vec![5, command, 0, 1];
    request.extend_from_slice(&address.ip().octets());
    request.extend_from_slice(&address.port().to_be_bytes());
    request
}

async fn read_ipv4_reply(stream: &mut TcpStream) -> SocketAddr {
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    SocketAddr::from((
        [reply[4], reply[5], reply[6], reply[7]],
        u16::from_be_bytes([reply[8], reply[9]]),
    ))
}

#[tokio::test]
async fn vector_tcp_relays_every_carrier_pair() {
    for (up, down) in CARRIER_MATRIX {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut ping = [0u8; 4];
            stream.read_exact(&mut ping).await.unwrap();
            assert_eq!(&ping, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });
        let runtime = start_runtime(up, down).await;
        timeout(TEST_TIMEOUT, async {
            let mut socks = TcpStream::connect(runtime.socks).await.unwrap();
            negotiate_socks(&mut socks).await;
            socks
                .write_all(&ip_request(1, target_address))
                .await
                .unwrap();
            read_ipv4_reply(&mut socks).await;
            socks.write_all(b"ping").await.unwrap();
            let mut pong = [0u8; 4];
            socks.read_exact(&mut pong).await.unwrap();
            assert_eq!(&pong, b"pong", "up={up} down={down}");
        })
        .await
        .unwrap();
        echo.await.unwrap();
        runtime.stop().await;
    }
}

#[tokio::test]
async fn vector_udp_associate_relays_every_carrier_pair() {
    for (up, down) in CARRIER_MATRIX {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let payload = vec![0x40 | (up == "udp") as u8 | (((down == "udp") as u8) << 1); 4_000];
        let echoed = payload.clone();
        let echo = tokio::spawn(async move {
            let mut packet = vec![0u8; 5_000];
            let (length, peer) = target.recv_from(&mut packet).await.unwrap();
            assert_eq!(&packet[..length], echoed);
            target.send_to(&echoed, peer).await.unwrap();
        });
        let runtime = start_runtime(up, down).await;
        timeout(TEST_TIMEOUT, async {
            let mut control = TcpStream::connect(runtime.socks).await.unwrap();
            negotiate_socks(&mut control).await;
            control
                .write_all(&ip_request(3, SocketAddr::from(([0, 0, 0, 0], 0))))
                .await
                .unwrap();
            let relay = read_ipv4_reply(&mut control).await;
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut packet = vec![0, 0, 0];
            packet.extend_from_slice(&ip_request(0, target_address)[3..]);
            packet.extend_from_slice(&payload);
            client.send_to(&packet, relay).await.unwrap();
            let mut response = vec![0u8; 5_000];
            let (length, _) = client.recv_from(&mut response).await.unwrap();
            assert_eq!(&response[10..length], payload, "up={up} down={down}");
            drop(control);
        })
        .await
        .unwrap();
        echo.await.unwrap();
        runtime.stop().await;
    }
}
