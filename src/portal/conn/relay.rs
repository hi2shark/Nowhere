// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Shared relay session accounting and relay dispatch exports.

#[path = "relay_stream.rs"]
mod stream;
#[path = "relay_tcp.rs"]
mod tcp;
#[path = "relay_uot.rs"]
mod uot;

use std::sync::Arc;

use crate::portal::PortalInner;
use crate::portal::pairing::LinkPath;
use crate::protocol::Carrier;

pub(in crate::portal) use self::tcp::relay_paired_tcp;
pub(super) use self::tcp::relay_tcp_target;
pub(in crate::portal) use self::uot::relay_paired_udp;
pub(super) use self::uot::relay_udp_over_tcp_target;

fn paired_exchange_path(
    uplink: Carrier,
    uplink_path: &LinkPath,
    target_local: &str,
    target: &str,
    downlink: Carrier,
    downlink_path: &LinkPath,
) -> String {
    format!(
        "UP[{}] {} -> {} -> {} -> {} | DOWN[{}] {} -> {} -> {} -> {}",
        carrier_name(uplink),
        uplink_path.peer,
        uplink_path.local,
        target_local,
        target,
        carrier_name(downlink),
        target,
        target_local,
        downlink_path.local,
        downlink_path.peer,
    )
}

fn symmetric_exchange_path(
    carrier: Carrier,
    peer: &str,
    local: &str,
    target_local: &str,
    target: &str,
) -> String {
    format!(
        "UP[{}] {peer} -> {local} -> {target_local} -> {target} | DOWN[{}] {target} -> {target_local} -> {local} -> {peer}",
        carrier_name(carrier),
        carrier_name(carrier),
    )
}

fn carrier_name(carrier: Carrier) -> &'static str {
    match carrier {
        Carrier::Tcp => "TCP",
        Carrier::Udp => "UDP",
    }
}

/// RAII guard that keeps active TCP/UDP session counters balanced.
struct SessionGuard {
    portal: Arc<PortalInner>,
    is_udp: bool,
}

impl SessionGuard {
    fn new(portal: Arc<PortalInner>, is_udp: bool) -> Self {
        Self { portal, is_udp }
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.portal.stats.done_session(self.is_udp);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;
    use url::Url;

    use crate::common::{LogLevel, Logger};
    use crate::portal::Portal;

    use self::stream::{RelayFirstEof, relay_stream};

    #[test]
    fn paired_path_contains_both_carriers_and_both_client_links() {
        let uplink = LinkPath {
            peer: "198.51.100.1:1000".into(),
            local: "192.0.2.1:2077".into(),
        };
        let downlink = LinkPath {
            peer: "[2001:db8::2]:2000".into(),
            local: "[2001:db8::1]:2077".into(),
        };
        assert_eq!(
            paired_exchange_path(
                Carrier::Tcp,
                &uplink,
                "192.0.2.1:3000",
                "target.test:443",
                Carrier::Udp,
                &downlink,
            ),
            "UP[TCP] 198.51.100.1:1000 -> 192.0.2.1:2077 -> 192.0.2.1:3000 -> target.test:443 | DOWN[UDP] target.test:443 -> 192.0.2.1:3000 -> [2001:db8::1]:2077 -> [2001:db8::2]:2000"
        );
    }

    #[test]
    fn symmetric_path_uses_the_same_carrier_prefix() {
        assert_eq!(
            symmetric_exchange_path(
                Carrier::Udp,
                "198.51.100.1:1000",
                "192.0.2.1:2077",
                "192.0.2.1:3000",
                "target.test:443",
            ),
            "UP[UDP] 198.51.100.1:1000 -> 192.0.2.1:2077 -> 192.0.2.1:3000 -> target.test:443 | DOWN[UDP] target.test:443 -> 192.0.2.1:3000 -> 192.0.2.1:2077 -> 198.51.100.1:1000"
        );
    }

    #[tokio::test]
    async fn relay_stream_reports_directional_summary_when_client_finishes_first() {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let (mut target, _) = target_listener.accept().await.unwrap();
            let mut request = [0; 4];
            target.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            target.write_all(b"pong").await.unwrap();
            let _ = target.shutdown().await;
        });

        let portal = Portal::new(
            Url::parse("portal://secret@127.0.0.1:2077?log=none&net=tcp").unwrap(),
            Logger::new(LogLevel::None, false),
        )
        .unwrap();
        let target_conn = TcpStream::connect(target_addr).await.unwrap();
        let (client, relay) = tokio::io::duplex(1024);
        let (mut client_read, mut client_write) = tokio::io::split(client);
        let (mut relay_read, mut relay_write) = tokio::io::split(relay);

        let relay_task = tokio::spawn(async move {
            relay_stream(
                portal.inner,
                &mut relay_read,
                &mut relay_write,
                target_conn,
                vec![0; 8],
                vec![0; 8],
                Some((Carrier::Tcp, Carrier::Tcp)),
            )
            .await
            .unwrap()
        });

        client_write.write_all(b"ping").await.unwrap();
        client_write.shutdown().await.unwrap();

        let mut response = [0; 4];
        client_read.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");

        let summary = relay_task.await.unwrap();
        assert_eq!(summary.client_to_target_bytes, 4);
        assert_eq!(summary.target_to_client_bytes, 4);
        assert_eq!(summary.first_eof, RelayFirstEof::Client);

        target_task.await.unwrap();
    }

    #[tokio::test]
    async fn relay_stream_flushes_target_to_client_writes_before_eof() {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let (release_target, wait_release) = oneshot::channel();
        let target_task = tokio::spawn(async move {
            let (mut target, _) = target_listener.accept().await.unwrap();
            target.write_all(b"chunk").await.unwrap();
            let _ = wait_release.await;
            let _ = target.shutdown().await;
        });

        let portal = Portal::new(
            Url::parse("portal://secret@127.0.0.1:2077?log=none&net=tcp").unwrap(),
            Logger::new(LogLevel::None, false),
        )
        .unwrap();
        let target_conn = TcpStream::connect(target_addr).await.unwrap();
        let mut relay_read = tokio::io::empty();
        let (flushed, wait_flushed) = oneshot::channel();
        let mut client_write = FlushSignalWriter::new(flushed);

        let relay_task = tokio::spawn(async move {
            relay_stream(
                portal.inner,
                &mut relay_read,
                &mut client_write,
                target_conn,
                vec![0; 8],
                vec![0; 8],
                Some((Carrier::Tcp, Carrier::Tcp)),
            )
            .await
            .unwrap()
        });

        let flushed = tokio::time::timeout(std::time::Duration::from_millis(250), wait_flushed)
            .await
            .expect("relay did not flush target_to_client write before target EOF")
            .unwrap();
        assert_eq!(flushed, b"chunk");

        let _ = release_target.send(());
        let summary = tokio::time::timeout(std::time::Duration::from_secs(2), relay_task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(summary.target_to_client_bytes, 5);

        target_task.await.unwrap();
    }

    struct FlushSignalWriter {
        buffered: Vec<u8>,
        flushed: Option<oneshot::Sender<Vec<u8>>>,
    }

    impl FlushSignalWriter {
        fn new(flushed: oneshot::Sender<Vec<u8>>) -> Self {
            Self {
                buffered: Vec::new(),
                flushed: Some(flushed),
            }
        }
    }

    impl tokio::io::AsyncWrite for FlushSignalWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.buffered.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            if let Some(flushed) = self.flushed.take() {
                let buffered = std::mem::take(&mut self.buffered);
                let _ = flushed.send(buffered);
            }
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
}
