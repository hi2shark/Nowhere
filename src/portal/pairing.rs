// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Bounded setup-only registry for pairing asymmetric TCP and QUIC flow halves.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{Result, bail};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tokio::sync::mpsc;

use bytes::Bytes;
use quinn::Connection;

use crate::protocol::{FlowHeader, FlowRole, SessionId};
use crate::transport::Stats;

pub(super) type BoxReader = Pin<Box<dyn AsyncRead + Send>>;
pub(super) type BoxWriter = Pin<Box<dyn AsyncWrite + Send>>;

struct GuardedReader<R> {
    inner: R,
    _guard: LinkGuard,
}

impl<R: AsyncRead + Unpin> AsyncRead for GuardedReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

struct GuardedWriter<W> {
    inner: W,
    _guard: LinkGuard,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for GuardedWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub(super) fn guarded_reader<R: AsyncRead + Send + Unpin + 'static>(
    reader: R,
    guard: LinkGuard,
) -> BoxReader {
    Box::pin(GuardedReader {
        inner: reader,
        _guard: guard,
    })
}

pub(super) fn guarded_writer<W: AsyncWrite + Send + Unpin + 'static>(
    writer: W,
    guard: LinkGuard,
) -> BoxWriter {
    Box::pin(GuardedWriter {
        inner: writer,
        _guard: guard,
    })
}

const DEFAULT_MAX_PENDING_FLOW_PAIRS: usize = 1024;
const DEFAULT_FLOW_PAIR_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FlowKey {
    session_id: SessionId,
    flow_id: u64,
}

#[derive(Debug, Eq, PartialEq)]
struct Metadata {
    kind: crate::protocol::FlowKind,
    uplink: crate::protocol::Carrier,
    downlink: crate::protocol::Carrier,
    target: String,
}

struct PendingTcp {
    metadata: Metadata,
    uplink: Option<BoxReader>,
    downlink: Option<BoxWriter>,
    uplink_path: Option<LinkPath>,
    downlink_path: Option<LinkPath>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct LinkPath {
    pub(super) peer: String,
    pub(super) local: String,
}

pub(super) enum UdpUp {
    Tcp(BoxReader),
    Quic(QuicUdpReceiver),
}

pub(super) struct QuicUdpReceiver {
    receiver: mpsc::Receiver<Bytes>,
    on_drop: Option<Box<dyn FnOnce() + Send>>,
}

impl QuicUdpReceiver {
    pub(super) fn new(
        receiver: mpsc::Receiver<Bytes>,
        on_drop: impl FnOnce() + Send + 'static,
    ) -> Self {
        Self {
            receiver,
            on_drop: Some(Box::new(on_drop)),
        }
    }

    pub(super) async fn recv(&mut self) -> Option<Bytes> {
        self.receiver.recv().await
    }
}

impl Drop for QuicUdpReceiver {
    fn drop(&mut self) {
        if let Some(on_drop) = self.on_drop.take() {
            on_drop();
        }
    }
}

pub(super) enum UdpDown {
    Tcp(BoxWriter),
    Quic(Connection),
}

struct PendingUdp {
    metadata: Metadata,
    uplink: Option<UdpUp>,
    downlink: Option<UdpDown>,
    uplink_path: Option<LinkPath>,
    downlink_path: Option<LinkPath>,
}

pub(super) struct PairedUdp {
    pub(super) flow_id: u64,
    pub(super) target: String,
    pub(super) uplink: UdpUp,
    pub(super) downlink: UdpDown,
    pub(super) uplink_carrier: crate::protocol::Carrier,
    pub(super) downlink_carrier: crate::protocol::Carrier,
    pub(super) uplink_path: LinkPath,
    pub(super) downlink_path: LinkPath,
}

pub(super) struct PairedTcp {
    pub(super) target: String,
    pub(super) uplink: BoxReader,
    pub(super) downlink: BoxWriter,
    pub(super) uplink_carrier: crate::protocol::Carrier,
    pub(super) downlink_carrier: crate::protocol::Carrier,
    pub(super) uplink_path: LinkPath,
    pub(super) downlink_path: LinkPath,
}

pub(super) struct PairingRegistry {
    tcp: Mutex<HashMap<FlowKey, PendingTcp>>,
    udp: Mutex<HashMap<FlowKey, PendingUdp>>,
    links: StdMutex<HashMap<SessionId, LinkCounts>>,
    max_pending: usize,
    timeout: Duration,
}

#[derive(Default)]
struct LinkCounts {
    tcp: usize,
    udp: usize,
}

pub(super) struct LinkGuard {
    registry: Arc<PairingRegistry>,
    stats: Arc<Stats>,
    session_id: SessionId,
    carrier: crate::protocol::Carrier,
}

impl Drop for LinkGuard {
    fn drop(&mut self) {
        let mut links = self.registry.links.lock().expect("link registry poisoned");
        let Some(counts) = links.get_mut(&self.session_id) else {
            return;
        };
        let was_paired = counts.tcp > 0 && counts.udp > 0;
        match self.carrier {
            crate::protocol::Carrier::Tcp => counts.tcp = counts.tcp.saturating_sub(1),
            crate::protocol::Carrier::Udp => counts.udp = counts.udp.saturating_sub(1),
        }
        let is_paired = counts.tcp > 0 && counts.udp > 0;
        if was_paired && !is_paired {
            self.stats.link_pairs.fetch_sub(1, Ordering::Relaxed);
        }
        if counts.tcp == 0 && counts.udp == 0 {
            links.remove(&self.session_id);
        }
        match self.carrier {
            crate::protocol::Carrier::Tcp => &self.stats.link_tcp,
            crate::protocol::Carrier::Udp => &self.stats.link_udp,
        }
        .fetch_sub(1, Ordering::Relaxed);
    }
}

impl PairingRegistry {
    pub(super) fn new() -> Self {
        Self {
            tcp: Mutex::new(HashMap::new()),
            udp: Mutex::new(HashMap::new()),
            links: StdMutex::new(HashMap::new()),
            max_pending: read_max_pending(),
            timeout: read_pair_timeout(),
        }
    }

    pub(super) fn register_link(
        self: &Arc<Self>,
        session_id: SessionId,
        carrier: crate::protocol::Carrier,
        stats: Arc<Stats>,
    ) -> Result<LinkGuard> {
        let mut links = self.links.lock().expect("link registry poisoned");
        let counts = links.entry(session_id).or_default();
        if carrier == crate::protocol::Carrier::Udp && counts.udp > 0 {
            bail!("portal::pairing: duplicate active QUIC session ID");
        }
        let was_paired = counts.tcp > 0 && counts.udp > 0;
        match carrier {
            crate::protocol::Carrier::Tcp => counts.tcp += 1,
            crate::protocol::Carrier::Udp => counts.udp += 1,
        }
        let is_paired = counts.tcp > 0 && counts.udp > 0;
        if !was_paired && is_paired {
            stats.link_pairs.fetch_add(1, Ordering::Relaxed);
        }
        match carrier {
            crate::protocol::Carrier::Tcp => &stats.link_tcp,
            crate::protocol::Carrier::Udp => &stats.link_udp,
        }
        .fetch_add(1, Ordering::Relaxed);
        drop(links);
        Ok(LinkGuard {
            registry: self.clone(),
            stats,
            session_id,
            carrier,
        })
    }

    pub(super) async fn submit_tcp(
        self: &Arc<Self>,
        session_id: SessionId,
        header: FlowHeader,
        target: String,
        path: LinkPath,
        reader: Option<BoxReader>,
        writer: Option<BoxWriter>,
    ) -> Result<Option<PairedTcp>> {
        let key = FlowKey {
            session_id,
            flow_id: header.flow_id,
        };
        let metadata = Metadata {
            kind: header.kind,
            uplink: header.uplink,
            downlink: header.downlink,
            target,
        };
        let mut guard = self.tcp.lock().await;
        let udp_guard = self.udp.lock().await;
        if !guard.contains_key(&key)
            && guard
                .keys()
                .chain(udp_guard.keys())
                .filter(|pending| pending.session_id == session_id)
                .count()
                >= self.max_pending
        {
            bail!("portal::pairing: pending flow pair limit reached");
        }
        drop(udp_guard);
        let new_entry = !guard.contains_key(&key);
        let pending = guard.entry(key).or_insert_with(|| PendingTcp {
            metadata: Metadata {
                kind: metadata.kind,
                uplink: metadata.uplink,
                downlink: metadata.downlink,
                target: metadata.target.clone(),
            },
            uplink: None,
            downlink: None,
            uplink_path: None,
            downlink_path: None,
        });
        if pending.metadata != metadata {
            bail!("portal::pairing: conflicting flow metadata");
        }
        match header.role {
            FlowRole::Open => {
                if pending.uplink.is_some() || reader.is_none() {
                    bail!("portal::pairing: duplicate or missing uplink half");
                }
                pending.uplink = reader;
                pending.uplink_path = Some(path);
            }
            FlowRole::Attach => {
                if pending.downlink.is_some() || writer.is_none() {
                    bail!("portal::pairing: duplicate or missing downlink half");
                }
                pending.downlink = writer;
                pending.downlink_path = Some(path);
            }
        }
        if pending.uplink.is_some() && pending.downlink.is_some() {
            let mut complete = guard.remove(&key).expect("pair exists");
            return Ok(Some(PairedTcp {
                target: complete.metadata.target,
                uplink: complete.uplink.take().expect("uplink paired"),
                downlink: complete.downlink.take().expect("downlink paired"),
                uplink_carrier: complete.metadata.uplink,
                downlink_carrier: complete.metadata.downlink,
                uplink_path: complete.uplink_path.take().expect("uplink path paired"),
                downlink_path: complete.downlink_path.take().expect("downlink path paired"),
            }));
        }
        drop(guard);
        if new_entry {
            let registry = self.clone();
            tokio::spawn(async move {
                tokio::time::sleep(registry.timeout).await;
                registry.tcp.lock().await.remove(&key);
            });
        }
        Ok(None)
    }

    pub(super) async fn submit_udp(
        self: &Arc<Self>,
        session_id: SessionId,
        header: FlowHeader,
        target: String,
        path: LinkPath,
        uplink: Option<UdpUp>,
        downlink: Option<UdpDown>,
    ) -> Result<Option<PairedUdp>> {
        let key = FlowKey {
            session_id,
            flow_id: header.flow_id,
        };
        let metadata = Metadata {
            kind: header.kind,
            uplink: header.uplink,
            downlink: header.downlink,
            target,
        };
        let tcp_guard = self.tcp.lock().await;
        let mut guard = self.udp.lock().await;
        if !guard.contains_key(&key)
            && guard
                .keys()
                .chain(tcp_guard.keys())
                .filter(|pending| pending.session_id == session_id)
                .count()
                >= self.max_pending
        {
            bail!("portal::pairing: pending UDP flow pair limit reached");
        }
        drop(tcp_guard);
        let new_entry = !guard.contains_key(&key);
        let pending = guard.entry(key).or_insert_with(|| PendingUdp {
            metadata: Metadata {
                kind: metadata.kind,
                uplink: metadata.uplink,
                downlink: metadata.downlink,
                target: metadata.target.clone(),
            },
            uplink: None,
            downlink: None,
            uplink_path: None,
            downlink_path: None,
        });
        if pending.metadata != metadata {
            bail!("portal::pairing: conflicting UDP flow metadata");
        }
        match header.role {
            FlowRole::Open => {
                if pending.uplink.is_some() || uplink.is_none() {
                    bail!("portal::pairing: duplicate or missing UDP uplink half");
                }
                pending.uplink = uplink;
                pending.uplink_path = Some(path);
            }
            FlowRole::Attach => {
                if pending.downlink.is_some() || downlink.is_none() {
                    bail!("portal::pairing: duplicate or missing UDP downlink half");
                }
                pending.downlink = downlink;
                pending.downlink_path = Some(path);
            }
        }
        if pending.uplink.is_some() && pending.downlink.is_some() {
            let mut complete = guard.remove(&key).expect("UDP pair exists");
            return Ok(Some(PairedUdp {
                flow_id: header.flow_id,
                target: complete.metadata.target,
                uplink: complete.uplink.take().expect("UDP uplink paired"),
                downlink: complete.downlink.take().expect("UDP downlink paired"),
                uplink_carrier: complete.metadata.uplink,
                downlink_carrier: complete.metadata.downlink,
                uplink_path: complete.uplink_path.take().expect("UDP uplink path paired"),
                downlink_path: complete
                    .downlink_path
                    .take()
                    .expect("UDP downlink path paired"),
            }));
        }
        drop(guard);
        if new_entry {
            let registry = self.clone();
            tokio::spawn(async move {
                tokio::time::sleep(registry.timeout).await;
                registry.udp.lock().await.remove(&key);
            });
        }
        Ok(None)
    }

    pub(super) async fn cancel_udp(&self, session_id: SessionId, flow_id: u64) {
        self.udp.lock().await.remove(&FlowKey {
            session_id,
            flow_id,
        });
    }
}

fn read_max_pending() -> usize {
    std::env::var("NOW_MAX_PENDING_FLOW_PAIRS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_MAX_PENDING_FLOW_PAIRS)
}

fn read_pair_timeout() -> Duration {
    std::env::var("NOW_FLOW_PAIR_TIMEOUT")
        .ok()
        .and_then(|value| humantime::parse_duration(&value).ok())
        .filter(|value| !value.is_zero())
        .unwrap_or(DEFAULT_FLOW_PAIR_TIMEOUT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Carrier, FlowKind, FlowRole, SESSION_ID_LEN};

    fn header(role: FlowRole) -> FlowHeader {
        header_with_id(role, 7)
    }

    fn header_with_id(role: FlowRole, flow_id: u64) -> FlowHeader {
        FlowHeader {
            role,
            flow_id,
            kind: FlowKind::Tcp,
            uplink: Carrier::Tcp,
            downlink: Carrier::Udp,
        }
    }

    fn path() -> LinkPath {
        LinkPath {
            peer: "client.test:1234".into(),
            local: "portal.test:2077".into(),
        }
    }

    #[test]
    fn duplicate_quic_session_is_rejected_until_previous_link_drops() {
        let registry = Arc::new(PairingRegistry::new());
        let stats = Arc::new(Stats::default());
        let session_id = [9; SESSION_ID_LEN];
        let first = registry
            .register_link(session_id, Carrier::Udp, stats.clone())
            .unwrap();
        assert!(
            registry
                .register_link(session_id, Carrier::Udp, stats.clone())
                .is_err()
        );
        drop(first);
        assert!(
            registry
                .register_link(session_id, Carrier::Udp, stats)
                .is_ok()
        );
    }

    #[tokio::test]
    async fn pairs_out_of_order_and_rejects_conflicting_metadata() {
        let registry = Arc::new(PairingRegistry::new());
        let (_, down) = tokio::io::duplex(64);
        assert!(
            registry
                .submit_tcp(
                    [1; SESSION_ID_LEN],
                    header(FlowRole::Attach),
                    "target.test:443".into(),
                    path(),
                    None,
                    Some(Box::pin(down)),
                )
                .await
                .unwrap()
                .is_none()
        );

        let (up, _) = tokio::io::duplex(64);
        let paired = registry
            .submit_tcp(
                [1; SESSION_ID_LEN],
                header(FlowRole::Open),
                "target.test:443".into(),
                path(),
                Some(Box::pin(up)),
                None,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(paired.target, "target.test:443");
        assert_eq!(paired.uplink_carrier, Carrier::Tcp);
        assert_eq!(paired.downlink_carrier, Carrier::Udp);

        let (up, _) = tokio::io::duplex(64);
        assert!(
            registry
                .submit_tcp(
                    [2; SESSION_ID_LEN],
                    header(FlowRole::Open),
                    "a.test:1".into(),
                    path(),
                    Some(Box::pin(up)),
                    None,
                )
                .await
                .unwrap()
                .is_none()
        );
        let (_, down) = tokio::io::duplex(64);
        assert!(
            registry
                .submit_tcp(
                    [2; SESSION_ID_LEN],
                    header(FlowRole::Attach),
                    "b.test:1".into(),
                    path(),
                    None,
                    Some(Box::pin(down)),
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn pending_limit_is_enforced_per_session() {
        let registry = Arc::new(PairingRegistry {
            tcp: Mutex::new(HashMap::new()),
            udp: Mutex::new(HashMap::new()),
            links: StdMutex::new(HashMap::new()),
            max_pending: 1,
            timeout: Duration::from_secs(60),
        });

        for (session, flow_id) in [([1; SESSION_ID_LEN], 1), ([2; SESSION_ID_LEN], 1)] {
            let (up, _) = tokio::io::duplex(64);
            assert!(
                registry
                    .submit_tcp(
                        session,
                        header_with_id(FlowRole::Open, flow_id),
                        "target.test:443".into(),
                        path(),
                        Some(Box::pin(up)),
                        None,
                    )
                    .await
                    .unwrap()
                    .is_none()
            );
        }

        let (up, _) = tokio::io::duplex(64);
        assert!(
            registry
                .submit_tcp(
                    [1; SESSION_ID_LEN],
                    header_with_id(FlowRole::Open, 2),
                    "target.test:443".into(),
                    path(),
                    Some(Box::pin(up)),
                    None,
                )
                .await
                .is_err()
        );

        let (up, _) = tokio::io::duplex(64);
        assert!(
            registry
                .submit_udp(
                    [1; SESSION_ID_LEN],
                    FlowHeader {
                        role: FlowRole::Open,
                        flow_id: 3,
                        kind: FlowKind::Udp,
                        uplink: Carrier::Tcp,
                        downlink: Carrier::Udp,
                    },
                    "target.test:53".into(),
                    path(),
                    Some(UdpUp::Tcp(Box::pin(up))),
                    None,
                )
                .await
                .is_err()
        );
    }
}
