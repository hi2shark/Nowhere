// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Pairing registry state types.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use quinn::Connection;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

use crate::protocol::{FlowKind, SessionId};

pub(in crate::portal) type BoxReader = Pin<Box<dyn AsyncRead + Send>>;
pub(in crate::portal) type BoxWriter = Pin<Box<dyn AsyncWrite + Send>>;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(in crate::portal) struct FlowKey {
    pub(in crate::portal) session_id: SessionId,
    pub(in crate::portal) flow_id: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub(in crate::portal) struct Metadata {
    pub(in crate::portal) kind: FlowKind,
    pub(in crate::portal) uplink: crate::protocol::Carrier,
    pub(in crate::portal) downlink: crate::protocol::Carrier,
    pub(in crate::portal) target: String,
}

pub(in crate::portal) struct PendingTcp {
    pub(in crate::portal) epoch: u64,
    pub(in crate::portal) metadata: Metadata,
    pub(in crate::portal) uplink: Option<BoxReader>,
    pub(in crate::portal) downlink: Option<BoxWriter>,
    pub(in crate::portal) uplink_path: Option<LinkPath>,
    pub(in crate::portal) downlink_path: Option<LinkPath>,
    pub(in crate::portal) uplink_generation: Option<u64>,
    pub(in crate::portal) downlink_generation: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::portal) struct LinkPath {
    pub(in crate::portal) peer: String,
    pub(in crate::portal) local: String,
}

pub(in crate::portal) struct LinkHalf {
    pub(in crate::portal) path: LinkPath,
    pub(in crate::portal) quic_generation: Option<u64>,
}

impl LinkHalf {
    pub(in crate::portal) fn tcp(path: LinkPath) -> Self {
        Self {
            path,
            quic_generation: None,
        }
    }

    pub(in crate::portal) fn quic(path: LinkPath, generation: u64) -> Self {
        Self {
            path,
            quic_generation: Some(generation),
        }
    }
}

pub(in crate::portal) enum UdpUp {
    Tcp(BoxReader),
    Quic(QuicUdpReceiver),
}

pub(in crate::portal) struct QuicUdpReceiver {
    receiver: mpsc::Receiver<crate::portal::conn::QueuedDatagram>,
    on_drop: Option<Box<dyn FnOnce() + Send>>,
}

impl QuicUdpReceiver {
    pub(in crate::portal) fn new(
        receiver: mpsc::Receiver<crate::portal::conn::QueuedDatagram>,
        on_drop: impl FnOnce() + Send + 'static,
    ) -> Self {
        Self {
            receiver,
            on_drop: Some(Box::new(on_drop)),
        }
    }

    pub(in crate::portal) async fn recv(&mut self) -> Option<bytes::Bytes> {
        self.receiver.recv().await.map(|datagram| datagram.payload)
    }
}

impl Drop for QuicUdpReceiver {
    fn drop(&mut self) {
        if let Some(on_drop) = self.on_drop.take() {
            on_drop();
        }
    }
}

pub(in crate::portal) enum UdpDown {
    Tcp(BoxWriter),
    Quic(Connection),
}

pub(in crate::portal) enum UdpHalf {
    Uplink {
        uplink: UdpUp,
        udp_ack: Option<UdpAck>,
        flow_permit: Option<Arc<OwnedSemaphorePermit>>,
    },
    Downlink(UdpDown),
}

pub(in crate::portal) struct UdpAck {
    pub(in crate::portal) conn: Connection,
    pub(in crate::portal) acked: Arc<AtomicBool>,
}

pub(in crate::portal) struct PendingUdp {
    pub(in crate::portal) epoch: u64,
    pub(in crate::portal) metadata: Metadata,
    pub(in crate::portal) uplink: Option<UdpUp>,
    pub(in crate::portal) downlink: Option<UdpDown>,
    pub(in crate::portal) udp_ack: Option<UdpAck>,
    pub(in crate::portal) flow_permit: Option<Arc<OwnedSemaphorePermit>>,
    pub(in crate::portal) uplink_path: Option<LinkPath>,
    pub(in crate::portal) downlink_path: Option<LinkPath>,
    pub(in crate::portal) uplink_generation: Option<u64>,
    pub(in crate::portal) downlink_generation: Option<u64>,
}

pub(in crate::portal) struct PairedUdp {
    pub(in crate::portal) flow_id: u64,
    pub(in crate::portal) target: String,
    pub(in crate::portal) uplink: UdpUp,
    pub(in crate::portal) downlink: UdpDown,
    pub(in crate::portal) uplink_carrier: crate::protocol::Carrier,
    pub(in crate::portal) downlink_carrier: crate::protocol::Carrier,
    pub(in crate::portal) uplink_path: LinkPath,
    pub(in crate::portal) downlink_path: LinkPath,
    pub(in crate::portal) udp_ack: Option<UdpAck>,
    pub(in crate::portal) _flow_permit: Option<Arc<OwnedSemaphorePermit>>,
}

pub(in crate::portal) struct PairedTcp {
    pub(in crate::portal) target: String,
    pub(in crate::portal) uplink: BoxReader,
    pub(in crate::portal) downlink: BoxWriter,
    pub(in crate::portal) uplink_carrier: crate::protocol::Carrier,
    pub(in crate::portal) downlink_carrier: crate::protocol::Carrier,
    pub(in crate::portal) uplink_path: LinkPath,
    pub(in crate::portal) downlink_path: LinkPath,
}

#[derive(Default)]
pub(in crate::portal) struct LinkCounts {
    pub(in crate::portal) tcp: usize,
    pub(in crate::portal) udp: Option<ActiveQuic>,
}

pub(in crate::portal) struct ActiveQuic {
    pub(in crate::portal) generation: u64,
    pub(in crate::portal) replacement: tokio_util::sync::CancellationToken,
    pub(in crate::portal) udp_flow_budget: Arc<Semaphore>,
}
