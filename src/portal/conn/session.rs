// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Authenticated QUIC session state for reliable flow setup and UDP DATAGRAM traffic.

#[path = "session_datagram.rs"]
mod datagram;
#[path = "session_flow.rs"]
mod flow;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use quinn::{Connection, RecvStream, SendStream};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::sync::{Mutex, Semaphore, mpsc};
use tokio::time::timeout;

use crate::common::handshake_timeout;
use crate::protocol::{
    FlowErrorCode, FlowKind, FlowResult, FlowRole, SessionId, read_flow_header, read_request,
    write_flow_result,
};

pub(in crate::portal) use self::flow::QueuedDatagram;
use self::flow::UdpReassembler;
use crate::portal::PortalInner;

const FLOW_REJECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// Per-authenticated QUIC connection state.
pub(super) struct PortalSession {
    portal: Arc<PortalInner>,
    conn: Connection,
    pub(super) session_id: SessionId,
    quic_generation: AtomicU64,
    udp_flows: Mutex<HashMap<u64, UdpState>>,
    udp_reassembler: Mutex<UdpReassembler>,
    udp_queue_budget: Arc<Semaphore>,
    udp_overload_logged: AtomicBool,
    closed: AtomicBool,
}

pub(super) struct UdpState {
    pub(super) sender: mpsc::Sender<QueuedDatagram>,
}

impl PortalSession {
    fn link_path(&self) -> crate::portal::pairing::LinkPath {
        crate::portal::pairing::LinkPath {
            peer: self.conn.remote_address().to_string(),
            local: self.conn.local_ip().map_or_else(
                || self.portal.endpoint_addr.clone(),
                |ip| std::net::SocketAddr::new(ip, self.portal.listen_port).to_string(),
            ),
        }
    }

    /// Creates session state for one authenticated QUIC connection.
    pub(super) fn new(portal: Arc<PortalInner>, conn: Connection, session_id: SessionId) -> Self {
        Self {
            udp_queue_budget: Arc::new(Semaphore::new(portal.udp_flow_limits.queue_bytes)),
            portal,
            conn,
            session_id,
            quic_generation: AtomicU64::new(0),
            udp_flows: Mutex::new(HashMap::new()),
            udp_reassembler: Mutex::new(UdpReassembler::default()),
            udp_overload_logged: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        }
    }

    pub(super) fn set_quic_generation(&self, generation: u64) {
        self.quic_generation.store(generation, Ordering::Release);
    }

    pub(super) fn quic_generation(&self) -> u64 {
        self.quic_generation.load(Ordering::Acquire)
    }

    /// Handles one reliable QUIC flow-control stream.
    pub(super) async fn handle_stream(self: Arc<Self>, mut send: SendStream, recv: RecvStream) {
        let mut recv = BufReader::new(recv);
        let header = match timeout(handshake_timeout(), read_flow_header(&mut recv)).await {
            Ok(Ok(header)) => header,
            Ok(Err(err)) => {
                self.portal.logger.debug(format_args!(
                    "portal::conn::handle_stream: invalid flow header: {err}"
                ));
                return;
            }
            Err(_) => return,
        };
        let target = if matches!(header.role, FlowRole::Open | FlowRole::Duplex) {
            match timeout(
                handshake_timeout(),
                read_request(&mut recv, &self.portal.credentials.protocol_spec),
            )
            .await
            {
                Ok(Ok(target)) => Some(target),
                _ => {
                    if header.role == FlowRole::Open {
                        self.portal
                            .pairing
                            .reject_flow_setup(
                                self.session_id,
                                header.flow_id,
                                FlowErrorCode::InvalidRequest,
                            )
                            .await;
                    } else if header.role == FlowRole::Duplex {
                        reject_quic_control(&mut send, FlowErrorCode::InvalidRequest).await;
                    }
                    return;
                }
            }
        } else {
            None
        };
        let link = crate::portal::pairing::LinkHalf::quic(self.link_path(), self.quic_generation());

        match header.kind {
            FlowKind::Tcp => {
                let (reader, writer) = match header.role {
                    FlowRole::Open => (Some(Box::pin(recv) as _), None),
                    FlowRole::Attach => (None, Some(Box::pin(send) as _)),
                    FlowRole::Duplex => (Some(Box::pin(recv) as _), Some(Box::pin(send) as _)),
                };
                match self
                    .portal
                    .pairing
                    .submit_tcp(self.session_id, header, target, link, reader, writer, None)
                    .await
                {
                    Ok(Some(paired)) => {
                        self.portal
                            .flow_tasks
                            .spawn(super::relay::relay_paired_tcp(self.portal.clone(), paired));
                    }
                    Ok(None) => {}
                    Err(err) => self.portal.logger.debug(format_args!(
                        "portal::conn::handle_stream: TCP flow rejected: {err}"
                    )),
                }
            }
            FlowKind::Udp => {
                let half = match header.role {
                    FlowRole::Open => {
                        let Some(receiver) = self.install_udp_uplink(header.flow_id).await else {
                            self.portal
                                .pairing
                                .reject_flow_setup(
                                    self.session_id,
                                    header.flow_id,
                                    FlowErrorCode::MetadataConflict,
                                )
                                .await;
                            return;
                        };
                        crate::portal::pairing::UdpHalf::Uplink {
                            uplink: crate::portal::pairing::UdpUp::Quic(receiver),
                        }
                    }
                    FlowRole::Attach => crate::portal::pairing::UdpHalf::Downlink(
                        crate::portal::pairing::UdpDown::Quic {
                            control: Box::pin(send),
                            conn: self.conn.clone(),
                        },
                    ),
                    FlowRole::Duplex => {
                        let Some(receiver) = self.install_udp_uplink(header.flow_id).await else {
                            reject_quic_control(&mut send, FlowErrorCode::MetadataConflict).await;
                            return;
                        };
                        crate::portal::pairing::UdpHalf::Duplex {
                            uplink: crate::portal::pairing::UdpUp::Quic(receiver),
                            downlink: crate::portal::pairing::UdpDown::Quic {
                                control: Box::pin(send),
                                conn: self.conn.clone(),
                            },
                        }
                    }
                };
                match self
                    .portal
                    .pairing
                    .submit_udp(self.session_id, header, target, link, half)
                    .await
                {
                    Ok(Some(paired)) => {
                        self.portal
                            .flow_tasks
                            .spawn(super::relay::relay_paired_udp(self.portal.clone(), paired));
                    }
                    Ok(None) => {}
                    Err(err) => {
                        if matches!(header.role, FlowRole::Open | FlowRole::Duplex) {
                            self.remove_udp_uplink(header.flow_id).await;
                        }
                        self.portal.logger.debug(format_args!(
                            "portal::conn::handle_stream: UDP flow rejected: {err}"
                        ));
                    }
                }
            }
        }
    }

    async fn install_udp_uplink(
        self: &Arc<Self>,
        flow_id: u64,
    ) -> Option<crate::portal::pairing::QuicUdpReceiver> {
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        let (sender, receiver) = mpsc::channel(64);
        let mut flows = self.udp_flows.lock().await;
        if flows.contains_key(&flow_id) {
            return None;
        }
        flows.insert(flow_id, UdpState { sender });
        drop(flows);
        let weak_session = Arc::downgrade(self);
        Some(crate::portal::pairing::QuicUdpReceiver::new(
            receiver,
            move || {
                let Some(session) = weak_session.upgrade() else {
                    return;
                };
                tokio::spawn(async move {
                    session.remove_udp_uplink(flow_id).await;
                });
            },
        ))
    }

    pub(super) async fn remove_udp_uplink(&self, flow_id: u64) {
        self.udp_flows.lock().await.remove(&flow_id);
        self.udp_reassembler.lock().await.remove_flow(flow_id);
    }

    /// Closes all UDP flows owned by the session exactly once.
    pub(super) async fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.udp_flows.lock().await.clear();
        *self.udp_reassembler.lock().await = UdpReassembler::default();
    }
}

async fn reject_quic_control(send: &mut SendStream, code: FlowErrorCode) {
    let write = async {
        let _ = write_flow_result(send, FlowResult::Reject(code)).await;
        let _ = send.shutdown().await;
    };
    let _ = timeout(FLOW_REJECT_TIMEOUT, write).await;
}
