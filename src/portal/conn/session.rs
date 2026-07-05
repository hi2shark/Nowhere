// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Authenticated QUIC session state for stream and datagram traffic.

#[path = "session_datagram.rs"]
mod datagram;
#[path = "session_flow.rs"]
mod flow;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use bytes::Bytes;
use quinn::{Connection, RecvStream, SendStream};
use tokio::sync::mpsc;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::timeout;

use crate::common::handshake_timeout;
use tokio::io::AsyncBufReadExt;
use tokio::io::BufReader;

use crate::protocol::{
    Carrier, FLOW_FRAME_MAGIC, FlowKind, FlowRole, SessionId, read_flow_header, read_request,
};

use self::flow::{PortalUdpFlow, UdpFlowKey};
use super::relay::relay_tcp_target;
use crate::portal::PortalInner;

/// Per-authenticated QUIC connection state.
pub(super) struct PortalSession {
    portal: Arc<PortalInner>,
    conn: Connection,
    pub(super) session_id: SessionId,
    quic_generation: AtomicU64,
    udp_flows: Mutex<HashMap<UdpFlowKey, Arc<PortalUdpFlow>>>,
    compact_udp_flows: Mutex<HashMap<u64, CompactUdpState>>,
    udp_queue_budget: Arc<Semaphore>,
    udp_overload_logged: AtomicBool,
    closed: AtomicBool,
}

pub(super) struct CompactUdpState {
    pub(super) target: String,
    pub(super) downlink: Carrier,
    pub(super) sender: mpsc::Sender<Bytes>,
    pub(super) acked: Arc<AtomicBool>,
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
        let udp_queue_budget = Arc::new(Semaphore::new(portal.udp_flow_limits.queue_bytes));
        Self {
            portal,
            conn,
            session_id,
            quic_generation: AtomicU64::new(0),
            udp_flows: Mutex::new(HashMap::new()),
            compact_udp_flows: Mutex::new(HashMap::new()),
            udp_queue_budget,
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

    /// Handles a bidirectional QUIC stream carrying one TCP target request.
    pub(super) async fn handle_stream(self: Arc<Self>, mut send: SendStream, recv: RecvStream) {
        let portal = &self.portal;
        let mut recv = BufReader::new(recv);
        let mut flow_header = None;
        let target_addr = match timeout(handshake_timeout(), async {
            if recv.fill_buf().await?.first() == Some(&FLOW_FRAME_MAGIC) {
                flow_header = Some(read_flow_header(&mut recv).await?);
            }
            read_request(&mut recv, &portal.credentials.protocol_spec).await
        })
        .await
        {
            Ok(Ok(addr)) => addr,
            Ok(Err(err)) => {
                portal.logger.error(format_args!(
                    "portal::conn::handle_stream: failed to read request: {err}"
                ));
                return;
            }
            Err(_) => {
                portal.logger.error(format_args!(
                    "portal::conn::handle_stream: failed to read request: deadline elapsed"
                ));
                return;
            }
        };

        if let Some(header) = flow_header {
            let valid_ingress = match header.role {
                FlowRole::Open => header.uplink == Carrier::Udp,
                FlowRole::Attach => header.downlink == Carrier::Udp,
            };
            if !valid_ingress || header.uplink == header.downlink {
                portal.logger.error(format_args!(
                    "portal::conn::handle_stream: invalid asymmetric flow header"
                ));
                return;
            }
            match header.kind {
                FlowKind::Tcp => {
                    let result = match header.role {
                        FlowRole::Open => {
                            portal
                                .pairing
                                .submit_tcp(
                                    self.session_id,
                                    header,
                                    target_addr,
                                    crate::portal::pairing::LinkHalf::quic(
                                        self.link_path(),
                                        self.quic_generation(),
                                    ),
                                    Some(Box::pin(recv)),
                                    None,
                                )
                                .await
                        }
                        FlowRole::Attach => {
                            portal
                                .pairing
                                .submit_tcp(
                                    self.session_id,
                                    header,
                                    target_addr,
                                    crate::portal::pairing::LinkHalf::quic(
                                        self.link_path(),
                                        self.quic_generation(),
                                    ),
                                    None,
                                    Some(Box::pin(send)),
                                )
                                .await
                        }
                    };
                    match result {
                        Ok(Some(paired)) => {
                            tokio::spawn(super::relay::relay_paired_tcp(portal.clone(), paired));
                        }
                        Ok(None) => {}
                        Err(err) => portal.logger.error(format_args!(
                            "portal::conn::handle_stream: failed to pair TCP flow: {err}"
                        )),
                    }
                }
                FlowKind::Udp => {
                    if header.role != FlowRole::Attach {
                        portal.logger.error(format_args!(
                            "portal::conn::handle_stream: UDP uplink must use DATAGRAM"
                        ));
                        return;
                    }
                    let result = portal
                        .pairing
                        .submit_udp(
                            self.session_id,
                            header,
                            target_addr,
                            crate::portal::pairing::LinkHalf::quic(
                                self.link_path(),
                                self.quic_generation(),
                            ),
                            crate::portal::pairing::UdpHalf::Downlink(
                                crate::portal::pairing::UdpDown::Quic(self.conn.clone()),
                            ),
                        )
                        .await;
                    match result {
                        Ok(Some(paired)) => {
                            tokio::spawn(super::relay::relay_paired_udp(portal.clone(), paired));
                        }
                        Ok(None) => {}
                        Err(err) => portal.logger.error(format_args!(
                            "portal::conn::handle_stream: failed to pair UDP flow: {err}"
                        )),
                    }
                }
            }
            return;
        }

        let peer = self.conn.remote_address();
        let local = self.conn.local_ip().map_or_else(
            || portal.endpoint_addr.clone(),
            |ip| std::net::SocketAddr::new(ip, portal.listen_port).to_string(),
        );
        relay_tcp_target(
            portal.clone(),
            &mut recv,
            &mut send,
            target_addr,
            peer.to_string(),
            local,
            Carrier::Udp,
        )
        .await;
    }

    /// Closes all UDP flows owned by the session exactly once.
    pub(super) async fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let flows = {
            let mut guard = self.udp_flows.lock().await;
            guard.drain().map(|(_, flow)| flow).collect::<Vec<_>>()
        };
        for flow in flows {
            flow.close().await;
        }
        self.compact_udp_flows.lock().await.clear();
    }
}
