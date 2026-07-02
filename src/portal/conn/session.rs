// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Authenticated QUIC session state for stream and datagram traffic.

#[path = "session_datagram.rs"]
mod datagram;
#[path = "session_flow.rs"]
mod flow;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use quinn::{Connection, RecvStream, SendStream};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::timeout;

use crate::common::handshake_timeout;
use crate::protocol::read_request;

use self::flow::{PortalUdpFlow, UdpFlowKey};
use super::relay::relay_tcp_target;
use crate::portal::PortalInner;

/// Per-authenticated QUIC connection state.
pub(super) struct PortalSession {
    portal: Arc<PortalInner>,
    conn: Connection,
    udp_flows: Mutex<HashMap<UdpFlowKey, Arc<PortalUdpFlow>>>,
    udp_queue_budget: Arc<Semaphore>,
    udp_overload_logged: AtomicBool,
    closed: AtomicBool,
}

impl PortalSession {
    /// Creates session state for one authenticated QUIC connection.
    pub(super) fn new(portal: Arc<PortalInner>, conn: Connection) -> Self {
        let udp_queue_budget = Arc::new(Semaphore::new(portal.udp_flow_limits.queue_bytes));
        Self {
            portal,
            conn,
            udp_flows: Mutex::new(HashMap::new()),
            udp_queue_budget,
            udp_overload_logged: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        }
    }

    /// Handles a bidirectional QUIC stream carrying one TCP target request.
    pub(super) async fn handle_stream(self: Arc<Self>, mut send: SendStream, mut recv: RecvStream) {
        let portal = &self.portal;
        let target_addr = match timeout(
            handshake_timeout(),
            read_request(&mut recv, &portal.credentials.protocol_spec),
        )
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
    }
}
