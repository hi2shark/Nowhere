// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! QUIC datagram dispatch for UDP proxy flows.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use bytes::Bytes;
use tokio::sync::OwnedSemaphorePermit;
use tokio_util::sync::CancellationToken;

use crate::protocol::{
    DATAGRAM_UDP_CLOSE, DATAGRAM_UDP_REQUEST, DATAGRAM_UDP_RESPONSE, decode_udp_datagram_parts,
    new_udp_datagram_header,
};

use super::PortalSession;
use super::flow::{PortalUdpFlow, QueuedDatagram, UdpFlowKey};

impl PortalSession {
    /// Consumes pending and live QUIC datagrams for this authenticated session.
    pub(in crate::portal::conn) async fn datagram_loop(
        self: Arc<Self>,
        mut pending: VecDeque<Bytes>,
        shutdown: CancellationToken,
    ) {
        loop {
            let data = if let Some(data) = pending.pop_front() {
                data
            } else {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    datagram = self.conn.read_datagram() => match datagram {
                        Ok(data) => data,
                        Err(err) => {
                            if !shutdown.is_cancelled() {
                                self.portal.logger.debug(format_args!("portal::conn::datagram_loop: failed to receive datagram: {err}"));
                            }
                            return;
                        }
                    }
                }
            };
            self.handle_datagram(data).await;
        }
    }

    async fn handle_datagram(self: &Arc<Self>, data: Bytes) {
        let decoded = match decode_udp_datagram_parts(&data, &self.portal.credentials.protocol_spec)
        {
            Ok(decoded) => decoded,
            Err(err) => {
                self.portal.logger.debug(format_args!(
                    "portal::conn::datagram_loop: failed to decode datagram: {err}"
                ));
                return;
            }
        };

        if decoded.frame_type == DATAGRAM_UDP_CLOSE {
            self.close_udp_flow(decoded.flow_id, decoded.target_addr)
                .await;
            return;
        }
        if decoded.frame_type != DATAGRAM_UDP_REQUEST {
            return;
        }

        let retained_bytes = data.len();
        let payload = data.slice(decoded.payload_offset..);
        self.handle_udp_request(
            decoded.flow_id,
            decoded.target_addr,
            payload,
            retained_bytes,
        )
        .await;
    }

    async fn close_udp_flow(&self, flow_id: u64, target_addr: String) {
        let key = UdpFlowKey::new(flow_id, target_addr);
        let flow = self.udp_flows.lock().await.get(&key).cloned();
        if let Some(flow) = flow {
            flow.close().await;
        }
    }

    async fn handle_udp_request(
        self: &Arc<Self>,
        flow_id: u64,
        target_addr: String,
        payload: Bytes,
        retained_bytes: usize,
    ) {
        let Some(budget) = self.try_reserve_udp_queue(retained_bytes) else {
            self.warn_udp_drop("connection queue byte limit reached");
            return;
        };
        let flow = match self.get_or_create_udp_flow(flow_id, target_addr).await {
            Ok(Some(flow)) => flow,
            Ok(None) => {
                self.warn_udp_drop("per-connection flow limit reached");
                return;
            }
            Err(err) => {
                self.portal.logger.error(format_args!(
                    "portal::conn::handle_udp_request: failed to create UDP flow: {err}"
                ));
                return;
            }
        };
        if !flow.enqueue(QueuedDatagram::new(payload, budget)) {
            self.warn_udp_drop("per-flow datagram queue is full");
        }
    }

    async fn get_or_create_udp_flow(
        self: &Arc<Self>,
        flow_id: u64,
        target_addr: String,
    ) -> anyhow::Result<Option<Arc<PortalUdpFlow>>> {
        let key = UdpFlowKey::new(flow_id, target_addr);
        let mut guard = self.udp_flows.lock().await;
        if self.closed.load(Ordering::Acquire) {
            return Ok(None);
        }
        if let Some(flow) = guard.get(&key).cloned() {
            if !flow.is_closed() {
                return Ok(Some(flow));
            }
            guard.remove(&key);
        }
        if guard.len() >= self.portal.udp_flow_limits.max_flows {
            return Ok(None);
        }
        let response_header = new_udp_datagram_header(
            DATAGRAM_UDP_RESPONSE,
            flow_id,
            key.target(),
            &self.portal.credentials.protocol_spec,
        )
        .map_err(|e| {
            anyhow::anyhow!(
                "portal::conn::get_or_create_udp_flow: failed to build response header: {e}"
            )
        })?;
        let (flow, receiver) = PortalUdpFlow::new(Arc::downgrade(self), key.clone());
        let flow = Arc::new(flow);
        guard.insert(key, flow.clone());
        self.portal.stats.add_session(true);
        drop(guard);

        tokio::spawn(flow.clone().run(receiver, response_header));
        Ok(Some(flow))
    }

    fn try_reserve_udp_queue(&self, bytes: usize) -> Option<OwnedSemaphorePermit> {
        let permits = u32::try_from(bytes).ok()?;
        self.udp_queue_budget
            .clone()
            .try_acquire_many_owned(permits)
            .ok()
    }

    fn warn_udp_drop(&self, reason: &str) {
        if !self.udp_overload_logged.swap(true, Ordering::AcqRel) {
            self.portal.logger.warn(format_args!(
                "portal::conn::datagram_loop: dropping UDP datagrams for {}: {reason}",
                self.conn.remote_address()
            ));
        }
    }
}
