// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! QUIC datagram dispatch for UDP proxy flows.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use bytes::Bytes;
use tokio_util::sync::CancellationToken;

use crate::common::udp_dial_timeout;
use crate::protocol::{
    DATAGRAM_UDP_CLOSE, DATAGRAM_UDP_REQUEST, DATAGRAM_UDP_RESPONSE, decode_udp_datagram,
    new_udp_datagram_header,
};

use super::PortalSession;
use super::flow::{PortalUdpFlow, UdpFlowKey};

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
        let (frame_type, flow_id, target_addr, payload) =
            match decode_udp_datagram(&data, &self.portal.credentials.protocol_spec) {
                Ok(decoded) => decoded,
                Err(err) => {
                    self.portal.logger.debug(format_args!(
                        "portal::conn::datagram_loop: failed to decode datagram: {err}"
                    ));
                    return;
                }
            };

        if frame_type == DATAGRAM_UDP_CLOSE {
            self.close_udp_flow(flow_id, target_addr).await;
            return;
        }
        if frame_type != DATAGRAM_UDP_REQUEST {
            return;
        }

        self.handle_udp_request(flow_id, target_addr, payload).await;
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
        payload: &[u8],
    ) {
        let flow = match self.get_udp_flow(flow_id, &target_addr).await {
            Ok(flow) => flow,
            Err(err) => {
                self.portal.logger.error(format_args!(
                    "portal::conn::handle_udp_request: failed to open UDP flow: {err}"
                ));
                return;
            }
        };
        flow.touch().await;

        if let Some(limiter) = &self.portal.rate_limiter {
            limiter.wait_read(payload.len() as i64).await;
        }

        match flow.send_to_target(payload).await {
            Ok(n) => {
                self.portal
                    .stats
                    .udp_rx
                    .fetch_add(n as u64, Ordering::Relaxed);
            }
            Err(err) => {
                self.portal.logger.error(format_args!(
                    "portal::conn::handle_udp_request: failed to write target: {err}"
                ));
                flow.close().await;
            }
        }
    }

    async fn get_udp_flow(
        self: &Arc<Self>,
        flow_id: u64,
        target_addr: &str,
    ) -> anyhow::Result<Arc<PortalUdpFlow>> {
        let key = UdpFlowKey::new(flow_id, target_addr);

        // Reuse an open flow for repeated datagrams with the same client flow ID
        // and target; closed flows are replaced below.
        if let Some(flow) = self.udp_flows.lock().await.get(&key).cloned()
            && !flow.is_closed()
        {
            return Ok(flow);
        }

        let socket = self
            .portal
            .outbound
            .dial_udp(target_addr, udp_dial_timeout())
            .await?;
        let response_header = new_udp_datagram_header(
            DATAGRAM_UDP_RESPONSE,
            flow_id,
            target_addr,
            &self.portal.credentials.protocol_spec,
        )
        .map_err(|e| {
            anyhow::anyhow!("portal::conn::get_udp_flow: failed to build response header: {e}")
        })?;
        let flow = Arc::new(PortalUdpFlow::new(
            Arc::downgrade(self),
            key.clone(),
            socket,
            response_header,
        ));

        let mut guard = self.udp_flows.lock().await;
        if let Some(existing) = guard.get(&key).cloned() {
            // Another task may have inserted the flow while this task was
            // dialing. Prefer the existing entry to keep ownership singular.
            return Ok(existing);
        }
        guard.insert(key, flow.clone());
        drop(guard);

        self.portal.stats.add_session(true);
        tokio::spawn(flow.clone().read_loop());
        tokio::spawn(flow.clone().idle_loop());
        Ok(flow)
    }
}
