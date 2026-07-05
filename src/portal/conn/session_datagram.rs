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
    Carrier, CompactUdpFrame, DATAGRAM_UDP_CLOSE, DATAGRAM_UDP_REQUEST, DATAGRAM_UDP_RESPONSE,
    FlowHeader, FlowKind, FlowRole, decode_udp_compact, decode_udp_datagram_parts,
    encode_udp_compact, new_udp_datagram_header,
};

use super::flow::{PortalUdpFlow, QueuedDatagram, UdpFlowKey};
use super::{CompactUdpState, PortalSession};

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
        if data.get(1).is_some_and(|kind| matches!(*kind, 0x11..=0x14)) {
            self.handle_compact_datagram(data).await;
            return;
        }
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

    async fn handle_compact_datagram(self: &Arc<Self>, data: Bytes) {
        let frame = match decode_udp_compact(&data) {
            Ok(frame) => frame,
            Err(err) => {
                self.portal.logger.debug(format_args!(
                    "portal::conn::datagram_loop: invalid compact UDP frame: {err}"
                ));
                return;
            }
        };
        match frame {
            CompactUdpFrame::OpenData {
                flow_id,
                downlink,
                target,
                payload,
            } => {
                let payload_offset = payload.as_ptr() as usize - data.as_ptr() as usize;
                let payload = data.slice(payload_offset..);
                let existing = self
                    .compact_udp_flows
                    .lock()
                    .await
                    .get(&flow_id)
                    .map(|state| {
                        (
                            state.target == target && state.downlink == downlink,
                            state.sender.clone(),
                        )
                    });
                if let Some((valid, sender)) = existing {
                    if valid {
                        let _ = sender.try_send(payload);
                    } else {
                        drop(sender);
                        self.reject_compact_flow(flow_id).await;
                    }
                    return;
                }
                if self.compact_udp_flows.lock().await.len()
                    >= self.portal.udp_flow_limits.max_flows
                {
                    self.warn_udp_drop("compact flow limit reached");
                    return;
                }
                let (sender, receiver) = tokio::sync::mpsc::channel(64);
                self.compact_udp_flows.lock().await.insert(
                    flow_id,
                    CompactUdpState {
                        target: target.clone(),
                        downlink,
                        sender: sender.clone(),
                    },
                );
                let _ = sender.try_send(payload);
                let weak_session = Arc::downgrade(self);
                let receiver = crate::portal::pairing::QuicUdpReceiver::new(receiver, move || {
                    let Some(session) = weak_session.upgrade() else {
                        return;
                    };
                    tokio::spawn(async move {
                        session.compact_udp_flows.lock().await.remove(&flow_id);
                    });
                });
                let paired = if downlink == Carrier::Udp {
                    let path = self.link_path();
                    Some(crate::portal::pairing::PairedUdp {
                        flow_id,
                        target,
                        uplink: crate::portal::pairing::UdpUp::Quic(receiver),
                        downlink: crate::portal::pairing::UdpDown::Quic(self.conn.clone()),
                        uplink_carrier: Carrier::Udp,
                        downlink_carrier: Carrier::Udp,
                        uplink_path: path.clone(),
                        downlink_path: path,
                    })
                } else {
                    let header = FlowHeader {
                        role: FlowRole::Open,
                        flow_id,
                        kind: FlowKind::Udp,
                        uplink: Carrier::Udp,
                        downlink,
                    };
                    match self
                        .portal
                        .pairing
                        .submit_udp(
                            self.session_id,
                            header,
                            target,
                            self.link_path(),
                            Some(crate::portal::pairing::UdpUp::Quic(receiver)),
                            None,
                        )
                        .await
                    {
                        Ok(paired) => paired,
                        Err(err) => {
                            self.portal.logger.error(format_args!(
                                "portal::conn::datagram_loop: failed to pair UDP flow: {err}"
                            ));
                            self.reject_compact_flow(flow_id).await;
                            None
                        }
                    }
                };
                if let Some(paired) = paired {
                    tokio::spawn(super::super::relay::relay_paired_udp(
                        self.portal.clone(),
                        paired,
                    ));
                }
            }
            CompactUdpFrame::Data { flow_id, payload } => {
                if let Some(sender) = self
                    .compact_udp_flows
                    .lock()
                    .await
                    .get(&flow_id)
                    .map(|s| s.sender.clone())
                {
                    let payload_offset = payload.as_ptr() as usize - data.as_ptr() as usize;
                    let _ = sender.try_send(data.slice(payload_offset..));
                }
            }
            CompactUdpFrame::Close { flow_id } => {
                self.compact_udp_flows.lock().await.remove(&flow_id);
                self.portal
                    .pairing
                    .cancel_udp(self.session_id, flow_id)
                    .await;
            }
            CompactUdpFrame::OpenAck { .. } => {}
        }
    }

    async fn reject_compact_flow(&self, flow_id: u64) {
        self.compact_udp_flows.lock().await.remove(&flow_id);
        self.portal
            .pairing
            .cancel_udp(self.session_id, flow_id)
            .await;
        if let Ok(frame) = encode_udp_compact(DATAGRAM_UDP_CLOSE, flow_id, &[]) {
            let _ = self.conn.send_datagram(Bytes::from(frame));
        }
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
