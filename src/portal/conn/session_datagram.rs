// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! QUIC DATAGRAM dispatch for UDP packets after reliable flow setup.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use bytes::Bytes;
use tokio_util::sync::CancellationToken;

use crate::protocol::{UdpFragment, UdpFrame, decode_udp_frame};

use super::flow::ReassemblyOutcome;
use super::{PortalSession, QueuedDatagram};

impl PortalSession {
    /// Consumes pending and live QUIC datagrams for this authenticated session.
    pub(in crate::portal::conn) async fn datagram_loop(
        self: Arc<Self>,
        mut pending: VecDeque<Bytes>,
        shutdown: CancellationToken,
    ) {
        let mut cleanup = tokio::time::interval(std::time::Duration::from_secs(1));
        cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let data = if let Some(data) = pending.pop_front() {
                data
            } else {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = cleanup.tick() => {
                        if self.udp_reassembler.lock().await.expire(tokio::time::Instant::now()) {
                            self.warn_udp_drop("incomplete UDP packet expired");
                        }
                        continue;
                    }
                    datagram = self.conn.read_datagram() => match datagram {
                        Ok(data) => data,
                        Err(err) => {
                            if !shutdown.is_cancelled() {
                                self.portal.logger.debug(format_args!("portal::conn::datagram_loop: receive closed: {err}"));
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
        match decode_udp_frame(&data) {
            Ok(UdpFrame::Data { flow_id, fragment }) => {
                self.handle_udp_fragment(flow_id, fragment).await;
            }
            Ok(UdpFrame::Close { flow_id }) => self.close_udp_flow(flow_id).await,
            Err(err) => self.portal.logger.debug(format_args!(
                "portal::conn::datagram_loop: invalid UDP frame: {err}"
            )),
        }
    }

    async fn handle_udp_fragment(self: &Arc<Self>, flow_id: u64, fragment: UdpFragment<'_>) {
        if !self.udp_flows.lock().await.contains_key(&flow_id) {
            self.warn_udp_drop("DATA for unknown UDP flow");
            return;
        }
        let payload = Bytes::copy_from_slice(fragment.payload);
        let outcome = self.udp_reassembler.lock().await.push(
            flow_id,
            fragment,
            payload,
            self.udp_queue_budget.clone(),
        );
        match outcome {
            ReassemblyOutcome::Pending { evicted_partial } => {
                if evicted_partial {
                    self.warn_udp_drop("incomplete UDP packet evicted");
                }
            }
            ReassemblyOutcome::Dropped(reason) => self.warn_udp_drop(reason),
            ReassemblyOutcome::Complete {
                datagram,
                evicted_partial,
            } => {
                if evicted_partial {
                    self.warn_udp_drop("incomplete UDP packet evicted");
                }
                self.handle_udp_data(flow_id, datagram).await;
            }
        }
    }

    async fn handle_udp_data(&self, flow_id: u64, datagram: QueuedDatagram) {
        let sender = self
            .udp_flows
            .lock()
            .await
            .get(&flow_id)
            .map(|state| state.sender.clone());
        if let Some(sender) = sender {
            self.enqueue_udp(&sender, datagram);
        } else {
            self.warn_udp_drop("DATA raced with UDP flow close");
        }
    }

    async fn close_udp_flow(&self, flow_id: u64) {
        self.remove_udp_uplink(flow_id).await;
        self.portal
            .pairing
            .cancel_udp(self.session_id, flow_id)
            .await;
    }

    fn enqueue_udp(
        &self,
        sender: &tokio::sync::mpsc::Sender<QueuedDatagram>,
        datagram: QueuedDatagram,
    ) -> bool {
        if sender.try_send(datagram).is_err() {
            self.warn_udp_drop("per-flow datagram queue is full");
            return false;
        }
        true
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
