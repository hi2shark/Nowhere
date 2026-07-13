// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! QUIC datagram dispatch for UDP proxy flows.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use tokio_util::sync::CancellationToken;

use crate::protocol::{
    Carrier, FlowHeader, FlowKind, FlowRole, UDP_FRAME_CLOSE, UDP_FRAME_OPEN_ACK, UdpFragment,
    UdpFrame, decode_udp_frame, encode_udp_control,
};

use super::flow::{OpenMetadata, ReassemblyOutcome};
use super::{PortalSession, QueuedDatagram, UdpState};

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
        let frame = match decode_udp_frame(&data) {
            Ok(frame) => frame,
            Err(err) => {
                self.portal.logger.debug(format_args!(
                    "portal::conn::datagram_loop: invalid UDP frame: {err}"
                ));
                return;
            }
        };
        match frame {
            UdpFrame::OpenData {
                flow_id,
                downlink,
                target,
                fragment,
            } => {
                self.handle_udp_fragment(
                    flow_id,
                    fragment,
                    Some(OpenMetadata { downlink, target }),
                )
                .await;
            }
            UdpFrame::Data { flow_id, fragment } => {
                self.handle_udp_fragment(flow_id, fragment, None).await;
            }
            UdpFrame::Close { flow_id } => self.close_udp_flow(flow_id).await,
            UdpFrame::OpenAck { .. } => {}
        }
    }

    async fn handle_udp_fragment(
        self: &Arc<Self>,
        flow_id: u64,
        fragment: UdpFragment<'_>,
        metadata: Option<OpenMetadata>,
    ) {
        // Copy only the fragment body. Retaining the complete QUIC DATAGRAM would
        // let repeated OPEN metadata bypass the packet-byte budget.
        let payload = Bytes::copy_from_slice(fragment.payload);
        let outcome = self.udp_reassembler.lock().await.push(
            flow_id,
            fragment,
            payload,
            metadata,
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
                metadata,
                evicted_partial,
            } => {
                if evicted_partial {
                    self.warn_udp_drop("incomplete UDP packet evicted");
                }
                if let Some(metadata) = metadata {
                    self.handle_udp_open(flow_id, metadata, datagram).await;
                } else {
                    self.handle_udp_data(flow_id, datagram).await;
                }
            }
        }
    }

    async fn handle_udp_open(
        self: &Arc<Self>,
        flow_id: u64,
        metadata: OpenMetadata,
        datagram: QueuedDatagram,
    ) {
        let existing = self.udp_flows.lock().await.get(&flow_id).map(|state| {
            (
                state.target == metadata.target && state.downlink == metadata.downlink,
                state.sender.clone(),
                state.acked.load(Ordering::Acquire),
            )
        });
        if let Some((valid, sender, acked)) = existing {
            if !valid {
                self.reject_udp_flow(flow_id).await;
                return;
            }
            self.enqueue_udp(&sender, datagram);
            if acked {
                let _ = self.send_udp_control(UDP_FRAME_OPEN_ACK, flow_id).await;
            }
            return;
        }
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        let Ok(flow_permit) = self.udp_flow_budget.clone().try_acquire_owned() else {
            self.warn_udp_drop("per-session UDP flow limit reached");
            return;
        };
        let flow_permit = Arc::new(flow_permit);
        let (sender, receiver) = tokio::sync::mpsc::channel(64);
        let acked = Arc::new(AtomicBool::new(false));
        self.udp_flows.lock().await.insert(
            flow_id,
            UdpState {
                target: metadata.target.clone(),
                downlink: metadata.downlink,
                sender: sender.clone(),
                acked: acked.clone(),
                _flow_permit: flow_permit.clone(),
            },
        );
        if !self.enqueue_udp(&sender, datagram) {
            self.udp_flows.lock().await.remove(&flow_id);
            return;
        }

        let weak_session = Arc::downgrade(self);
        let receiver = crate::portal::pairing::QuicUdpReceiver::new(receiver, move || {
            let Some(session) = weak_session.upgrade() else {
                return;
            };
            tokio::spawn(async move {
                session.udp_flows.lock().await.remove(&flow_id);
            });
        });
        let paired = if metadata.downlink == Carrier::Udp {
            let path = self.link_path();
            Some(crate::portal::pairing::PairedUdp {
                flow_id,
                target: metadata.target,
                uplink: crate::portal::pairing::UdpUp::Quic(receiver),
                downlink: crate::portal::pairing::UdpDown::Quic(self.conn.clone()),
                uplink_carrier: Carrier::Udp,
                downlink_carrier: Carrier::Udp,
                uplink_path: path.clone(),
                downlink_path: path,
                udp_ack: Some(crate::portal::pairing::UdpAck {
                    conn: self.conn.clone(),
                    acked,
                }),
                _flow_permit: Some(flow_permit),
            })
        } else {
            let header = FlowHeader {
                role: FlowRole::Open,
                flow_id,
                kind: FlowKind::Udp,
                uplink: Carrier::Udp,
                downlink: metadata.downlink,
            };
            match self
                .portal
                .pairing
                .submit_udp(
                    self.session_id,
                    header,
                    metadata.target,
                    crate::portal::pairing::LinkHalf::quic(
                        self.link_path(),
                        self.quic_generation(),
                    ),
                    crate::portal::pairing::UdpHalf::Uplink {
                        uplink: crate::portal::pairing::UdpUp::Quic(receiver),
                        udp_ack: Some(crate::portal::pairing::UdpAck {
                            conn: self.conn.clone(),
                            acked,
                        }),
                        flow_permit: Some(flow_permit),
                    },
                )
                .await
            {
                Ok(paired) => paired,
                Err(err) => {
                    self.portal.logger.error(format_args!(
                        "portal::conn::datagram_loop: failed to pair UDP flow: {err}"
                    ));
                    self.reject_udp_flow(flow_id).await;
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
            self.reject_udp_flow(flow_id).await;
        }
    }

    async fn close_udp_flow(&self, flow_id: u64) {
        self.udp_flows.lock().await.remove(&flow_id);
        self.portal
            .pairing
            .cancel_udp(self.session_id, flow_id)
            .await;
    }

    async fn reject_udp_flow(&self, flow_id: u64) {
        self.close_udp_flow(flow_id).await;
        let _ = self.send_udp_control(UDP_FRAME_CLOSE, flow_id).await;
    }

    async fn send_udp_control(&self, frame_type: u8, flow_id: u64) -> anyhow::Result<()> {
        let frame = encode_udp_control(frame_type, flow_id)?;
        self.conn.send_datagram_wait(Bytes::from(frame)).await?;
        Ok(())
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
