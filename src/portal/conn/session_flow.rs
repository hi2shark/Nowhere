// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! UDP flow state and response forwarding for QUIC sessions.

use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

use bytes::Bytes;
use tokio::sync::Mutex;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::common::{OutboundUdpSocket, UDP_FRAME_SCRATCH_SIZE, udp_idle_timeout};
use crate::protocol::append_frame_payload;

use super::PortalSession;

/// Key that scopes a UDP flow to both client flow ID and target address.
#[derive(Clone, Debug, Eq)]
pub(super) struct UdpFlowKey {
    flow_id: u64,
    target: String,
}

impl UdpFlowKey {
    /// Creates a UDP flow key.
    pub(super) fn new(flow_id: u64, target: impl Into<String>) -> Self {
        Self {
            flow_id,
            target: target.into(),
        }
    }
}

impl PartialEq for UdpFlowKey {
    fn eq(&self, other: &Self) -> bool {
        self.flow_id == other.flow_id && self.target == other.target
    }
}

impl Hash for UdpFlowKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.flow_id.hash(state);
        self.target.hash(state);
    }
}

/// Target UDP socket and response state for one proxied UDP flow.
pub(super) struct PortalUdpFlow {
    session: Weak<PortalSession>,
    key: UdpFlowKey,
    socket: Arc<OutboundUdpSocket>,
    response_header: Vec<u8>,
    closed: AtomicBool,
    last_used: Mutex<Instant>,
    cancel: CancellationToken,
}

impl PortalUdpFlow {
    /// Creates a UDP flow around a connected target socket.
    pub(super) fn new(
        session: Weak<PortalSession>,
        key: UdpFlowKey,
        socket: OutboundUdpSocket,
        response_header: Vec<u8>,
    ) -> Self {
        Self {
            session,
            key,
            socket: Arc::new(socket),
            response_header,
            closed: AtomicBool::new(false),
            last_used: Mutex::new(Instant::now()),
            cancel: CancellationToken::new(),
        }
    }

    /// Returns whether this flow has begun closing.
    pub(super) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Sends one client payload to the target UDP socket.
    pub(super) async fn send_to_target(&self, payload: &[u8]) -> anyhow::Result<usize> {
        self.socket.send(payload).await
    }

    /// Reads target responses and sends them back as QUIC DATAGRAM frames.
    pub(super) async fn read_loop(self: Arc<Self>) {
        let Some(session) = self.session.upgrade() else {
            return;
        };
        let mut buf = session.portal.buffers.get_udp_buffer();
        let mut frame_buf = Vec::with_capacity(UDP_FRAME_SCRATCH_SIZE);

        loop {
            let n = tokio::select! {
                _ = self.cancel.cancelled() => return,
                read = self.socket.recv(&mut buf) => match read {
                    Ok(n) => n,
                    Err(err) => {
                        if !self.closed.load(Ordering::Acquire) {
                            session.portal.logger.debug(format_args!("portal::conn::udp_read_loop: failed to read target socket: {err}"));
                        }
                        self.close().await;
                        return;
                    }
                }
            };
            if n == 0 {
                continue;
            }

            self.touch().await;
            session
                .portal
                .stats
                .udp_tx
                .fetch_add(n as u64, Ordering::Relaxed);
            frame_buf.clear();
            append_frame_payload(&mut frame_buf, &self.response_header, &buf[..n]);
            if let Some(limiter) = &session.portal.rate_limiter {
                limiter.wait_write(n as i64).await;
            }
            if let Err(err) = session
                .conn
                .send_datagram(Bytes::copy_from_slice(&frame_buf))
            {
                session.portal.logger.debug(format_args!(
                    "portal::conn::send_response: failed to send datagram: {err}"
                ));
            }
        }
    }

    /// Closes the flow after the configured UDP idle timeout.
    pub(super) async fn idle_loop(self: Arc<Self>) {
        loop {
            let deadline = {
                let last = *self.last_used.lock().await;
                last + udp_idle_timeout()
            };
            tokio::select! {
                _ = self.cancel.cancelled() => return,
                _ = tokio::time::sleep_until(deadline) => {}
            }
            let expired = {
                let last = *self.last_used.lock().await;
                Instant::now().duration_since(last) >= udp_idle_timeout()
            };
            if expired {
                self.close().await;
                return;
            }
        }
    }

    /// Updates the last-used timestamp for traffic in either direction.
    pub(super) async fn touch(&self) {
        *self.last_used.lock().await = Instant::now();
    }

    /// Closes the flow, removes it from the session map, and updates counters.
    pub(super) async fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.cancel.cancel();

        if let Some(session) = self.session.upgrade() {
            let mut guard = session.udp_flows.lock().await;
            if guard
                .get(&self.key)
                .is_some_and(|flow| std::ptr::eq(flow.as_ref(), self))
            {
                guard.remove(&self.key);
            }
            session.portal.stats.done_session(true);
        }
    }
}
