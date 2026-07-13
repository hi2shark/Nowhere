// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Bounded setup-only registry for pairing asymmetric TCP and QUIC flow halves.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Result, bail};
use tokio::sync::Mutex;

use crate::protocol::{FlowHeader, FlowRole, SessionId};

mod link;
mod state;

pub(super) use self::link::{guarded_reader, guarded_writer};
pub(super) use self::state::{
    BoxReader, BoxWriter, LinkHalf, LinkPath, PairedTcp, PairedUdp, QuicUdpReceiver, UdpAck,
    UdpDown, UdpHalf, UdpUp,
};
use self::state::{FlowKey, LinkCounts, Metadata, PendingTcp, PendingUdp};

const DEFAULT_MAX_PENDING_PAIRS: usize = 1024;
const DEFAULT_FLOW_PAIR_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) struct PairingRegistry {
    pub(super) tcp: Mutex<HashMap<FlowKey, PendingTcp>>,
    pub(super) udp: Mutex<HashMap<FlowKey, PendingUdp>>,
    pub(super) links: StdMutex<HashMap<SessionId, LinkCounts>>,
    pub(super) next_quic_generation: AtomicU64,
    next_pending_epoch: AtomicU64,
    pub(super) max_pending: usize,
    pub(super) timeout: Duration,
}

impl PairingRegistry {
    pub(super) fn new() -> Self {
        Self {
            tcp: Mutex::new(HashMap::new()),
            udp: Mutex::new(HashMap::new()),
            links: StdMutex::new(HashMap::new()),
            next_quic_generation: AtomicU64::new(1),
            next_pending_epoch: AtomicU64::new(1),
            max_pending: read_max_pending(),
            timeout: read_pair_timeout(),
        }
    }

    fn active_quic_generation(&self, session_id: SessionId) -> Option<u64> {
        self.links
            .lock()
            .expect("link registry poisoned")
            .get(&session_id)
            .and_then(|counts| counts.udp.as_ref().map(|active| active.generation))
    }

    pub(super) async fn submit_tcp(
        self: &Arc<Self>,
        session_id: SessionId,
        header: FlowHeader,
        target: String,
        link: LinkHalf,
        reader: Option<BoxReader>,
        writer: Option<BoxWriter>,
    ) -> Result<Option<PairedTcp>> {
        let LinkHalf {
            path,
            quic_generation,
        } = link;
        let key = FlowKey {
            session_id,
            flow_id: header.flow_id,
        };
        let metadata = Metadata {
            kind: header.kind,
            uplink: header.uplink,
            downlink: header.downlink,
            target,
        };
        let role_uses_quic = match header.role {
            FlowRole::Open => header.uplink == crate::protocol::Carrier::Udp,
            FlowRole::Attach => header.downlink == crate::protocol::Carrier::Udp,
        };
        if role_uses_quic != quic_generation.is_some()
            || quic_generation.is_some()
                && self.active_quic_generation(session_id) != quic_generation
        {
            bail!("portal::pairing: stale or missing QUIC generation");
        }
        let mut guard = self.tcp.lock().await;
        let udp_guard = self.udp.lock().await;
        if !guard.contains_key(&key)
            && guard
                .keys()
                .chain(udp_guard.keys())
                .filter(|pending| pending.session_id == session_id)
                .count()
                >= self.max_pending
        {
            bail!("portal::pairing: pending flow pair limit reached");
        }
        drop(udp_guard);
        let links = self.links.lock().expect("link registry poisoned");
        let active_generation = links
            .get(&session_id)
            .and_then(|counts| counts.udp.as_ref().map(|active| active.generation));
        if quic_generation.is_some() && quic_generation != active_generation {
            bail!("portal::pairing: stale QUIC generation");
        }
        let pending = guard.entry(key).or_insert_with(|| PendingTcp {
            epoch: 0,
            metadata: Metadata {
                kind: metadata.kind,
                uplink: metadata.uplink,
                downlink: metadata.downlink,
                target: metadata.target.clone(),
            },
            uplink: None,
            downlink: None,
            uplink_path: None,
            downlink_path: None,
            uplink_generation: None,
            downlink_generation: None,
        });
        if pending.metadata != metadata {
            bail!("portal::pairing: conflicting flow metadata");
        }
        if pending.metadata.uplink == crate::protocol::Carrier::Udp
            && pending.uplink_generation != active_generation
        {
            pending.uplink = None;
            pending.uplink_path = None;
            pending.uplink_generation = None;
        }
        if pending.metadata.downlink == crate::protocol::Carrier::Udp
            && pending.downlink_generation != active_generation
        {
            pending.downlink = None;
            pending.downlink_path = None;
            pending.downlink_generation = None;
        }
        match header.role {
            FlowRole::Open => {
                if pending.uplink.is_some() || reader.is_none() {
                    bail!("portal::pairing: duplicate or missing uplink half");
                }
                pending.uplink = reader;
                pending.uplink_path = Some(path);
                pending.uplink_generation = quic_generation;
            }
            FlowRole::Attach => {
                if pending.downlink.is_some() || writer.is_none() {
                    bail!("portal::pairing: duplicate or missing downlink half");
                }
                pending.downlink = writer;
                pending.downlink_path = Some(path);
                pending.downlink_generation = quic_generation;
            }
        }
        let pending_epoch = self.next_pending_epoch.fetch_add(1, Ordering::Relaxed);
        pending.epoch = pending_epoch;
        if pending.uplink.is_some() && pending.downlink.is_some() {
            let mut complete = guard.remove(&key).expect("pair exists");
            drop(links);
            return Ok(Some(PairedTcp {
                target: complete.metadata.target,
                uplink: complete.uplink.take().expect("uplink paired"),
                downlink: complete.downlink.take().expect("downlink paired"),
                uplink_carrier: complete.metadata.uplink,
                downlink_carrier: complete.metadata.downlink,
                uplink_path: complete.uplink_path.take().expect("uplink path paired"),
                downlink_path: complete.downlink_path.take().expect("downlink path paired"),
            }));
        }
        drop(links);
        drop(guard);
        let registry = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(registry.timeout).await;
            let mut pending = registry.tcp.lock().await;
            if pending
                .get(&key)
                .is_some_and(|flow| flow.epoch == pending_epoch)
            {
                pending.remove(&key);
            }
        });
        Ok(None)
    }

    pub(super) async fn submit_udp(
        self: &Arc<Self>,
        session_id: SessionId,
        header: FlowHeader,
        target: String,
        link: LinkHalf,
        half: UdpHalf,
    ) -> Result<Option<PairedUdp>> {
        let LinkHalf {
            path,
            quic_generation,
        } = link;
        let key = FlowKey {
            session_id,
            flow_id: header.flow_id,
        };
        let metadata = Metadata {
            kind: header.kind,
            uplink: header.uplink,
            downlink: header.downlink,
            target,
        };
        let role_uses_quic = match header.role {
            FlowRole::Open => header.uplink == crate::protocol::Carrier::Udp,
            FlowRole::Attach => header.downlink == crate::protocol::Carrier::Udp,
        };
        if role_uses_quic != quic_generation.is_some()
            || quic_generation.is_some()
                && self.active_quic_generation(session_id) != quic_generation
        {
            bail!("portal::pairing: stale or missing QUIC generation");
        }
        let tcp_guard = self.tcp.lock().await;
        let mut guard = self.udp.lock().await;
        if !guard.contains_key(&key)
            && guard
                .keys()
                .chain(tcp_guard.keys())
                .filter(|pending| pending.session_id == session_id)
                .count()
                >= self.max_pending
        {
            bail!("portal::pairing: pending UDP flow pair limit reached");
        }
        drop(tcp_guard);
        let links = self.links.lock().expect("link registry poisoned");
        let active_generation = links
            .get(&session_id)
            .and_then(|counts| counts.udp.as_ref().map(|active| active.generation));
        if quic_generation.is_some() && quic_generation != active_generation {
            bail!("portal::pairing: stale QUIC generation");
        }
        let pending = guard.entry(key).or_insert_with(|| PendingUdp {
            epoch: 0,
            metadata: Metadata {
                kind: metadata.kind,
                uplink: metadata.uplink,
                downlink: metadata.downlink,
                target: metadata.target.clone(),
            },
            uplink: None,
            downlink: None,
            udp_ack: None,
            flow_permit: None,
            uplink_path: None,
            downlink_path: None,
            uplink_generation: None,
            downlink_generation: None,
        });
        if pending.metadata != metadata {
            bail!("portal::pairing: conflicting UDP flow metadata");
        }
        if pending.metadata.uplink == crate::protocol::Carrier::Udp
            && pending.uplink_generation != active_generation
        {
            pending.uplink = None;
            pending.uplink_path = None;
            pending.uplink_generation = None;
            pending.udp_ack = None;
            pending.flow_permit = None;
        }
        if pending.metadata.downlink == crate::protocol::Carrier::Udp
            && pending.downlink_generation != active_generation
        {
            pending.downlink = None;
            pending.downlink_path = None;
            pending.downlink_generation = None;
        }
        match header.role {
            FlowRole::Open => {
                let UdpHalf::Uplink {
                    uplink,
                    udp_ack,
                    flow_permit,
                } = half
                else {
                    bail!("portal::pairing: missing UDP uplink half");
                };
                if pending.uplink.is_some() {
                    bail!("portal::pairing: duplicate or missing UDP uplink half");
                }
                if (metadata.uplink == crate::protocol::Carrier::Udp) != flow_permit.is_some() {
                    bail!("portal::pairing: invalid UDP flow permit ownership");
                }
                pending.uplink = Some(uplink);
                pending.udp_ack = udp_ack;
                pending.flow_permit = flow_permit;
                pending.uplink_path = Some(path);
                pending.uplink_generation = quic_generation;
            }
            FlowRole::Attach => {
                let UdpHalf::Downlink(downlink) = half else {
                    bail!("portal::pairing: missing UDP downlink half");
                };
                if pending.downlink.is_some() {
                    bail!("portal::pairing: duplicate or missing UDP downlink half");
                }
                pending.downlink = Some(downlink);
                pending.downlink_path = Some(path);
                pending.downlink_generation = quic_generation;
            }
        }
        let pending_epoch = self.next_pending_epoch.fetch_add(1, Ordering::Relaxed);
        pending.epoch = pending_epoch;
        if pending.uplink.is_some() && pending.downlink.is_some() {
            let mut complete = guard.remove(&key).expect("UDP pair exists");
            let flow_permit = if complete.metadata.uplink == crate::protocol::Carrier::Tcp
                && complete.metadata.downlink == crate::protocol::Carrier::Udp
            {
                let budget = links
                    .get(&session_id)
                    .and_then(|counts| counts.udp.as_ref())
                    .ok_or_else(|| anyhow::anyhow!("portal::pairing: missing active QUIC link"))?
                    .udp_flow_budget
                    .clone();
                Some(Arc::new(budget.try_acquire_owned().map_err(|_| {
                    anyhow::anyhow!("portal::pairing: UDP flow limit reached")
                })?))
            } else {
                Some(
                    complete.flow_permit.take().ok_or_else(|| {
                        anyhow::anyhow!("portal::pairing: missing UDP flow permit")
                    })?,
                )
            };
            drop(links);
            return Ok(Some(PairedUdp {
                flow_id: header.flow_id,
                target: complete.metadata.target,
                uplink: complete.uplink.take().expect("UDP uplink paired"),
                downlink: complete.downlink.take().expect("UDP downlink paired"),
                uplink_carrier: complete.metadata.uplink,
                downlink_carrier: complete.metadata.downlink,
                uplink_path: complete.uplink_path.take().expect("UDP uplink path paired"),
                downlink_path: complete
                    .downlink_path
                    .take()
                    .expect("UDP downlink path paired"),
                udp_ack: complete.udp_ack.take(),
                _flow_permit: flow_permit,
            }));
        }
        drop(links);
        drop(guard);
        let registry = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(registry.timeout).await;
            let mut pending = registry.udp.lock().await;
            if pending
                .get(&key)
                .is_some_and(|flow| flow.epoch == pending_epoch)
            {
                pending.remove(&key);
            }
        });
        Ok(None)
    }

    pub(super) async fn cancel_udp(&self, session_id: SessionId, flow_id: u64) {
        self.udp.lock().await.remove(&FlowKey {
            session_id,
            flow_id,
        });
    }
}

fn read_max_pending() -> usize {
    std::env::var("NOW_MAX_PENDING_PAIRS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_MAX_PENDING_PAIRS)
}

fn read_pair_timeout() -> Duration {
    std::env::var("NOW_FLOW_PAIR_TIMEOUT")
        .ok()
        .and_then(|value| humantime::parse_duration(&value).ok())
        .filter(|value| !value.is_zero())
        .unwrap_or(DEFAULT_FLOW_PAIR_TIMEOUT)
}

#[cfg(test)]
#[path = "../tests/portal/pairing.rs"]
mod tests;
