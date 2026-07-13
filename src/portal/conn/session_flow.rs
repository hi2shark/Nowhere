// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Bounded per-session UDP packet reassembly and relay queue values.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

use crate::protocol::UdpFragment;

const UDP_REASSEMBLY_SLOTS: usize = 64;
const UDP_REASSEMBLY_TTL: Duration = Duration::from_secs(10);

/// One complete UDP packet plus its retained-byte budget.
pub(in crate::portal) struct QueuedDatagram {
    pub(in crate::portal) payload: Bytes,
    _budget: OwnedSemaphorePermit,
}

impl QueuedDatagram {
    pub(in crate::portal) fn new(payload: Bytes, budget: OwnedSemaphorePermit) -> Self {
        Self {
            payload,
            _budget: budget,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ReassemblyKey {
    flow_id: u64,
    packet_id: u32,
}

struct ReassemblySlot {
    created_at: Instant,
    fragment_count: u8,
    total_len: u16,
    fragments: Vec<Option<Bytes>>,
    received: usize,
    retained_bytes: usize,
    budget: OwnedSemaphorePermit,
}

pub(super) enum ReassemblyOutcome {
    Pending {
        evicted_partial: bool,
    },
    Complete {
        datagram: QueuedDatagram,
        evicted_partial: bool,
    },
    Dropped(&'static str),
}

#[derive(Default)]
pub(super) struct UdpReassembler {
    slots: HashMap<ReassemblyKey, ReassemblySlot>,
}

impl UdpReassembler {
    pub(super) fn expire(&mut self, now: Instant) -> bool {
        self.evict_expired(now)
    }

    pub(super) fn remove_flow(&mut self, flow_id: u64) {
        self.slots.retain(|key, _| key.flow_id != flow_id);
    }

    pub(super) fn push(
        &mut self,
        flow_id: u64,
        fragment: UdpFragment<'_>,
        payload: Bytes,
        budget: Arc<Semaphore>,
    ) -> ReassemblyOutcome {
        let key = ReassemblyKey {
            flow_id,
            packet_id: fragment.packet_id,
        };
        if fragment.fragment_count == 1 {
            let Some(permit) = reserve_packet_budget(budget, fragment.total_len) else {
                return ReassemblyOutcome::Dropped("connection queue byte limit reached");
            };
            return ReassemblyOutcome::Complete {
                datagram: QueuedDatagram::new(payload, permit),
                evicted_partial: false,
            };
        }

        let now = Instant::now();
        let mut evicted_partial = self.evict_expired(now);
        if let Some(slot) = self.slots.get(&key)
            && (slot.fragment_count != fragment.fragment_count
                || slot.total_len != fragment.total_len)
        {
            return ReassemblyOutcome::Dropped("conflicting UDP fragment metadata");
        }
        if !self.slots.contains_key(&key) {
            if self.slots.len() >= UDP_REASSEMBLY_SLOTS
                && let Some(oldest) = self
                    .slots
                    .iter()
                    .min_by_key(|(_, slot)| slot.created_at)
                    .map(|(key, _)| *key)
            {
                self.slots.remove(&oldest);
                evicted_partial = true;
            }
            let Some(permit) = reserve_packet_budget(budget, fragment.total_len) else {
                return ReassemblyOutcome::Dropped("connection queue byte limit reached");
            };
            self.slots.insert(
                key,
                ReassemblySlot {
                    created_at: now,
                    fragment_count: fragment.fragment_count,
                    total_len: fragment.total_len,
                    fragments: vec![None; fragment.fragment_count as usize],
                    received: 0,
                    retained_bytes: 0,
                    budget: permit,
                },
            );
        }

        let slot = self.slots.get_mut(&key).expect("reassembly slot inserted");
        let index = fragment.fragment_id as usize;
        if let Some(existing) = &slot.fragments[index] {
            if existing != &payload {
                self.slots.remove(&key);
                return ReassemblyOutcome::Dropped("conflicting duplicate UDP fragment");
            }
        } else {
            let retained_bytes = slot.retained_bytes.saturating_add(payload.len());
            if retained_bytes > slot.total_len as usize {
                self.slots.remove(&key);
                return ReassemblyOutcome::Dropped("UDP fragments exceed total length");
            }
            slot.fragments[index] = Some(payload);
            slot.received += 1;
            slot.retained_bytes = retained_bytes;
        }
        if slot.received < slot.fragment_count as usize {
            return ReassemblyOutcome::Pending { evicted_partial };
        }

        let slot = self.slots.remove(&key).expect("complete reassembly slot");
        let mut payload = BytesMut::with_capacity(slot.total_len as usize);
        for fragment in slot.fragments {
            let Some(fragment) = fragment else {
                return ReassemblyOutcome::Dropped("missing UDP fragment");
            };
            payload.extend_from_slice(&fragment);
        }
        if payload.len() != slot.total_len as usize {
            return ReassemblyOutcome::Dropped("reassembled UDP length mismatch");
        }
        ReassemblyOutcome::Complete {
            datagram: QueuedDatagram::new(payload.freeze(), slot.budget),
            evicted_partial,
        }
    }

    fn evict_expired(&mut self, now: Instant) -> bool {
        let before = self.slots.len();
        self.slots
            .retain(|_, slot| now.duration_since(slot.created_at) <= UDP_REASSEMBLY_TTL);
        self.slots.len() != before
    }
}

fn reserve_packet_budget(budget: Arc<Semaphore>, packet_len: u16) -> Option<OwnedSemaphorePermit> {
    budget
        .try_acquire_many_owned(u32::from(packet_len).max(1))
        .ok()
}

#[cfg(test)]
#[path = "../../tests/portal/conn/session_flow.rs"]
mod tests;
