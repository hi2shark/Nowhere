// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Atomic portal traffic and session counters.

use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

/// Atomic counters used by telemetry and relay accounting.
#[derive(Debug, Default)]
pub struct Stats {
    /// Bytes read from TCP clients and sent to targets.
    pub tcp_rx: AtomicU64,
    /// Bytes read from TCP targets and sent to clients.
    pub tcp_tx: AtomicU64,
    /// Bytes read from UDP clients and sent to targets.
    pub udp_rx: AtomicU64,
    /// Bytes read from UDP targets and sent to clients.
    pub udp_tx: AtomicU64,
    /// Currently active TCP relay sessions.
    pub tcp_active: AtomicI32,
    /// Currently active UDP relay sessions.
    pub udp_active: AtomicI32,
    /// Authenticated TLS/TCP carrier lanes.
    pub link_tcp: AtomicU64,
    /// Authenticated QUIC/UDP carrier sessions.
    pub link_udp: AtomicU64,
    /// Logical sessions with both carrier types ready.
    pub link_pairs: AtomicU64,
    /// Client-to-target payload bytes carried over TLS/TCP.
    pub up_tcp: AtomicU64,
    /// Client-to-target payload bytes carried over QUIC/UDP.
    pub up_udp: AtomicU64,
    /// Target-to-client payload bytes carried over TLS/TCP.
    pub down_tcp: AtomicU64,
    /// Target-to-client payload bytes carried over QUIC/UDP.
    pub down_udp: AtomicU64,
}

impl Stats {
    /// Increments the active session counter for the selected transport.
    pub fn add_session(&self, is_udp: bool) {
        if is_udp {
            self.udp_active.fetch_add(1, Ordering::Relaxed);
        } else {
            self.tcp_active.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Decrements the active session counter for the selected transport.
    pub fn done_session(&self, is_udp: bool) {
        if is_udp {
            self.udp_active.fetch_sub(1, Ordering::Relaxed);
        } else {
            self.tcp_active.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
#[path = "../tests/transport/stats.rs"]
mod tests;
