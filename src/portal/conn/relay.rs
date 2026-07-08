// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Shared relay session accounting and relay dispatch exports.

#[path = "relay_stream.rs"]
mod stream;
#[path = "relay_tcp.rs"]
mod tcp;
#[path = "relay_uot.rs"]
mod uot;

use std::sync::Arc;

use crate::portal::PortalInner;
use crate::portal::pairing::LinkPath;
use crate::protocol::Carrier;

pub(in crate::portal) use self::tcp::relay_paired_tcp;
pub(super) use self::tcp::relay_tcp_target;
pub(in crate::portal) use self::uot::relay_paired_udp;
pub(super) use self::uot::relay_udp_over_tcp_target;

pub(in crate::portal::conn) const TCP_EXCHANGE_STARTING: &str = "exchange starting";
pub(in crate::portal::conn) const TCP_EXCHANGE_COMPLETE: &str = "exchange complete";
pub(in crate::portal::conn) const UDP_TRANSFER_STARTING: &str = "transfer starting";
pub(in crate::portal::conn) const UDP_TRANSFER_COMPLETE: &str = "transfer complete";

fn paired_exchange_path(
    uplink: Carrier,
    uplink_path: &LinkPath,
    target_local: &str,
    target: &str,
    downlink: Carrier,
    downlink_path: &LinkPath,
) -> String {
    format!(
        "UP[{}] {} -> {} -> {} -> {} | DOWN[{}] {} -> {} -> {} -> {}",
        carrier_name(uplink),
        uplink_path.peer,
        uplink_path.local,
        target_local,
        target,
        carrier_name(downlink),
        target,
        target_local,
        downlink_path.local,
        downlink_path.peer,
    )
}

pub(in crate::portal::conn) fn symmetric_exchange_path(
    carrier: Carrier,
    peer: &str,
    local: &str,
    target_local: &str,
    target: &str,
) -> String {
    format!(
        "UP[{}] {peer} -> {local} -> {target_local} -> {target} | DOWN[{}] {target} -> {target_local} -> {local} -> {peer}",
        carrier_name(carrier),
        carrier_name(carrier),
    )
}

fn carrier_name(carrier: Carrier) -> &'static str {
    match carrier {
        Carrier::Tcp => "TCP",
        Carrier::Udp => "UDP",
    }
}

/// RAII guard that keeps active TCP/UDP session counters balanced.
struct SessionGuard {
    portal: Arc<PortalInner>,
    is_udp: bool,
}

impl SessionGuard {
    fn new(portal: Arc<PortalInner>, is_udp: bool) -> Self {
        Self { portal, is_udp }
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.portal.stats.done_session(self.is_udp);
    }
}

#[cfg(test)]
#[path = "../../tests/portal/conn/relay.rs"]
mod tests;
