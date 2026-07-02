// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Periodic event telemetry emitted by a running portal.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio_util::sync::CancellationToken;

use crate::common::report_interval;

use super::PortalInner;

pub(super) async fn event_loop(portal: Arc<PortalInner>, shutdown: CancellationToken) {
    loop {
        portal.logger.event(format_args!(
            "CHECK_POINT|MODE={}|PING=0ms|POOL={}|TCPS={}|UDPS={}|TCPRX={}|TCPTX={}|UDPRX={}|UDPTX={}",
            portal.network_mode.checkpoint_value(),
            portal.pool_active.load(Ordering::Relaxed),
            portal.stats.tcp_active.load(Ordering::Relaxed),
            portal.stats.udp_active.load(Ordering::Relaxed),
            portal.stats.tcp_rx.load(Ordering::Relaxed),
            portal.stats.tcp_tx.load(Ordering::Relaxed),
            portal.stats.udp_rx.load(Ordering::Relaxed),
            portal.stats.udp_tx.load(Ordering::Relaxed),
        ));

        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tokio::time::sleep(report_interval()) => {}
        }
    }
}
