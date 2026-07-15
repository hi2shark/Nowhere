// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Portal-compatible Vector telemetry.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio_util::sync::CancellationToken;

use crate::common::report_interval;

use super::VectorInner;

pub(super) async fn event_loop(vector: Arc<VectorInner>, shutdown: CancellationToken) {
    loop {
        let tcp_links = vector.stats.link_tcp.load(Ordering::Relaxed);
        let udp_links = vector.stats.link_udp.load(Ordering::Relaxed);
        vector.stats.link_pairs.store(
            u64::from(tcp_links != 0 && udp_links != 0),
            Ordering::Relaxed,
        );
        vector.logger.event(format_args!(
            "CHECK_POINT|MODE={}|PING=0ms|POOL={}|TCPS={}|UDPS={}|TCPRX={}|TCPTX={}|UDPRX={}|UDPTX={}",
            vector.config.checkpoint_mode(),
            vector.tls_pool.idle_count().await,
            vector.stats.tcp_active.load(Ordering::Relaxed),
            vector.stats.udp_active.load(Ordering::Relaxed),
            vector.stats.tcp_rx.load(Ordering::Relaxed),
            vector.stats.tcp_tx.load(Ordering::Relaxed),
            vector.stats.udp_rx.load(Ordering::Relaxed),
            vector.stats.udp_tx.load(Ordering::Relaxed),
        ));
        vector.logger.debug(format_args!(
            "LINK_STATUS|TCP={}|UDP={}|PAIRS={}|UPTCP={}|UPUDP={}|DOWNTCP={}|DOWNUDP={}",
            tcp_links,
            udp_links,
            vector.stats.link_pairs.load(Ordering::Relaxed),
            vector.stats.up_tcp.load(Ordering::Relaxed),
            vector.stats.up_udp.load(Ordering::Relaxed),
            vector.stats.down_tcp.load(Ordering::Relaxed),
            vector.stats.down_udp.load(Ordering::Relaxed),
        ));
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tokio::time::sleep(report_interval()) => {}
        }
    }
}
