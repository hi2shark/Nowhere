// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! TCP target dialing and stream relay setup.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::common::rate_limit_bytes_per_second;
use crate::common::tcp_dial_timeout;
use crate::portal::PortalInner;
use crate::portal::pairing::PairedTcp;
use crate::protocol::Carrier;

use super::stream::relay_stream;
use super::{SessionGuard, paired_exchange_path, per_flow_limiter, symmetric_exchange_path};

/// Dials a TCP target and relays bytes between the client stream and target.
pub(in crate::portal::conn) async fn relay_tcp_target<R, W>(
    portal: Arc<PortalInner>,
    client_read: &mut R,
    client_write: &mut W,
    target_addr: String,
    peer: String,
    local: String,
    carrier: Carrier,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    portal.stats.add_session(false);
    let _done = SessionGuard::new(portal.clone(), false);

    portal.logger.debug(format_args!(
        "portal::conn::relay_tcp_target: accept_tcp carrier={} peer={} local={} target={}",
        carrier_name(carrier),
        peer,
        local,
        target_addr,
    ));
    portal.logger.debug(format_args!(
        "portal::conn::relay_tcp_target: target_dial_start target={}",
        target_addr,
    ));
    let target_conn = match portal
        .outbound
        .dial_tcp(&target_addr, tcp_dial_timeout())
        .await
    {
        Ok(conn) => conn,
        Err(err) => {
            portal.logger.error(format_args!(
                "portal::conn::relay_tcp_target: failed to dial target: {err}"
            ));
            return;
        }
    };
    let target_local = target_conn
        .local_addr()
        .map(|address| address.to_string())
        .unwrap_or_else(|_| "<unknown>".to_string());
    portal.logger.debug(format_args!(
        "portal::conn::relay_tcp_target: target_dial_ok target_local={}",
        target_local,
    ));
    portal.logger.info(format_args!(
        "portal::conn::relay_tcp_target: relay_start: {}",
        symmetric_exchange_path(carrier, &peer, &local, &target_local, &target_addr)
    ));
    portal.logger.debug(format_args!(
        "portal::conn::relay_tcp_target: relay_start limiter_per_flow={}",
        per_flow_limiter_summary(&portal),
    ));

    // Each relay session gets its own limiter bucket so concurrent flows do not
    // contend on a process-wide limiter (which capped aggregate throughput at
    // the single-flow ceiling during multi-thread speedtests).
    let limiter = per_flow_limiter(&portal);
    let result = relay_stream(
        portal.clone(),
        client_read,
        client_write,
        target_conn,
        portal.buffers.get_tcp_buffer(),
        portal.buffers.get_tcp_buffer(),
        Some((carrier, carrier)),
        limiter,
    )
    .await;
    match result {
        Ok(()) => portal.logger.info(format_args!(
            "portal::conn::relay_tcp_target: relay_end close_reason=EOF"
        )),
        Err(err) => portal.logger.info(format_args!(
            "portal::conn::relay_tcp_target: relay_end close_reason=error: {err}"
        )),
    }
}

/// Relays a TCP target through independently selected upload and download halves.
pub(in crate::portal) async fn relay_paired_tcp(portal: Arc<PortalInner>, paired: PairedTcp) {
    let PairedTcp {
        target: target_addr,
        uplink: mut client_read,
        downlink: mut client_write,
        uplink_carrier: uplink,
        downlink_carrier: downlink,
        uplink_path,
        downlink_path,
    } = paired;
    portal.stats.add_session(false);
    let _done = SessionGuard::new(portal.clone(), false);
    portal.logger.debug(format_args!(
        "portal::conn::relay_paired_tcp: accept_tcp uplink={} downlink={} uplink_peer={} downlink_peer={} target={}",
        carrier_name(uplink),
        carrier_name(downlink),
        uplink_path.peer,
        downlink_path.peer,
        target_addr,
    ));
    portal.logger.debug(format_args!(
        "portal::conn::relay_paired_tcp: target_dial_start target={}",
        target_addr,
    ));
    let target_conn = match portal
        .outbound
        .dial_tcp(&target_addr, tcp_dial_timeout())
        .await
    {
        Ok(conn) => conn,
        Err(err) => {
            portal.logger.error(format_args!(
                "portal::conn::relay_paired_tcp: failed to dial target {target_addr}: {err}"
            ));
            return;
        }
    };
    let target_local = target_conn
        .local_addr()
        .map(|address| address.to_string())
        .unwrap_or_else(|_| "<unknown>".to_string());
    portal.logger.debug(format_args!(
        "portal::conn::relay_paired_tcp: target_dial_ok target_local={}",
        target_local,
    ));
    portal.logger.info(format_args!(
        "portal::conn::relay_paired_tcp: relay_start: {}",
        paired_exchange_path(
            uplink,
            &uplink_path,
            &target_local,
            &target_addr,
            downlink,
            &downlink_path,
        )
    ));
    portal.logger.debug(format_args!(
        "portal::conn::relay_paired_tcp: relay_start limiter_per_flow={}",
        per_flow_limiter_summary(&portal),
    ));
    let limiter = per_flow_limiter(&portal);
    let result = relay_stream(
        portal.clone(),
        &mut client_read,
        &mut client_write,
        target_conn,
        portal.buffers.get_tcp_buffer(),
        portal.buffers.get_tcp_buffer(),
        Some((uplink, downlink)),
        limiter,
    )
    .await;
    match result {
        Ok(()) => portal.logger.info(format_args!(
            "portal::conn::relay_paired_tcp: relay_end close_reason=EOF"
        )),
        Err(err) => portal.logger.info(format_args!(
            "portal::conn::relay_paired_tcp: relay_end close_reason=error: {err}"
        )),
    }
}

fn carrier_name(carrier: Carrier) -> &'static str {
    match carrier {
        Carrier::Tcp => "TCP",
        Carrier::Udp => "UDP",
    }
}

/// Renders the per-flow limiter configuration for debug logging.
fn per_flow_limiter_summary(portal: &PortalInner) -> String {
    let r = rate_limit_bytes_per_second(portal.rate_limit);
    let w = rate_limit_bytes_per_second(portal.etar_limit);
    if r == 0 && w == 0 {
        "none(unlimited)".to_string()
    } else {
        format!("read={}B/s write={}B/s", r, w)
    }
}
