// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! TCP target dialing and stream relay setup.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::common::tcp_dial_timeout;
use crate::portal::PortalInner;
use crate::portal::pairing::PairedTcp;
use crate::protocol::Carrier;

use super::stream::relay_stream;
use super::{
    SessionGuard, TCP_EXCHANGE_COMPLETE, TCP_EXCHANGE_STARTING, paired_exchange_path,
    symmetric_exchange_path,
};

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
        "portal::conn::relay_tcp_target: {}: {}",
        TCP_EXCHANGE_STARTING,
        symmetric_exchange_path(carrier, &peer, &local, &target_local, &target_addr)
    ));

    let result = relay_stream(
        portal.clone(),
        client_read,
        client_write,
        target_conn,
        portal.buffers.get_tcp_buffer(),
        portal.buffers.get_tcp_buffer(),
        Some((carrier, carrier)),
    )
    .await;
    match result {
        Ok(()) => portal.logger.debug(format_args!(
            "portal::conn::relay_tcp_target: {}: relay_stream: EOF",
            TCP_EXCHANGE_COMPLETE
        )),
        Err(err) => portal.logger.debug(format_args!(
            "portal::conn::relay_tcp_target: {}: relay_stream: {err}",
            TCP_EXCHANGE_COMPLETE
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
        "portal::conn::relay_paired_tcp: {}: {}",
        TCP_EXCHANGE_STARTING,
        paired_exchange_path(
            uplink,
            &uplink_path,
            &target_local,
            &target_addr,
            downlink,
            &downlink_path,
        )
    ));
    let result = relay_stream(
        portal.clone(),
        &mut client_read,
        &mut client_write,
        target_conn,
        portal.buffers.get_tcp_buffer(),
        portal.buffers.get_tcp_buffer(),
        Some((uplink, downlink)),
    )
    .await;
    match result {
        Ok(()) => portal.logger.debug(format_args!(
            "portal::conn::relay_paired_tcp: {}: relay_stream: EOF",
            TCP_EXCHANGE_COMPLETE
        )),
        Err(err) => portal.logger.debug(format_args!(
            "portal::conn::relay_paired_tcp: {}: {err}",
            TCP_EXCHANGE_COMPLETE
        )),
    }
}
