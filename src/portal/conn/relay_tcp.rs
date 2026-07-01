// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! TCP target dialing and stream relay setup.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::common::tcp_dial_timeout;
use crate::portal::PortalInner;

use super::SessionGuard;
use super::stream::relay_stream;

/// Dials a TCP target and relays bytes between the client stream and target.
pub(in crate::portal::conn) async fn relay_tcp_target<R, W>(
    portal: Arc<PortalInner>,
    client_read: &mut R,
    client_write: &mut W,
    target_addr: String,
    peer: String,
    local: String,
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
    portal.logger.info(format_args!(
        "portal::conn::relay_tcp_target: exchange starting: {peer} <-> {local} <-> {target_local} <-> {target_addr}"
    ));

    let result = relay_stream(
        portal.clone(),
        client_read,
        client_write,
        target_conn,
        portal.buffers.get_tcp_buffer(),
        portal.buffers.get_tcp_buffer(),
    )
    .await;
    match result {
        Ok(()) => portal.logger.info(format_args!(
            "portal::conn::relay_tcp_target: exchange complete: relay_stream: EOF"
        )),
        Err(err) => portal.logger.info(format_args!(
            "portal::conn::relay_tcp_target: exchange complete: relay_stream: {err}"
        )),
    }
}
