// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Authenticated QUIC connection handling and dispatch.

mod auth;
mod relay;
mod session;
mod tcp;

pub(in crate::portal) use self::session::DatagramReadyRequest;
pub(in crate::portal) use self::session::QueuedDatagram;

use std::sync::Arc;

use quinn::{Connection, Incoming, VarInt};
use tokio_util::sync::CancellationToken;

use self::auth::{
    AuthenticationOutcome, authenticate_connection, authentication_deadline,
    authentication_failure_close,
};
pub(super) use self::tcp::handle_tcp_incoming;
use super::PortalInner;
use super::admission::UnauthenticatedGuard;
use crate::common::{quic_max_streams, rate_limit_bytes_per_second};

pub(super) async fn handle_incoming(
    portal: Arc<PortalInner>,
    incoming: Incoming,
    admission: UnauthenticatedGuard,
    shutdown: CancellationToken,
) {
    let conn = match incoming.await {
        Ok(conn) => conn,
        Err(err) => {
            portal.logger.error(format_args!(
                "portal::conn::handle_incoming: failed to accept connection: {err}"
            ));
            return;
        }
    };
    handle_connection(portal, conn, admission, shutdown).await;
}

/// Runs authentication and then dispatches accepted streams/datagrams.
async fn handle_connection(
    portal: Arc<PortalInner>,
    conn: Connection,
    admission: UnauthenticatedGuard,
    shutdown: CancellationToken,
) {
    let auth_deadline = authentication_deadline();
    let authenticated =
        match authenticate_connection(portal.clone(), conn.clone(), auth_deadline, &shutdown).await
        {
            AuthenticationOutcome::Success(authenticated) => authenticated,
            AuthenticationOutcome::Failure(err) => {
                let (code, reason) = authentication_failure_close();
                conn.close(code, reason);
                drop(admission);
                portal.logger.error(format_args!(
                    "portal::conn::handle_connection: authentication failed: {err}"
                ));
                return;
            }
            AuthenticationOutcome::Shutdown => return,
        };
    // Once auth succeeds, expand the conservative pre-auth limits to the normal
    // data-plane limits and release the admission slot.
    conn.set_receive_window(VarInt::from_u32(super::listener::QUIC_RECEIVE_WINDOW));
    conn.set_max_concurrent_bi_streams(VarInt::from_u32(quic_max_streams()));
    drop(admission);
    let session = authenticated.session;
    let link_replaced = CancellationToken::new();
    let link_guard = portal
        .pairing
        .register_quic_link(
            session.session_id,
            portal.stats.clone(),
            link_replaced.clone(),
        )
        .await;
    session.set_quic_generation(link_guard.quic_generation());
    let _link_guard = link_guard;

    let etar_bps = rate_limit_bytes_per_second(portal.etar_limit);
    if etar_bps > 0 {
        portal.logger.debug(format_args!(
            "portal::conn::handle_connection: enabled TX rate limiter at {etar_bps} Bps"
        ));
    }

    let datagram_task = tokio::spawn(session.clone().datagram_loop(shutdown.clone()));
    let first_session = session.clone();
    let first_tasks = portal.flow_tasks.clone();
    first_tasks.spawn(async move {
        first_session
            .handle_first_stream(authenticated.first_send, authenticated.first_recv)
            .await;
    });

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = link_replaced.cancelled() => {
                portal.logger.debug(format_args!(
                    "portal::conn::handle_connection: authenticated QUIC carrier replaced"
                ));
                break;
            },
            stream = conn.accept_bi() => {
                match stream {
                    Ok((send, recv)) => {
                        let session = session.clone();
                        let tasks = portal.flow_tasks.clone();
                        tasks.spawn(async move {
                            session.handle_stream(send, recv).await;
                        });
                    }
                    Err(err) => {
                        if !shutdown.is_cancelled() {
                            portal.logger.debug(format_args!("portal::conn::handle_connection: bidirectional stream accept loop closed: {err}"));
                        }
                        break;
                    }
                }
            }
        }
    }

    session.close();
    datagram_task.abort();
    let _ = datagram_task.await;
    conn.close(VarInt::from_u32(0), b"");
}

#[cfg(test)]
#[path = "../tests/portal/conn.rs"]
mod tests;
