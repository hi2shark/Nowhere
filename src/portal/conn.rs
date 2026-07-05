// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Authenticated QUIC connection handling and dispatch.

mod auth;
mod relay;
mod session;
mod tcp;

use std::sync::Arc;

use quinn::{Connection, Incoming, VarInt};
use tokio_util::sync::CancellationToken;

use crate::common::{quic_max_streams, rate_limit_bytes_per_second};
use crate::protocol::Carrier;

use self::auth::{
    AuthenticationOutcome, authenticate_connection, authentication_deadline,
    authentication_failure_close,
};
#[cfg(test)]
use self::auth::{
    PRE_AUTH_DATAGRAM_BUFFER_SIZE, jittered_auth_timeout, retain_pre_auth_datagram,
    scaled_auth_timeout,
};
pub(super) use self::tcp::handle_tcp_incoming;
#[cfg(test)]
use self::tcp::handle_tcp_incoming_with_pool_ttl;
use super::PortalInner;
use super::admission::UnauthenticatedGuard;
#[cfg(test)]
use super::admission::{
    MAX_UNAUTHENTICATED_CONNECTIONS, MAX_UNAUTHENTICATED_PER_SOURCE, UnauthenticatedAdmission,
};

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
    let _link_guard =
        match portal
            .pairing
            .register_link(session.session_id, Carrier::Udp, portal.stats.clone())
        {
            Ok(guard) => guard,
            Err(err) => {
                conn.close(VarInt::from_u32(1), b"duplicate session");
                portal.logger.error(format_args!(
                    "portal::conn::handle_connection: failed to register link: {err}"
                ));
                return;
            }
        };

    let etar_bps = rate_limit_bytes_per_second(portal.etar_limit);
    if etar_bps > 0 {
        portal.logger.debug(format_args!(
            "portal::conn::handle_connection: enabled TX rate limiter at {etar_bps} Bps"
        ));
    }

    let datagram_task = tokio::spawn(
        session
            .clone()
            .datagram_loop(authenticated.pending_datagrams, shutdown.clone()),
    );

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            stream = conn.accept_bi() => {
                match stream {
                    Ok((send, recv)) => {
                        let session = session.clone();
                        tokio::spawn(async move {
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

    session.close().await;
    datagram_task.abort();
    conn.close(VarInt::from_u32(0), b"");
}

#[cfg(test)]
#[path = "../tests/portal/conn.rs"]
mod tests;
