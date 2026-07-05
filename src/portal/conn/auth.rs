// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! QUIC authentication flow and pre-auth datagram buffering.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use quinn::{Connection, VarInt};
use tokio::time::{Instant, sleep_until};
use tokio_util::sync::CancellationToken;

use crate::common::handshake_timeout;
use crate::protocol::read_auth_stream;

use super::session::PortalSession;
use crate::portal::PortalInner;

/// Maximum bytes retained from QUIC DATAGRAMs that arrive before auth succeeds.
pub(super) const PRE_AUTH_DATAGRAM_BUFFER_SIZE: usize = 64 * 1024;
const AUTH_TIMEOUT_MIN_BASIS_POINTS: u64 = 8_000;
const AUTH_TIMEOUT_BASIS_POINT_RANGE: u64 = 4_001;

/// QUIC close code and reason used for authentication failures.
pub(super) fn authentication_failure_close() -> (VarInt, &'static [u8]) {
    (VarInt::from_u32(1), b"access denied")
}

/// Authenticated session plus DATAGRAM frames received before auth completed.
pub(super) struct AuthenticatedConnection {
    pub(super) session: Arc<PortalSession>,
    pub(super) pending_datagrams: VecDeque<Bytes>,
}

/// Result of the QUIC authentication phase.
pub(super) enum AuthenticationOutcome {
    Success(AuthenticatedConnection),
    Failure(anyhow::Error),
    Shutdown,
}

/// Authenticates the first bidirectional stream while buffering early DATAGRAMs.
pub(super) async fn authenticate_connection(
    portal: Arc<PortalInner>,
    conn: Connection,
    deadline: Instant,
    shutdown: &CancellationToken,
) -> AuthenticationOutcome {
    let auth = async {
        let (_send, mut recv) = conn.accept_bi().await.map_err(|err| {
            anyhow::anyhow!(
                "portal::conn::authenticate_connection: failed to accept auth stream: {err}"
            )
        })?;
        read_auth_stream(
            &mut recv,
            portal.credentials.key,
            &portal.credentials.protocol_spec,
        )
        .await
        .map_err(|err| {
            anyhow::anyhow!("portal::conn::authenticate_connection: failed to read auth: {err}")
        })
    };
    tokio::pin!(auth);

    let mut auth_pending = true;
    let mut datagrams_open = true;
    let mut auth_error = None;
    let mut pending_datagrams = VecDeque::new();
    let mut pending_bytes = 0usize;

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return AuthenticationOutcome::Shutdown,
            _ = sleep_until(deadline) => {
                return AuthenticationOutcome::Failure(auth_error.unwrap_or_else(|| {
                    anyhow::anyhow!(
                        "portal::conn::authenticate_connection: authentication deadline elapsed"
                    )
                }));
            }
            result = &mut auth, if auth_pending => {
                auth_pending = false;
                match result {
                    Ok(session_id) => {
                        return AuthenticationOutcome::Success(AuthenticatedConnection {
                            session: Arc::new(PortalSession::new(
                                portal.clone(),
                                conn.clone(),
                                session_id,
                            )),
                            pending_datagrams,
                        });
                    }
                    Err(err) => auth_error = Some(err),
                }
            }
            datagram = conn.read_datagram(), if datagrams_open => match datagram {
                Ok(datagram) => {
                    if auth_error.is_none() {
                        // DATAGRAM frames are unordered relative to streams; hold
                        // early UDP packets until the auth stream succeeds.
                        retain_pre_auth_datagram(
                            &mut pending_datagrams,
                            &mut pending_bytes,
                            datagram,
                        );
                    }
                }
                Err(err) => {
                    datagrams_open = false;
                    if auth_error.is_none() {
                        auth_error = Some(anyhow::anyhow!(
                            "portal::conn::authenticate_connection: failed to receive pre-auth datagram: {err}"
                        ));
                        auth_pending = false;
                    }
                }
            },
        }
    }
}

/// Appends a pre-auth datagram when it fits within the retention budget.
pub(super) fn retain_pre_auth_datagram(
    pending: &mut VecDeque<Bytes>,
    pending_bytes: &mut usize,
    datagram: Bytes,
) -> bool {
    if pending_bytes.saturating_add(datagram.len()) > PRE_AUTH_DATAGRAM_BUFFER_SIZE {
        return false;
    }
    *pending_bytes += datagram.len();
    pending.push_back(datagram);
    true
}

/// Returns the absolute authentication deadline with jitter applied.
pub(super) fn authentication_deadline() -> Instant {
    Instant::now() + jittered_auth_timeout(handshake_timeout())
}

/// Applies randomized jitter to the configured authentication timeout.
pub(super) fn jittered_auth_timeout(base: Duration) -> Duration {
    let mut random = [0u8; 8];
    if getrandom::fill(&mut random).is_err() {
        return base;
    }
    scaled_auth_timeout(base, u64::from_le_bytes(random))
}

/// Scales `base` into the 80%-120% timeout window using `sample`.
pub(super) fn scaled_auth_timeout(base: Duration, sample: u64) -> Duration {
    let basis_points = AUTH_TIMEOUT_MIN_BASIS_POINTS + sample % AUTH_TIMEOUT_BASIS_POINT_RANGE;
    Duration::try_from_secs_f64(base.as_secs_f64() * basis_points as f64 / 10_000.0).unwrap_or(base)
}

/// Waits for the same auth deadline after a failed auth read.
pub(super) async fn wait_for_auth_deadline(
    deadline: Instant,
    shutdown: &CancellationToken,
) -> bool {
    tokio::select! {
        _ = sleep_until(deadline) => true,
        _ = shutdown.cancelled() => false,
    }
}
