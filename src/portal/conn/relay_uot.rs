// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! UDP-over-TCP relay loop for UoT clients.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::time::{Instant, timeout};

use crate::common::{handshake_timeout, udp_dial_timeout, udp_idle_timeout};
use crate::portal::PortalInner;
use crate::protocol::{read_uot_packet, read_uot_setup_target, write_uot_packet_frame};

use super::SessionGuard;

/// Relays UDP packets through a length-prefixed TCP stream after UoT setup.
pub(in crate::portal::conn) async fn relay_udp_over_tcp_target<R, W>(
    portal: Arc<PortalInner>,
    client_read: &mut R,
    client_write: &mut W,
    peer: String,
    local: String,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let target_addr = match timeout(handshake_timeout(), read_uot_setup_target(client_read)).await {
        Ok(Ok(target)) => target,
        Ok(Err(err)) => {
            portal.logger.error(format_args!(
                "portal::conn::relay_udp_over_tcp_target: failed to read setup target: {err}"
            ));
            return;
        }
        Err(_) => {
            portal.logger.error(format_args!(
                "portal::conn::relay_udp_over_tcp_target: failed to read setup target: deadline elapsed"
            ));
            return;
        }
    };

    let socket = match portal
        .outbound
        .dial_udp(&target_addr, udp_dial_timeout())
        .await
    {
        Ok(socket) => socket,
        Err(err) => {
            portal.logger.error(format_args!(
                "portal::conn::relay_udp_over_tcp_target: failed to dial target: {err}"
            ));
            return;
        }
    };
    let target_local = socket
        .local_addr()
        .map(|address| address.to_string())
        .unwrap_or_else(|_| "<unknown>".to_string());
    portal.logger.info(format_args!(
        "portal::conn::relay_udp_over_tcp_target: exchange starting: {peer} <-> {local} <-> {target_local} <-> {target_addr}"
    ));

    portal.stats.add_session(true);
    let _done = SessionGuard::new(portal.clone(), true);
    let mut target_buf = portal.buffers.get_udp_buffer();
    let mut last_used = Instant::now();

    loop {
        // UoT is connection-oriented, so the idle timer is based on traffic in
        // either direction rather than target socket lifetime alone.
        let idle_deadline = last_used + udp_idle_timeout();
        tokio::select! {
            packet = read_uot_packet(client_read) => {
                let payload = match packet {
                    Ok(Some(payload)) => payload,
                    Ok(None) => break,
                    Err(err) => {
                        portal.logger.info(format_args!(
                            "portal::conn::relay_udp_over_tcp_target: exchange complete: client frame error: {err}"
                        ));
                        break;
                    }
                };
                last_used = Instant::now();
                if let Some(limiter) = &portal.rate_limiter {
                    limiter.wait_read(payload.len() as i64).await;
                }
                match socket.send(&payload).await {
                    Ok(n) => {
                        portal.stats.udp_rx.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    Err(err) => {
                        portal.logger.error(format_args!(
                            "portal::conn::relay_udp_over_tcp_target: failed to write target: {err}"
                        ));
                        break;
                    }
                }
            }
            read = socket.recv(&mut target_buf) => {
                let n = match read {
                    Ok(n) => n,
                    Err(err) => {
                        portal.logger.debug(format_args!(
                            "portal::conn::relay_udp_over_tcp_target: failed to read target socket: {err}"
                        ));
                        break;
                    }
                };
                last_used = Instant::now();
                if let Some(limiter) = &portal.rate_limiter {
                    limiter.wait_write(n as i64).await;
                }
                let frame = match write_uot_packet_frame(&target_buf[..n]) {
                    Ok(frame) => frame,
                    Err(err) => {
                        portal.logger.error(format_args!(
                            "portal::conn::relay_udp_over_tcp_target: failed to frame response: {err}"
                        ));
                        break;
                    }
                };
                if let Err(err) = client_write.write_all(&frame).await {
                    portal.logger.info(format_args!(
                        "portal::conn::relay_udp_over_tcp_target: exchange complete: client write error: {err}"
                    ));
                    break;
                }
                portal.stats.udp_tx.fetch_add(n as u64, Ordering::Relaxed);
            }
            _ = tokio::time::sleep_until(idle_deadline) => {
                portal.logger.debug(format_args!(
                    "portal::conn::relay_udp_over_tcp_target: exchange complete: idle timeout"
                ));
                break;
            }
        }
    }
}
