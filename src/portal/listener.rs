// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! QUIC endpoint and TCP listener setup plus accept loops.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result};
use quinn::{Endpoint, EndpointConfig, IdleTimeout, ServerConfig, VarInt, default_runtime};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio::time::{Duration, sleep};
use tokio_util::sync::CancellationToken;

use crate::common::udp_idle_timeout;

use super::{PortalInner, conn};

const QUIC_STREAM_RECEIVE_WINDOW: u32 = 16 * 1024 * 1024;
/// Post-authentication QUIC connection receive window.
pub(super) const QUIC_RECEIVE_WINDOW: u32 = 32 * 1024 * 1024;
const QUIC_PRE_AUTH_RECEIVE_WINDOW: u32 = 64 * 1024;
const QUIC_SEND_WINDOW: u64 = 32 * 1024 * 1024;
// Quinn allocates this receive queue per connection before application
// authentication. Keep it intentionally small; authenticated DATAGRAM traffic
// is drained continuously into the separately budgeted flow queues.
const QUIC_DATAGRAM_RECEIVE_BUFFER_SIZE: usize = 256 * 1024;
const QUIC_DATAGRAM_SEND_BUFFER_SIZE: usize = 4 * 1024 * 1024;
const QUIC_SOCKET_BUFFER_SIZE: usize = 4 * 1024 * 1024;
const TCP_LISTEN_BACKLOG: i32 = 1024;

pub(super) async fn accept_endpoint_loop(
    portal: Arc<PortalInner>,
    endpoint: Endpoint,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    break;
                };
                if !incoming.remote_address_validated() {
                    // Require address validation before spending authentication
                    // work or admission slots on the connection.
                    if let Err(err) = incoming.retry() {
                        portal.logger.error(format_args!(
                            "portal::accept_endpoint_loop: failed to send QUIC Retry: {err}"
                        ));
                    }
                    continue;
                }
                let peer = incoming.remote_address();
                let Some(admission) = portal.unauthenticated_admission.try_acquire(peer.ip()) else {
                    portal.logger.error(format_args!(
                        "portal::accept_endpoint_loop: unauthenticated connection limit exceeded: {peer}"
                    ));
                    incoming.ignore();
                    continue;
                };
                let portal = portal.clone();
                let child_shutdown = shutdown.clone();
                let tasks = portal.flow_tasks.clone();
                tasks.spawn(async move {
                    conn::handle_incoming(portal, incoming, admission, child_shutdown).await;
                });
            }
        }
    }
}

pub(super) async fn accept_tcp_loop(
    portal: Arc<PortalInner>,
    listener: TcpListener,
    shutdown: CancellationToken,
) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            result = listener.accept() => match result {
                Ok((stream, peer)) => {
                    let Some(admission) = portal.unauthenticated_admission.try_acquire(peer.ip()) else {
                        portal.logger.error(format_args!(
                            "portal::accept_tcp_loop: unauthenticated connection limit exceeded: {peer}"
                        ));
                        drop(stream);
                        continue;
                    };
                    let portal = portal.clone();
                    let child_shutdown = shutdown.clone();
                    connections.spawn(async move {
                        conn::handle_tcp_incoming(portal, stream, peer, admission, child_shutdown).await;
                    });
                }
                Err(err) => {
                    portal.logger.error(format_args!(
                        "portal::accept_tcp_loop: failed to accept TCP connection: {err}"
                    ));
                    sleep(Duration::from_millis(100)).await;
                }
            },
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    // The portal runtime owns the single absolute shutdown deadline. If this
    // loop is aborted at that deadline, dropping the JoinSet aborts any
    // remaining connection tasks.
    while connections.join_next().await.is_some() {}
}

/// Opens a Quinn endpoint on an already configured server config.
pub(super) fn listen_endpoint(server_config: ServerConfig, addr: SocketAddr) -> Result<Endpoint> {
    let socket = bind_quic_socket(addr)
        .with_context(|| format!("portal::listen_endpoint: failed to bind UDP socket: {addr}"))?;
    let runtime = default_runtime()
        .ok_or_else(|| anyhow::anyhow!("portal::listen_endpoint: no async runtime found"))?;
    Endpoint::new(
        EndpointConfig::default(),
        Some(server_config),
        socket,
        runtime,
    )
    .with_context(|| format!("portal::listen_endpoint: failed to listen for QUIC on {addr}"))
}

fn bind_quic_socket(addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    let socket = if addr.is_ipv6() {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_only_v6(true)?;
        socket
    } else {
        Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?
    };
    let _ = socket.set_send_buffer_size(QUIC_SOCKET_BUFFER_SIZE);
    let _ = socket.set_recv_buffer_size(QUIC_SOCKET_BUFFER_SIZE);
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

/// Opens a nonblocking TCP listener for TLS-over-TCP service.
pub(super) fn listen_tcp(addr: SocketAddr) -> Result<TcpListener> {
    let socket = if addr.is_ipv6() {
        let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_only_v6(true)?;
        socket
    } else {
        Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?
    };
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(TCP_LISTEN_BACKLOG)?;
    let listener = std::net::TcpListener::from(socket);
    TcpListener::from_std(listener)
        .with_context(|| format!("portal::listen_tcp: failed to listen for TLS/TCP on {addr}"))
}

/// Formats a visible endpoint address without adding brackets to empty hosts.
pub(super) fn format_endpoint_addr(host: &str, port: u16) -> String {
    match host.parse::<IpAddr>() {
        Ok(ip) => SocketAddr::new(ip, port).to_string(),
        Err(_) if host.is_empty() => format!(":{port}"),
        Err(_) => format!("{host}:{port}"),
    }
}

/// Applies transport limits that should be set before the config is shared.
pub(super) fn configure_transport(server_config: &mut quinn::ServerConfig) -> Result<()> {
    let transport = Arc::get_mut(&mut server_config.transport).ok_or_else(|| {
        anyhow::anyhow!("portal::configure_transport: server transport already shared")
    })?;
    transport.datagram_receive_buffer_size(Some(QUIC_DATAGRAM_RECEIVE_BUFFER_SIZE));
    transport.datagram_send_buffer_size(QUIC_DATAGRAM_SEND_BUFFER_SIZE);
    transport.stream_receive_window(VarInt::from_u32(QUIC_STREAM_RECEIVE_WINDOW));
    transport.receive_window(VarInt::from_u32(QUIC_PRE_AUTH_RECEIVE_WINDOW));
    transport.send_window(QUIC_SEND_WINDOW);
    transport.max_concurrent_bidi_streams(VarInt::from_u32(1));
    transport.max_concurrent_uni_streams(VarInt::from_u32(0));
    transport.max_idle_timeout(Some(IdleTimeout::try_from(udp_idle_timeout())?));
    transport.keep_alive_interval(None);
    transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));

    Ok(())
}
