// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! TLS/TCP ingress handling and universal flow setup.

use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use socket2::SockRef;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::{timeout, timeout_at};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::common::handshake_timeout;
use crate::protocol::{
    FlowErrorCode, FlowKind, FlowResult, FlowRole, UDP_STREAM_REJECT, read_auth_frame,
    read_flow_header, read_request, write_flow_result, write_udp_stream_frame,
};

use super::auth::{authentication_deadline, wait_for_auth_deadline};
use crate::portal::PortalInner;
use crate::portal::admission::UnauthenticatedGuard;

const TCP_POOL_TTL: Duration = Duration::from_secs(40);
const FLOW_REJECT_TIMEOUT: Duration = Duration::from_secs(1);

pub(in crate::portal) async fn handle_tcp_incoming(
    portal: Arc<PortalInner>,
    stream: TcpStream,
    peer: SocketAddr,
    admission: UnauthenticatedGuard,
    shutdown: CancellationToken,
) {
    handle_tcp_incoming_with_pool_ttl(portal, stream, peer, admission, shutdown, TCP_POOL_TTL)
        .await;
}

pub(super) async fn handle_tcp_incoming_with_pool_ttl(
    portal: Arc<PortalInner>,
    stream: TcpStream,
    peer: SocketAddr,
    admission: UnauthenticatedGuard,
    shutdown: CancellationToken,
    pool_ttl: Duration,
) {
    if let Err(err) = stream.set_nodelay(true) {
        portal.logger.debug(format_args!(
            "portal::conn::handle_tcp_incoming: TCP_NODELAY failed: {err}"
        ));
    }
    let local = stream.local_addr().ok();
    let acceptor = TlsAcceptor::from(portal.tls_server_config.clone());
    let tls_stream = match timeout(handshake_timeout(), acceptor.accept(stream)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            if matches!(
                err.kind(),
                ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset | ErrorKind::BrokenPipe
            ) {
                portal.logger.debug(format_args!(
                    "portal::conn::handle_tcp_incoming: TLS client disconnected: {err}"
                ));
            } else {
                portal.logger.debug(format_args!(
                    "portal::conn::handle_tcp_incoming: TLS handshake failed: {err}"
                ));
            }
            return;
        }
        Err(_) => return,
    };
    let auth_deadline = authentication_deadline();
    let mut tls_stream = tls_stream;
    let auth = tokio::select! {
        _ = shutdown.cancelled() => return,
        result = timeout_at(
            auth_deadline,
            read_auth_frame(
                &mut tls_stream,
                portal.credentials.key,
                &portal.credentials.protocol_spec,
            ),
        ) => result,
    };
    let session_id = match auth {
        Ok(Ok(session_id)) => {
            drop(admission);
            session_id
        }
        Ok(Err(err)) => {
            if !wait_for_auth_deadline(auth_deadline, &shutdown).await {
                return;
            }
            drop(tls_stream);
            drop(admission);
            portal.logger.debug(format_args!(
                "portal::conn::handle_tcp_incoming: authentication failed: {err}"
            ));
            return;
        }
        Err(_) => {
            drop(tls_stream);
            drop(admission);
            return;
        }
    };
    let pool_permit = match portal.tcp_idle_pool_budget.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return,
    };
    let mut link_guard = Some(
        portal
            .pairing
            .register_tcp_link(session_id, portal.stats.clone()),
    );

    if let Err(err) = SockRef::from(tls_stream.get_ref().0).set_keepalive(true) {
        portal.logger.debug(format_args!(
            "portal::conn::handle_tcp_incoming: TCP keepalive failed: {err}"
        ));
        return;
    }
    let (recv, mut send) = tokio::io::split(tls_stream);
    let mut recv = BufReader::new(recv);

    let pool_guard = PoolGuard::new(&portal.pool_active);
    let header = match tokio::select! {
        result = timeout(pool_ttl, async {
            match recv.fill_buf().await {
                Ok([]) => return Ok(None),
                Ok(_) => {}
                Err(err) if err.kind() == ErrorKind::UnexpectedEof => return Ok(None),
                Err(err) => return Err(err.into()),
            }
            read_flow_header(&mut recv).await.map(Some)
        }) => Some(result),
        _ = shutdown.cancelled() => None,
    } {
        Some(Ok(Ok(Some(header)))) => header,
        Some(Ok(Ok(None))) | Some(Err(_)) | None => return,
        Some(Ok(Err(err))) => {
            portal.logger.debug(format_args!(
                "portal::conn::handle_tcp_incoming: invalid flow header: {err}"
            ));
            return;
        }
    };
    let target = if matches!(header.role, FlowRole::Open | FlowRole::Duplex) {
        match timeout(
            handshake_timeout(),
            read_request(&mut recv, &portal.credentials.protocol_spec),
        )
        .await
        {
            Ok(Ok(target)) => Some(target),
            _ => {
                if header.role == FlowRole::Open {
                    portal
                        .pairing
                        .reject_flow_setup(
                            session_id,
                            header.flow_id,
                            FlowErrorCode::InvalidRequest,
                        )
                        .await;
                } else if header.role == FlowRole::Duplex {
                    let write = async {
                        match header.kind {
                            FlowKind::Tcp => {
                                let _ = write_flow_result(
                                    &mut send,
                                    FlowResult::Reject(FlowErrorCode::InvalidRequest),
                                )
                                .await;
                            }
                            FlowKind::Udp => {
                                let _ = write_udp_stream_frame(
                                    &mut send,
                                    UDP_STREAM_REJECT,
                                    &[FlowErrorCode::InvalidRequest as u8],
                                )
                                .await;
                            }
                        }
                        let _ = send.shutdown().await;
                    };
                    let _ = timeout(FLOW_REJECT_TIMEOUT, write).await;
                }
                return;
            }
        }
    } else {
        None
    };
    drop(pool_guard);
    drop(pool_permit);

    let path = crate::portal::pairing::LinkPath {
        peer: peer.to_string(),
        local: local.map_or_else(
            || portal.endpoint_addr.clone(),
            |address| address.to_string(),
        ),
    };
    let link = crate::portal::pairing::LinkHalf::tcp(path);

    match header.kind {
        FlowKind::Tcp => {
            let (reader, writer, liveness) = match header.role {
                FlowRole::Open => (
                    Some(crate::portal::pairing::guarded_reader(
                        recv,
                        link_guard.take().expect("TCP link guard"),
                    )),
                    None,
                    None,
                ),
                FlowRole::Attach => (
                    None,
                    Some(crate::portal::pairing::guarded_writer(
                        send,
                        link_guard.take().expect("TCP link guard"),
                    )),
                    Some(Box::pin(recv) as crate::portal::pairing::BoxReader),
                ),
                FlowRole::Duplex => (
                    Some(Box::pin(recv) as crate::portal::pairing::BoxReader),
                    Some(crate::portal::pairing::guarded_writer(
                        send,
                        link_guard.take().expect("TCP link guard"),
                    )),
                    None,
                ),
            };
            match portal
                .pairing
                .submit_tcp(session_id, header, target, link, reader, writer, liveness)
                .await
            {
                Ok(Some(paired)) => {
                    portal
                        .flow_tasks
                        .spawn(super::relay::relay_paired_tcp(portal.clone(), paired));
                }
                Ok(None) => {}
                Err(err) => portal.logger.debug(format_args!(
                    "portal::conn::handle_tcp_incoming: TCP flow rejected: {err}"
                )),
            }
        }
        FlowKind::Udp => {
            let half = match header.role {
                FlowRole::Open => crate::portal::pairing::UdpHalf::Uplink {
                    uplink: crate::portal::pairing::UdpUp::TlsTcp(
                        crate::portal::pairing::guarded_reader(
                            recv,
                            link_guard.take().expect("TCP link guard"),
                        ),
                    ),
                },
                FlowRole::Attach => crate::portal::pairing::UdpHalf::Downlink(
                    crate::portal::pairing::UdpDown::TlsTcp {
                        writer: crate::portal::pairing::guarded_writer(
                            send,
                            link_guard.take().expect("TCP link guard"),
                        ),
                        liveness: Some(Box::pin(recv)),
                    },
                ),
                FlowRole::Duplex => crate::portal::pairing::UdpHalf::Duplex {
                    uplink: crate::portal::pairing::UdpUp::TlsTcp(Box::pin(recv)),
                    downlink: crate::portal::pairing::UdpDown::TlsTcp {
                        writer: crate::portal::pairing::guarded_writer(
                            send,
                            link_guard.take().expect("TCP link guard"),
                        ),
                        liveness: None,
                    },
                },
            };
            match portal
                .pairing
                .submit_udp(session_id, header, target, link, half)
                .await
            {
                Ok(Some(paired)) => {
                    portal
                        .flow_tasks
                        .spawn(super::relay::relay_paired_udp(portal.clone(), paired));
                }
                Ok(None) => {}
                Err(err) => portal.logger.debug(format_args!(
                    "portal::conn::handle_tcp_incoming: UDP flow rejected: {err}"
                )),
            }
        }
    }
}

struct PoolGuard<'a>(&'a AtomicU64);

impl<'a> PoolGuard<'a> {
    fn new(active: &'a AtomicU64) -> Self {
        active.fetch_add(1, Ordering::Relaxed);
        Self(active)
    }
}

impl Drop for PoolGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}
