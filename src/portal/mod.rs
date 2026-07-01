// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Portal server state and module wiring.

mod admission;
mod conn;
mod event;
mod listener;
mod mode;
mod runtime;
mod setup;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use crate::common::{Logger, OutboundDialer, TLSMode};
use crate::protocol::Credentials;
use crate::transport::{Buffers, RateLimiter, Stats};

pub(crate) use self::mode::NetworkMode;

/// Portal server configured from a `portal://` URL.
#[derive(Clone)]
pub struct Portal {
    inner: Arc<PortalInner>,
}

struct PortalInner {
    credentials: Credentials,
    tls_mode: TLSMode,
    network_mode: NetworkMode,
    endpoint_addr: String,
    bind_addrs: Vec<SocketAddr>,
    listen_port: u16,
    outbound: OutboundDialer,
    rate_limit: i32,
    etar_limit: i32,
    logger: Logger,
    stats: Arc<Stats>,
    pool_active: AtomicU64,
    buffers: Buffers,
    rate_limiter: Option<Arc<RateLimiter>>,
    tls_server_config: Arc<rustls::ServerConfig>,
    quic_server_config: quinn::ServerConfig,
    unauthenticated_admission: Arc<admission::UnauthenticatedAdmission>,
}

#[cfg(test)]
#[path = "../tests/portal.rs"]
mod tests;
