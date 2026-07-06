// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Portal server state and module wiring.

mod admission;
mod conn;
mod event;
mod listener;
mod mode;
mod pairing;
mod runtime;
mod setup;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use crate::common::{Logger, OutboundDialer, TLSMode};
use crate::protocol::Credentials;
use crate::transport::{Buffers, RateLimiter, Stats};

pub(crate) use self::mode::NetworkMode;

const DEFAULT_QUIC_MAX_UDP_FLOWS: usize = 256;
const DEFAULT_QUIC_UDP_QUEUE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
struct UdpFlowLimits {
    max_flows: usize,
    queue_bytes: usize,
}

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
    // NOTE: relay paths no longer read this shared limiter. Each relay session
    // builds its own per-flow limiter via `per_flow_limiter` (see conn/relay.rs)
    // so concurrent flows get independent token buckets. This field is retained
    // for compatibility with setup/runtime and may be removed in a follow-up.
    rate_limiter: Option<Arc<RateLimiter>>,
    udp_flow_limits: UdpFlowLimits,
    tls_server_config: Arc<rustls::ServerConfig>,
    quic_server_config: quinn::ServerConfig,
    unauthenticated_admission: Arc<admission::UnauthenticatedAdmission>,
    pairing: Arc<pairing::PairingRegistry>,
}

#[cfg(test)]
#[path = "../tests/portal.rs"]
mod tests;
