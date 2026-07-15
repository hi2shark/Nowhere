// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Portal construction from URL configuration.

use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use anyhow::Result;
use tokio::sync::Semaphore;
use url::Url;

use crate::common::{
    DEFAULT_RATE_LIMIT, Logger, OutboundDialer, SocksConfig, bind_udp_addrs, env_positive_usize,
    init_dialer_ip, new_server_configs, query_first, rate_limit_bytes_per_second,
    tcp_data_buf_size, udp_data_buf_size,
};
use crate::protocol::Credentials;
use crate::transport::{Buffers, RateLimiter, Stats};

use super::listener::{configure_transport, format_endpoint_addr};
use super::{
    DEFAULT_ALPN, DEFAULT_QUIC_MAX_UDP_FLOWS, DEFAULT_QUIC_UDP_QUEUE_BYTES,
    DEFAULT_TCP_IDLE_POOL_CONNECTIONS, NetworkMode, Portal, PortalInner, UdpFlowLimits, admission,
};

const PORTAL_QUERY_PARAMETERS: &[&str] = &[
    "net", "tls", "crt", "key", "alpn", "rate", "etar", "dial", "socks", "log",
];

impl Portal {
    /// Builds a portal using the listen host encoded in the URL.
    pub fn new(parsed_url: Url, logger: Logger) -> Result<Self> {
        Self::new_with_listen_host(parsed_url, None, logger)
    }

    /// Builds a portal while optionally overriding the URL listen host.
    ///
    /// Tests use the override to bind ephemeral local endpoints without
    /// changing the URL-derived visible configuration.
    pub fn new_with_listen_host(
        parsed_url: Url,
        listen_host: Option<&str>,
        logger: Logger,
    ) -> Result<Self> {
        if parsed_url.scheme() != "portal" {
            anyhow::bail!("portal::new: URL scheme must be portal");
        }
        if parsed_url.password().is_some() {
            anyhow::bail!("portal::new: password userinfo is not supported");
        }
        if parsed_url.fragment().is_some() {
            anyhow::bail!("portal::new: URL fragments are not supported");
        }
        if !parsed_url.path().is_empty() {
            anyhow::bail!("portal::new: URL paths are not supported");
        }
        let query = query_first(&parsed_url, PORTAL_QUERY_PARAMETERS)
            .map_err(|e| anyhow::anyhow!("portal::new: {e}"))?;
        validate_query(&query).map_err(|e| anyhow::anyhow!("portal::new: {e}"))?;
        let port = parsed_url
            .port()
            .ok_or_else(|| anyhow::anyhow!("portal::new: missing listen port"))?;
        if port == 0 {
            anyhow::bail!("portal::new: listen port must be non-zero");
        }
        let credentials =
            Credentials::new(&parsed_url).map_err(|e| anyhow::anyhow!("portal::new: {e}"))?;
        let alpn = query
            .get("alpn")
            .cloned()
            .unwrap_or_else(|| DEFAULT_ALPN.to_string());
        let network_mode =
            NetworkMode::from_url(&parsed_url).map_err(|e| anyhow::anyhow!("portal::new: {e}"))?;
        let (tls_mode, tls_server_config, mut quic_server_config) =
            new_server_configs(&parsed_url, &alpn, logger.clone())
                .map_err(|e| anyhow::anyhow!("portal::new: {e}"))?;

        let host = listen_host.unwrap_or_else(|| parsed_url.host_str().unwrap_or_default());
        let endpoint_addr = format_endpoint_addr(host, port);
        let bind_addrs = bind_udp_addrs(host, port)
            .map_err(|e| anyhow::anyhow!("portal::new: failed to bind listen address: {e}"))?;

        let dialer_ip = init_dialer_ip(query.get("dial").map(String::as_str));
        let socks = SocksConfig::from_url(&parsed_url).map_err(|e| {
            anyhow::anyhow!("portal::new: failed to parse socks configuration: {e}")
        })?;
        let rate_limit = parse_rate(&query, "rate")?;
        let etar_limit = parse_rate(&query, "etar")?;

        configure_transport(&mut quic_server_config)?;

        let read_bps = rate_limit_bytes_per_second(rate_limit) as i64;
        let write_bps = rate_limit_bytes_per_second(etar_limit) as i64;
        let rate_limiter = RateLimiter::new(read_bps, write_bps).map(Arc::new);
        let udp_flow_limits = UdpFlowLimits {
            max_flows: read_positive_env(
                "NOW_QUIC_MAX_UDP_FLOWS",
                DEFAULT_QUIC_MAX_UDP_FLOWS,
                u32::MAX as usize,
                &logger,
            ),
            queue_bytes: read_positive_env(
                "NOW_QUIC_UDP_QUEUE_BYTES",
                DEFAULT_QUIC_UDP_QUEUE_BYTES,
                Semaphore::MAX_PERMITS.min(u32::MAX as usize),
                &logger,
            ),
        };
        let tcp_idle_pool_connections = read_positive_env(
            "NOW_TCP_IDLE_POOL_CONNS",
            DEFAULT_TCP_IDLE_POOL_CONNECTIONS,
            Semaphore::MAX_PERMITS,
            &logger,
        );

        Ok(Self {
            inner: Arc::new(PortalInner {
                credentials,
                alpn,
                tls_mode,
                network_mode,
                endpoint_addr,
                bind_addrs,
                listen_port: port,
                outbound: OutboundDialer::new(dialer_ip, socks),
                rate_limit,
                etar_limit,
                logger,
                stats: Arc::new(Stats::default()),
                pool_active: AtomicU64::new(0),
                tcp_idle_pool_budget: Arc::new(Semaphore::new(tcp_idle_pool_connections)),
                buffers: Buffers::new(tcp_data_buf_size(), udp_data_buf_size()),
                rate_limiter,
                udp_flow_limits,
                tls_server_config,
                quic_server_config,
                unauthenticated_admission: Arc::new(admission::UnauthenticatedAdmission::new()),
                pairing: Arc::new(super::pairing::PairingRegistry::new(
                    udp_flow_limits.max_flows,
                )),
                flow_tasks: Arc::new(super::tasks::FlowTaskTracker::default()),
            }),
        })
    }
}

fn validate_query(query: &std::collections::HashMap<String, String>) -> Result<()> {
    for name in [
        "log", "tls", "crt", "key", "net", "alpn", "rate", "etar", "dial", "socks",
    ] {
        if query.get(name).is_some_and(String::is_empty) {
            anyhow::bail!("empty {name} parameter");
        }
    }
    if let Some(log) = query.get("log")
        && !matches!(
            log.as_str(),
            "none" | "debug" | "info" | "warn" | "error" | "event"
        )
    {
        anyhow::bail!("invalid log level");
    }
    if let Some(tls) = query.get("tls")
        && !matches!(tls.as_str(), "1" | "2")
    {
        anyhow::bail!("tls=1 or tls=2 required");
    }
    if let Some(net) = query.get("net")
        && !matches!(net.as_str(), "mix" | "tcp" | "udp")
    {
        anyhow::bail!("invalid net mode");
    }
    if let Some(alpn) = query.get("alpn")
        && alpn.len() > u8::MAX as usize
    {
        anyhow::bail!("alpn exceeds 255 bytes");
    }
    let tls_is_ca = query.get("tls").is_some_and(|value| value == "2");
    let has_crt = query.contains_key("crt");
    let has_key = query.contains_key("key");
    if (tls_is_ca && !(has_crt && has_key)) || (!tls_is_ca && (has_crt || has_key)) {
        anyhow::bail!("crt and key are required exactly when tls=2");
    }
    if let Some(dial) = query.get("dial")
        && dial != "auto"
        && dial.parse::<std::net::IpAddr>().is_err()
    {
        anyhow::bail!("dial must be auto or an IP literal");
    }
    Ok(())
}

fn parse_rate(query: &std::collections::HashMap<String, String>, name: &str) -> Result<i32> {
    query.get(name).map_or(Ok(DEFAULT_RATE_LIMIT), |value| {
        value
            .parse::<i32>()
            .ok()
            .filter(|value| *value >= 0)
            .ok_or_else(|| anyhow::anyhow!("invalid {name} rate limit"))
    })
}

fn read_positive_env(name: &str, default_value: usize, max_value: usize, logger: &Logger) -> usize {
    let (value, invalid) = env_positive_usize(name, default_value);
    if invalid || value > max_value {
        logger.warn(format_args!(
            "portal::new: invalid {name}; using default {default_value}"
        ));
        return default_value;
    }
    value
}
