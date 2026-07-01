// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Portal construction from URL configuration.

use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use anyhow::Result;
use url::Url;

use crate::common::{
    DEFAULT_RATE_LIMIT, Logger, OutboundDialer, SocksConfig, bind_udp_addrs, init_dialer_ip,
    new_server_configs, query_int, rate_limit_bytes_per_second, tcp_data_buf_size,
    udp_data_buf_size,
};
use crate::protocol::Credentials;
use crate::transport::{Buffers, RateLimiter, Stats};

use super::listener::{configure_transport, format_endpoint_addr};
use super::{NetworkMode, Portal, PortalInner, admission};

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
        let port = parsed_url
            .port()
            .ok_or_else(|| anyhow::anyhow!("portal::new: missing listen port"))?;
        let credentials =
            Credentials::new(&parsed_url).map_err(|e| anyhow::anyhow!("portal::new: {e}"))?;
        let network_mode =
            NetworkMode::from_url(&parsed_url).map_err(|e| anyhow::anyhow!("portal::new: {e}"))?;
        let (tls_mode, tls_server_config, mut quic_server_config) = new_server_configs(
            &parsed_url,
            &credentials.protocol_spec.effective_alpn,
            logger.clone(),
        )
        .map_err(|e| anyhow::anyhow!("portal::new: {e}"))?;

        let host = listen_host.unwrap_or_else(|| parsed_url.host_str().unwrap_or_default());
        let endpoint_addr = format_endpoint_addr(host, port);
        let bind_addrs = bind_udp_addrs(host, port)
            .map_err(|e| anyhow::anyhow!("portal::new: failed to bind listen address: {e}"))?;

        let dialer_ip = init_dialer_ip(
            parsed_url
                .query_pairs()
                .find(|(k, _)| k == "dial")
                .map(|(_, v)| v.into_owned())
                .as_deref(),
        );
        let socks = SocksConfig::from_url(&parsed_url).map_err(|e| {
            anyhow::anyhow!("portal::new: failed to parse socks configuration: {e}")
        })?;
        let rate_limit = query_int(
            parsed_url
                .query_pairs()
                .find(|(k, _)| k == "rate")
                .map(|(_, v)| v.into_owned())
                .as_deref(),
            DEFAULT_RATE_LIMIT,
        );
        let etar_limit = query_int(
            parsed_url
                .query_pairs()
                .find(|(k, _)| k == "etar")
                .map(|(_, v)| v.into_owned())
                .as_deref(),
            DEFAULT_RATE_LIMIT,
        );

        configure_transport(&mut quic_server_config)?;

        let read_bps = rate_limit_bytes_per_second(rate_limit) as i64;
        let write_bps = rate_limit_bytes_per_second(etar_limit) as i64;
        let rate_limiter = RateLimiter::new(read_bps, write_bps).map(Arc::new);

        Ok(Self {
            inner: Arc::new(PortalInner {
                credentials,
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
                buffers: Buffers::new(tcp_data_buf_size(), udp_data_buf_size()),
                rate_limiter,
                tls_server_config,
                quic_server_config,
                unauthenticated_admission: Arc::new(admission::UnauthenticatedAdmission::new()),
            }),
        })
    }
}
