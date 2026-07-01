// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Portal runtime orchestration and shutdown handling.

use anyhow::Result;
use quinn::{Endpoint, VarInt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::common::shutdown_timeout;

use super::listener::{accept_endpoint_loop, accept_tcp_loop, listen_endpoint, listen_tcp};
use super::{Portal, event};

impl Portal {
    /// Starts listeners, event reporting, and graceful shutdown handling.
    pub async fn run(self) -> Result<()> {
        let shutdown = CancellationToken::new();
        let endpoints = self.listen_endpoints()?;
        let tcp_listeners = self.listen_tcp_listeners()?;
        self.log_info("starting");

        let event_task = tokio::spawn(event::event_loop(self.inner.clone(), shutdown.clone()));
        let mut accept_tasks = Vec::with_capacity(endpoints.len() + tcp_listeners.len());
        for endpoint in endpoints.iter().cloned() {
            let portal = self.inner.clone();
            let child_shutdown = shutdown.clone();
            accept_tasks.push(tokio::spawn(async move {
                accept_endpoint_loop(portal, endpoint, child_shutdown).await;
            }));
        }
        for listener in tcp_listeners {
            let portal = self.inner.clone();
            let child_shutdown = shutdown.clone();
            accept_tasks.push(tokio::spawn(async move {
                accept_tcp_loop(portal, listener, child_shutdown).await;
            }));
        }

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                shutdown.cancel();
            }
            _ = shutdown.cancelled() => {}
        }

        for endpoint in &endpoints {
            endpoint.close(VarInt::from_u32(0), b"");
        }
        for endpoint in &endpoints {
            let _ = tokio::time::timeout(shutdown_timeout(), endpoint.wait_idle()).await;
        }
        for task in accept_tasks {
            let _ = task.await;
        }
        let _ = event_task.await;
        if let Some(rate) = &self.inner.rate_limiter {
            rate.reset();
        }
        self.inner
            .logger
            .info(format_args!("portal::run: portal shutdown complete"));
        self.inner.logger.flush();
        Ok(())
    }

    fn log_info(&self, prefix: &str) {
        self.inner.logger.info(format_args!(
            "portal::run: {prefix}: {}",
            self.effective_url()
        ));
    }

    /// Returns the effective startup URL that is logged for operators.
    pub(super) fn effective_url(&self) -> String {
        format!(
            "portal://{}?tls={}&net={}&spec={}&alpn={}&rate={}&etar={}&dial={}&socks={}",
            self.inner.endpoint_addr,
            self.inner.tls_mode,
            self.inner.network_mode,
            self.inner.credentials.protocol_spec.effective_spec,
            self.inner.credentials.protocol_spec.effective_alpn,
            self.inner.rate_limit,
            self.inner.etar_limit,
            self.inner.outbound.dialer_ip(),
            self.inner.outbound.socks_endpoint()
        )
    }

    /// Opens QUIC endpoints for network modes that accept UDP service.
    pub(super) fn listen_endpoints(&self) -> Result<Vec<Endpoint>> {
        if !self.inner.network_mode.listens_udp() {
            return Ok(Vec::new());
        }
        self.inner
            .bind_addrs
            .iter()
            .copied()
            .map(|addr| listen_endpoint(self.inner.quic_server_config.clone(), addr))
            .collect()
    }

    /// Opens TLS/TCP listeners for network modes that accept TCP service.
    pub(super) fn listen_tcp_listeners(&self) -> Result<Vec<TcpListener>> {
        if !self.inner.network_mode.listens_tcp() {
            return Ok(Vec::new());
        }
        self.inner
            .bind_addrs
            .iter()
            .copied()
            .map(listen_tcp)
            .collect()
    }
}
