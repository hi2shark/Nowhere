// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Portal runtime orchestration and shutdown handling.

use anyhow::Result;
use quinn::{Endpoint, VarInt};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout_at};
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

        let mut runtime_tasks = JoinSet::new();
        runtime_tasks.spawn(event::event_loop(self.inner.clone(), shutdown.clone()));
        for endpoint in endpoints.iter().cloned() {
            let portal = self.inner.clone();
            let child_shutdown = shutdown.clone();
            runtime_tasks.spawn(async move {
                accept_endpoint_loop(portal, endpoint, child_shutdown).await;
            });
        }
        for listener in tcp_listeners {
            let portal = self.inner.clone();
            let child_shutdown = shutdown.clone();
            runtime_tasks.spawn(async move {
                accept_tcp_loop(portal, listener, child_shutdown).await;
            });
        }

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                shutdown.cancel();
            }
            _ = shutdown.cancelled() => {}
        }

        let shutdown_deadline = Instant::now() + shutdown_timeout();
        for endpoint in &endpoints {
            endpoint.close(VarInt::from_u32(0), b"");
        }
        self.inner.flow_tasks.close();
        let _ = timeout_at(shutdown_deadline, self.inner.pairing.cancel_all()).await;

        let mut endpoint_tasks = JoinSet::new();
        for endpoint in &endpoints {
            let endpoint = endpoint.clone();
            endpoint_tasks.spawn(async move {
                endpoint.wait_idle().await;
            });
        }
        let graceful = timeout_at(shutdown_deadline, async {
            while endpoint_tasks.join_next().await.is_some() {}
            while runtime_tasks.join_next().await.is_some() {}
            self.inner.flow_tasks.wait().await;
        })
        .await
        .is_ok();
        if !graceful {
            endpoint_tasks.abort_all();
            runtime_tasks.abort_all();
            self.inner.flow_tasks.abort_all();
            while endpoint_tasks.join_next().await.is_some() {}
            while runtime_tasks.join_next().await.is_some() {}
            self.inner.flow_tasks.wait().await;
        }
        // Setup tasks that were already running when admission closed may have
        // reached the registry after the first sweep.  No tracked ingress task
        // remains here, so a final deterministic sweep closes that race.
        self.inner.pairing.cancel_all().await;
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
