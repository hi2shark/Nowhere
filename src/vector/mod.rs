// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Native Rust client exposed by the `vector://` command URL.

mod config;
mod event;
mod flow;
mod flow_id;
mod session;
mod socks;
mod tls;
mod udp_flow;

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::common::{
    Logger, quic_max_streams, rate_limit_bytes_per_second, shutdown_timeout, tcp_data_buf_size,
    udp_data_buf_size,
};
use crate::protocol::{Credentials, SESSION_ID_LEN};
use crate::transport::{Buffers, RateLimiter, Stats};

use self::config::VectorConfig;
use self::flow_id::FlowIdAllocator;
use self::session::{QuicManager, TlsPool};
use self::tls::ClientTls;

const DEFAULT_MAX_UDP_FLOWS: usize = 256;

/// Runnable native client serving a local SOCKS5 endpoint.
pub struct Vector {
    inner: Arc<VectorInner>,
}

pub(super) struct VectorInner {
    config: VectorConfig,
    logger: Logger,
    stats: Arc<Stats>,
    buffers: Buffers,
    rate_limiter: Option<Arc<RateLimiter>>,
    flow_ids: Arc<FlowIdAllocator>,
    tcp_flow_permits: Arc<Semaphore>,
    udp_flow_permits: Arc<Semaphore>,
    local_udp_budget: Arc<Semaphore>,
    socks_admission: Arc<Semaphore>,
    tls_pool: Arc<TlsPool>,
    quic: Arc<QuicManager>,
    shutdown: CancellationToken,
}

impl Vector {
    /// Validates a `vector://` URL and prepares client transport state.
    pub fn new(parsed_url: Url, logger: Logger) -> Result<Self> {
        let config = VectorConfig::from_url(&parsed_url)
            .context("vector::Vector::new: invalid Vector configuration")?;
        let credentials =
            Credentials::new(&parsed_url).context("vector::Vector::new: invalid shared key")?;
        let tls = ClientTls::new(&config)
            .context("vector::Vector::new: failed to build client TLS policy")?;
        let mut session_id = [0u8; SESSION_ID_LEN];
        getrandom::fill(&mut session_id).map_err(|error| {
            anyhow::anyhow!("vector::Vector::new: failed to generate logical session ID: {error}")
        })?;
        let stats = Arc::new(Stats::default());
        let shutdown = CancellationToken::new();
        let tls_pool = TlsPool::new(
            &config,
            tls.clone(),
            &credentials,
            session_id,
            stats.clone(),
        );
        let quic = QuicManager::new(
            config.clone(),
            tls.clone(),
            &credentials,
            session_id,
            stats.clone(),
            shutdown.clone(),
        );
        let tcp_limit = quic_max_streams().max(1) as usize;
        let udp_limit =
            crate::common::env_int("NOW_QUIC_MAX_UDP_FLOWS", DEFAULT_MAX_UDP_FLOWS as i32)
                .clamp(1, DEFAULT_MAX_UDP_FLOWS as i32) as usize;
        let read_bps = rate_limit_bytes_per_second(config.rate_mbps) as i64;
        let write_bps = rate_limit_bytes_per_second(config.etar_mbps) as i64;
        let rate_limiter = RateLimiter::new(read_bps, write_bps).map(Arc::new);
        let udp_queue_bytes = crate::common::env_int("NOW_QUIC_UDP_QUEUE_BYTES", 4 * 1024 * 1024)
            .clamp(1, i32::MAX) as usize;

        Ok(Self {
            inner: Arc::new(VectorInner {
                config,
                logger,
                stats,
                buffers: Buffers::new(tcp_data_buf_size(), udp_data_buf_size()),
                rate_limiter,
                flow_ids: FlowIdAllocator::new(tcp_limit.saturating_add(udp_limit)),
                tcp_flow_permits: Arc::new(Semaphore::new(tcp_limit)),
                udp_flow_permits: Arc::new(Semaphore::new(udp_limit)),
                local_udp_budget: Arc::new(Semaphore::new(udp_queue_bytes)),
                socks_admission: Arc::new(Semaphore::new(tcp_limit.saturating_add(udp_limit))),
                tls_pool,
                quic,
                shutdown,
            }),
        })
    }

    /// Runs SOCKS listeners, transport maintenance, telemetry, and graceful shutdown.
    pub async fn run(self) -> Result<()> {
        let listeners = socks::listen(&self.inner.config.socks.host, self.inner.config.socks.port)
            .context("vector::Vector::run: failed to open SOCKS listener")?;
        self.inner.logger.info(format_args!(
            "vector::Vector::run: starting: {}",
            self.inner.config.effective_url()
        ));
        if self.inner.config.socks.authenticated() {
            self.inner.logger.info(format_args!(
                "vector::Vector::run: local SOCKS5 RFC1929 authentication enabled"
            ));
        }

        let mut tasks = JoinSet::new();
        tasks.spawn(event::event_loop(
            self.inner.clone(),
            self.inner.shutdown.clone(),
        ));
        if self.inner.config.pool != 0 {
            tasks.spawn(
                self.inner
                    .tls_pool
                    .clone()
                    .maintain(self.inner.shutdown.clone()),
            );
        }
        for listener in listeners {
            tasks.spawn(socks::serve_listener(
                self.inner.clone(),
                listener,
                self.inner.shutdown.clone(),
            ));
        }

        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.context("vector::Vector::run: failed to install Ctrl-C handler")?;
            }
            _ = self.inner.shutdown.cancelled() => {}
        }
        self.inner.shutdown.cancel();
        let deadline = Instant::now() + shutdown_timeout();
        if timeout_at(deadline, async {
            while tasks.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }
        self.inner.quic.close(deadline).await;
        if let Some(rate) = &self.inner.rate_limiter {
            rate.reset();
        }
        self.inner.logger.info(format_args!(
            "vector::Vector::run: Vector shutdown complete"
        ));
        self.inner.logger.flush();
        Ok(())
    }
}

#[cfg(test)]
#[path = "../tests/vector.rs"]
mod tests;
