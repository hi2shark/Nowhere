// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Bidirectional byte-stream relay with idle/read timeouts.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use crate::common::tcp_read_timeout;
use crate::portal::PortalInner;
use crate::protocol::Carrier;

const BLOCK_LOG_THRESHOLD: Duration = Duration::from_secs(1);

/// Per-direction outcome for a completed TCP relay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RelaySummary {
    pub(super) client_to_target_bytes: u64,
    pub(super) target_to_client_bytes: u64,
    pub(super) first_eof: RelayFirstEof,
}

/// Identifies which relay direction observed EOF first.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RelayFirstEof {
    Client,
    Target,
}

impl RelayFirstEof {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client_to_target",
            Self::Target => "target_to_client",
        }
    }
}

/// Relays both directions until one side closes or either direction errors.
pub(super) async fn relay_stream<R, W>(
    portal: Arc<PortalInner>,
    client_read: &mut R,
    client_write: &mut W,
    target_conn: tokio::net::TcpStream,
    mut buffer1: Vec<u8>,
    mut buffer2: Vec<u8>,
    carriers: Option<(Carrier, Carrier)>,
) -> anyhow::Result<RelaySummary>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (mut target_read, mut target_write) = target_conn.into_split();
    let client_to_target_bytes = AtomicU64::new(0);
    let target_to_client_bytes = AtomicU64::new(0);

    let client_to_target = async {
        loop {
            let started = Instant::now();
            let n = client_read.read(&mut buffer1).await?;
            log_block_duration(&portal, "read", "client_to_target", started, n);
            if n == 0 {
                target_write.shutdown().await?;
                return Ok::<(), anyhow::Error>(());
            }
            client_to_target_bytes.fetch_add(n as u64, Ordering::Relaxed);
            portal.stats.tcp_rx.fetch_add(n as u64, Ordering::Relaxed);
            if let Some((uplink, _)) = carriers {
                match uplink {
                    Carrier::Tcp => &portal.stats.up_tcp,
                    Carrier::Udp => &portal.stats.up_udp,
                }
                .fetch_add(n as u64, Ordering::Relaxed);
            }
            if let Some(limiter) = &portal.rate_limiter {
                limiter.wait_read(n as i64).await;
            }
            let started = Instant::now();
            target_write.write_all(&buffer1[..n]).await?;
            log_block_duration(&portal, "write", "client_to_target", started, n);
            let started = Instant::now();
            target_write.flush().await?;
            log_block_duration(&portal, "flush", "client_to_target", started, n);
        }
    };

    let target_to_client = async {
        loop {
            let started = Instant::now();
            let n = target_read.read(&mut buffer2).await?;
            log_block_duration(&portal, "read", "target_to_client", started, n);
            if n == 0 {
                client_write.shutdown().await?;
                return Ok::<(), anyhow::Error>(());
            }
            if let Some(limiter) = &portal.rate_limiter {
                limiter.wait_write(n as i64).await;
            }
            let started = Instant::now();
            client_write.write_all(&buffer2[..n]).await?;
            log_block_duration(&portal, "write", "target_to_client", started, n);
            let started = Instant::now();
            client_write.flush().await?;
            log_block_duration(&portal, "flush", "target_to_client", started, n);
            target_to_client_bytes.fetch_add(n as u64, Ordering::Relaxed);
            portal.stats.tcp_tx.fetch_add(n as u64, Ordering::Relaxed);
            if let Some((_, downlink)) = carriers {
                match downlink {
                    Carrier::Tcp => &portal.stats.down_tcp,
                    Carrier::Udp => &portal.stats.down_udp,
                }
                .fetch_add(n as u64, Ordering::Relaxed);
            }
        }
    };

    tokio::pin!(client_to_target);
    tokio::pin!(target_to_client);

    let first = tokio::select! {
        r = &mut client_to_target => EitherDone::Client(r),
        r = &mut target_to_client => EitherDone::Target(r),
    };

    let first_eof = match first {
        EitherDone::Client(Ok(())) => {
            // After a clean half-close, give the other direction a short drain
            // window so protocol trailers or final response bytes can pass.
            match timeout(tcp_read_timeout(), &mut target_to_client).await {
                Ok(result) => result?,
                Err(_elapsed) => {
                    portal.logger.debug(format_args!(
                        "portal::conn::relay_stream: drain_timeout after_first_eof=client_to_target"
                    ));
                }
            }
            RelayFirstEof::Client
        }
        EitherDone::Target(Ok(())) => {
            // Symmetric drain window for target-initiated close.
            match timeout(tcp_read_timeout(), &mut client_to_target).await {
                Ok(result) => result?,
                Err(_elapsed) => {
                    portal.logger.debug(format_args!(
                        "portal::conn::relay_stream: drain_timeout after_first_eof=target_to_client"
                    ));
                }
            }
            RelayFirstEof::Target
        }
        EitherDone::Client(Err(err)) | EitherDone::Target(Err(err)) => return Err(err),
    };

    Ok(RelaySummary {
        client_to_target_bytes: client_to_target_bytes.load(Ordering::Relaxed),
        target_to_client_bytes: target_to_client_bytes.load(Ordering::Relaxed),
        first_eof,
    })
}

enum EitherDone {
    Client(anyhow::Result<()>),
    Target(anyhow::Result<()>),
}

fn log_block_duration(
    portal: &PortalInner,
    operation: &'static str,
    direction: &'static str,
    started: Instant,
    bytes: usize,
) {
    let elapsed = started.elapsed();
    if elapsed >= BLOCK_LOG_THRESHOLD {
        portal.logger.debug(format_args!(
            "portal::conn::relay_stream: {operation}_block_duration dir={direction} ms={} bytes={bytes}",
            elapsed.as_millis()
        ));
    }
}
