// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Bidirectional byte-stream relay with idle/read timeouts.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use crate::common::tcp_read_timeout;
use crate::portal::PortalInner;
use crate::protocol::Carrier;
use crate::transport::RateLimiter;

/// A read/write is considered "blocked" once it takes longer than this; only
/// such slow operations are logged to avoid swamping the debug log on every
/// loop iteration of a fast bulk transfer.
const BLOCK_LOG_THRESHOLD: Duration = Duration::from_secs(1);

/// Relays both directions until one side closes or either direction errors.
///
/// `limiter` is a per-flow limiter built by the caller (see `per_flow_limiter`).
/// Each relay session owns its own bucket so concurrent flows do not contend on
/// a shared limiter; passing `None` means unlimited in both directions.
pub(super) async fn relay_stream<R, W>(
    portal: Arc<PortalInner>,
    client_read: &mut R,
    client_write: &mut W,
    target_conn: tokio::net::TcpStream,
    mut buffer1: Vec<u8>,
    mut buffer2: Vec<u8>,
    carriers: Option<(Carrier, Carrier)>,
    limiter: Option<RateLimiter>,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (mut target_read, mut target_write) = target_conn.into_split();

    let client_to_target = async {
        loop {
            let read_start = Instant::now();
            let n = client_read.read(&mut buffer1).await?;
            let read_elapsed = read_start.elapsed();
            if read_elapsed >= BLOCK_LOG_THRESHOLD {
                portal.logger.debug(format_args!(
                    "portal::conn::relay_stream: read_block_duration={}ms bytes={} dir=client_to_target",
                    read_elapsed.as_millis(),
                    n
                ));
            }
            if n == 0 {
                target_write.shutdown().await?;
                return Ok::<(), anyhow::Error>(());
            }
            portal.stats.tcp_rx.fetch_add(n as u64, Ordering::Relaxed);
            if let Some((uplink, _)) = carriers {
                match uplink {
                    Carrier::Tcp => &portal.stats.up_tcp,
                    Carrier::Udp => &portal.stats.up_udp,
                }
                .fetch_add(n as u64, Ordering::Relaxed);
            }
            if let Some(limiter) = &limiter {
                limiter.wait_read(n as i64).await;
            }
            let write_start = Instant::now();
            target_write.write_all(&buffer1[..n]).await?;
            let write_elapsed = write_start.elapsed();
            if write_elapsed >= BLOCK_LOG_THRESHOLD {
                portal.logger.debug(format_args!(
                    "portal::conn::relay_stream: write_block_duration={}ms bytes={} dir=client_to_target",
                    write_elapsed.as_millis(),
                    n
                ));
            }
        }
    };

    let target_to_client = async {
        loop {
            let read_start = Instant::now();
            let n = target_read.read(&mut buffer2).await?;
            let read_elapsed = read_start.elapsed();
            if read_elapsed >= BLOCK_LOG_THRESHOLD {
                portal.logger.debug(format_args!(
                    "portal::conn::relay_stream: read_block_duration={}ms bytes={} dir=target_to_client",
                    read_elapsed.as_millis(),
                    n
                ));
            }
            if n == 0 {
                client_write.shutdown().await?;
                return Ok::<(), anyhow::Error>(());
            }
            if let Some(limiter) = &limiter {
                limiter.wait_write(n as i64).await;
            }
            let write_start = Instant::now();
            client_write.write_all(&buffer2[..n]).await?;
            let write_elapsed = write_start.elapsed();
            if write_elapsed >= BLOCK_LOG_THRESHOLD {
                portal.logger.debug(format_args!(
                    "portal::conn::relay_stream: write_block_duration={}ms bytes={} dir=target_to_client",
                    write_elapsed.as_millis(),
                    n
                ));
            }
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

    match first {
        EitherDone::Client(Ok(())) => {
            // After a clean half-close, give the other direction a short drain
            // window so protocol trailers or final response bytes can pass.
            timeout(tcp_read_timeout(), &mut target_to_client)
                .await
                .unwrap_or(Ok(()))?;
        }
        EitherDone::Target(Ok(())) => {
            // Symmetric drain window for target-initiated close.
            timeout(tcp_read_timeout(), &mut client_to_target)
                .await
                .unwrap_or(Ok(()))?;
        }
        EitherDone::Client(Err(err)) | EitherDone::Target(Err(err)) => return Err(err),
    }

    Ok(())
}

enum EitherDone {
    Client(anyhow::Result<()>),
    Target(anyhow::Result<()>),
}
