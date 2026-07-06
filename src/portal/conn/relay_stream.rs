// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Bidirectional byte-stream relay with idle/read timeouts.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};


use crate::portal::PortalInner;
use crate::protocol::Carrier;
use crate::transport::RateLimiter;

/// A read/write is considered "blocked" once it takes longer than this; only
/// such slow operations are logged to avoid swamping the debug log on every
/// loop iteration of a fast bulk transfer.
const BLOCK_LOG_THRESHOLD: Duration = Duration::from_secs(1);

/// After one direction of a relay observes a clean EOF, the OTHER direction is
/// drained under an *activity-refreshing* idle timeout rather than a fixed
/// wall-clock window. Two problems with a single fixed window:
///   - too short (the old 30s) killed slow single-flow downloads on high-RTT
///     links (e.g. speed.cloudflare.com) before the response body drained;
///   - too long (a 300s cap) let an idle HTTP keep-alive carrier hang for the
///     full window doing nothing.
///
/// The drain now ticks every `DRAIN_IDLE_TICK` and resets its idle budget
/// whenever bytes keep flowing; it only gives up after `DRAIN_IDLE_TIMEOUT` of
/// continuous silence. So a slow-but-steady download drains to completion, and
/// a parked keep-alive connection is released promptly.
const DRAIN_IDLE_TICK: Duration = Duration::from_secs(5);
const DRAIN_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Per-direction accounting returned to the caller so the `relay_end` summary
/// can report how many bytes actually crossed each leg of the relay.
#[derive(Debug, Default)]
pub(super) struct RelaySummary {
    pub client_to_target_bytes: u64,
    pub target_to_client_bytes: u64,
    /// Which side initiated the first clean EOF, if any:
    ///   - `"client"`  -> the local client half-closed (upload direction EOF)
    ///   - `"target"`  -> the remote target half-closed (download direction EOF)
    ///   - `"none"`    -> the relay ended with an error or a timeout
    pub first_eof: &'static str,
}

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
) -> anyhow::Result<RelaySummary>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (mut target_read, mut target_write) = target_conn.into_split();

    let client_to_target_bytes = Arc::new(AtomicU64::new(0));
    let target_to_client_bytes = Arc::new(AtomicU64::new(0));

    let c2t_bytes = Arc::clone(&client_to_target_bytes);
    let client_to_target = async {
        portal.logger.debug(format_args!(
            "portal::conn::relay_stream: copy_start dir=client_to_target"
        ));
        loop {
            let read_start = Instant::now();
            let n = match client_read.read(&mut buffer1).await {
                Ok(n) => n,
                Err(err) => {
                    let copied = c2t_bytes.load(Ordering::Relaxed);
                    portal.logger.debug(format_args!(
                        "portal::conn::relay_stream: copy_end dir=client_to_target eof=false copied={} err={} propagation=none",
                        copied, err
                    ));
                    return Err::<(), anyhow::Error>(err.into());
                }
            };
            let read_elapsed = read_start.elapsed();
            if read_elapsed >= BLOCK_LOG_THRESHOLD {
                portal.logger.debug(format_args!(
                    "portal::conn::relay_stream: read_block_duration={}ms bytes={} dir=client_to_target",
                    read_elapsed.as_millis(),
                    n
                ));
            }
            if n == 0 {
                let copied = c2t_bytes.load(Ordering::Relaxed);
                match target_write.shutdown().await {
                    Ok(()) => {
                        portal.logger.debug(format_args!(
                            "portal::conn::relay_stream: copy_end dir=client_to_target eof=true copied={} err=nil propagation=shutdown_write",
                            copied
                        ));
                    }
                    Err(err) => {
                        portal.logger.debug(format_args!(
                            "portal::conn::relay_stream: copy_end dir=client_to_target eof=true copied={} err={} propagation=shutdown_failed",
                            copied, err
                        ));
                        return Err(err.into());
                    }
                }
                return Ok(());
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
            if let Err(err) = target_write.write_all(&buffer1[..n]).await {
                let copied = c2t_bytes.load(Ordering::Relaxed);
                portal.logger.debug(format_args!(
                    "portal::conn::relay_stream: copy_end dir=client_to_target eof=false copied={} err={} propagation=none",
                    copied, err
                ));
                return Err(err.into());
            }
            c2t_bytes.fetch_add(n as u64, Ordering::Relaxed);
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

    let t2c_bytes = Arc::clone(&target_to_client_bytes);
    let target_to_client = async {
        portal.logger.debug(format_args!(
            "portal::conn::relay_stream: copy_start dir=target_to_client"
        ));
        loop {
            let read_start = Instant::now();
            let n = match target_read.read(&mut buffer2).await {
                Ok(n) => n,
                Err(err) => {
                    let copied = t2c_bytes.load(Ordering::Relaxed);
                    portal.logger.debug(format_args!(
                        "portal::conn::relay_stream: copy_end dir=target_to_client eof=false copied={} err={} propagation=none",
                        copied, err
                    ));
                    return Err::<(), anyhow::Error>(err.into());
                }
            };
            let read_elapsed = read_start.elapsed();
            if read_elapsed >= BLOCK_LOG_THRESHOLD {
                portal.logger.debug(format_args!(
                    "portal::conn::relay_stream: read_block_duration={}ms bytes={} dir=target_to_client",
                    read_elapsed.as_millis(),
                    n
                ));
            }
            if n == 0 {
                let copied = t2c_bytes.load(Ordering::Relaxed);
                match client_write.shutdown().await {
                    Ok(()) => {
                        portal.logger.debug(format_args!(
                            "portal::conn::relay_stream: copy_end dir=target_to_client eof=true copied={} err=nil propagation=shutdown_write",
                            copied
                        ));
                    }
                    Err(err) => {
                        portal.logger.debug(format_args!(
                            "portal::conn::relay_stream: copy_end dir=target_to_client eof=true copied={} err={} propagation=shutdown_failed",
                            copied, err
                        ));
                        return Err(err.into());
                    }
                }
                return Ok(());
            }
            if let Some(limiter) = &limiter {
                limiter.wait_write(n as i64).await;
            }
            let write_start = Instant::now();
            if let Err(err) = client_write.write_all(&buffer2[..n]).await {
                let copied = t2c_bytes.load(Ordering::Relaxed);
                portal.logger.debug(format_args!(
                    "portal::conn::relay_stream: copy_end dir=target_to_client eof=false copied={} err={} propagation=none",
                    copied, err
                ));
                return Err(err.into());
            }
            t2c_bytes.fetch_add(n as u64, Ordering::Relaxed);
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

    let first_eof = match &first {
        EitherDone::Client(Ok(())) => "client",
        EitherDone::Target(Ok(())) => "target",
        _ => "none",
    };

    match first {
        EitherDone::Client(Ok(())) => {
            // After the client half-closes (upload EOF), drain the download side
            // under an activity-refreshing idle budget: keep going as long as
            // bytes keep flowing, give up after DRAIN_IDLE_TIMEOUT of silence.
            drain_with_idle_budget(
                &portal,
                "target_to_client",
                &mut target_to_client,
                &target_to_client_bytes,
            )
            .await;
        }
        EitherDone::Target(Ok(())) => {
            // Symmetric drain for target-initiated close.
            drain_with_idle_budget(
                &portal,
                "client_to_target",
                &mut client_to_target,
                &client_to_target_bytes,
            )
            .await;
        }
        EitherDone::Client(Err(err)) | EitherDone::Target(Err(err)) => return Err(err),
    }

    Ok(RelaySummary {
        client_to_target_bytes: client_to_target_bytes.load(Ordering::Relaxed),
        target_to_client_bytes: target_to_client_bytes.load(Ordering::Relaxed),
        first_eof,
    })
}

/// Drains the remaining relay direction under an *activity-refreshing* idle
/// budget instead of a fixed wall-clock window.
///
/// Every `DRAIN_IDLE_TICK` we sample the direction's byte counter. If it has
/// advanced since the last tick, the direction is still making progress and the
/// idle budget is reset; otherwise the idle budget is consumed. The drain ends
/// when the future completes naturally (clean EOF or error) OR when the
/// direction has been silent for `DRAIN_IDLE_TIMEOUT` consecutive seconds. This
/// lets a slow-but-steady download finish while releasing a parked keep-alive
/// carrier promptly.
async fn drain_with_idle_budget<F>(
    portal: &Arc<PortalInner>,
    dir: &'static str,
    future: &mut F,
    bytes: &Arc<AtomicU64>,
) where
    F: std::future::Future<Output = anyhow::Result<()>> + Unpin,
{
    let mut last_bytes = bytes.load(Ordering::Relaxed);
    let mut idle = Duration::ZERO;
    loop {
        // Try to make progress for one tick. If the future completes in that
        // window, the drain is done (clean EOF or error — either way the
        // direction finished).
        match tokio::time::timeout(DRAIN_IDLE_TICK, &mut *future).await {
            Ok(Ok(())) => return,
            Ok(Err(_err)) => return,
            Err(_) => {
                // The tick elapsed without the future completing. Sample bytes
                // to decide whether the direction is still active.
                let now_bytes = bytes.load(Ordering::Relaxed);
                if now_bytes != last_bytes {
                    last_bytes = now_bytes;
                    idle = Duration::ZERO;
                } else {
                    idle += DRAIN_IDLE_TICK;
                    if idle >= DRAIN_IDLE_TIMEOUT {
                        portal.logger.debug(format_args!(
                            "portal::conn::relay_stream: drain_idle_timeout dir={} idle_s={} tick_s={}",
                            dir,
                            idle.as_secs(),
                            DRAIN_IDLE_TICK.as_secs()
                        ));
                        return;
                    }
                }
            }
        }
    }
}

enum EitherDone {
    Client(anyhow::Result<()>),
    Target(anyhow::Result<()>),
}
