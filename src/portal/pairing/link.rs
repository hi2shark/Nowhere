// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Pairing link lifecycle and guarded I/O wrappers.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite};

use super::PairingRegistry;
use super::state::{ActiveQuic, BoxReader, BoxWriter};
use crate::protocol::SessionId;
use crate::transport::Stats;

struct GuardedReader<R> {
    inner: R,
    _guard: LinkGuard,
}

impl<R: AsyncRead + Unpin> AsyncRead for GuardedReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

struct GuardedWriter<W> {
    inner: W,
    _guard: LinkGuard,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for GuardedWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub(in crate::portal) fn guarded_reader<R: AsyncRead + Send + Unpin + 'static>(
    reader: R,
    guard: LinkGuard,
) -> BoxReader {
    Box::pin(GuardedReader {
        inner: reader,
        _guard: guard,
    })
}

pub(in crate::portal) fn guarded_writer<W: AsyncWrite + Send + Unpin + 'static>(
    writer: W,
    guard: LinkGuard,
) -> BoxWriter {
    Box::pin(GuardedWriter {
        inner: writer,
        _guard: guard,
    })
}

pub(in crate::portal) struct LinkGuard {
    registry: Arc<PairingRegistry>,
    stats: Arc<Stats>,
    session_id: SessionId,
    carrier: crate::protocol::Carrier,
    quic_generation: Option<u64>,
}

impl LinkGuard {
    pub(in crate::portal) fn quic_generation(&self) -> u64 {
        self.quic_generation.expect("QUIC link guard generation")
    }
}

impl Drop for LinkGuard {
    fn drop(&mut self) {
        let mut links = self.registry.links.lock().expect("link registry poisoned");
        let Some(counts) = links.get_mut(&self.session_id) else {
            return;
        };
        let was_paired = counts.tcp > 0 && counts.udp.is_some();
        match self.carrier {
            crate::protocol::Carrier::Tcp => counts.tcp = counts.tcp.saturating_sub(1),
            crate::protocol::Carrier::Udp => {
                let Some(generation) = self.quic_generation else {
                    return;
                };
                if counts.udp.as_ref().map(|active| active.generation) != Some(generation) {
                    return;
                }
                counts.udp = None;
            }
        }
        let is_paired = counts.tcp > 0 && counts.udp.is_some();
        if was_paired && !is_paired {
            self.stats.link_pairs.fetch_sub(1, Ordering::Relaxed);
        }
        if counts.tcp == 0 && counts.udp.is_none() {
            links.remove(&self.session_id);
        }
        match self.carrier {
            crate::protocol::Carrier::Tcp => &self.stats.link_tcp,
            crate::protocol::Carrier::Udp => &self.stats.link_udp,
        }
        .fetch_sub(1, Ordering::Relaxed);
    }
}

impl PairingRegistry {
    pub(in crate::portal) fn register_tcp_link(
        self: &Arc<Self>,
        session_id: SessionId,
        stats: Arc<Stats>,
    ) -> LinkGuard {
        let mut links = self.links.lock().expect("link registry poisoned");
        let counts = links.entry(session_id).or_default();
        let was_paired = counts.tcp > 0 && counts.udp.is_some();
        counts.tcp += 1;
        let is_paired = counts.udp.is_some();
        if !was_paired && is_paired {
            stats.link_pairs.fetch_add(1, Ordering::Relaxed);
        }
        stats.link_tcp.fetch_add(1, Ordering::Relaxed);
        drop(links);
        LinkGuard {
            registry: self.clone(),
            stats,
            session_id,
            carrier: crate::protocol::Carrier::Tcp,
            quic_generation: None,
        }
    }

    /// Registers the latest authenticated QUIC carrier for a transport bundle.
    pub(in crate::portal) fn register_quic_link(
        self: &Arc<Self>,
        session_id: SessionId,
        stats: Arc<Stats>,
        replacement: tokio_util::sync::CancellationToken,
    ) -> LinkGuard {
        let generation = self.next_quic_generation.fetch_add(1, Ordering::Relaxed);
        let mut links = self.links.lock().expect("link registry poisoned");
        let counts = links.entry(session_id).or_default();
        let was_paired = counts.tcp > 0 && counts.udp.is_some();
        let previous = counts.udp.replace(ActiveQuic {
            generation,
            replacement,
        });
        let is_paired = counts.tcp > 0;
        if previous.is_none() {
            stats.link_udp.fetch_add(1, Ordering::Relaxed);
            if !was_paired && is_paired {
                stats.link_pairs.fetch_add(1, Ordering::Relaxed);
            }
        }
        drop(links);
        if let Some(previous) = previous {
            previous.replacement.cancel();
        }
        LinkGuard {
            registry: self.clone(),
            stats,
            session_id,
            carrier: crate::protocol::Carrier::Udp,
            quic_generation: Some(generation),
        }
    }
}
