// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! UDP-over-TCP and split-carrier UDP relay loops.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::{Instant, timeout};

use crate::common::{handshake_timeout, udp_dial_timeout, udp_idle_timeout};
use crate::portal::PortalInner;
use crate::portal::pairing::PairedUdp;
use crate::protocol::{
    Carrier, UDP_FRAME_CLOSE, UDP_FRAME_OPEN_ACK, UDP_STREAM_CLOSE, UDP_STREAM_DATA,
    UDP_STREAM_OPEN_ACK, UdpStreamFrame, encode_udp_control, encode_udp_data_fragments,
    read_udp_stream_frame, read_uot_setup_target, write_udp_stream_frame,
};

use super::{
    SessionGuard, UDP_TRANSFER_COMPLETE, UDP_TRANSFER_STARTING, paired_exchange_path,
    symmetric_exchange_path,
};

/// Relays UDP packets through a typed TCP stream after UoT setup.
pub(in crate::portal::conn) async fn relay_udp_over_tcp_target<R, W>(
    portal: Arc<PortalInner>,
    client_read: &mut R,
    client_write: &mut W,
    peer: SocketAddr,
    local: Option<SocketAddr>,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let target_addr = match timeout(handshake_timeout(), read_uot_setup_target(client_read)).await {
        Ok(Ok(target)) => target,
        Ok(Err(err)) => {
            portal.logger.error(format_args!(
                "portal::conn::relay_udp_over_tcp_target: failed to read setup target: {err}"
            ));
            return;
        }
        Err(_) => {
            portal.logger.error(format_args!(
                "portal::conn::relay_udp_over_tcp_target: failed to read setup target: deadline elapsed"
            ));
            return;
        }
    };

    let socket = match portal
        .outbound
        .dial_udp(&target_addr, udp_dial_timeout())
        .await
    {
        Ok(socket) => socket,
        Err(err) => {
            portal.logger.error(format_args!(
                "portal::conn::relay_udp_over_tcp_target: failed to dial target: {err}"
            ));
            return;
        }
    };
    if portal.logger.debug_enabled() {
        let peer = peer.to_string();
        let local = local.map_or_else(
            || portal.endpoint_addr.clone(),
            |address| address.to_string(),
        );
        let target_local = socket
            .local_addr()
            .map(|address| address.to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());
        portal.logger.debug(format_args!(
            "portal::conn::relay_udp_over_tcp_target: {}: {}",
            UDP_TRANSFER_STARTING,
            symmetric_exchange_path(Carrier::Tcp, &peer, &local, &target_local, &target_addr)
        ));
    }

    portal.stats.add_session(true);
    let _done = SessionGuard::new(portal.clone(), true);
    let mut target_buf = portal.buffers.get_udp_buffer();
    let mut target_packet = Vec::new();
    let idle_sleep = tokio::time::sleep_until(Instant::now() + udp_idle_timeout());
    tokio::pin!(idle_sleep);

    let complete_reason = loop {
        tokio::select! {
            frame = read_udp_stream_frame(client_read) => {
                let payload = match frame {
                    Ok(Some(UdpStreamFrame::Data(payload))) => payload,
                    Ok(Some(UdpStreamFrame::Close)) => break "client CLOSE".to_string(),
                    Ok(Some(UdpStreamFrame::OpenAck)) => break "unexpected client ACK".to_string(),
                    Ok(None) => break "client EOF".to_string(),
                    Err(err) => break format!("client frame error: {err}"),
                };
                idle_sleep.as_mut().reset(Instant::now() + udp_idle_timeout());
                if let Some(limiter) = &portal.rate_limiter {
                    limiter.wait_read(payload.len() as i64).await;
                }
                match socket.send(&payload, &mut target_packet).await {
                    Ok(n) => {
                        portal.stats.udp_rx.fetch_add(n as u64, Ordering::Relaxed);
                        portal.stats.up_tcp.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    Err(err) => {
                        portal.logger.error(format_args!(
                            "portal::conn::relay_udp_over_tcp_target: failed to write target: {err}"
                        ));
                        break format!("target write error: {err}");
                    }
                }
            }
            read = socket.recv(&mut target_buf) => {
                let payload = match read {
                    Ok(range) => &target_buf[range],
                    Err(err) => break format!("target read error: {err}"),
                };
                let n = payload.len();
                idle_sleep.as_mut().reset(Instant::now() + udp_idle_timeout());
                if let Some(limiter) = &portal.rate_limiter {
                    limiter.wait_write(n as i64).await;
                }
                if let Err(err) = write_udp_stream_frame(client_write, UDP_STREAM_DATA, payload).await {
                    break format!("client write error: {err}");
                }
                portal.stats.udp_tx.fetch_add(n as u64, Ordering::Relaxed);
                portal.stats.down_tcp.fetch_add(n as u64, Ordering::Relaxed);
            }
            _ = &mut idle_sleep => break "idle timeout".to_string(),
        }
    };
    portal.logger.debug(format_args!(
        "portal::conn::relay_udp_over_tcp_target: {}: {complete_reason}",
        UDP_TRANSFER_COMPLETE
    ));
}

/// Relays one UDP flow through independently selected upload and download carriers.
pub(in crate::portal) async fn relay_paired_udp(portal: Arc<PortalInner>, paired: PairedUdp) {
    let PairedUdp {
        flow_id,
        target: target_addr,
        mut uplink,
        mut downlink,
        uplink_carrier,
        downlink_carrier,
        uplink_path,
        downlink_path,
        udp_ack,
        _flow_permit,
    } = paired;
    let socket = match portal
        .outbound
        .dial_udp(&target_addr, udp_dial_timeout())
        .await
    {
        Ok(socket) => socket,
        Err(err) => {
            portal.logger.error(format_args!(
                "portal::conn::relay_paired_udp: failed to dial target {target_addr}: {err}"
            ));
            return;
        }
    };
    if portal.logger.debug_enabled() {
        let target_local = socket
            .local_addr()
            .map(|address| address.to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());
        portal.logger.debug(format_args!(
            "portal::conn::relay_paired_udp: {}: {}",
            UDP_TRANSFER_STARTING,
            paired_exchange_path(
                uplink_carrier,
                &uplink_path,
                &target_local,
                &target_addr,
                downlink_carrier,
                &downlink_path,
            )
        ));
    }
    portal.stats.add_session(true);
    let _done = SessionGuard::new(portal.clone(), true);
    let mut ack_sent = false;
    let mut packet_id = 1u16;
    let mut target_buf = portal.buffers.get_udp_buffer();
    let mut target_packet = Vec::new();
    let idle_sleep = tokio::time::sleep_until(Instant::now() + udp_idle_timeout());
    tokio::pin!(idle_sleep);
    let complete_reason = loop {
        tokio::select! {
            packet = read_paired_udp(&mut uplink) => {
                let payload = match packet {
                    Ok(Some(payload)) => payload,
                    Ok(None) => break "uplink CLOSE or EOF".to_string(),
                    Err(err) => break format!("uplink error: {err}"),
                };
                idle_sleep.as_mut().reset(Instant::now() + udp_idle_timeout());
                if let Some(limiter) = &portal.rate_limiter {
                    limiter.wait_read(payload.len() as i64).await;
                }
                match socket.send(&payload, &mut target_packet).await {
                    Ok(n) => {
                        if !ack_sent {
                            if let Err(err) = send_udp_ack(&mut downlink, flow_id, udp_ack.as_ref()).await {
                                break format!("client ACK write error: {err}");
                            }
                            ack_sent = true;
                        }
                        portal.stats.udp_rx.fetch_add(n as u64, Ordering::Relaxed);
                        match uplink_carrier {
                            Carrier::Tcp => &portal.stats.up_tcp,
                            Carrier::Udp => &portal.stats.up_udp,
                        }.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    Err(err) => break format!("target write error: {err}"),
                }
            }
            read = socket.recv(&mut target_buf) => {
                let payload = match read {
                    Ok(range) => &target_buf[range],
                    Err(err) => break format!("target read error: {err}"),
                };
                let n = payload.len();
                idle_sleep.as_mut().reset(Instant::now() + udp_idle_timeout());
                if let Some(limiter) = &portal.rate_limiter {
                    limiter.wait_write(n as i64).await;
                }
                match send_paired_udp(&mut downlink, flow_id, &mut packet_id, payload).await {
                    Ok(SendPacketOutcome::Sent) => {
                        portal.stats.udp_tx.fetch_add(n as u64, Ordering::Relaxed);
                        match downlink_carrier {
                            Carrier::Tcp => &portal.stats.down_tcp,
                            Carrier::Udp => &portal.stats.down_udp,
                        }.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    Ok(SendPacketOutcome::DroppedTooLarge) => {}
                    Err(err) => break format!("client write error: {err}"),
                }
            }
            _ = &mut idle_sleep => break "idle timeout".to_string(),
        }
    };
    if let Err(err) = send_udp_close(&mut downlink, flow_id).await {
        portal.logger.debug(format_args!(
            "portal::conn::relay_paired_udp: failed to send CLOSE: {err}"
        ));
    }
    portal.logger.debug(format_args!(
        "portal::conn::relay_paired_udp: {}: {complete_reason}",
        UDP_TRANSFER_COMPLETE
    ));
}

async fn read_paired_udp(
    uplink: &mut crate::portal::pairing::UdpUp,
) -> anyhow::Result<Option<Bytes>> {
    match uplink {
        crate::portal::pairing::UdpUp::Tcp(reader) => match read_udp_stream_frame(reader).await? {
            Some(UdpStreamFrame::Data(payload)) => Ok(Some(Bytes::from(payload))),
            Some(UdpStreamFrame::Close) | None => Ok(None),
            Some(UdpStreamFrame::OpenAck) => anyhow::bail!("unexpected uplink ACK"),
        },
        crate::portal::pairing::UdpUp::Quic(receiver) => Ok(receiver.recv().await),
    }
}

async fn send_udp_ack(
    downlink: &mut crate::portal::pairing::UdpDown,
    flow_id: u64,
    udp_ack: Option<&crate::portal::pairing::UdpAck>,
) -> anyhow::Result<()> {
    match downlink {
        crate::portal::pairing::UdpDown::Tcp(writer) => {
            write_udp_stream_frame(writer, UDP_STREAM_OPEN_ACK, &[]).await?;
        }
        crate::portal::pairing::UdpDown::Quic(conn) if udp_ack.is_none() => {
            send_quic_control(conn, UDP_FRAME_OPEN_ACK, flow_id).await?;
        }
        crate::portal::pairing::UdpDown::Quic(_) => {}
    }
    if let Some(ack) = udp_ack {
        send_quic_control(&ack.conn, UDP_FRAME_OPEN_ACK, flow_id).await?;
        ack.acked.store(true, Ordering::Release);
    }
    Ok(())
}

enum SendPacketOutcome {
    Sent,
    DroppedTooLarge,
}

async fn send_paired_udp(
    downlink: &mut crate::portal::pairing::UdpDown,
    flow_id: u64,
    packet_id: &mut u16,
    payload: &[u8],
) -> anyhow::Result<SendPacketOutcome> {
    match downlink {
        crate::portal::pairing::UdpDown::Tcp(writer) => {
            write_udp_stream_frame(writer, UDP_STREAM_DATA, payload).await?;
            Ok(SendPacketOutcome::Sent)
        }
        crate::portal::pairing::UdpDown::Quic(conn) => {
            send_quic_udp_packet(conn, flow_id, packet_id, payload).await
        }
    }
}

async fn send_quic_udp_packet(
    conn: &quinn::Connection,
    flow_id: u64,
    next_packet_id: &mut u16,
    payload: &[u8],
) -> anyhow::Result<SendPacketOutcome> {
    for _ in 0..2 {
        let max_size = conn
            .max_datagram_size()
            .ok_or_else(|| anyhow::anyhow!("QUIC DATAGRAM unsupported"))?;
        let packet_id = take_packet_id(next_packet_id);
        let frames = match encode_udp_data_fragments(flow_id, packet_id, payload, max_size) {
            Ok(frames) => frames,
            Err(_) => return Ok(SendPacketOutcome::DroppedTooLarge),
        };
        let mut too_large = false;
        for frame in frames {
            match conn.send_datagram_wait(Bytes::from(frame)).await {
                Ok(()) => {}
                Err(quinn::SendDatagramError::TooLarge) => {
                    too_large = true;
                    break;
                }
                Err(err) => return Err(err.into()),
            }
        }
        if !too_large {
            return Ok(SendPacketOutcome::Sent);
        }
    }
    Ok(SendPacketOutcome::DroppedTooLarge)
}

fn take_packet_id(next: &mut u16) -> u16 {
    let packet_id = *next;
    *next = next.wrapping_add(1);
    if *next == 0 {
        *next = 1;
    }
    packet_id
}

async fn send_udp_close(
    downlink: &mut crate::portal::pairing::UdpDown,
    flow_id: u64,
) -> anyhow::Result<()> {
    match downlink {
        crate::portal::pairing::UdpDown::Tcp(writer) => {
            write_udp_stream_frame(writer, UDP_STREAM_CLOSE, &[]).await?;
        }
        crate::portal::pairing::UdpDown::Quic(conn) => {
            send_quic_control(conn, UDP_FRAME_CLOSE, flow_id).await?;
        }
    }
    Ok(())
}

async fn send_quic_control(
    conn: &quinn::Connection,
    frame_type: u8,
    flow_id: u64,
) -> anyhow::Result<()> {
    let frame = encode_udp_control(frame_type, flow_id)?;
    conn.send_datagram_wait(Bytes::from(frame)).await?;
    Ok(())
}
