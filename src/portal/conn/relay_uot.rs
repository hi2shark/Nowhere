// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Typed UoT and QUIC DATAGRAM relay for split or duplex UDP flows.

use std::future::pending;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::time::Instant;

use crate::common::{UdpDatagramSend, send_quic_udp_packet, udp_dial_timeout, udp_idle_timeout};
use crate::portal::PortalInner;
use crate::portal::pairing::{PairedUdp, UdpDown, UdpUp};
use crate::protocol::{
    Carrier, FlowErrorCode, FlowResult, encode_udp_close, read_udp_packet_into, write_flow_result,
    write_udp_packet,
};

use super::{SessionGuard, UDP_TRANSFER_COMPLETE, UDP_TRANSFER_STARTING, paired_exchange_path};

const FLOW_RESULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);
const FLOW_CLOSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// Relays one UDP flow through independently selected upload and download carriers.
pub(in crate::portal) async fn relay_paired_udp(portal: Arc<PortalInner>, paired: PairedUdp) {
    let PairedUdp {
        flow_id,
        target,
        mut uplink,
        mut downlink,
        uplink_carrier,
        downlink_carrier,
        uplink_path,
        downlink_path,
        _flow_lease,
    } = paired;
    let target_addr = target.to_string();
    let cancel = _flow_lease.cancellation_token();
    let socket = match tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            let _ = send_udp_result_bounded(
                &mut downlink,
                FlowResult::Reject(FlowErrorCode::SessionReplaced),
            ).await;
            return;
        },
        result = portal.outbound.dial_udp_target(&target, udp_dial_timeout()) => result,
    } {
        Ok(socket) => socket,
        Err(err) => {
            let code = if cancel.is_cancelled() {
                FlowErrorCode::SessionReplaced
            } else {
                FlowErrorCode::DialFailed
            };
            let _ = send_udp_result_bounded(&mut downlink, FlowResult::Reject(code)).await;
            portal.logger.debug(format_args!(
                "portal::conn::relay_paired_udp: target dial failed: {err}"
            ));
            return;
        }
    };
    if let UdpUp::Quic(receiver) = &mut uplink
        && !receiver.prepare_ready().await
    {
        let _ = send_udp_result_bounded(
            &mut downlink,
            FlowResult::Reject(FlowErrorCode::InternalError),
        )
        .await;
        return;
    }
    match commit_udp_ready(&cancel, &mut downlink).await {
        Ok(true) => {
            // READY is now queued on the authoritative downlink. Activate the
            // DATAGRAM route synchronously before the peer can observe it and
            // return its first packet.
            if let UdpUp::Quic(receiver) = &uplink {
                receiver.activate();
            }
        }
        Ok(false) | Err(_) => return,
    }
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
    let mut packet_id = 1u32;
    let mut target_buf = portal.buffers.get_udp_buffer();
    let mut target_packet = Vec::new();
    let mut uot_packet = Vec::new();
    let mut downlink_liveness = match &mut downlink {
        UdpDown::TlsTcp { liveness, .. } => liveness.take(),
        UdpDown::Quic { .. } => None,
    };
    let idle_sleep = tokio::time::sleep_until(Instant::now() + udp_idle_timeout());
    tokio::pin!(idle_sleep);
    let activity = Notify::new();
    let mut downlink_frame_incomplete = false;
    let complete_reason = {
        let uplink_pipeline = async {
            loop {
                let n = match &mut uplink {
                    UdpUp::TlsTcp(reader) => {
                        let Some(length) = read_udp_packet_into(reader, &mut uot_packet).await?
                        else {
                            return anyhow::Ok(());
                        };
                        if let Some(limiter) = &portal.rate_limiter {
                            limiter.wait_read(length as i64).await;
                        }
                        socket
                            .send(&uot_packet[..length], &mut target_packet)
                            .await?
                    }
                    UdpUp::Quic(receiver) => {
                        let Some(payload) = receiver.recv().await else {
                            return anyhow::Ok(());
                        };
                        if let Some(limiter) = &portal.rate_limiter {
                            limiter.wait_read(payload.len() as i64).await;
                        }
                        socket.send(&payload, &mut target_packet).await?
                    }
                };
                portal.stats.udp_rx.fetch_add(n as u64, Ordering::Relaxed);
                match uplink_carrier {
                    Carrier::TlsTcp => &portal.stats.up_tcp,
                    Carrier::Quic => &portal.stats.up_udp,
                }
                .fetch_add(n as u64, Ordering::Relaxed);
                activity.notify_one();
            }
        };
        let downlink_pipeline = async {
            loop {
                let range = match socket.recv(&mut target_buf).await {
                    Ok(range) => range,
                    Err(err) => return Err::<(), anyhow::Error>(err),
                };
                let payload = &target_buf[range];
                let n = payload.len();
                if let Some(limiter) = &portal.rate_limiter {
                    limiter.wait_write(n as i64).await;
                }
                downlink_frame_incomplete = true;
                let outcome =
                    send_paired_udp(&mut downlink, flow_id, &mut packet_id, payload).await;
                let outcome = match outcome {
                    Ok(outcome) => {
                        downlink_frame_incomplete = false;
                        outcome
                    }
                    Err(err) => return Err::<(), anyhow::Error>(err),
                };
                match outcome {
                    UdpDatagramSend::Sent => {
                        portal.stats.udp_tx.fetch_add(n as u64, Ordering::Relaxed);
                        match downlink_carrier {
                            Carrier::TlsTcp => &portal.stats.down_tcp,
                            Carrier::Quic => &portal.stats.down_udp,
                        }
                        .fetch_add(n as u64, Ordering::Relaxed);
                    }
                    UdpDatagramSend::DroppedTooLarge => {}
                }
                activity.notify_one();
            }
        };
        tokio::pin!(uplink_pipeline);
        tokio::pin!(downlink_pipeline);
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break "cancelled".to_string(),
                _ = async {
                    if let Some(liveness) = &mut downlink_liveness {
                        let mut byte = [0u8; 1];
                        let _ = liveness.read(&mut byte).await;
                    } else {
                        pending::<()>().await;
                    }
                } => break "downlink closed".to_string(),
                result = &mut uplink_pipeline => break match result {
                    Ok(()) => "uplink closed".to_string(),
                    Err(err) => format!("uplink or target write error: {err}"),
                },
                result = &mut downlink_pipeline => break match result {
                    Ok(()) => "downlink closed".to_string(),
                    Err(err) => format!("target read or downlink write error: {err}"),
                },
                _ = activity.notified() => {
                    idle_sleep.as_mut().reset(Instant::now() + udp_idle_timeout());
                }
                _ = &mut idle_sleep => break "idle timeout".to_string(),
            }
        }
    };
    finish_udp_downlink(&mut downlink, flow_id, downlink_frame_incomplete).await;
    portal.logger.debug(format_args!(
        "portal::conn::relay_paired_udp: {}: {complete_reason}",
        UDP_TRANSFER_COMPLETE
    ));
}

async fn send_udp_result(downlink: &mut UdpDown, result: FlowResult) -> anyhow::Result<()> {
    match downlink {
        UdpDown::TlsTcp { writer, .. } => {
            write_flow_result(writer, result).await?;
            if matches!(result, FlowResult::Reject(_)) {
                writer.shutdown().await?;
            }
        }
        UdpDown::Quic { control, .. } => {
            send_quic_control_result(control, result).await?;
        }
    }
    Ok(())
}

async fn send_quic_control_result(
    control: &mut crate::portal::pairing::BoxWriter,
    result: FlowResult,
) -> anyhow::Result<()> {
    write_flow_result(control, result).await?;
    control.shutdown().await?;
    Ok(())
}

/// Commits the single setup result. As with TCP, cancellation is sampled only
/// before READY starts so a partially written READY is never followed by a
/// second control result.
async fn commit_udp_ready(
    cancel: &tokio_util::sync::CancellationToken,
    downlink: &mut UdpDown,
) -> anyhow::Result<bool> {
    if cancel.is_cancelled() {
        send_udp_result_bounded(downlink, FlowResult::Reject(FlowErrorCode::SessionReplaced))
            .await?;
        return Ok(false);
    }
    send_udp_result_bounded(downlink, FlowResult::Ready).await?;
    Ok(true)
}

async fn send_udp_result_bounded(downlink: &mut UdpDown, result: FlowResult) -> anyhow::Result<()> {
    tokio::time::timeout(FLOW_RESULT_TIMEOUT, send_udp_result(downlink, result))
        .await
        .map_err(|_| anyhow::anyhow!("flow result write timeout"))?
}

async fn send_paired_udp(
    downlink: &mut UdpDown,
    flow_id: u32,
    packet_id: &mut u32,
    payload: &[u8],
) -> anyhow::Result<UdpDatagramSend> {
    match downlink {
        UdpDown::TlsTcp { writer, .. } => {
            write_udp_packet(writer, payload).await?;
            Ok(UdpDatagramSend::Sent)
        }
        UdpDown::Quic { conn, .. } => send_quic_udp_packet(conn, flow_id, packet_id, payload).await,
    }
}

async fn send_udp_close(downlink: &mut UdpDown, flow_id: u32) -> anyhow::Result<()> {
    match downlink {
        UdpDown::TlsTcp { writer, .. } => {
            writer.shutdown().await?;
        }
        UdpDown::Quic { conn, .. } => {
            conn.send_datagram_wait(Bytes::copy_from_slice(&encode_udp_close(flow_id)?))
                .await?;
        }
    }
    Ok(())
}

async fn finish_udp_downlink(downlink: &mut UdpDown, flow_id: u32, frame_incomplete: bool) {
    // A cancelled write_all may have emitted only a prefix of a UoT DATA
    // frame. Appending CLOSE would corrupt the stream; each UoT flow owns its
    // connection, so EOF is the only safe termination in that case. QUIC
    // DATAGRAM frames are atomic and can still receive an advisory CLOSE.
    if frame_incomplete && matches!(&*downlink, UdpDown::TlsTcp { .. }) {
        return;
    }
    let _ = tokio::time::timeout(FLOW_CLOSE_TIMEOUT, send_udp_close(downlink, flow_id)).await;
}

#[cfg(test)]
#[path = "../../tests/portal/conn/relay_uot.rs"]
mod tests;
