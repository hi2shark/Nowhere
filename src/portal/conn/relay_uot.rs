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

use crate::common::{udp_dial_timeout, udp_idle_timeout};
use crate::portal::PortalInner;
use crate::portal::pairing::{PairedUdp, UdpDown, UdpUp};
use crate::protocol::{
    Carrier, FlowErrorCode, FlowResult, UDP_STREAM_CLOSE, UDP_STREAM_DATA, UDP_STREAM_READY,
    UDP_STREAM_REJECT, UdpStreamFrame, encode_udp_close, encode_udp_data_fragments,
    read_udp_stream_frame, write_flow_result, write_udp_stream_frame,
};

use super::{SessionGuard, UDP_TRANSFER_COMPLETE, UDP_TRANSFER_STARTING, paired_exchange_path};

const FLOW_RESULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);
const FLOW_CLOSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

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
        _flow_lease,
    } = paired;
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
        result = portal.outbound.dial_udp(&target_addr, udp_dial_timeout()) => result,
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
    match commit_udp_ready(&cancel, &mut downlink).await {
        Ok(true) => {}
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
                let Some(payload) = read_paired_udp(&mut uplink).await? else {
                    return anyhow::Ok(());
                };
                if let Some(limiter) = &portal.rate_limiter {
                    limiter.wait_read(payload.len() as i64).await;
                }
                let n = socket.send(&payload, &mut target_packet).await?;
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
                    SendPacketOutcome::Sent => {
                        portal.stats.udp_tx.fetch_add(n as u64, Ordering::Relaxed);
                        match downlink_carrier {
                            Carrier::TlsTcp => &portal.stats.down_tcp,
                            Carrier::Quic => &portal.stats.down_udp,
                        }
                        .fetch_add(n as u64, Ordering::Relaxed);
                    }
                    SendPacketOutcome::DroppedTooLarge => {}
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

async fn read_paired_udp(uplink: &mut UdpUp) -> anyhow::Result<Option<Bytes>> {
    match uplink {
        UdpUp::TlsTcp(reader) => match read_udp_stream_frame(reader).await? {
            Some(UdpStreamFrame::Data(payload)) => Ok(Some(Bytes::from(payload))),
            Some(UdpStreamFrame::Close) | None => Ok(None),
            Some(UdpStreamFrame::Ready) | Some(UdpStreamFrame::Reject(_)) => {
                anyhow::bail!("unexpected uplink control frame")
            }
        },
        UdpUp::Quic(receiver) => Ok(receiver.recv().await),
    }
}

async fn send_udp_result(downlink: &mut UdpDown, result: FlowResult) -> anyhow::Result<()> {
    match downlink {
        UdpDown::TlsTcp { writer, .. } => match result {
            FlowResult::Ready => write_udp_stream_frame(writer, UDP_STREAM_READY, &[]).await?,
            FlowResult::Reject(code) => {
                write_udp_stream_frame(writer, UDP_STREAM_REJECT, &[code as u8]).await?;
                writer.shutdown().await?;
            }
        },
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

enum SendPacketOutcome {
    Sent,
    DroppedTooLarge,
}

async fn send_paired_udp(
    downlink: &mut UdpDown,
    flow_id: u64,
    packet_id: &mut u32,
    payload: &[u8],
) -> anyhow::Result<SendPacketOutcome> {
    match downlink {
        UdpDown::TlsTcp { writer, .. } => {
            write_udp_stream_frame(writer, UDP_STREAM_DATA, payload).await?;
            Ok(SendPacketOutcome::Sent)
        }
        UdpDown::Quic { conn, .. } => send_quic_udp_packet(conn, flow_id, packet_id, payload).await,
    }
}

async fn send_quic_udp_packet(
    conn: &quinn::Connection,
    flow_id: u64,
    next_packet_id: &mut u32,
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

fn take_packet_id(next: &mut u32) -> u32 {
    let packet_id = *next;
    *next = next.wrapping_add(1);
    if *next == 0 {
        *next = 1;
    }
    packet_id
}

async fn send_udp_close(downlink: &mut UdpDown, flow_id: u64) -> anyhow::Result<()> {
    match downlink {
        UdpDown::TlsTcp { writer, .. } => {
            write_udp_stream_frame(writer, UDP_STREAM_CLOSE, &[]).await?;
        }
        UdpDown::Quic { conn, .. } => {
            conn.send_datagram_wait(Bytes::from(encode_udp_close(flow_id)?))
                .await?;
        }
    }
    Ok(())
}

async fn finish_udp_downlink(downlink: &mut UdpDown, flow_id: u64, frame_incomplete: bool) {
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
mod tests {
    use super::*;
    use crate::protocol::{FlowErrorCode, UdpStreamFrame, read_flow_result, read_udp_stream_frame};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::task::{Context, Poll};
    use tokio::io::AsyncWrite;
    use tokio::io::{AsyncReadExt, duplex};
    use tokio::sync::Notify;

    struct PendingWriter {
        polled: Arc<Notify>,
    }

    #[derive(Default)]
    struct PartialWriterState {
        bytes: Vec<u8>,
        close_mode: bool,
    }

    struct PartialDataWriter {
        state: Arc<Mutex<PartialWriterState>>,
        blocked: Arc<Notify>,
    }

    impl AsyncWrite for PendingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.polled.notify_one();
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for PartialDataWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let mut state = self.state.lock().unwrap();
            if state.close_mode || buf.first() == Some(&UDP_STREAM_CLOSE) {
                state.close_mode = true;
                state.bytes.extend_from_slice(buf);
                return Poll::Ready(Ok(buf.len()));
            }
            if state.bytes.is_empty() {
                state.bytes.push(buf[0]);
                return Poll::Ready(Ok(1));
            }
            drop(state);
            self.blocked.notify_one();
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn cancelled_uot_ready_returns_typed_session_replaced_and_fin() {
        let cancel = tokio_util::sync::CancellationToken::new();
        cancel.cancel();
        let (writer, mut peer) = duplex(64);
        let mut downlink = UdpDown::TlsTcp {
            writer: Box::pin(writer),
            liveness: None,
        };

        assert!(!commit_udp_ready(&cancel, &mut downlink).await.unwrap());

        assert_eq!(
            read_udp_stream_frame(&mut peer).await.unwrap(),
            Some(UdpStreamFrame::Reject(FlowErrorCode::SessionReplaced))
        );
        let mut byte = [0u8; 1];
        assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn quic_control_rejection_uses_f2_and_fin() {
        let (writer, mut peer) = duplex(64);
        let mut writer: crate::portal::pairing::BoxWriter = Box::pin(writer);

        send_quic_control_result(
            &mut writer,
            FlowResult::Reject(FlowErrorCode::SessionReplaced),
        )
        .await
        .unwrap();

        assert_eq!(
            read_flow_result(&mut peer).await.unwrap(),
            FlowResult::Reject(FlowErrorCode::SessionReplaced)
        );
        let mut byte = [0u8; 1];
        assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn blocked_uot_downlink_send_yields_to_flow_cancellation() {
        let polled = Arc::new(Notify::new());
        let mut downlink = UdpDown::TlsTcp {
            writer: Box::pin(PendingWriter {
                polled: polled.clone(),
            }),
            liveness: None,
        };
        let cancel = tokio_util::sync::CancellationToken::new();
        let task_cancel = cancel.clone();
        let task = tokio::spawn(async move {
            let mut packet_id = 1;
            tokio::select! {
                biased;
                _ = task_cancel.cancelled() => false,
                _ = send_paired_udp(&mut downlink, 1, &mut packet_id, b"blocked") => true,
            }
        });

        tokio::time::timeout(std::time::Duration::from_secs(1), polled.notified())
            .await
            .unwrap();
        cancel.cancel();
        assert!(
            !tokio::time::timeout(std::time::Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap()
        );
    }

    #[tokio::test]
    async fn interrupted_uot_data_frame_does_not_append_close() {
        let state = Arc::new(Mutex::new(PartialWriterState::default()));
        let blocked = Arc::new(Notify::new());
        let mut downlink = UdpDown::TlsTcp {
            writer: Box::pin(PartialDataWriter {
                state: state.clone(),
                blocked: blocked.clone(),
            }),
            liveness: None,
        };
        let cancel = tokio_util::sync::CancellationToken::new();
        let task_cancel = cancel.clone();
        let task = tokio::spawn(async move {
            let mut packet_id = 1;
            let mut frame_incomplete = false;
            tokio::select! {
                biased;
                _ = task_cancel.cancelled() => {}
                _ = async {
                    frame_incomplete = true;
                    let result = send_paired_udp(
                        &mut downlink,
                        1,
                        &mut packet_id,
                        b"partial",
                    ).await;
                    if result.is_ok() {
                        frame_incomplete = false;
                    }
                    result
                } => panic!("partial writer unexpectedly completed"),
            }
            finish_udp_downlink(&mut downlink, 1, frame_incomplete).await;
        });

        tokio::time::timeout(std::time::Duration::from_secs(1), blocked.notified())
            .await
            .unwrap();
        cancel.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.lock().unwrap().bytes, vec![UDP_STREAM_DATA]);
    }

    #[test]
    fn packet_id_wrap_skips_zero() {
        let mut next = u32::MAX;
        assert_eq!(take_packet_id(&mut next), u32::MAX);
        assert_eq!(next, 1);
        assert_eq!(take_packet_id(&mut next), 1);
        assert_eq!(next, 2);
    }
}
