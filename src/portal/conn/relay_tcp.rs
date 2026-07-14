// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! TCP target dialing and split/duplex stream relay.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common::tcp_dial_timeout;
use crate::portal::PortalInner;
use crate::portal::pairing::PairedTcp;
use crate::protocol::{FlowErrorCode, FlowResult, write_flow_result};

use super::stream::relay_stream;
use super::{SessionGuard, TCP_EXCHANGE_COMPLETE, TCP_EXCHANGE_STARTING, paired_exchange_path};

const FLOW_RESULT_TIMEOUT: Duration = Duration::from_secs(1);

/// Relays a TCP target through independently selected upload and download halves.
pub(in crate::portal) async fn relay_paired_tcp(portal: Arc<PortalInner>, paired: PairedTcp) {
    let PairedTcp {
        target: target_addr,
        uplink: mut client_read,
        downlink: mut client_write,
        downlink_liveness,
        uplink_carrier: uplink,
        downlink_carrier: downlink,
        uplink_path,
        downlink_path,
        _flow_lease,
    } = paired;
    let cancel = _flow_lease.cancellation_token();
    let target_conn = match tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            let _ = write_flow_result_bounded(
                &mut client_write,
                FlowResult::Reject(FlowErrorCode::SessionReplaced),
                true,
            ).await;
            return;
        },
        result = portal.outbound.dial_tcp(&target_addr, tcp_dial_timeout()) => result,
    } {
        Ok(conn) => conn,
        Err(err) => {
            let code = if cancel.is_cancelled() {
                FlowErrorCode::SessionReplaced
            } else {
                FlowErrorCode::DialFailed
            };
            let _ =
                write_flow_result_bounded(&mut client_write, FlowResult::Reject(code), true).await;
            portal.logger.debug(format_args!(
                "portal::conn::relay_paired_tcp: target dial failed: {err}"
            ));
            return;
        }
    };
    match commit_ready(&cancel, &mut client_write).await {
        Ok(true) => {}
        Ok(false) | Err(_) => return,
    }
    portal.stats.add_session(false);
    let _done = SessionGuard::new(portal.clone(), false);
    if portal.logger.debug_enabled() {
        let target_local = target_conn
            .local_addr()
            .map(|address| address.to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());
        portal.logger.debug(format_args!(
            "portal::conn::relay_paired_tcp: {}: {}",
            TCP_EXCHANGE_STARTING,
            paired_exchange_path(
                uplink,
                &uplink_path,
                &target_local,
                &target_addr,
                downlink,
                &downlink_path,
            )
        ));
    }

    let relay = relay_stream(
        portal.clone(),
        &mut client_read,
        &mut client_write,
        target_conn,
        portal.buffers.get_tcp_buffer(),
        portal.buffers.get_tcp_buffer(),
        Some((uplink, downlink)),
    );
    tokio::pin!(relay);
    let result = if let Some(mut liveness) = downlink_liveness {
        let mut byte = [0u8; 1];
        tokio::select! {
            result = &mut relay => Some(result),
            _ = cancel.cancelled() => None,
            _ = liveness.read(&mut byte) => None,
        }
    } else {
        tokio::select! {
            result = &mut relay => Some(result),
            _ = cancel.cancelled() => None,
        }
    };
    portal.logger.debug(format_args!(
        "portal::conn::relay_paired_tcp: {}: {}",
        TCP_EXCHANGE_COMPLETE,
        match result {
            Some(Ok(())) => "EOF".to_string(),
            Some(Err(err)) => err.to_string(),
            None => "cancelled".to_string(),
        }
    ));
}

/// Commits the single setup result. Cancellation is sampled before the READY
/// write starts; after that point READY owns the writer and must finish without
/// a competing REJECT that could corrupt a partially written frame.
async fn commit_ready(
    cancel: &tokio_util::sync::CancellationToken,
    writer: &mut crate::portal::pairing::BoxWriter,
) -> anyhow::Result<bool> {
    if cancel.is_cancelled() {
        write_flow_result_bounded(
            writer,
            FlowResult::Reject(FlowErrorCode::SessionReplaced),
            true,
        )
        .await?;
        return Ok(false);
    }
    write_flow_result_bounded(writer, FlowResult::Ready, false).await?;
    Ok(true)
}

async fn write_flow_result_bounded(
    writer: &mut crate::portal::pairing::BoxWriter,
    result: FlowResult,
    finish: bool,
) -> anyhow::Result<()> {
    tokio::time::timeout(FLOW_RESULT_TIMEOUT, async {
        write_flow_result(writer, result).await?;
        if finish {
            writer.shutdown().await?;
        }
        anyhow::Ok(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("flow result write timeout"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{encode_flow_result, read_flow_result};
    use tokio::io::{AsyncReadExt, duplex};

    #[tokio::test]
    async fn cancellation_before_ready_returns_session_replaced_and_fin() {
        let cancel = tokio_util::sync::CancellationToken::new();
        cancel.cancel();
        let (writer, mut peer) = duplex(64);
        let mut writer: crate::portal::pairing::BoxWriter = Box::pin(writer);

        assert!(!commit_ready(&cancel, &mut writer).await.unwrap());

        assert_eq!(
            read_flow_result(&mut peer).await.unwrap(),
            FlowResult::Reject(FlowErrorCode::SessionReplaced)
        );
        let mut byte = [0u8; 1];
        assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn cancellation_during_ready_never_appends_a_second_result() {
        let cancel = tokio_util::sync::CancellationToken::new();
        let task_cancel = cancel.clone();
        let (writer, mut peer) = duplex(1);
        let task = tokio::spawn(async move {
            let mut writer: crate::portal::pairing::BoxWriter = Box::pin(writer);
            assert!(commit_ready(&task_cancel, &mut writer).await.unwrap());
        });

        let mut result = [0u8; 4];
        peer.read_exact(&mut result[..1]).await.unwrap();
        cancel.cancel();
        peer.read_exact(&mut result[1..]).await.unwrap();
        task.await.unwrap();

        assert_eq!(result, encode_flow_result(FlowResult::Ready));
        let mut byte = [0u8; 1];
        assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
    }
}
