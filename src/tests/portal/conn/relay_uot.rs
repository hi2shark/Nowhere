use super::*;
use crate::protocol::{FlowErrorCode, read_flow_result};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncReadExt, AsyncWrite, duplex};
use tokio::sync::Notify;

struct PendingWriter {
    polled: Arc<Notify>,
}

#[derive(Default)]
struct PartialWriterState {
    bytes: Vec<u8>,
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
        read_flow_result(&mut peer).await.unwrap(),
        FlowResult::Reject(FlowErrorCode::SessionReplaced)
    );
    let mut byte = [0u8; 1];
    assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
}

#[tokio::test]
async fn quic_control_rejection_uses_single_result_byte_and_fin() {
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
    assert_eq!(state.lock().unwrap().bytes, vec![0]);
}
