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

    let mut result = [0u8; 1];
    peer.read_exact(&mut result).await.unwrap();
    cancel.cancel();
    task.await.unwrap();

    assert_eq!(result, encode_flow_result(FlowResult::Ready));
    let mut byte = [0u8; 1];
    assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
}
