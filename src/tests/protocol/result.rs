// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

use super::*;

#[test]
fn every_result_has_one_stable_wire_byte() {
    let cases = [
        SetupResult::Ready,
        SetupResult::InvalidRequest,
        SetupResult::MetadataConflict,
        SetupResult::PairTimeout,
        SetupResult::FlowLimit,
        SetupResult::DialFailed,
        SetupResult::SessionReplaced,
        SetupResult::InternalError,
    ];
    for (byte, result) in cases.into_iter().enumerate() {
        assert_eq!(encode_setup_result(result), [byte as u8]);
        assert_eq!(decode_setup_result(&[byte as u8]).unwrap(), result);
        assert!(!result.as_str().is_empty());
    }
    assert!(SetupResult::Ready.is_ready());
    assert!(!SetupResult::DialFailed.is_ready());
}

#[test]
fn application_flow_result_converts_without_changing_the_wire() {
    assert_eq!(encode_flow_result(FlowResult::Ready), [0]);
    for code in [
        FlowErrorCode::InvalidRequest,
        FlowErrorCode::MetadataConflict,
        FlowErrorCode::PairTimeout,
        FlowErrorCode::FlowLimit,
        FlowErrorCode::DialFailed,
        FlowErrorCode::SessionReplaced,
        FlowErrorCode::InternalError,
    ] {
        let setup: SetupResult = code.into();
        assert_eq!(FlowResult::from(setup), FlowResult::Reject(code));
        assert_eq!(FlowErrorCode::try_from(code as u8).unwrap(), code);
        assert_eq!(encode_flow_result(FlowResult::Reject(code)), [code as u8]);
    }
}

#[test]
fn rejects_unknown_and_non_single_byte_results() {
    assert!(decode_setup_result(&[]).is_err());
    assert!(decode_setup_result(&[0, 1]).is_err());
    assert!(decode_setup_result(&[8]).is_err());
    assert!(FlowErrorCode::try_from(0).is_err());
}

#[tokio::test]
async fn async_setup_and_flow_result_io_are_one_byte() {
    let mut output = Vec::new();
    write_setup_result(&mut output, SetupResult::MetadataConflict)
        .await
        .unwrap();
    write_flow_result(&mut output, FlowResult::Ready)
        .await
        .unwrap();
    assert_eq!(output, [2, 0]);

    let mut input = output.as_slice();
    assert_eq!(
        read_setup_result(&mut input).await.unwrap(),
        SetupResult::MetadataConflict
    );
    assert_eq!(
        read_flow_result(&mut input).await.unwrap(),
        FlowResult::Ready
    );
    assert!(read_setup_result(&mut input).await.is_err());
}
